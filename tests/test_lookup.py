import pathlib
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

from tornado.testing import AsyncHTTPTestCase
from tornado.web import create_signed_value

from main import SESSION_COOKIE_NAME, make_app
from reputation import parse_lookup_target


class LookupTargetTest(unittest.TestCase):
    def test_normalization_and_validation(self):
        for value, expected in (
            (' 8.8.8.8 ', ('8.8.8.8', True)),
            ('2001:0db8::1', ('2001:db8::1', True)),
            ('Example.COM.', ('example.com', False)),
            ('пример.рф', ('xn--e1afmkfd.xn--p1ai', False)),
        ):
            self.assertEqual(expected, parse_lookup_target(value))
        for value in (
            '',
            ' ',
            'https://example.com/',
            'example.com:443',
            'a..com',
            'example.com..',
            '-bad.com',
            'a' * 64 + '.com',
            '999.1.2.3',
            'fe80::1%lo0',
            '<script>alert(1)</script>',
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_lookup_target(value)


class LookupPageTest(AsyncHTTPTestCase):
    def get_app(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / 'hosts.json').write_text('[]')
        (root / 'passwd.json').write_text('{}')
        return make_app(root, root, root, root, 'test-secret')

    def lookup(self, target=None):
        session = self._app.settings['session_store'].create('alice', 'password')
        cookie = create_signed_value(
            'test-secret', SESSION_COOKIE_NAME, session
        ).decode()
        path = '/lookup' + (
            '?' + urlencode({'target': target}) if target is not None else ''
        )
        return self.fetch(path, headers={'Cookie': f'{SESSION_COOKIE_NAME}={cookie}'})

    def test_auth_form_and_invalid_input_do_not_trigger_checks(self):
        self.assertEqual(302, self.fetch('/lookup', follow_redirects=False).code)
        with (
            patch('main.get_reputation', new_callable=AsyncMock) as check,
            patch('main.resolve_host_addresses', new_callable=AsyncMock) as dns,
        ):
            response = self.lookup()
            self.assertEqual(200, response.code)
            self.assertIn('IP-адрес или домен', response.body.decode())
            response = self.lookup('<script>alert(1)</script>')
            self.assertEqual(400, response.code)
            self.assertNotIn(b'<script>', response.body)
            self.assertIn(b'&lt;script&gt;', response.body)
            check.assert_not_awaited()
            dns.assert_not_awaited()

    def test_ip_skips_dns_and_renders_reputation(self):
        results = [
            {
                'name': 'Cloudflare Radar',
                'status': 'ok',
                'cached': True,
                'checked_at': 1800000000,
                'fields': {'Провайдер': 'Example', 'VPN': False},
            }
        ]
        with (
            patch('main.get_reputation', new=AsyncMock(return_value=results)) as check,
            patch('main.resolve_host_addresses', new_callable=AsyncMock) as dns,
        ):
            response = self.lookup('2001:0db8::1')
            self.assertEqual(200, response.code)
            text = response.body.decode()
            self.assertIn('2001:db8::1', text)
            self.assertIn('Example', text)
            self.assertIn('Из кеша', text)
            self.assertIn('Нет', text)
            check.assert_awaited_once_with('2001:db8::1', {})
            dns.assert_not_awaited()

    def test_domain_unions_dns_answers_even_if_one_resolver_fails(self):
        result = {
            'system': {'ok': False, 'addresses': [], 'error': 'Timeout'},
            'cloudflare': {
                'ok': True,
                'addresses': ['192.0.2.1', '2001:db8::1'],
                'error': None,
            },
        }
        with (
            patch(
                'main.resolve_host_addresses', new=AsyncMock(return_value=result)
            ) as dns,
            patch('main.get_reputation', new=AsyncMock(return_value=[])) as check,
        ):
            response = self.lookup('ПРИМЕР.РФ.')
            self.assertEqual(200, response.code)
            self.assertIn('Timeout', response.body.decode())
            dns.assert_awaited_once_with('xn--e1afmkfd.xn--p1ai')
            self.assertEqual(
                ['192.0.2.1', '2001:db8::1'],
                [call.args[0] for call in check.await_args_list],
            )

    def test_dns_failure_and_domain_lookup_limit(self):
        result = {
            name: {'ok': False, 'addresses': [], 'error': 'NXDOMAIN'}
            for name in ('system', 'cloudflare')
        }
        with (
            patch('main.resolve_host_addresses', new=AsyncMock(return_value=result)),
            patch('main.get_reputation', new=AsyncMock(return_value=[])) as check,
        ):
            response = self.lookup('missing.example')
            self.assertIn('DNS не вернул IP-адресов', response.body.decode())
            check.assert_not_awaited()
            result['system']['addresses'] = [
                f'192.0.2.{index}' for index in range(1, 19)
            ]
            response = self.lookup('many.example')
            self.assertEqual(16, check.await_count)
            self.assertIn('остальные можно проверить отдельно', response.body.decode())
