import json
import pathlib
import re
import tempfile
import unittest
from http.cookies import SimpleCookie
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from tornado.testing import AsyncHTTPTestCase
from tornado.web import create_signed_value

from main import SESSION_COOKIE_NAME, make_app, safe_retpath


class RetpathTest(unittest.TestCase):
    def test_only_local_paths_are_accepted(self):
        for value in (
            '/',
            '/health',
            '/lookup?target=example.com#result',
            '/lookup?target=%D1%82%D0%B5%D1%81%D1%82',
        ):
            with self.subTest(value=value):
                self.assertEqual(value, safe_retpath(value))
        for value in (
            '',
            'https://evil.test/',
            '//evil.test/',
            '///evil.test',
            '\\evil.test',
            '/\\evil.test',
            ' /health',
            '\n/health',
            '/%2fevil.test',
            '/%252fevil.test',
            '/%5cevil.test',
            '/health%0d%0aLocation:https://evil.test',
            '/health\x00',
            '/%FF',
            '/' + 'a' * 2048,
        ):
            with self.subTest(value=value):
                self.assertEqual('/', safe_retpath(value))


class AuthRedirectTest(AsyncHTTPTestCase):
    def get_app(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / 'hosts.json').write_text('[]')
        (root / 'passwd.json').write_text('{}')
        return make_app(root, root, root, root, 'test-secret')

    def test_pages_preserve_path_and_query(self):
        for target in (
            '/health',
            '/lookup?target=example.com',
            '/doc',
            '/admin',
            '/admin/auth.log?order=asc',
        ):
            with self.subTest(target=target):
                response = self.fetch(target, follow_redirects=False)
                self.assertEqual(302, response.code)
                location = urlsplit(response.headers['Location'])
                self.assertEqual('/', location.path)
                self.assertEqual([target], parse_qs(location.query)['retpath'])

    def test_login_preserves_retpath_after_failure_and_validates_post(self):
        target = '/lookup?target=1.1.1.1&extra=2'
        page = self.fetch('/?' + urlencode({'retpath': target}))
        self.assertIn(
            b'name="retpath" value="/lookup?target=1.1.1.1&amp;extra=2"', page.body
        )
        xsrf = re.search(rb'name="_xsrf" value="([^"]+)"', page.body).group(1).decode()
        cookies = SimpleCookie()
        cookies.load(page.headers['Set-Cookie'])
        headers = {'Cookie': '_xsrf=' + cookies['_xsrf'].value}
        with patch.object(
            self._app.settings['password_store'], 'verify', return_value=False
        ):
            failed = self.fetch(
                '/',
                method='POST',
                headers=headers,
                body=urlencode(
                    {
                        '_xsrf': xsrf,
                        'retpath': target,
                        'username': 'alice',
                        'password': 'wrong',
                    }
                ),
                follow_redirects=False,
            )
        self.assertEqual(401, failed.code)
        self.assertIn(
            b'name="retpath" value="/lookup?target=1.1.1.1&amp;extra=2"', failed.body
        )
        with patch.object(
            self._app.settings['password_store'], 'verify', return_value=True
        ):
            for value, expected in (
                (target, target),
                ('//evil.test', '/'),
                ('/%252fevil.test', '/'),
            ):
                response = self.fetch(
                    '/',
                    method='POST',
                    headers=headers,
                    body=urlencode(
                        {
                            '_xsrf': xsrf,
                            'retpath': value,
                            'username': 'alice',
                            'password': 'secret',
                        }
                    ),
                    follow_redirects=False,
                )
                self.assertEqual(302, response.code)
                self.assertEqual(expected, response.headers['Location'])
                self.assertIn(SESSION_COOKIE_NAME, response.headers['Set-Cookie'])

    def test_expired_session_returns_401_and_admin_denial_stays_403(self):
        session = self._app.settings['session_store'].create('alice', 'secret')
        cookie = create_signed_value(
            'test-secret', SESSION_COOKIE_NAME, session
        ).decode()
        headers = {'Cookie': f'{SESSION_COOKIE_NAME}={cookie}'}
        self.assertEqual(403, self.fetch('/admin', headers=headers).code)
        self._app.settings['session_store'].delete(session)
        response = self.fetch('/api', headers=headers, follow_redirects=False)
        self.assertEqual(401, response.code)
        self.assertEqual(
            {'error': 'authentication_required'}, json.loads(response.body)
        )
