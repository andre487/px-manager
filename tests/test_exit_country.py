import unittest
from unittest.mock import AsyncMock, patch

from main import (
    COUNTRY_ENDPOINTS,
    HEALTH_RESULT_CACHE,
    IP_ECHO_ENDPOINTS,
    extract_ip_echo,
    parse_country_response,
    run_https_proxy_country_check,
    run_https_proxy_request_check,
    run_https_proxy_request_check_endpoint,
)


class ExitCountryTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        HEALTH_RESULT_CACHE.clear()

    def tearDown(self):
        HEALTH_RESULT_CACHE.clear()

    async def test_country_cache_reused_only_for_same_exit(self):
        with patch(
            'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
        ) as request:
            request.side_effect = [
                {'ok': True, 'exit_ip': '192.0.2.1'},
                {'ok': True, 'country_code': 'NL'},
                {'ok': True, 'exit_ip': '192.0.2.1'},
                {'ok': True, 'exit_ip': '192.0.2.2'},
                {'ok': True, 'country_code': 'DE'},
            ]
            results = [
                await run_https_proxy_request_check({'host': 'proxy.example'}, 'u', 'p')
                for _ in range(3)
            ]
        self.assertEqual(
            ['NL', 'NL', 'DE'], [result['country_code'] for result in results]
        )
        self.assertEqual(5, request.await_count)

    def test_parsers(self):
        for value in (
            ' nl\n',
            '{"country":"nl"}',
            'ip=192.0.2.1\nloc=NL\ntls=TLSv1.3\n',
        ):
            self.assertEqual('NL', parse_country_response(value))
        for value in (
            'NLD',
            '<html>NL</html>',
            '{"country":null}',
            '{}',
            '12',
            'ip=192.0.2.1',
            'loc=123',
            'loc=',
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_country_response(value)
        self.assertEqual('2001:db8::1', extract_ip_echo('2001:db8::1\n'))
        self.assertEqual('192.0.2.1', extract_ip_echo('fl=123\nip=192.0.2.1\nloc=NL\n'))
        self.assertEqual('', extract_ip_echo('ip=invalid\nloc=NL'))
        self.assertEqual('', extract_ip_echo('error 192.0.2.1'))
        self.assertEqual('', extract_ip_echo('999.2.3.4'))

    async def test_country_fallback_preserves_proxy_credentials(self):
        host = {'host': 'proxy.example'}
        with patch(
            'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
        ) as request:
            request.side_effect = [
                {'ok': False, 'error': 'Timeout'},
                {'ok': False, 'error': 'HTTP 429'},
                {'ok': False, 'error': 'Invalid response'},
                {'ok': True, 'country_code': 'NL'},
            ]
            result = await run_https_proxy_country_check(host, 'user', 'password')
        self.assertEqual('NL', result['country_code'])
        self.assertEqual('api.country.is', result['country_provider'])
        self.assertEqual(
            list(COUNTRY_ENDPOINTS), [call.args[3:] for call in request.call_args_list]
        )
        for call in request.call_args_list:
            self.assertEqual((host, 'user', 'password'), call.args[:3])
            self.assertEqual('country', call.kwargs['response_kind'])

    async def test_cloudflare_country_stops_fallbacks(self):
        with patch(
            'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
        ) as request:
            request.return_value = {'ok': True, 'country_code': 'NL'}
            result = await run_https_proxy_country_check({}, 'u', 'p')
        self.assertEqual('speed.cloudflare.com', result['country_provider'])
        self.assertEqual('NL', result['country_code'])
        request.assert_awaited_once_with(
            {},
            'u',
            'p',
            'speed.cloudflare.com',
            443,
            '/cdn-cgi/trace',
            response_kind='country',
        )

    async def test_country_failure_does_not_fail_working_proxy(self):
        with patch(
            'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
        ) as request:
            request.side_effect = [
                {'ok': True, 'exit_ip': '192.0.2.1'},
                *[{'ok': False, 'error': 'Unavailable'} for _ in COUNTRY_ENDPOINTS],
            ]
            result = await run_https_proxy_request_check(
                {'host': 'proxy.example'}, 'u', 'p'
            )
        self.assertTrue(result['ok'])
        self.assertEqual('192.0.2.1', result['exit_ip'])
        self.assertIsNone(result['country_code'])
        self.assertIn('Unavailable', result['country_error'])

    async def test_no_country_lookup_after_ip_failure(self):
        with patch(
            'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
        ) as request:
            request.return_value = {'ok': False, 'error': 'Denied'}
            result = await run_https_proxy_request_check(
                {'host': 'proxy.example'}, 'u', 'p'
            )
        self.assertFalse(result['ok'])
        self.assertEqual(len(IP_ECHO_ENDPOINTS), request.await_count)

    async def test_exit_preserves_transport_metadata(self):
        metadata = {
            'proxy_http_version': 'HTTP/3',
            'proxy_tls_version': 'TLSv1.3',
            'proxy_certificate': {'subject': 'CN=proxy.example'},
        }
        with patch(
            'main.proxy_request',
            new=AsyncMock(
                return_value=(
                    200,
                    {},
                    '192.0.2.1',
                    metadata,
                )
            ),
        ) as request:
            result = await run_https_proxy_request_check_endpoint(
                {'host': 'proxy.example'},
                'u',
                'p',
                'api.ipify.org',
                443,
                '/',
            )
        self.assertTrue(result['ok'])
        self.assertEqual('192.0.2.1', result['exit_ip'])
        for key, value in metadata.items():
            self.assertEqual(value, result[key])
        request.assert_awaited_once_with(
            {'host': 'proxy.example'}, 'u', 'p', 'api.ipify.org', 443, '/', method='GET'
        )

    async def test_cloudflare_exit_first_and_fallback_only_on_failure(self):
        for fail_cloudflare in (False, True):
            success = {'ok': True, 'exit_ip': '192.0.2.1'}
            with (
                self.subTest(fallback=fail_cloudflare),
                patch(
                    'main.run_https_proxy_request_check_endpoint',
                    new=AsyncMock(
                        side_effect=(
                            [{'ok': False, 'error': 'Timeout'}]
                            if fail_cloudflare
                            else []
                        )
                        + [success]
                    ),
                ) as request,
                patch(
                    'main.run_https_proxy_country_check',
                    new=AsyncMock(return_value={'country_code': 'NL'}),
                ),
            ):
                result = await run_https_proxy_request_check(
                    {'host': 'proxy.example'}, 'u', 'p'
                )
            self.assertTrue(result['ok'])
            self.assertEqual(
                ('speed.cloudflare.com', 443, '/cdn-cgi/trace'),
                request.await_args_list[0].args[3:],
            )
            self.assertEqual(2 if fail_cloudflare else 1, request.await_count)
            if fail_cloudflare:
                self.assertEqual(
                    ('ifconfig.me', 443, '/ip'), request.await_args_list[1].args[3:]
                )
