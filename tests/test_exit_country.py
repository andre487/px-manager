import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from main import (
    HEALTH_RESULT_CACHE,
    extract_ip_echo,
    parse_country_response,
    read_http_response_body,
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
        for value in (' nl\n', '{"country":"nl"}'):
            self.assertEqual('NL', parse_country_response(value))
        for value in ('NLD', '<html>NL</html>', '{"country":null}', '{}', '12'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_country_response(value)
        self.assertEqual('2001:db8::1', extract_ip_echo('2001:db8::1\n'))
        self.assertEqual('', extract_ip_echo('error 192.0.2.1'))
        self.assertEqual('', extract_ip_echo('999.2.3.4'))

    async def test_country_fallback_preserves_proxy_credentials(self):
        host = {'host': 'proxy.example'}
        with patch(
            'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
        ) as request:
            request.side_effect = [
                {'ok': False, 'error': 'HTTP 429'},
                {'ok': False, 'error': 'Invalid response'},
                {'ok': True, 'country_code': 'NL'},
            ]
            result = await run_https_proxy_country_check(host, 'user', 'password')
        self.assertEqual('NL', result['country_code'])
        self.assertEqual('api.country.is', result['country_provider'])
        for call in request.call_args_list:
            self.assertEqual((host, 'user', 'password'), call.args[:3])
            self.assertEqual('country', call.kwargs['response_kind'])

    async def test_country_failure_does_not_fail_working_proxy(self):
        with patch(
            'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
        ) as request:
            request.side_effect = [
                {'ok': True, 'exit_ip': '192.0.2.1'},
                *[{'ok': False, 'error': 'Unavailable'} for _ in range(3)],
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
        self.assertEqual(3, request.await_count)

    async def test_http_body_framing(self):
        for headers, body in (
            ({'content-length': '3'}, b'NL\n'),
            ({}, b'NL\n'),
            (
                {'transfer-encoding': 'chunked'},
                b'1\r\nN\r\n2;ext=1\r\nL\n\r\n0\r\n\r\n',
            ),
        ):
            reader = asyncio.StreamReader()
            reader.feed_data(body)
            reader.feed_eof()
            self.assertEqual('NL', await read_http_response_body(reader, headers))

    async def test_body_size_limit(self):
        reader = asyncio.StreamReader()
        with self.assertRaises(ValueError):
            await read_http_response_body(reader, {'content-length': '100000000'})

    async def test_country_request_uses_authenticated_connect_and_target_tls(self):
        reader = asyncio.StreamReader()
        reader.feed_data(
            b'HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nNL'
        )
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        loop = asyncio.get_running_loop()
        with (
            patch(
                'main.asyncio.open_connection',
                new=AsyncMock(return_value=(reader, writer)),
            ) as connect,
            patch.object(loop, 'start_tls', new_callable=AsyncMock) as tls,
        ):
            result = await run_https_proxy_request_check_endpoint(
                {'host': 'proxy.example', 'port': 8443},
                'u',
                'p',
                'ifconfig.co',
                443,
                '/country-iso',
                response_kind='country',
            )
        self.assertTrue(result['ok'])
        self.assertEqual('NL', result['country_code'])
        self.assertEqual(('proxy.example', 8443), connect.call_args.args)
        self.assertEqual('ifconfig.co', tls.call_args.kwargs['server_hostname'])
        sent = [call.args[0] for call in writer.write.call_args_list]
        self.assertIn(b'CONNECT ifconfig.co:443', sent[0])
        self.assertIn(b'Proxy-Authorization: Basic dTpw', sent[0])
        self.assertNotIn(b'Proxy-Authorization', sent[1])
        self.assertIn(b'GET /country-iso', sent[1])
        writer.close.assert_called_once()
