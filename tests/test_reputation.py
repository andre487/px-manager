import asyncio
import json
import unittest
from unittest.mock import AsyncMock, Mock, patch

import reputation
from main import run_https_proxy_request_check_endpoint


class ReputationTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reputation.CACHE.clear()
        reputation.PENDING.clear()

    async def test_cache_ttl_lru_and_shared_requests(self):
        check = AsyncMock(return_value={'status': 'ok', 'fields': {'VPN': False}})
        with patch('reputation.monotonic', return_value=100) as clock:
            results = await asyncio.gather(
                *(
                    reputation.cached_check('test', '192.0.2.1', 'key', check)
                    for _ in range(3)
                )
            )
            self.assertEqual(1, check.await_count)
            self.assertTrue(all(result['status'] == 'ok' for result in results))
            clock.return_value += reputation.CACHE_TTL_SECONDS - 1
            cached = await reputation.cached_check('test', '192.0.2.1', 'key', check)
            self.assertTrue(cached['cached'])
            clock.return_value += 1
            await reputation.cached_check('test', '192.0.2.1', 'key', check)
            self.assertEqual(2, check.await_count)
        with patch('reputation.CACHE_MAX_SIZE', 2):
            await reputation.cached_check('test', '192.0.2.2', 'key', check)
            await reputation.cached_check('test', '192.0.2.1', 'key', check)
            await reputation.cached_check('test', '192.0.2.3', 'key', check)
        self.assertEqual(
            ['192.0.2.1', '192.0.2.3'], [key[1] for key in reputation.CACHE]
        )

    async def test_failures_unknown_and_missing_keys_are_not_cached(self):
        for status in ('error', 'unknown'):
            check = AsyncMock(return_value={'status': status})
            for _ in range(2):
                await reputation.cached_check('test', '192.0.2.1', '', check)
            self.assertEqual(2, check.await_count)
        result = await reputation.get_reputation(
            '192.0.2.1',
            {},
            AsyncMock(return_value={'status': 'ok', 'fields': {'VPN': False}}),
        )
        self.assertEqual(4, sum(item['status'] == 'unconfigured' for item in result))
        self.assertEqual(1, len(reputation.CACHE))

    async def test_arbitrary_ip_skips_yandex_and_reuses_shared_cache(self):
        ip = '192.0.2.1'
        with patch(
            'reputation.check_service',
            new=AsyncMock(return_value={'status': 'ok', 'fields': {'VPN': False}}),
        ) as check:
            first = await reputation.get_reputation(
                ip,
                {'ipqs': 'key'},
                AsyncMock(return_value={'status': 'ok', 'fields': {'VPN': False}}),
            )
            second = await reputation.get_reputation(ip, {'ipqs': 'key'})
        self.assertNotIn('yandex', [result['provider'] for result in second])
        self.assertTrue(
            next(result for result in second if result['provider'] == 'ipqs')['cached']
        )
        check.assert_awaited_once_with('ipqs', ip, 'key')

    def test_provider_responses(self):
        ip = '192.0.2.1'
        for provider, data, field, value in (
            (
                'cloudflare',
                {
                    'success': True,
                    'result': {
                        'ip': {
                            'ip': ip,
                            'asn': '15169',
                            'asnOrgName': 'Google LLC',
                            'asnName': 'GOOGLE',
                        }
                    },
                },
                'Провайдер',
                'Google LLC',
            ),
            (
                'proxycheck',
                {'status': 'ok', ip: {'proxy': 'yes', 'type': 'VPN', 'risk': 73}},
                'Риск (0–100)',
                73,
            ),
            ('ipqs', {'success': True, 'vpn': False, 'fraud_score': 0}, 'VPN', False),
            ('ipapi', {'ip': ip, 'is_vpn': True}, 'VPN', True),
        ):
            with self.subTest(provider=provider):
                result = reputation.parse_result(provider, ip, data)
                self.assertEqual('ok', result['status'])
                self.assertEqual(value, result['fields'][field])
                with self.assertRaises((ValueError, KeyError)):
                    reputation.parse_result(provider, ip, {})

    async def test_api_keys_stay_server_side_and_errors_are_redacted(self):
        client = Mock(fetch=AsyncMock(side_effect=RuntimeError('secret-api-key')))
        with patch('reputation.AsyncHTTPClient', return_value=client):
            for provider in ('cloudflare', 'proxycheck', 'ipqs', 'ipapi'):
                result = await reputation.check_service(
                    provider, '2001:db8::1', 'secret-api-key'
                )
                self.assertEqual('error', result['status'])
                self.assertNotIn('secret-api-key', json.dumps(result))
                request = client.fetch.call_args.args[0]
                self.assertFalse(request.follow_redirects)
                if provider == 'cloudflare':
                    self.assertEqual(
                        'Bearer secret-api-key', request.headers['Authorization']
                    )
                    self.assertNotIn('secret-api-key', request.url)
                if provider in ('ipqs', 'ipapi'):
                    self.assertEqual('POST', request.method)
                    body = json.loads(request.body)
                    self.assertEqual('secret-api-key', body['key'])

    async def test_successful_api_requests(self):
        ip = '192.0.2.1'
        samples = {
            'cloudflare': {
                'success': True,
                'result': {
                    'ip': {'ip': ip, 'asn': '15169', 'asnOrgName': 'Google LLC'}
                },
            },
            'proxycheck': {'status': 'ok', ip: {'proxy': 'no', 'risk': 0}},
            'ipqs': {'success': True, 'vpn': False, 'fraud_score': 0},
            'ipapi': {'ip': ip, 'is_vpn': False},
        }
        for provider, data in samples.items():
            client = Mock(
                fetch=AsyncMock(return_value=Mock(body=json.dumps(data).encode()))
            )
            with (
                self.subTest(provider=provider),
                patch('reputation.AsyncHTTPClient', return_value=client),
            ):
                result = await reputation.check_service(provider, ip, 'test-key')
                self.assertEqual('ok', result['status'])
                request = client.fetch.call_args.args[0]
                self.assertTrue(request.url.startswith('https://'))
                if provider == 'cloudflare':
                    self.assertEqual(
                        'Bearer test-key', request.headers['Authorization']
                    )
                    self.assertIn('ip=192.0.2.1', request.url)
                elif provider == 'proxycheck':
                    self.assertIn('vpn=1', request.url)
                    self.assertIn('risk=1', request.url)
                else:
                    body = json.loads(request.body)
                    self.assertEqual(ip, body['ip' if provider == 'ipqs' else 'q'])
        self.assertNotIn('abuseipdb', reputation.PROVIDERS)

    def test_cloudflare_rejects_wrong_ip_and_handles_missing_organization(self):
        data = {
            'success': True,
            'result': {
                'ip': {
                    'ip': '8.8.8.8',
                    'asn': '15169',
                    'asnName': 'GOOGLE',
                }
            },
        }
        result = reputation.parse_result('cloudflare', '8.8.8.8', data)
        self.assertEqual('GOOGLE', result['fields']['Провайдер'])
        with self.assertRaises(ValueError):
            reputation.parse_result('cloudflare', '1.1.1.1', data)

    async def test_yandex_post_through_proxy_and_three_way_result(self):
        for header, expected in (
            (b'0', False),
            (b'1', True),
            (b'2', None),
            (None, None),
        ):
            headers = {'x-yandex-eu-request': header.decode()} if header else {}
            with patch(
                'main.proxy_request',
                new=AsyncMock(
                    return_value=(
                        200,
                        headers,
                        '',
                        {},
                    )
                ),
            ) as request:
                result = await run_https_proxy_request_check_endpoint(
                    {'host': 'proxy.example'},
                    'alice',
                    'password',
                    'mobileproxy.passport.yandex.net',
                    443,
                    '/tmgrdfrend/checkvpn',
                    'yandex',
                )
            if expected is None:
                self.assertEqual('unknown', result['status'])
            else:
                self.assertIs(expected, result['fields']['VPN обнаружен'])
            request.assert_awaited_once_with(
                {'host': 'proxy.example'},
                'alice',
                'password',
                'mobileproxy.passport.yandex.net',
                443,
                '/tmgrdfrend/checkvpn',
                method='POST',
            )
