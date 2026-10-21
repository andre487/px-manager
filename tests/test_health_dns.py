import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from main import (
    DNS_TIMEOUT_SECONDS,
    resolve_host_with_public_dns,
    resolve_host_with_system_dns,
)


class HealthDnsTest(unittest.IsolatedAsyncioTestCase):
    async def test_dns_timeouts(self):
        loop = asyncio.get_running_loop()
        with (
            patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=[])),
            patch("main.asyncio.wait_for", wraps=asyncio.wait_for) as wait,
        ):
            await resolve_host_with_system_dns("proxy.example")
        self.assertEqual(DNS_TIMEOUT_SECONDS, wait.call_args.kwargs["timeout"])
        with (
            patch("main.dns.asyncresolver.Resolver") as factory,
            patch(
                "main.resolve_dns_record", new=AsyncMock(return_value=([], None))
            ) as resolve,
        ):
            await resolve_host_with_public_dns("proxy.example", "1.1.1.1")
        self.assertEqual(DNS_TIMEOUT_SECONDS, factory.return_value.lifetime)
        self.assertEqual(15, factory.return_value.timeout)
        self.assertEqual(2, resolve.await_count)

    async def test_verbose_timeout_is_logged_but_returned_once_as_short_message(self):
        import dns.exception

        details = 'The resolution lifetime expired: Server Do53:1.1.1.1@53 ' * 20
        error = dns.exception.Timeout(details)
        with patch('main.dns.asyncresolver.Resolver') as factory:
            resolver = factory.return_value
            resolver.resolve = AsyncMock(side_effect=error)
            with self.assertLogs('px_manager.error', level='WARNING') as logs:
                result = await resolve_host_with_public_dns('proxy.example', '1.1.1.1')
        self.assertEqual('Превышено время ожидания DNS', result['error'])
        self.assertFalse(result['ok'])
        self.assertEqual(2, len(logs.output))
        for record_type, log in zip(('A', 'AAAA'), logs.output):
            self.assertIn(details, log)
            self.assertIn(
                'host=proxy.example nameserver=1.1.1.1 record=' + record_type, log
            )

    async def test_system_timeout_is_short_and_logged(self):
        loop = asyncio.get_running_loop()
        with (
            patch.object(
                loop,
                'getaddrinfo',
                new=AsyncMock(side_effect=TimeoutError('Detailed system timeout')),
            ),
            self.assertLogs('px_manager.error', level='WARNING') as logs,
        ):
            result = await resolve_host_with_system_dns('proxy.example')
        self.assertEqual('Превышено время ожидания DNS', result['error'])
        self.assertIn('Detailed system timeout', logs.output[0])
        self.assertIn('nameserver=system', logs.output[0])

    async def test_success_cache_is_per_resolver_and_errors_are_not_cached(self):
        from main import DNS_RESULT_CACHE, resolve_host_with_dns

        DNS_RESULT_CACHE.clear()
        self.addCleanup(DNS_RESULT_CACHE.clear)
        success = {'ok': True, 'addresses': ['192.0.2.1'], 'error': None}
        failure = {'ok': False, 'addresses': [], 'error': 'Timeout'}
        with (
            patch(
                'main.resolve_host_with_system_dns', new=AsyncMock(return_value=success)
            ) as system,
            patch(
                'main.resolve_host_with_public_dns',
                new=AsyncMock(side_effect=[success, failure, failure]),
            ) as public,
        ):
            for host in ('Proxy.example', 'proxy.example'):
                self.assertEqual(success, await resolve_host_with_dns(host, 'system'))
                self.assertEqual(
                    success, await resolve_host_with_dns(host, 'cloudflare')
                )
                self.assertEqual(failure, await resolve_host_with_dns('failed.example', 'cloudflare'))
        system.assert_awaited_once()
        self.assertEqual(3, public.await_count)
        self.assertEqual(2, len(DNS_RESULT_CACHE))

    async def test_lru_eviction_and_expiry_after_one_hour(self):
        import time

        from main import DNS_CACHE_TTL_SECONDS, DNS_RESULT_CACHE, resolve_host_with_dns

        DNS_RESULT_CACHE.clear()
        self.addCleanup(DNS_RESULT_CACHE.clear)
        success = {'ok': True, 'addresses': ['192.0.2.1'], 'error': None}
        with (
            patch('main.DNS_CACHE_MAX_SIZE', 2),
            patch(
                'main.resolve_host_with_system_dns', new=AsyncMock(return_value=success)
            ) as resolve,
        ):
            await resolve_host_with_dns('a.example', 'system')
            expires, result = DNS_RESULT_CACHE[('a.example', 'system')]
            self.assertEqual(3600, DNS_CACHE_TTL_SECONDS)
            self.assertAlmostEqual(3600, expires - time.monotonic(), delta=1)
            await resolve_host_with_dns('b.example', 'system')
            await resolve_host_with_dns('a.example', 'system')
            await resolve_host_with_dns('c.example', 'system')
            self.assertEqual(
                [('a.example', 'system'), ('c.example', 'system')],
                list(DNS_RESULT_CACHE),
            )
            DNS_RESULT_CACHE[('a.example', 'system')] = (0, result)
            await resolve_host_with_dns('a.example', 'system')
            self.assertEqual(4, resolve.await_count)
