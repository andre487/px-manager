import asyncio
import json
import pathlib
import tempfile
from http.cookies import SimpleCookie
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.web import create_signed_value

from main import SESSION_COOKIE_NAME, make_app


class ConfigDownloadTest(AsyncHTTPTestCase):
    def get_app(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / "hosts.json").write_text(
            json.dumps(
                [
                    {"host": "one.example", "title": "One"},
                    {"host": "two.example", "port": 8443, "selected": True},
                ]
            )
        )
        (root / "passwd.json").write_text("{}")
        return make_app(root, root, root, root, "test-secret")

    def test_all_downloads(self):
        session = self._app.settings["session_store"].create("alice", "s@cret")
        cookie = create_signed_value(
            "test-secret", SESSION_COOKIE_NAME, session
        ).decode()
        with (
            patch("main.get_tls_fingerprint", return_value="ab" * 20) as fingerprint,
            patch(
                "main.socket.create_connection",
                side_effect=AssertionError("unexpected network"),
            ),
        ):
            for name, extension, content_type in (
                ("proxy-list", "txt", "text/plain"),
                ("super-proxy", "txt", "text/plain"),
                ("foxy-proxy", "json", "application/json"),
                ("mega-proxy", "json", "application/json"),
                ("shadowrocket", "conf", "text/plain"),
            ):
                with self.subTest(name=name):
                    response = self.fetch(
                        "/api/generate/" + name,
                        headers={"Cookie": f"{SESSION_COOKIE_NAME}={cookie}"},
                    )
                    self.assertEqual(200, response.code)
                    self.assertEqual(
                        content_type + "; charset=utf-8",
                        response.headers["Content-Type"],
                    )
                    self.assertIn(
                        f'filename="alice-{name}.{extension}"',
                        response.headers["Content-Disposition"],
                    )
                    self.assertIn(b"one.example", response.body)
                    self.assertIn(b"two.example", response.body)
                    if extension == "json":
                        json.loads(response.body)
                    if name == "super-proxy":
                        self.assertIn(
                            ("?fingerprint=" + "ab" * 20).encode(), response.body
                        )
                        self.assertIn(b"@two.example:8443?fingerprint=", response.body)
                        self.assertTrue(response.body.endswith(b'"two.example" *\n'))
            self.assertEqual(2, fingerprint.call_count)

    def test_reputation_requires_auth_and_matches_proxy_exit(self):
        path = '/api/health/reputation?host=one.example&ip=192.0.2.1'
        self.assertEqual(401, self.fetch(path).code)
        session = self._app.settings['session_store'].create('alice', 'password')
        cookie = create_signed_value('test-secret', SESSION_COOKIE_NAME, session).decode()
        headers = {'Cookie': f'{SESSION_COOKIE_NAME}={cookie}'}
        with (
            patch('main.run_https_proxy_request_check', new=AsyncMock(return_value={'ok': True, 'exit_ip': '192.0.2.1'})),
            patch('main.get_reputation', new=AsyncMock(return_value=[])) as check,
        ):
            response = self.fetch(path, headers=headers)
            self.assertEqual(200, response.code)
            self.assertEqual('no-store', response.headers['Cache-Control'])
            self.assertEqual('192.0.2.1', json.loads(response.body)['ip'])
            check.assert_awaited_once()
            self.assertEqual(
                409,
                self.fetch(
                    path.replace('192.0.2.1', '192.0.2.2'), headers=headers
                ).code,
            )
            self.assertEqual(
                400,
                self.fetch(
                    path.replace('one.example', 'not-allowed.example'), headers=headers
                ).code,
            )
            self.assertEqual(1, check.await_count)

    def test_yandex_does_not_classify_a_changed_exit(self):
        session = self._app.settings['session_store'].create('alice', 'password')
        cookie = create_signed_value('test-secret', SESSION_COOKIE_NAME, session).decode()

        async def check(ip, keys, yandex_check):
            return [await yandex_check()]

        with (
            patch(
                'main.run_https_proxy_request_check',
                new=AsyncMock(
                    side_effect=[
                        {'ok': True, 'exit_ip': '192.0.2.1'},
                        {'ok': True, 'exit_ip': '192.0.2.2'},
                    ]
                ),
            ),
            patch('main.get_reputation', side_effect=check),
            patch(
                'main.run_https_proxy_request_check_endpoint', new_callable=AsyncMock
            ) as request,
        ):
            response = self.fetch(
                '/api/health/reputation?host=one.example&ip=192.0.2.1',
                headers={'Cookie': f'{SESSION_COOKIE_NAME}={cookie}'},
            )
        self.assertEqual(200, response.code)
        self.assertEqual('error', json.loads(response.body)['results'][0]['status'])
        request.assert_not_awaited()

    def test_speed_stream_validation_csrf_and_lock_cleanup(self):
        session = self._app.settings['session_store'].create('alice', 'password')
        cookie = create_signed_value(
            'test-secret', SESSION_COOKIE_NAME, session
        ).decode()
        session_cookie = f'{SESSION_COOKIE_NAME}={cookie}'
        page = self.fetch('/health', headers={'Cookie': session_cookie})
        self.assertEqual(200, page.code)
        cookies = SimpleCookie()
        for value in page.headers.get_list('Set-Cookie'):
            cookies.load(value)
        xsrf = cookies['_xsrf'].value
        headers = {'Cookie': session_cookie + '; _xsrf=' + xsrf}
        body = {'_xsrf': xsrf, 'megabytes': '10', 'protocol': 'h2'}
        path = '/api/health/speed?host=one.example'

        async def run(host, username, password, megabytes, protocol, publish):
            self.assertEqual(
                ('alice', 'password', 10, 'h2'),
                (username, password, megabytes, protocol),
            )
            await publish({'stage': 'metadata', 'protocol': protocol})
            await publish({'stage': 'complete', 'download_mbps': 12.5})

        with patch('main.run_speed_test', side_effect=run) as check:
            response = self.fetch(
                path, method='POST', headers=headers, body=urlencode(body)
            )
            self.assertEqual(200, response.code)
            self.assertIn('application/x-ndjson', response.headers['Content-Type'])
            self.assertEqual('no-store', response.headers['Cache-Control'])
            self.assertEqual(
                ['metadata', 'complete'],
                [json.loads(line)['stage'] for line in response.body.splitlines()],
            )
            self.assertFalse(self._app.settings['speed_test_running'])

            for values in ({**body, 'megabytes': '1000'}, {**body, 'protocol': 'h3'}):
                self.assertEqual(
                    400,
                    self.fetch(
                        path, method='POST', headers=headers, body=urlencode(values)
                    ).code,
                )
            self.assertEqual(
                400,
                self.fetch(
                    path.replace('one.example', 'evil.example'),
                    method='POST',
                    headers=headers,
                    body=urlencode(body),
                ).code,
            )
            self.assertEqual(
                403,
                self.fetch(
                    path, method='POST', headers=headers, body='megabytes=10'
                ).code,
            )
            self.assertEqual(
                401,
                self.fetch(
                    path,
                    method='POST',
                    headers={'Cookie': '_xsrf=' + xsrf},
                    body=urlencode(body),
                ).code,
            )
            self._app.settings['speed_test_running'] = True
            self.assertEqual(
                409,
                self.fetch(
                    path, method='POST', headers=headers, body=urlencode(body)
                ).code,
            )
            self._app.settings['speed_test_running'] = False
            self.assertEqual(1, check.call_count)
        with patch('main.run_speed_test', side_effect=ValueError('Test failure')):
            response = self.fetch(
                path, method='POST', headers=headers, body=urlencode(body)
            )
            self.assertEqual('error', json.loads(response.body)['stage'])
            self.assertFalse(self._app.settings['speed_test_running'])

    @gen_test
    async def test_speed_disconnect_cancels_measurement(self):
        session = self._app.settings['session_store'].create('alice', 'password')
        cookie = create_signed_value(
            'test-secret', SESSION_COOKIE_NAME, session
        ).decode()
        session_cookie = f'{SESSION_COOKIE_NAME}={cookie}'
        page = await self.http_client.fetch(
            self.get_url('/health'), headers={'Cookie': session_cookie}
        )
        cookies = SimpleCookie()
        for value in page.headers.get_list('Set-Cookie'):
            cookies.load(value)
        xsrf = cookies['_xsrf'].value
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def run(host, username, password, megabytes, protocol, publish):
            try:
                await publish({'stage': 'metadata'})
                started.set()
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        body = urlencode({'_xsrf': xsrf, 'megabytes': 10, 'protocol': 'h2'})
        with patch('main.run_speed_test', side_effect=run):
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', self.get_http_port()
            )
            writer.write(
                (
                    f'POST /api/health/speed?host=one.example HTTP/1.1\r\n'
                    f'Host: localhost\r\nCookie: {session_cookie}; _xsrf={xsrf}\r\n'
                    f'Content-Type: application/x-www-form-urlencoded\r\n'
                    f'Content-Length: {len(body)}\r\n\r\n{body}'
                ).encode()
            )
            await writer.drain()
            await asyncio.wait_for(started.wait(), 2)
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(cancelled.wait(), 2)
            await asyncio.sleep(0)
            self.assertFalse(self._app.settings['speed_test_running'])

    @gen_test
    async def test_dns_resolvers_respond_independently(self):
        session = self._app.settings['session_store'].create('alice', 'password')
        cookie = create_signed_value('test-secret', SESSION_COOKIE_NAME, session).decode()
        headers = {'Cookie': f'{SESSION_COOKIE_NAME}={cookie}'}
        cloudflare_started, release_cloudflare = asyncio.Event(), asyncio.Event()

        async def resolve(host, resolver):
            if resolver == 'cloudflare':
                cloudflare_started.set()
                await release_cloudflare.wait()
                return {'ok': False, 'addresses': [], 'error': 'Превышено время ожидания DNS'}
            return {'ok': True, 'addresses': ['192.0.2.1'], 'error': None}

        with patch('main.resolve_host_with_dns', side_effect=resolve):
            cloudflare = self.http_client.fetch(self.get_url('/api/health/dns?host=one.example&resolver=cloudflare'), headers=headers)
            try:
                await asyncio.wait_for(cloudflare_started.wait(), 1)
                for resolver in ('system',):
                    response = await asyncio.wait_for(self.http_client.fetch(self.get_url('/api/health/dns?host=one.example&resolver=' + resolver), headers=headers), 1)
                    data = json.loads(response.body)
                    self.assertTrue(data['ok'])
                    self.assertEqual(resolver, data['resolver'])
                    self.assertEqual(['192.0.2.1'], data['addresses'])
                    self.assertFalse(cloudflare.done())
            finally:
                release_cloudflare.set()
                response = await cloudflare
            self.assertFalse(json.loads(response.body)['ok'])
            invalid = await self.http_client.fetch(self.get_url('/api/health/dns?host=one.example&resolver=google'), headers=headers, raise_error=False)
            self.assertEqual(400, invalid.code)

    def test_protocol_checks_are_authenticated_strict_and_independent(self):
        path = '/api/health/protocol?host=one.example&protocol=h2'
        self.assertEqual(401, self.fetch(path).code)
        session = self._app.settings['session_store'].create('alice', 'password')
        cookie = create_signed_value('test-secret', SESSION_COOKIE_NAME, session).decode()
        headers = {'Cookie': f'{SESSION_COOKIE_NAME}={cookie}'}
        metadata = {'proxy_http_version': 'HTTP/2', 'proxy_tls_version': 'TLSv1.3'}
        with patch('main.proxy_request', new=AsyncMock(side_effect=[(200, {}, 'ip=192.0.2.1', metadata), TimeoutError()])) as request:
            response = self.fetch(path, headers=headers)
            self.assertTrue(json.loads(response.body)['ok'])
            self.assertEqual('h2', request.await_args.kwargs['protocol'])
            response = self.fetch(path.replace('protocol=h2', 'protocol=h3'), headers=headers)
            self.assertFalse(json.loads(response.body)['ok'])
            self.assertEqual('h3', request.await_args.kwargs['protocol'])
            invalid = self.fetch(path.replace('protocol=h2', 'protocol=auto'), headers=headers)
            self.assertEqual(400, invalid.code)
            invalid = self.fetch(path.replace('one.example', 'evil.example'), headers=headers)
            self.assertEqual(400, invalid.code)
