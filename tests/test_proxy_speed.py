import asyncio
import base64
import contextlib
import datetime
import ipaddress
import pathlib
import ssl
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import h2.config
import h2.connection
import h2.events
import httpx
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DatagramReceived, DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import proxy_speed


class SpeedLogicTest(unittest.IsolatedAsyncioTestCase):
    async def test_stages_median_and_exact_byte_count(self):
        request = AsyncMock(
            side_effect=[
                {'body': b'ip=192.0.2.1\nloc=NL'},
                *[{'ttfb_ms': value} for value in (9, 3, 6)],
                {'bytes': 10_000_000, 'seconds': 2},
                {'bytes': 2, 'seconds': 4},
            ]
        )
        publish = AsyncMock()
        await proxy_speed.measure(request, 10, 'h2', publish)
        result = publish.await_args.args[0]
        self.assertEqual('complete', result['stage'])
        self.assertEqual(6, result['latency_ms'])
        self.assertEqual(40, result['download_mbps'])
        self.assertEqual(20, result['upload_mbps'])
        self.assertEqual(10_000_000, request.await_args.kwargs['upload'])
        self.assertEqual(
            ['metadata', 'latency', 'download', 'upload', 'complete'],
            [call.args[0]['stage'] for call in publish.await_args_list],
        )

    async def test_invalid_route_and_size_never_connect(self):
        for host, size, protocol in (
            ({'host': 'proxy', 'proxy_kind': 'mtproxy'}, 10, 'h2'),
            ({'host': 'proxy'}, 1000, 'h2'),
            ({'host': 'proxy'}, 10, 'h3'),
            ({'host': 'proxy'}, 10, 'auto'),
        ):
            with self.assertRaises(ValueError):
                await proxy_speed.run_speed_test(
                    host, 'u', 'p', size, protocol, AsyncMock()
                )

    async def test_http2_does_not_accept_http1_or_truncated_download(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, content=b'', extensions={'http_version': b'HTTP/1.1'}
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            with self.assertRaisesRegex(ValueError, 'не согласован'):
                await proxy_speed.http_request(client, 'h2', '/__down?bytes=0')
        request = AsyncMock(
            side_effect=[
                {'body': b'ip=192.0.2.1'},
                *[{'ttfb_ms': 1} for _ in range(3)],
                {'bytes': 1, 'seconds': 1},
            ]
        )
        with self.assertRaisesRegex(ValueError, 'неполную'):
            await proxy_speed.measure(request, 10, 'h3', AsyncMock())
        self.assertEqual(5, request.await_count)


class SpeedTransportTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        self.cert, self.key = root / 'cert.pem', root / 'key.pem'
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName('localhost'),
                        x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                    ]
                ),
                False,
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.requests, self.proxy_requests, self.uploads = [], [], []

    def tls_context(self, alpn):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        context.set_alpn_protocols(alpn)
        return context

    def response_body(self, path, uploaded):
        if path == '/cdn-cgi/trace':
            return b'ip=192.0.2.1\nloc=NL\n'
        if path == '/__up':
            self.uploads.append(uploaded)
            return b'ok'
        return bytes(int(parse_qs(urlsplit(path).query)['bytes'][0]))

    async def h2_origin(self, reader, writer):
        connection = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False)
        )
        connection.initiate_connection()
        writer.write(connection.data_to_send())
        streams = {}
        try:
            while data := await reader.read(65536):
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        headers = dict(event.headers)
                        self.requests.append(headers)
                        streams[event.stream_id] = [headers[b':path'].decode(), 0]
                    elif isinstance(event, h2.events.DataReceived):
                        streams[event.stream_id][1] += len(event.data)
                        connection.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        path, uploaded = streams.pop(event.stream_id)
                        body = self.response_body(path, uploaded)
                        connection.send_headers(
                            event.stream_id,
                            [
                                (b':status', b'200'),
                                (b'content-length', str(len(body)).encode()),
                            ],
                        )
                        connection.send_data(event.stream_id, body, end_stream=True)
                writer.write(connection.data_to_send())
                await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def test_http2_uses_authenticated_https_proxy(self):
        target = await asyncio.start_server(
            self.h2_origin, '127.0.0.1', 0, ssl=self.tls_context(['h2'])
        )
        self.addAsyncCleanup(target.wait_closed)
        self.addCleanup(target.close)
        target_port = target.sockets[0].getsockname()[1]

        async def proxy(reader, writer):
            headers = await reader.readuntil(b'\r\n\r\n')
            self.proxy_requests.append(headers)
            upstream, outgoing = await asyncio.open_connection('127.0.0.1', target_port)
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()

            async def copy(source, destination):
                try:
                    while data := await source.read(65536):
                        destination.write(data)
                        await destination.drain()
                finally:
                    destination.close()

            await asyncio.gather(copy(reader, outgoing), copy(upstream, writer))

        server = await asyncio.start_server(
            proxy, '127.0.0.1', 0, ssl=self.tls_context(['http/1.1'])
        )
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        publish = AsyncMock()
        with (
            patch('proxy_speed.ORIGIN', f'https://localhost:{target_port}'),
            patch('proxy_speed.MEGABYTE', 64),
            patch('certifi.where', return_value=str(self.cert)),
        ):
            await proxy_speed.run_speed_test(
                {'host': '127.0.0.1', 'port': server.sockets[0].getsockname()[1]},
                'alice',
                'password',
                10,
                'h2',
                publish,
            )
        self.assertEqual('complete', publish.await_args.args[0]['stage'])
        self.assertEqual('h2', publish.await_args.args[0]['protocol'])
        self.assertEqual([640], self.uploads)
        self.assertEqual(6, len(self.requests))
        self.assertEqual(1, len(self.proxy_requests))
        self.assertIn(
            b'Proxy-Authorization: Basic ' + base64.b64encode(b'alice:password'),
            self.proxy_requests[0],
        )
        self.assertTrue(
            all(b'proxy-authorization' not in headers for headers in self.requests)
        )
        with patch('proxy_speed.ORIGIN', f'https://localhost:{target_port}'):
            with self.assertRaises(httpx.ConnectError):
                await proxy_speed.run_speed_test(
                    {'host': '127.0.0.1', 'port': server.sockets[0].getsockname()[1]},
                    'alice',
                    'password',
                    10,
                    'h2',
                    AsyncMock(),
                )
        self.assertEqual(6, len(self.requests))

    async def test_http3_uses_masque_datagrams_without_direct_target_socket(self):
        fixture = self
        relays = []
        packets = []

        class Origin(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.http, self.streams = H3Connection(self._quic), {}

            def quic_event_received(self, event):
                for message in self.http.handle_event(event):
                    if isinstance(message, HeadersReceived):
                        headers = dict(message.headers)
                        fixture.requests.append(headers)
                        self.streams[message.stream_id] = [
                            headers[b':path'].decode(),
                            0,
                        ]
                    elif isinstance(message, DataReceived):
                        self.streams[message.stream_id][1] += len(message.data)
                    if getattr(message, 'stream_ended', False):
                        path, uploaded = self.streams.pop(message.stream_id)
                        body = fixture.response_body(path, uploaded)
                        self.http.send_headers(
                            message.stream_id,
                            [
                                (b':status', b'200'),
                                (b'content-length', str(len(body)).encode()),
                            ],
                        )
                        self.http.send_data(message.stream_id, body, end_stream=True)
                        self.transmit()

        class Proxy(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.http, self.relays = proxy_speed.DatagramHttp3(self._quic), {}

            def quic_event_received(self, event):
                for message in self.http.handle_event(event):
                    if isinstance(message, HeadersReceived):
                        headers = dict(message.headers)
                        fixture.proxy_requests.append(headers)
                        asyncio.create_task(self.open_relay(message.stream_id, headers))
                    elif isinstance(message, DatagramReceived):
                        packets.append(message.data)
                        self.relays[message.stream_id].sendto(message.data[1:])

            async def open_relay(self, stream, headers):
                outer = self

                class Relay(asyncio.DatagramProtocol):
                    def datagram_received(self, data, addr):
                        outer.http.send_datagram(stream, b'\x00' + data)
                        outer.transmit()

                relay, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    Relay, remote_addr=('127.0.0.1', target_port)
                )
                self.relays[stream] = relay
                relays.append(relay)
                self.http.send_headers(
                    stream, [(b':status', b'200'), (b'capsule-protocol', b'?1')]
                )
                self.transmit()

        def configuration(datagrams=True):
            config = QuicConfiguration(
                is_client=False,
                alpn_protocols=['h3'],
                max_datagram_frame_size=65536,
                max_datagram_size=1350 if datagrams else 1200,
            )
            config.load_cert_chain(self.cert, self.key)
            return config

        target = await serve(
            '127.0.0.1', 0, configuration=configuration(False), create_protocol=Origin
        )
        target_port = target._transport.get_extra_info('sockname')[1]
        server = await serve(
            '127.0.0.1', 0, configuration=configuration(), create_protocol=Proxy
        )
        self.addCleanup(target.close)
        self.addCleanup(server.close)
        self.addCleanup(lambda: [relay.close() for relay in relays])
        publish = AsyncMock()
        with (
            patch('proxy_speed.ORIGIN', f'https://localhost:{target_port}'),
            patch('proxy_speed.MEGABYTE', 64),
            patch('certifi.where', return_value=str(self.cert)),
        ):
            await proxy_speed.run_speed_test(
                {
                    'host': '127.0.0.1',
                    'port': server._transport.get_extra_info('sockname')[1],
                    'http3_enabled': True,
                },
                'alice',
                'password',
                10,
                'h3',
                publish,
            )
        self.assertEqual('complete', publish.await_args.args[0]['stage'])
        self.assertEqual('h3', publish.await_args.args[0]['protocol'])
        self.assertTrue(packets)
        self.assertEqual([640], self.uploads)
        self.assertEqual(6, len(self.requests))
        self.assertEqual(1, len(self.proxy_requests))
        headers = self.proxy_requests[0]
        self.assertEqual(b'connect-udp', headers[b':protocol'])
        self.assertEqual(
            b'Basic ' + base64.b64encode(b'alice:password'),
            headers[b'proxy-authorization'],
        )
        self.assertTrue(
            all(b'proxy-authorization' not in headers for headers in self.requests)
        )

    async def test_health_transport_and_certificate_for_http1_http2_http3(self):
        import os

        from proxy_transport import certificate_info, proxy_request

        async def origin(reader, writer):
            try:
                request = await reader.readuntil(b'\r\n\r\n')
                self.requests.append(request)
                self.assertNotIn(b'Proxy-Authorization', request)
                self.assertEqual(
                    'TLSv1.2', writer.get_extra_info('ssl_object').version()
                )
                writer.write(
                    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n192.0.2.1\r\n0\r\n\r\n'
                )
                await writer.drain()
            finally:
                writer.close()

        context = self.tls_context(['http/1.1'])
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        target = await asyncio.start_server(origin, '127.0.0.1', 0, ssl=context)
        self.addAsyncCleanup(target.wait_closed)
        self.addCleanup(target.close)
        target_port = target.sockets[0].getsockname()[1]
        tasks = []

        async def relay(send, end):
            upstream, outgoing = await asyncio.open_connection('127.0.0.1', target_port)

            async def receive():
                try:
                    while data := await upstream.read(65536):
                        await send(data)
                finally:
                    await end()
                    outgoing.close()

            tasks.append(asyncio.create_task(receive()))
            return outgoing

        async def tcp_proxy(reader, writer):
            outgoing = None
            connection = None
            try:
                if writer.get_extra_info('ssl_object').selected_alpn_protocol() == 'h2':
                    connection = h2.connection.H2Connection(
                        h2.config.H2Configuration(client_side=False)
                    )
                    connection.initiate_connection()
                    writer.write(connection.data_to_send())

                    async def send(data):
                        connection.send_data(1, data)
                        writer.write(connection.data_to_send())
                        await writer.drain()

                    async def end():
                        connection.end_stream(1)
                        writer.write(connection.data_to_send())
                        await writer.drain()

                    while data := await reader.read(65536):
                        for event in connection.receive_data(data):
                            if isinstance(event, h2.events.RequestReceived):
                                self.proxy_requests.append(dict(event.headers))
                                outgoing = await relay(send, end)
                                connection.send_headers(1, [(b':status', b'200')])
                            elif isinstance(event, h2.events.DataReceived):
                                outgoing.write(event.data)
                                await outgoing.drain()
                                connection.acknowledge_received_data(
                                    event.flow_controlled_length, 1
                                )
                        writer.write(connection.data_to_send())
                        await writer.drain()
                else:
                    self.proxy_requests.append(await reader.readuntil(b'\r\n\r\n'))

                    async def send(data):
                        writer.write(data)
                        await writer.drain()

                    async def end():
                        writer.close()

                    outgoing = await relay(send, end)
                    writer.write(b'HTTP/1.1 200 OK\r\n\r\n')
                    await writer.drain()
                    while data := await reader.read(65536):
                        outgoing.write(data)
                        await outgoing.drain()
            finally:
                if outgoing:
                    outgoing.close()
                writer.close()

        fixture = self

        class Proxy(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.http = H3Connection(self._quic)
                self.outgoing = None
                self.pending = bytearray()

            async def open(self, stream):
                async def send(data):
                    self.http.send_data(stream, data, end_stream=False)
                    self.transmit()

                async def end():
                    self.http.send_data(stream, b'', end_stream=True)
                    self.transmit()

                self.outgoing = await relay(send, end)
                self.http.send_headers(stream, [(b':status', b'200')])
                self.transmit()

            def quic_event_received(self, event):
                for message in self.http.handle_event(event):
                    if isinstance(message, HeadersReceived):
                        fixture.proxy_requests.append(dict(message.headers))
                        tasks.append(asyncio.create_task(self.open(message.stream_id)))
                    elif isinstance(message, DataReceived):
                        self.outgoing.write(message.data)

        try:
            for protocol in ('HTTP/1.1', 'HTTP/2', 'HTTP/3'):
                with self.subTest(protocol=protocol):
                    if protocol == 'HTTP/3':
                        config = QuicConfiguration(
                            is_client=False, alpn_protocols=['h3']
                        )
                        config.load_cert_chain(self.cert, self.key)
                        server = await serve(
                            '127.0.0.1', 0, configuration=config, create_protocol=Proxy
                        )
                        port = server._transport.get_extra_info('sockname')[1]
                    else:
                        server = await asyncio.start_server(
                            tcp_proxy,
                            '127.0.0.1',
                            0,
                            ssl=self.tls_context(
                                ['h2' if protocol == 'HTTP/2' else 'http/1.1']
                            ),
                        )
                        port = server.sockets[0].getsockname()[1]
                    try:
                        with (
                            patch.dict(os.environ, {'SSL_CERT_FILE': str(self.cert)}),
                            patch('certifi.where', return_value=str(self.cert)),
                        ):
                            async with asyncio.timeout(5):
                                status, headers, body, metadata = await proxy_request(
                                    {
                                        'host': '127.0.0.1',
                                        'port': port,
                                        'http3_enabled': False,
                                    },
                                    'alice',
                                    'password',
                                    'localhost',
                                    target_port,
                                    '/',
                                    protocol={'HTTP/2': 'h2', 'HTTP/3': 'h3'}.get(
                                        protocol, 'auto'
                                    ),
                                )
                        self.assertEqual((200, '192.0.2.1'), (status, body))
                        self.assertEqual(protocol, metadata['proxy_http_version'])
                        self.assertEqual('TLSv1.3', metadata['proxy_tls_version'])
                        self.assertEqual(
                            certificate_info(
                                x509.load_pem_x509_certificate(self.cert.read_bytes())
                            ),
                            metadata['proxy_certificate'],
                        )
                        expected = b'Basic ' + base64.b64encode(b'alice:password')
                        request = self.proxy_requests[-1]
                        self.assertIn(
                            expected,
                            (
                                request
                                if isinstance(request, bytes)
                                else request[b'proxy-authorization']
                            ),
                        )
                    finally:
                        server.close()
                        if protocol != 'HTTP/3':
                            await server.wait_closed()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        self.assertEqual(3, len(self.requests))
