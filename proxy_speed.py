import asyncio
import base64
import contextlib
import ipaddress
import statistics
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import certifi
import httpx
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, H3Connection, Setting
from aioquic.h3.events import DatagramReceived, DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamReset
from aioquic.quic.packet import (
    pull_quic_transport_parameters,
    push_quic_transport_parameters,
)

ORIGIN = 'https://h3.speed.cloudflare.com'
SIZES_MB = (10, 25, 50)
MEGABYTE = 1_000_000
ZERO_BLOCK = bytes(65536)


def quic_config(host, *, datagrams=False):
    return QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        server_name=host,
        cafile=certifi.where(),
        max_datagram_frame_size=65536 if datagrams else None,
        max_datagram_size=1350 if datagrams else 1200,
        max_data=16_000_000,
        max_stream_data=8_000_000,
        idle_timeout=30,
    )


class VerifiedQuicProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake = asyncio.Event()
        self.disconnected = False

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake.set()
        elif isinstance(event, ConnectionTerminated):
            self.disconnected = True
            self.handshake.set()

    async def wait_connected(self):
        await self.handshake.wait()
        if self.disconnected:
            raise ConnectionError('Не удалось установить проверенное QUIC-соединение')


class TunnelQuicConnection(QuicConnection):
    def _serialize_transport_parameters(self):
        # aioquic's send MTU does not advertise a receive MTU; reserve outer QUIC overhead.
        parameters = pull_quic_transport_parameters(
            Buffer(data=super()._serialize_transport_parameters())
        )
        parameters.max_udp_payload_size = 1200
        buffer = Buffer(capacity=65536)
        push_quic_transport_parameters(buffer, parameters)
        return buffer.data


class Http3Client(VerifiedQuicProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.response = None
        self.stream = None

    def quic_event_received(self, event):
        super().quic_event_received(event)
        if isinstance(event, (ConnectionTerminated, StreamReset)):
            if self.response and not self.response.done():
                self.response.set_exception(
                    ConnectionError('HTTP/3 соединение прервано')
                )
        for message in self.http.handle_event(event):
            if (
                not self.response
                or self.response.done()
                or getattr(message, 'stream_id', None) != self.stream
            ):
                continue
            if isinstance(message, HeadersReceived):
                headers = dict(message.headers)
                if b':status' in headers:
                    status = int(headers[b':status'])
                    if status < 200:
                        continue
                    if status >= 300:
                        self.response.set_exception(
                            ValueError(f'Cloudflare HTTP {status}')
                        )
                        continue
                    self.ttfb = (time.monotonic() - self.started) * 1000
            elif isinstance(message, DataReceived):
                self.received += len(message.data)
                if self.received > self.limit:
                    self.response.set_exception(
                        ValueError('Слишком большой ответ Cloudflare')
                    )
                    continue
                if self.capture:
                    self.body.extend(message.data)
            if getattr(message, 'stream_ended', False):
                if self.ttfb is None:
                    self.response.set_exception(
                        ValueError('HTTP/3 ответ без заголовков')
                    )
                else:
                    self.response.set_result(None)

    async def request(self, path, upload=0, limit=65536, capture=False):
        self.stream = self._quic.get_next_available_stream_id()
        response = self.response = asyncio.get_running_loop().create_future()
        self.received, self.limit, self.capture = 0, limit, capture
        self.body, self.ttfb = bytearray(), None
        self.started = time.monotonic()
        headers = [
            (b':method', b'POST' if upload else b'GET'),
            (b':scheme', b'https'),
            (b':authority', urlsplit(ORIGIN).netloc.encode()),
            (b':path', path.encode()),
            (b'accept-encoding', b'identity'),
            (b'user-agent', b'PX Manager speed-test'),
        ]
        if upload:
            headers += [
                (b'content-length', str(upload).encode()),
                (b'content-type', b'application/octet-stream'),
            ]
        self.http.send_headers(self.stream, headers, end_stream=not upload)
        self.transmit()
        try:
            async with asyncio.timeout(120):
                # ponytail: at most 50 MB queued in aioquic; flow-aware streaming for larger tests.
                for offset in range(0, upload, len(ZERO_BLOCK)):
                    self.http.send_data(
                        self.stream,
                        ZERO_BLOCK[: min(len(ZERO_BLOCK), upload - offset)],
                        end_stream=offset + len(ZERO_BLOCK) >= upload,
                    )
                    self.transmit()
                    await asyncio.sleep(0)
                    if response.done() and offset + len(ZERO_BLOCK) < upload:
                        await response
                        raise ConnectionError(
                            'Cloudflare ответил до завершения отправки'
                        )
                await response
            return {
                'bytes': self.received,
                'body': bytes(self.body),
                'ttfb_ms': self.ttfb,
                'seconds': time.monotonic() - self.started,
            }
        finally:
            if not response.done():
                response.cancel()
            self.response = None


class DatagramHttp3(H3Connection):
    def _get_local_settings(self):
        return {**super()._get_local_settings(), Setting.H3_DATAGRAM: 1}


class MasqueClient(VerifiedQuicProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = DatagramHttp3(self._quic)
        self.settings_ready = asyncio.Event()
        self.accepted = None
        self.stream = None
        self.inner = None
        self.failed = False

    def quic_event_received(self, event):
        super().quic_event_received(event)
        if isinstance(event, (ConnectionTerminated, StreamReset)):
            self.failed = True
            self.settings_ready.set()
            if self.accepted and not self.accepted.done():
                self.accepted.set_exception(
                    ConnectionError('MASQUE соединение прервано')
                )
            if self.inner:
                self.inner.close()
        for message in self.http.handle_event(event):
            if (
                isinstance(message, HeadersReceived)
                and message.stream_id == self.stream
            ):
                headers = dict(message.headers)
                status = int(headers.get(b':status', b'0'))
                if status < 200:
                    continue
                if self.accepted and not self.accepted.done():
                    if status != 200 or headers.get(b'capsule-protocol') != b'?1':
                        self.accepted.set_exception(
                            ValueError(f'MASQUE CONNECT-UDP отклонён: HTTP {status}')
                        )
                    else:
                        self.accepted.set_result(None)
                if message.stream_ended and self.inner:
                    self.inner.close()
            elif (
                isinstance(message, DatagramReceived)
                and message.stream_id == self.stream
            ):
                if self.inner and message.data.startswith(b'\x00'):
                    self.inner.datagram_received(message.data[1:], ('192.0.2.1', 443))
            elif (
                isinstance(message, DataReceived)
                and message.stream_id == self.stream
                and message.stream_ended
            ):
                if self.inner:
                    self.inner.close()
        if self.http.received_settings is not None:
            self.settings_ready.set()

    async def tunnel(self, authority, username, password):
        await self.settings_ready.wait()
        settings = self.http.received_settings or {}
        if (
            self.failed
            or not settings.get(Setting.H3_DATAGRAM)
            or not settings.get(Setting.ENABLE_CONNECT_PROTOCOL)
        ):
            raise ValueError(
                'Прокси не поддерживает MASQUE CONNECT-UDP и HTTP Datagrams'
            )
        target = urlsplit(ORIGIN)
        self.stream = self._quic.get_next_available_stream_id()
        self.accepted = asyncio.get_running_loop().create_future()
        credentials = base64.b64encode(f'{username}:{password}'.encode())
        self.http.send_headers(
            self.stream,
            [
                (b':method', b'CONNECT'),
                (b':protocol', b'connect-udp'),
                (b':scheme', b'https'),
                (b':authority', authority.encode()),
                (
                    b':path',
                    f'/.well-known/masque/udp/{target.hostname}/{target.port or 443}/'.encode(),
                ),
                (b'capsule-protocol', b'?1'),
                (b'proxy-authorization', b'Basic ' + credentials),
            ],
        )
        self.transmit()
        await self.accepted


class TunnelDatagrams(asyncio.DatagramTransport):
    def __init__(self, proxy):
        self.proxy = proxy

    def sendto(self, data, addr=None):
        self.proxy.http.send_datagram(self.proxy.stream, b'\x00' + data)
        self.proxy.transmit()

    def get_extra_info(self, name, default=None):
        return default

    def close(self):
        pass


@asynccontextmanager
async def http3_client(host, port, username, password):
    async with connect(
        host,
        port,
        configuration=quic_config(host, datagrams=True),
        create_protocol=MasqueClient,
    ) as proxy:
        authority = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        await proxy.tunnel(authority, username, password)
        inner = Http3Client(
            TunnelQuicConnection(configuration=quic_config(urlsplit(ORIGIN).hostname))
        )
        # Virtual peer: every inner QUIC packet travels inside CONNECT-UDP, never directly.
        inner.connection_made(TunnelDatagrams(proxy))
        proxy.inner = inner
        try:
            inner.connect(('192.0.2.1', 443))
            await inner.wait_connected()
            yield inner
        finally:
            inner.close()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(inner.wait_closed(), 3)
            proxy.inner = None


async def http_request(client, protocol, path, upload=0, limit=65536, capture=False):
    async def body():
        for offset in range(0, upload, len(ZERO_BLOCK)):
            yield ZERO_BLOCK[: min(len(ZERO_BLOCK), upload - offset)]

    started = time.monotonic()
    headers = {'Accept-Encoding': 'identity', 'User-Agent': 'PX Manager speed-test'}
    if upload:
        headers.update(
            {'Content-Length': str(upload), 'Content-Type': 'application/octet-stream'}
        )
    async with client.stream(
        'POST' if upload else 'GET',
        ORIGIN + path,
        content=body() if upload else None,
        headers=headers,
    ) as response:
        ttfb = (time.monotonic() - started) * 1000
        if response.http_version != {'h1': 'HTTP/1.1', 'h2': 'HTTP/2'}[protocol]:
            raise ValueError('Запрошенный HTTP-протокол не согласован')
        if not 200 <= response.status_code < 300:
            raise ValueError(f'Cloudflare HTTP {response.status_code}')
        size, data = 0, bytearray()
        async for chunk in response.aiter_raw():
            size += len(chunk)
            if size > limit:
                raise ValueError('Слишком большой ответ Cloudflare')
            if capture:
                data.extend(chunk)
    return {
        'bytes': size,
        'body': bytes(data),
        'ttfb_ms': ttfb,
        'seconds': time.monotonic() - started,
    }


async def measure(request, megabytes, protocol, publish):
    result = {'protocol': protocol, 'megabytes': megabytes}
    await publish({'stage': 'metadata', **result})
    trace = await request('/cdn-cgi/trace', capture=True)
    fields = dict(
        line.split('=', 1)
        for line in trace['body'].decode().splitlines()
        if '=' in line
    )
    result['exit_ip'] = str(ipaddress.ip_address(fields.get('ip', '')))
    result['country_code'] = fields.get('loc')
    await publish({'stage': 'latency', **result})
    samples = [await request('/__down?bytes=0') for _ in range(3)]
    result['latency_ms'] = round(
        statistics.median(sample['ttfb_ms'] for sample in samples), 2
    )
    await publish({'stage': 'download', **result})
    size = megabytes * MEGABYTE
    download = await request(f'/__down?bytes={size}', limit=size)
    if download['bytes'] != size:
        raise ValueError('Cloudflare вернул неполную загрузку')
    result['download_mbps'] = round(size * 8 / download['seconds'] / MEGABYTE, 2)
    await publish({'stage': 'upload', **result})
    upload = await request('/__up', upload=size)
    result['upload_mbps'] = round(size * 8 / upload['seconds'] / MEGABYTE, 2)
    await publish({'stage': 'complete', **result})


async def run_speed_test(host_data, username, password, megabytes, protocol, publish):
    if megabytes not in SIZES_MB or protocol not in ('h1', 'h2', 'h3'):
        raise ValueError('Некорректные параметры замера')
    if host_data.get('proxy_kind') == 'mtproxy':
        raise ValueError('MTProxy не поддерживает HTTP-запросы к Cloudflare')
    host, port = host_data['host'], host_data.get('port', 443)
    async with asyncio.timeout(300):
        if protocol == 'h3':
            if not host_data.get('http3_enabled'):
                raise ValueError('Для этого маршрута не настроен MASQUE/HTTP3')
            async with contextlib.AsyncExitStack() as stack:
                async with asyncio.timeout(15):
                    client = await stack.enter_async_context(
                        http3_client(host, port, username, password)
                    )
                await measure(client.request, megabytes, protocol, publish)
        else:
            kind = 'socks5' if host_data.get('proxy_kind') == 'socks5' else 'https'
            auth = (
                (host_data.get('username', ''), host_data.get('password', ''))
                if kind == 'socks5'
                else (username, password)
            )
            proxy = httpx.Proxy(
                httpx.URL(scheme=kind, host=host, port=port),
                auth=auth if any(auth) else None,
            )
            async with httpx.AsyncClient(
                proxy=proxy,
                http2=protocol == 'h2',
                http1=protocol == 'h1',
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(120, connect=10),
            ) as client:

                async def request(*args, **kwargs):
                    return await http_request(client, protocol, *args, **kwargs)

                await measure(request, megabytes, protocol, publish)
