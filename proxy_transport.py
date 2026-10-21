import asyncio
import base64
import contextlib
import ssl
from contextlib import asynccontextmanager

import anyio
import h2.config
import h2.connection
import h2.events
import h11
from aioquic.asyncio import connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.events import ConnectionTerminated, StreamReset
from anyio.abc import ByteStream
from anyio.streams.tls import TLSStream
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from proxy_speed import VerifiedQuicProtocol, quic_config


def certificate_info(certificate):
    return {
        'subject': certificate.subject.rfc4514_string(),
        'issuer': certificate.issuer.rfc4514_string(),
        'not_before': certificate.not_valid_before_utc.isoformat(),
        'not_after': certificate.not_valid_after_utc.isoformat(),
        'sha256': certificate.fingerprint(hashes.SHA256()).hex(':'),
    }


def authority(host, port):
    return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'


class TcpTunnel(ByteStream):
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.connection = None
        self.pending = bytearray()
        self.ended = False

    async def frames(self):
        data = await self.reader.read(65536)
        if not data:
            raise anyio.EndOfStream
        events = self.connection.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.DataReceived):
                self.pending.extend(event.data)
                if len(self.pending) > 131072:
                    raise ValueError('Слишком большой ответ прокси')
                self.connection.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            elif isinstance(
                event,
                (
                    h2.events.StreamEnded,
                    h2.events.StreamReset,
                    h2.events.ConnectionTerminated,
                ),
            ):
                self.ended = True
        self.writer.write(self.connection.data_to_send())
        await self.writer.drain()
        return events

    async def receive(self, max_bytes=65536):
        if self.connection is None:
            data = await self.reader.read(max_bytes)
            if not data:
                raise anyio.EndOfStream
            return data
        while not self.pending:
            if self.ended:
                raise anyio.EndOfStream
            await self.frames()
        data = bytes(self.pending[:max_bytes])
        del self.pending[:max_bytes]
        return data

    async def send(self, item):
        if self.connection is None:
            self.writer.write(item)
        else:
            offset = 0
            while offset < len(item):
                window = min(
                    self.connection.local_flow_control_window(1),
                    self.connection.max_outbound_frame_size,
                )
                if not window:
                    if self.ended:
                        raise anyio.EndOfStream
                    self.writer.write(self.connection.data_to_send())
                    await self.writer.drain()
                    await self.frames()
                    continue
                self.connection.send_data(1, item[offset : offset + window])
                offset += window
            self.writer.write(self.connection.data_to_send())
        await self.writer.drain()

    async def send_eof(self):
        await self.aclose()

    async def aclose(self):
        self.writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.writer.wait_closed(), 1)


class QuicTunnel(ByteStream):
    def __init__(self, protocol):
        self.protocol = protocol
        self.reader = asyncio.StreamReader()
        self.buffered = 0

    def feed(self, data):
        self.buffered += len(data)
        if self.buffered > 131072:
            self.reader.set_exception(ValueError('Слишком большой ответ прокси'))
            self.protocol.close()
        else:
            self.reader.feed_data(data)

    async def receive(self, max_bytes=65536):
        data = await self.reader.read(max_bytes)
        if not data:
            raise anyio.EndOfStream
        self.buffered -= len(data)
        return data

    async def send(self, item):
        self.protocol.http.send_data(self.protocol.stream, item, end_stream=False)
        self.protocol.transmit()

    async def send_eof(self):
        await self.aclose()

    async def aclose(self):
        self.protocol.close()


class Http3Connect(VerifiedQuicProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.stream = None
        self.accepted = None
        self.tunnel = QuicTunnel(self)

    def quic_event_received(self, event):
        super().quic_event_received(event)
        if isinstance(event, (ConnectionTerminated, StreamReset)):
            error = ConnectionError('HTTP/3 CONNECT прерван')
            if self.accepted and not self.accepted.done():
                self.accepted.set_exception(error)
            self.tunnel.reader.set_exception(error)
        for message in self.http.handle_event(event):
            if getattr(message, 'stream_id', None) != self.stream:
                continue
            if isinstance(message, HeadersReceived):
                status = int(dict(message.headers).get(b':status', b'0'))
                if status >= 200 and self.accepted and not self.accepted.done():
                    if status == 200:
                        self.accepted.set_result(None)
                    else:
                        self.accepted.set_exception(
                            ValueError(f'CONNECT HTTP {status}')
                        )
            elif isinstance(message, DataReceived):
                self.tunnel.feed(message.data)
            if getattr(message, 'stream_ended', False):
                self.tunnel.reader.feed_eof()

    async def open(self, target, credentials):
        self.stream = self._quic.get_next_available_stream_id()
        self.accepted = asyncio.get_running_loop().create_future()
        self.http.send_headers(
            self.stream,
            [
                (b':method', b'CONNECT'),
                (b':authority', target.encode()),
                (b'proxy-authorization', b'Basic ' + credentials),
            ],
        )
        self.transmit()
        await self.accepted


async def connect_tcp(host, port, target, credentials, protocol='auto'):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2'] if protocol == 'h2' else ['h2', 'http/1.1'])
    reader, writer = await asyncio.open_connection(
        host, port, ssl=context, server_hostname=host
    )
    tunnel = TcpTunnel(reader, writer)
    try:
        tls = writer.get_extra_info('ssl_object')
        selected = tls.selected_alpn_protocol()
        if protocol == 'h2' and selected != 'h2':
            raise ValueError('HTTP/2 не согласован')
        protocol = selected
        metadata = {
            'proxy_http_version': 'HTTP/2' if protocol == 'h2' else 'HTTP/1.1',
            'proxy_tls_version': tls.version(),
            'proxy_certificate': certificate_info(
                x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
            ),
        }
        if protocol == 'h2':
            connection = tunnel.connection = h2.connection.H2Connection(
                h2.config.H2Configuration(client_side=True)
            )
            connection.initiate_connection()
            connection.send_headers(
                1,
                [
                    (b':method', b'CONNECT'),
                    (b':authority', target.encode()),
                    (b'proxy-authorization', b'Basic ' + credentials),
                ],
            )
            writer.write(connection.data_to_send())
            await writer.drain()
            while True:
                events = await tunnel.frames()
                response = next(
                    (
                        event
                        for event in events
                        if isinstance(event, h2.events.ResponseReceived)
                    ),
                    None,
                )
                if response:
                    status = int(dict(response.headers)[b':status'])
                    break
                if tunnel.ended:
                    raise ConnectionError('HTTP/2 CONNECT прерван')
        else:
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=16384)
            writer.write(
                connection.send(
                    h11.Request(
                        method='CONNECT',
                        target=target,
                        headers=[
                            ('Host', target),
                            ('Proxy-Authorization', 'Basic ' + credentials.decode()),
                        ],
                    )
                )
            )
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
            while True:
                event = connection.next_event()
                if isinstance(event, h11.Response):
                    status = event.status_code
                    metadata['proxy_http_version'] = (
                        'HTTP/' + event.http_version.decode()
                    )
                    break
                if event is h11.NEED_DATA:
                    connection.receive_data(await tunnel.receive())
                elif isinstance(event, h11.ConnectionClosed):
                    raise ConnectionError('HTTP CONNECT прерван')
        if status != 200:
            raise ValueError(f'CONNECT HTTP {status}')
        return tunnel, metadata
    except BaseException:
        await tunnel.aclose()
        raise


@asynccontextmanager
async def proxy_tunnel(
    host_data, username, password, target_host, target_port, protocol='auto'
):
    if protocol not in ('auto', 'h2', 'h3'):
        raise ValueError('Неизвестный протокол прокси')
    target = authority(target_host, target_port)
    credentials = base64.b64encode(f'{username}:{password}'.encode())
    if protocol == 'h3' or (protocol == 'auto' and host_data.get('http3_enabled')):
        async with contextlib.AsyncExitStack() as stack:
            try:
                async with asyncio.timeout(3):
                    quic = await stack.enter_async_context(
                        connect(
                            host_data['host'],
                            int(host_data.get('port', 443)),
                            configuration=quic_config(host_data['host']),
                            create_protocol=Http3Connect,
                        )
                    )
                    await quic.open(target, credentials)
            except TimeoutError:
                if protocol == 'h3':
                    raise
                fallback = True
            else:
                yield quic.tunnel, {
                    'proxy_http_version': 'HTTP/3',
                    'proxy_tls_version': 'TLSv1.3',
                    'proxy_certificate': certificate_info(
                        quic._quic.tls._peer_certificate
                    ),
                }
                return
    else:
        fallback = False
    tunnel, metadata = await connect_tcp(
        host_data['host'],
        int(host_data.get('port', 443)),
        target,
        credentials,
        protocol=protocol,
    )
    if fallback:
        metadata['proxy_fallback_from'] = 'HTTP/3'
    try:
        yield tunnel, metadata
    finally:
        await tunnel.aclose()


async def proxy_request(
    host_data,
    username,
    password,
    target_host,
    target_port,
    path,
    method='GET',
    protocol='auto',
):
    async with proxy_tunnel(
        host_data,
        username,
        password,
        target_host,
        target_port,
        protocol=protocol,
    ) as (tunnel, metadata):
        tls = await TLSStream.wrap(
            tunnel,
            hostname=target_host,
            ssl_context=ssl.create_default_context(),
            standard_compatible=False,
        )
        connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=16384)
        headers = [
            ('Host', target_host),
            ('User-Agent', 'px-manager/health'),
            ('Accept', 'text/plain'),
            ('Connection', 'close'),
        ]
        if method == 'POST':
            headers.append(('Content-Length', '0'))
        await tls.send(
            connection.send(h11.Request(method=method, target=path, headers=headers))
        )
        await tls.send(connection.send(h11.EndOfMessage()))
        status, response_headers, body = None, {}, bytearray()
        while True:
            event = connection.next_event()
            if event is h11.NEED_DATA:
                try:
                    data = await tls.receive(65536)
                except anyio.EndOfStream:
                    data = b''
                connection.receive_data(data)
            elif isinstance(event, h11.Response):
                status = event.status_code
                response_headers = {
                    key.decode().lower(): value.decode('iso-8859-1')
                    for key, value in event.headers
                }
            elif isinstance(event, h11.Data):
                body.extend(event.data)
                if len(body) > 4096:
                    raise ValueError('Слишком большой ответ геосервиса')
            elif isinstance(event, h11.EndOfMessage):
                return (
                    status,
                    response_headers,
                    body.decode('utf-8', 'replace').strip(),
                    metadata,
                )
            elif isinstance(event, h11.ConnectionClosed):
                raise ConnectionError('Ответ внешнего сервиса прерван')
