import contextlib
import unittest
from unittest.mock import AsyncMock, Mock, patch

import anyio

import proxy_transport


class TransportTest(unittest.IsolatedAsyncioTestCase):
    async def test_response_framing_and_limits(self):
        for response, expected in (
            (b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nNL\n', 'NL'),
            (b'HTTP/1.1 200 OK\r\n\r\nNL\n', 'NL'),
            (
                b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nN\r\n2;ext=1\r\nL\n\r\n0\r\n\r\n',
                'NL',
            ),
            (b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nN', None),
            (b'HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n' + b'N' * 5000, None),
        ):

            @contextlib.asynccontextmanager
            async def tunnel(*args, **kwargs):
                yield Mock(), {}

            stream = Mock(
                send=AsyncMock(),
                receive=AsyncMock(side_effect=[response, anyio.EndOfStream]),
            )
            with (
                self.subTest(response=response[:60]),
                patch('proxy_transport.proxy_tunnel', tunnel),
                patch(
                    'proxy_transport.TLSStream.wrap', new=AsyncMock(return_value=stream)
                ),
            ):
                if expected is None:
                    with self.assertRaises(Exception):
                        await proxy_transport.proxy_request(
                            {}, 'u', 'p', 'example.com', 443, '/'
                        )
                else:
                    result = await proxy_transport.proxy_request(
                        {}, 'u', 'p', 'example.com', 443, '/'
                    )
                    self.assertEqual(expected, result[2])
                    sent = b''.join(
                        call.args[0] for call in stream.send.await_args_list
                    )
                    self.assertNotIn(b'Proxy-Authorization', sent)

    async def test_only_quic_timeout_falls_back_to_tcp(self):
        for error in (
            TimeoutError(),
            ConnectionError('Certificate invalid'),
            ValueError('CONNECT HTTP 407'),
        ):

            @contextlib.asynccontextmanager
            async def connect(*args, **kwargs):
                raise error
                yield

            stream = Mock(aclose=AsyncMock())
            tcp = AsyncMock(return_value=(stream, {'proxy_http_version': 'HTTP/2'}))
            with (
                self.subTest(error=type(error)),
                patch('proxy_transport.connect', connect),
                patch('proxy_transport.connect_tcp', tcp),
            ):
                if isinstance(error, TimeoutError):
                    async with proxy_transport.proxy_tunnel(
                        {'host': 'localhost', 'http3_enabled': True},
                        'u',
                        'p',
                        'example.com',
                        443,
                    ) as (_, metadata):
                        self.assertEqual('HTTP/3', metadata['proxy_fallback_from'])
                        self.assertEqual('HTTP/2', metadata['proxy_http_version'])
                    stream.aclose.assert_awaited_once()
                else:
                    with self.assertRaises(type(error)):
                        async with proxy_transport.proxy_tunnel(
                            {'host': 'localhost', 'http3_enabled': True},
                            'u',
                            'p',
                            'example.com',
                            443,
                        ):
                            self.fail('Unexpected tunnel')
                    tcp.assert_not_called()

    async def test_strict_h3_never_falls_back_even_if_inventory_disables_h3(self):
        @contextlib.asynccontextmanager
        async def timeout(*args, **kwargs):
            raise TimeoutError()
            yield

        with (
            patch('proxy_transport.connect', timeout),
            patch('proxy_transport.connect_tcp', new_callable=AsyncMock) as tcp,
        ):
            with self.assertRaises(TimeoutError):
                async with proxy_transport.proxy_tunnel(
                    {'host': 'localhost', 'http3_enabled': False},
                    'u',
                    'p',
                    'example.com',
                    443,
                    protocol='h3',
                ):
                    self.fail('Unexpected tunnel')
            tcp.assert_not_called()

    async def test_strict_h2_rejects_other_alpn_and_closes_connection(self):
        writer = Mock(wait_closed=AsyncMock())
        writer.get_extra_info.return_value.selected_alpn_protocol.return_value = (
            'http/1.1'
        )
        with patch(
            'proxy_transport.asyncio.open_connection',
            new=AsyncMock(return_value=(Mock(), writer)),
        ):
            with self.assertRaisesRegex(ValueError, 'HTTP/2 не согласован'):
                await proxy_transport.connect_tcp(
                    'localhost', 443, 'example.com:443', b'dTpw', protocol='h2'
                )
        writer.close.assert_called_once()
