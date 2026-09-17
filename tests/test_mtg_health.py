import asyncio
import base64
import hmac
import struct
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlencode

from telethon.tl.types import ResPQ

from main import (
    parse_tg_proxy_health_host,
    run_mtproxy_request_check,
    run_mtg_request_check,
)
from mtg_health import MTGConnection, handshake, make_client_hello, read_record

SECRET = b'\xee' + bytes(range(16)) + b'example.org'


def record(kind, data):
    return bytes([kind]) + b'\x03\x03' + len(data).to_bytes(2, 'big') + data


class MTGHealthTest(unittest.IsolatedAsyncioTestCase):
    async def test_real_plain_sender_accepts_matching_telegram_response(self):
        connection = Mock(stage='Telegram', connect=AsyncMock(), disconnect=AsyncMock())
        connection.send = AsyncMock()

        async def receive():
            request = connection.send.call_args.args[0]
            nonce = int.from_bytes(request[24:40], 'little', signed=True)
            response = bytes(ResPQ(nonce, 1, b'\x01\x43', [1]))
            return struct.pack('<qqi', 0, 1, len(response)) + response

        connection.recv = receive
        with patch('main.MTGConnection', return_value=connection):
            result = await run_mtg_request_check(
                {'host': 'proxy.example', 'port': 443, 'secret': SECRET.hex()}
            )
        self.assertTrue(result['ok'])
        self.assertIn('dc1/Fake TLS', result['status_line'])
        connection.disconnect.assert_awaited_once()

    async def test_cancellation_closes_connection(self):
        connection = Mock(
            stage='Fake TLS',
            connect=AsyncMock(side_effect=asyncio.CancelledError),
            disconnect=AsyncMock(),
        )
        with patch('main.MTGConnection', return_value=connection):
            with self.assertRaises(asyncio.CancelledError):
                await run_mtg_request_check(
                    {'host': 'proxy.example', 'port': 443, 'secret': SECRET.hex()}
                )
        connection.disconnect.assert_awaited_once()

    def test_client_hello_authentication_and_sni(self):
        with patch('mtg_health.time.time', return_value=1700000000):
            hello, random = make_client_hello(SECRET)
        self.assertIn(b'example.org', hello)
        digest = hmac.digest(
            SECRET[1:17], hello[:11] + bytes(32) + hello[43:], 'sha256'
        )
        decoded = bytes(a ^ b for a, b in zip(random, digest))
        self.assertEqual(bytes(28) + (1700000000).to_bytes(4, 'little'), decoded)

    def test_enables_request_for_hex_and_base64_on_domain_and_ip(self):
        for host in ('proxy.example', '192.0.2.1'):
            for secret in (
                SECRET.hex(),
                base64.urlsafe_b64encode(SECRET).decode().rstrip('='),
            ):
                with self.subTest(host=host, secret_format=len(secret)):
                    url = 'tg://proxy?' + urlencode(
                        dict(server=host, port=443, secret=secret)
                    )
                    parsed = parse_tg_proxy_health_host(url, 1)
                    self.assertIn('head', parsed['health_checks'])

    async def test_server_signature_validation(self):
        for valid in (True, False):
            with self.subTest(valid=valid):
                reader = asyncio.StreamReader()
                writer = Mock(drain=AsyncMock())

                def reply(hello):
                    if hello[0] != 22:
                        return
                    server = record(
                        22,
                        b'\x02\x00\x00\x26\x03\x03' + bytes(32) + b'\x00\x13\x01\x00',
                    )
                    suffix = record(20, b'\x01') + record(23, b'noise')
                    signature = hmac.digest(
                        SECRET[1:17], hello[11:43] + server + suffix, 'sha256'
                    )
                    if not valid:
                        signature = bytes(32)
                    reader.feed_data(server[:11] + signature + server[43:] + suffix)

                writer.write.side_effect = reply
                if valid:
                    await handshake(reader, writer, SECRET)
                    self.assertEqual(
                        record(20, b'\x01'), writer.write.call_args.args[0]
                    )
                else:
                    with self.assertRaisesRegex(ValueError, 'Подпись'):
                        await handshake(reader, writer, SECRET)

    async def test_rejects_oversized_record_before_reading_payload(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x17\x03\x03\xff\xff')
        with self.assertRaises(ValueError):
            await read_record(reader)

    async def test_receive_handles_fragmented_records_and_padding(self):
        connection = MTGConnection('proxy.example', 443, SECRET, 1)
        connection.reader = asyncio.StreamReader()
        connection.decrypt = Mock(encrypt=lambda data: data)
        packet = (11).to_bytes(4, 'little') + b'abcdefghXYZ'
        for chunk in (packet[:2], packet[2:7], packet[7:]):
            connection.reader.feed_data(record(23, chunk))
        self.assertEqual(b'abcdefgh', await connection.recv())

    async def test_fake_tls_dispatch(self):
        with patch('main.run_mtg_request_check', new_callable=AsyncMock) as probe:
            probe.return_value = {'ok': True}
            host = {'secret': SECRET.hex()}
            self.assertEqual({'ok': True}, await run_mtproxy_request_check(host))
            probe.assert_awaited_once_with(host)

    async def test_failed_handshake_is_closed_without_retrying_dcs(self):
        connection = Mock(
            stage='Fake TLS',
            connect=AsyncMock(side_effect=TimeoutError),
            disconnect=AsyncMock(),
        )
        with patch('main.MTGConnection', return_value=connection) as factory:
            result = await run_mtg_request_check(
                {'host': 'proxy.example', 'port': 443, 'secret': SECRET.hex()}
            )
        self.assertFalse(result['ok'])
        self.assertIn('Fake TLS: timeout', result['error'])
        self.assertEqual(1, factory.call_count)
        connection.disconnect.assert_awaited_once()

    async def test_nonce_mismatch_never_reports_success(self):
        connections = []

        def create(*args):
            connection = Mock(
                stage='Telegram', connect=AsyncMock(), disconnect=AsyncMock()
            )
            connections.append(connection)
            return connection

        sender = Mock(send=AsyncMock(return_value=Mock(nonce=-1)))
        with (
            patch('main.MTGConnection', side_effect=create),
            patch('main.MTProtoPlainSender', return_value=sender),
        ):
            result = await run_mtg_request_check(
                {'host': 'proxy.example', 'port': 443, 'secret': SECRET.hex()}
            )
        self.assertFalse(result['ok'])
        self.assertIn('nonce', result['error'])
        for connection in connections:
            connection.disconnect.assert_awaited_once()
