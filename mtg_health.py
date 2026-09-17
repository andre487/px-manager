import asyncio
import hmac
import secrets
import ssl
import time

from telethon.network.connection.tcpintermediate import (
    RandomizedIntermediatePacketCodec,
)
from telethon.network.connection.tcpmtproxy import MTProxyIO

MAX_RECORD_SIZE = 18432
MAX_PACKET_SIZE = 1024 * 1024


def make_client_hello(secret: bytes) -> tuple[bytes, bytes]:
    if len(secret) <= 17 or secret[0] != 0xEE:
        raise ValueError('Некорректный секрет Fake TLS')
    domain = secret[17:].decode('ascii')
    if not domain or len(domain) > 253 or any(c.isspace() for c in domain):
        raise ValueError('Некорректный домен Fake TLS')
    outgoing = ssl.MemoryBIO()
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    client = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=domain)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = bytearray(outgoing.read())
    if len(hello) < 43 or int.from_bytes(hello[3:5], 'big') != len(hello) - 5:
        raise ValueError('Не удалось сформировать ClientHello')
    # Fake TLS authenticates the entire record with its random field zeroed.
    hello[11:43] = bytes(32)
    random = bytearray(hmac.digest(secret[1:17], hello, 'sha256'))
    timestamp = int(time.time()).to_bytes(4, 'little')
    for index, value in enumerate(timestamp, 28):
        random[index] ^= value
    hello[11:43] = random
    return bytes(hello), bytes(random)


async def read_record(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(5)
    size = int.from_bytes(header[3:5], 'big')
    if header[1:3] != b'\x03\x03' or not 0 < size <= MAX_RECORD_SIZE:
        raise ValueError('Некорректная запись Fake TLS')
    return header + await reader.readexactly(size)


async def handshake(reader, writer, secret: bytes):
    hello, random = make_client_hello(secret)
    writer.write(hello)
    await writer.drain()
    server = await read_record(reader)
    if len(server) < 44 or server[0] != 22 or server[5] != 2:
        raise ValueError('Прокси не вернул ServerHello Fake TLS')
    ccs = await read_record(reader)
    if ccs != b'\x14\x03\x03\x00\x01\x01':
        raise ValueError('Некорректный ChangeCipherSpec Fake TLS')
    noise = await read_record(reader)
    if noise[0] != 23:
        raise ValueError('Прокси не вернул данные Fake TLS')
    received = server[11:43]
    unsigned = server[:11] + bytes(32) + server[43:] + ccs + noise
    expected = hmac.digest(secret[1:17], random + unsigned, 'sha256')
    if not hmac.compare_digest(received, expected):
        raise ValueError('Подпись Fake TLS не совпала: проверьте секрет и адрес прокси')
    writer.write(ccs)
    await writer.drain()


class MTGConnection:
    def __init__(self, host: str, port: int, secret: bytes, dc_id: int):
        self.host = host
        self.port = port
        self.secret = secret
        self.dc_id = dc_id
        self.stage = 'TCP'
        self.reader = None
        self.writer = None
        self.buffer = bytearray()

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.stage = 'Fake TLS'
        await handshake(self.reader, self.writer, self.secret)
        header, self.encrypt, self.decrypt = MTProxyIO.init_header(
            self.secret[1:17], self.dc_id, RandomizedIntermediatePacketCodec
        )
        self.write_record(header)
        await self.writer.drain()
        self.stage = 'Telegram'

    def write_record(self, data: bytes):
        self.writer.write(b'\x17\x03\x03' + len(data).to_bytes(2, 'big') + data)

    async def send(self, data: bytes):
        padding = secrets.token_bytes(secrets.randbelow(4))
        packet = (len(data) + len(padding)).to_bytes(4, 'little') + data + padding
        encrypted = self.encrypt.encrypt(packet)
        for offset in range(0, len(encrypted), 16384):
            self.write_record(encrypted[offset : offset + 16384])
        await self.writer.drain()

    async def readexactly(self, size: int) -> bytes:
        while len(self.buffer) < size:
            record = await read_record(self.reader)
            if record[0] != 23:
                raise ValueError('Неожиданный тип записи Fake TLS')
            self.buffer.extend(self.decrypt.encrypt(record[5:]))
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    async def recv(self) -> bytes:
        size = int.from_bytes(await self.readexactly(4), 'little')
        if not 0 < size <= MAX_PACKET_SIZE:
            raise ValueError('Некорректная длина ответа Telegram')
        packet = await self.readexactly(size)
        return packet[: size - size % 4]

    async def disconnect(self):
        if self.writer is not None:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=1)
            except OSError, TimeoutError:
                pass
