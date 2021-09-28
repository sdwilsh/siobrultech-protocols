import asyncio
from typing import List, Optional, Tuple


class MockGemProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self._transport: Optional[asyncio.WriteTransport] = None
        self._expects_and_replies: List[Tuple[bytes, bytes]] = []
        self._buffer = bytearray()

    def connection_made(self, transport: asyncio.WriteTransport) -> None:
        self._transport = transport

    def data_received(self, data: bytes) -> None:
        assert self._transport is not None

        self._buffer += data

        while len(self._buffer) > 0 and len(self._expects_and_replies) > 0:
            expected, reply = self._expects_and_replies[0]
            if self._buffer.startswith(expected):
                del self._buffer[0 : len(expected)]
                self._transport.write(reply)
                del self._expects_and_replies[0]
            else:
                # Should have received the first part of it anyway
                assert expected.startswith(self._buffer)

    def expect(self, received: bytes, reply: bytes) -> None:
        self._expects_and_replies.append((received, reply))
