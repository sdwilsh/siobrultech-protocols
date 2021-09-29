import asyncio
import logging
from typing import List, Optional, Tuple

import pytest

LOG = logging.getLogger(__name__)


class MockGem(asyncio.Protocol):
    def __init__(self) -> None:
        self._transport: Optional[asyncio.WriteTransport] = None
        self._expects_and_replies: List[Tuple[bytes, Optional[bytes]]] = []
        self._buffer = bytearray()

    def connection_made(self, transport: asyncio.WriteTransport) -> None:
        self._transport = transport

    def data_received(self, data: bytes) -> None:
        assert self._transport is not None

        self._buffer += data

        while len(self._buffer) > 0 and len(self._expects_and_replies) > 0:
            expected, reply = self._expects_and_replies[0]
            if self._buffer.startswith(expected):
                LOG.debug(f"Mock GEM received expected: {expected}")
                del self._buffer[0 : len(expected)]
                if reply is not None:
                    LOG.debug(f"Sending reply: {reply}")
                    self.send(reply)
                else:
                    LOG.debug(f"No reply specified")
                del self._expects_and_replies[0]
            else:
                # Should have received the first part of it anyway
                if not expected.startswith(self._buffer):
                    pytest.fail(
                        f"Mock GEM received unexpected data\n\tExpected: {expected}\n\tReceived: {bytes(self._buffer)}\n"
                    )

    def expect(self, received: bytes, reply: Optional[bytes]) -> None:
        self._expects_and_replies.append((received, reply))

    def send(self, data: bytes) -> None:
        assert self._transport is not None

        self._transport.write(data)
