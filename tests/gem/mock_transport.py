import asyncio
from typing import List

from siobrultech_protocols.gem.protocol import BidirectionalProtocol


class MockTransport(asyncio.WriteTransport):
    def __init__(self) -> None:
        self.writes: List[bytes] = []
        self.closed: bool = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def close(self) -> None:
        self.closed = True


class MockRespondingTransport(asyncio.WriteTransport):
    def __init__(
        self,
        protocol: BidirectionalProtocol,
        encoded_response: bytes,
    ) -> None:
        self._protocol = protocol
        self._encoded_response = encoded_response

    def write(self, data: bytes) -> None:
        loop = asyncio.get_event_loop()
        loop.call_soon(self._protocol.data_received, self._encoded_response)
