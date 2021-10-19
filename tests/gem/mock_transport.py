import asyncio
from typing import List


class MockTransport(asyncio.WriteTransport):
    def __init__(self) -> None:
        self.writes: List[bytes] = []

    def write(self, data: bytes) -> None:
        self.writes.append(data)
