import asyncio


class MockTransport(asyncio.WriteTransport):
    def __init__(self) -> None:
        self.writes = []

    def write(self, data) -> None:
        self.writes.append(data)
