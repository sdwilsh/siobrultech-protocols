import asyncio
import logging
import socket
import sys
import unittest
from typing import Optional

from siobrultech_protocols.gem.api import (
    CMD_DELAY_NEXT_PACKET,
    CMD_GET_SERIAL_NUMBER,
    GemApi,
)
from siobrultech_protocols.gem.protocol import PacketProtocol
from tests.gem.mock_gem import MockGem
from tests.gem.packet_test_data import assert_packet, read_packet

LOG = logging.getLogger(__name__)


class TestApi(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loop = asyncio.get_event_loop()
        api_ready = asyncio.Condition()
        api: Optional[GemApi] = None

        async def set_api(value: GemApi):
            nonlocal api_ready, api
            async with api_ready:
                api = value
                LOG.debug(f"API set {id(api)}")
                api_ready.notify_all()

        def on_connection_made(api: GemApi):
            asyncio.ensure_future(set_api(api))

        self._queue = asyncio.Queue()
        self._server = await loop.create_server(
            lambda: PacketProtocol(self._queue, on_connection_made),
            port=0,
            family=socket.AF_INET,
        )

        port = self._server.sockets[0].getsockname()[1]
        self._transport, gem = await loop.create_connection(
            MockGem, port=port, family=socket.AF_INET
        )
        assert isinstance(gem, MockGem)
        self._gem = gem

        async with api_ready:
            api = await api_ready.wait_for(lambda: api)
            assert api is not None
            self._api = api

    async def asyncTearDown(self) -> None:
        self._transport.close()
        self._server.close()
        await self._server.wait_closed()
        await self._queue.join()

    async def testPacketRacingWithApi(self):
        """Tests that the protocol can handle a packet coming in right after it has
        requested a packet delay from the GEM."""
        self._gem.expect(
            CMD_DELAY_NEXT_PACKET.encode(), reply=read_packet("BIN32-ABS.bin")
        )
        self._gem.expect(CMD_GET_SERIAL_NUMBER.encode(), reply=b"1234567")

        await self.assertSerialNumber(1234567)
        await self.assertPacket("BIN32-ABS.bin")

    async def testApiCallWithPacketInProgress(self):
        """Tests that the protocol can handle a packet that's partially arrived when it
        requested a packet delay from the GEM."""
        packet = read_packet("BIN32-ABS.bin")
        bytes_sent_before_packet_delay_command = 32
        self._gem.send(packet[0:bytes_sent_before_packet_delay_command])
        self._gem.expect(
            CMD_DELAY_NEXT_PACKET.encode(),
            reply=packet[bytes_sent_before_packet_delay_command:],
        )
        self._gem.expect(CMD_GET_SERIAL_NUMBER.encode(), reply=b"1234567")

        await self.assertSerialNumber(1234567)
        await self.assertPacket("BIN32-ABS.bin")

    async def testApiCallToIdleGem(self):
        """Tests that the protocol can handle no packets arriving after it has
        requested a packet delay from the GEM."""
        self._gem.expect(CMD_DELAY_NEXT_PACKET.encode(), reply=None)
        self._gem.expect(CMD_GET_SERIAL_NUMBER.encode(), reply=b"1234567")

        await self.assertSerialNumber(1234567)

    async def assertSerialNumber(self, expected_serial_number: int):
        serial_number = await self._api.get_serial_number()
        assert serial_number == expected_serial_number

    async def assertPacket(self, expected_packet: str):
        packet = await self._queue.get()
        self._queue.task_done()
        assert_packet(expected_packet, packet)


if __name__ == "__main__":
    unittest.main()
