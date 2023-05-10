import asyncio
from typing import Callable
import unittest

from siobrultech_protocols.gem.const import CMD_DELAY_NEXT_PACKET
from siobrultech_protocols.gem.protocol import (
    ApiCall,
    BidirectionalProtocol,
    ConnectionLostMessage,
    ConnectionMadeMessage,
    PacketProtocolMessage,
    PacketReceivedMessage,
    ProtocolStateException,
)
from tests.gem.mock_transport import MockTransport
from tests.gem.packet_test_data import assert_packet, read_packet


TestCall = ApiCall[str, str](
    formatter=lambda x: x, parser=lambda x: x if x.endswith("\n") else None
)


class TestBidirectionalProtocol(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._queue: asyncio.Queue[PacketProtocolMessage] = asyncio.Queue()
        self._transport = MockTransport()
        self._protocol = BidirectionalProtocol(self._queue)
        self._protocol.connection_made(self._transport)
        self._result: asyncio.Future[str] = asyncio.get_event_loop().create_future()
        message = self._queue.get_nowait()
        assert isinstance(message, ConnectionMadeMessage)
        assert message.protocol is self._protocol

    def tearDown(self) -> None:
        if not self._transport.closed:
            exc = Exception("Test")
            self._protocol.connection_lost(exc=exc)
            message = self._queue.get_nowait()
            assert isinstance(message, ConnectionLostMessage)
            assert message.protocol is self._protocol
            assert message.exc is exc

    def testBeginApi(self):
        self._protocol.begin_api_request()
        self.assertEqual(self._transport.writes, [CMD_DELAY_NEXT_PACKET.encode()])

    def testBeginApiWithoutDelay(self):
        self._protocol._send_packet_delay = False
        self._protocol.begin_api_request()
        self.assertEqual(self._transport.writes, [])

    def testSendWithoutBeginFails(self):
        with self.assertRaises(ProtocolStateException):
            self._protocol.invoke_api(TestCall, "request", self._result)

    def testSendRequest(self):
        self._protocol.begin_api_request()
        self._transport.writes.clear()
        self._protocol.invoke_api(TestCall, "request", self._result)
        self.assertEqual(self._transport.writes, ["request".encode()])

    async def testPacketRacingWithApi(self):
        """Tests that the protocol can handle a packet coming in right after it has
        requested a packet delay from the GEM."""
        self._protocol.begin_api_request()
        self._protocol.data_received(read_packet("BIN32-ABS.bin"))
        self._protocol.invoke_api(TestCall, "REQUEST", self._result)
        self._protocol.data_received(b"RESPONSE\n")
        response = await self.get_response()
        self._protocol.end_api_request()

        self.assertEqual(response, "RESPONSE\n")
        self.assertPacket("BIN32-ABS.bin")

    async def testPacketInterleavingWithApi(self):
        """Tests that the protocol can handle a packet coming in in the middle of the API response.
        (I don't know whether this can happen in practice.)"""
        self._protocol.begin_api_request()
        self._protocol.data_received(read_packet("BIN32-ABS.bin"))
        self._protocol.invoke_api(TestCall, "REQUEST", self._result)
        self._protocol.data_received(b"RES")
        self._protocol.data_received(read_packet("BIN32-ABS.bin"))
        self._protocol.data_received(b"PONSE\n")
        response = await self.get_response()
        self._protocol.end_api_request()

        self.assertEqual(response, "RESPONSE\n")
        self.assertPacket("BIN32-ABS.bin")
        self.assertPacket("BIN32-ABS.bin")

    def testDeviceIgnoresApi(self):
        """Tests that the protocol fails appropriately if a device ignores API calls and just keeps sending packets."""
        self._protocol.begin_api_request()
        self._protocol.data_received(read_packet("BIN32-ABS.bin"))
        self._protocol.invoke_api(TestCall, "REQUEST", self._result)
        self._protocol.data_received(read_packet("BIN32-ABS.bin"))
        assert not self._result.done()
        self._protocol.end_api_request()

        self.assertPacket("BIN32-ABS.bin")
        self.assertPacket("BIN32-ABS.bin")

    async def testApiCallWithPacketInProgress(self):
        """Tests that the protocol can handle a packet that's partially arrived when it
        requested a packet delay from the GEM."""
        packet = read_packet("BIN32-ABS.bin")
        bytes_sent_before_packet_delay_command = 32
        self._protocol.data_received(packet[0:bytes_sent_before_packet_delay_command])
        self._protocol.begin_api_request()
        self._protocol.data_received(packet[bytes_sent_before_packet_delay_command:])
        self._protocol.invoke_api(TestCall, "REQUEST", self._result)
        self._protocol.data_received(b"RESPONSE\n")
        response = await self.get_response()
        self._protocol.end_api_request()

        self.assertEqual(response, "RESPONSE\n")
        self.assertPacket("BIN32-ABS.bin")

    async def testApiCallToIdleGem(self):
        """Tests that the protocol can handle no packets arriving after it has
        requested a packet delay from the GEM."""
        self._protocol.begin_api_request()
        self._protocol.invoke_api(TestCall, "REQUEST", self._result)
        self._protocol.data_received(b"RESPONSE\n")
        response = await self.get_response()
        self._protocol.end_api_request()

        self.assertEqual(response, "RESPONSE\n")
        self.assertNoPacket()

    def testEndAfterBegin(self):
        """Checks for the case where user-code may fail, and we just call end_api_request
        after calling begin_api_request."""
        self._protocol.begin_api_request()
        self._protocol.end_api_request()

    async def get_response(self) -> str:
        return await asyncio.wait_for(self._result, 0)

    def assertNoPacket(self):
        self.assertTrue(self._queue.empty())

    def assertPacket(self, expected_packet: str):
        message = self._queue.get_nowait()
        assert isinstance(message, PacketReceivedMessage)
        assert message.protocol is self._protocol
        assert_packet(expected_packet, message.packet)


if __name__ == "__main__":
    unittest.main()
