import asyncio
import unittest

from siobrultech_protocols.gem.const import CMD_DELAY_NEXT_PACKET
from siobrultech_protocols.gem.protocol import (
    BidirectionalProtocol,
    ProtocolStateException,
)
from tests.gem.mock_transport import MockTransport
from tests.gem.packet_test_data import assert_packet, read_packet


class TestBidirectionalProtocol(unittest.TestCase):
    def setUp(self):
        self._queue = asyncio.Queue()
        self._transport = MockTransport()
        self._protocol = BidirectionalProtocol(self._queue)
        self._protocol.connection_made(self._transport)

    def testBeginApi(self):
        self._protocol.begin_api_request()
        self.assertEqual(self._transport.writes, [CMD_DELAY_NEXT_PACKET.encode()])

    def testSendWithoutBeginFails(self):
        with self.assertRaises(ProtocolStateException):
            self._protocol.send_api_request("request")

    def testSendRequest(self):
        self._protocol.begin_api_request()
        self._transport.writes.clear()
        self._protocol.send_api_request("request")
        self.assertEqual(self._transport.writes, ["request".encode()])

    def testPacketRacingWithApi(self):
        """Tests that the protocol can handle a packet coming in right after it has
        requested a packet delay from the GEM."""
        self._protocol.begin_api_request()
        self._protocol.data_received(read_packet("BIN32-ABS.bin"))
        self._protocol.send_api_request("REQUEST")
        self._protocol.data_received(b"RESPONSE")
        response = self._protocol.receive_api_response()
        self._protocol.end_api_request()

        self.assertEqual(response, "RESPONSE")
        self.assertPacket("BIN32-ABS.bin")

    def testApiCallWithPacketInProgress(self):
        """Tests that the protocol can handle a packet that's partially arrived when it
        requested a packet delay from the GEM."""
        packet = read_packet("BIN32-ABS.bin")
        bytes_sent_before_packet_delay_command = 32
        self._protocol.data_received(packet[0:bytes_sent_before_packet_delay_command])
        self._protocol.begin_api_request()
        self._protocol.data_received(packet[bytes_sent_before_packet_delay_command:])
        self._protocol.send_api_request("REQUEST")
        self._protocol.data_received(b"RESPONSE")
        response = self._protocol.receive_api_response()
        self._protocol.end_api_request()

        self.assertEqual(response, "RESPONSE")
        self.assertPacket("BIN32-ABS.bin")

    def testApiCallToIdleGem(self):
        """Tests that the protocol can handle no packets arriving after it has
        requested a packet delay from the GEM."""
        self._protocol.begin_api_request()
        self._protocol.send_api_request("REQUEST")
        self._protocol.data_received(b"RESPONSE")
        response = self._protocol.receive_api_response()
        self._protocol.end_api_request()

        self.assertEqual(response, "RESPONSE")
        self.assertNoPacket()

    def assertNoPacket(self):
        self.assertTrue(self._queue.empty())

    def assertPacket(self, expected_packet: str):
        packet = self._queue.get_nowait()
        assert_packet(expected_packet, packet)


if __name__ == "__main__":
    unittest.main()
