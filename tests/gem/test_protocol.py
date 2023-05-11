import asyncio
import logging
import sys
import unittest

from siobrultech_protocols.gem.packets import BIN48_NET, Packet
from siobrultech_protocols.gem.protocol import (
    ConnectionLostMessage,
    ConnectionMadeMessage,
    PacketProtocol,
    PacketProtocolMessage,
    PacketReceivedMessage,
)
from tests.gem.mock_transport import MockTransport
from tests.gem.packet_test_data import assert_packet, read_packet, read_packets

logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s](%(levelname)s) %(message)s",
)


class TestPacketAccumulator(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._queue: asyncio.Queue[PacketProtocolMessage] = asyncio.Queue()
        self._transport = MockTransport()
        self._protocol = PacketProtocol(queue=self._queue)
        self._protocol.connection_made(self._transport)
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

    def test_single_packet(self):
        packet_data = read_packet("BIN32-ABS.bin")
        self._protocol.data_received(packet_data)
        packet = self.expect_packet_recieved()
        assert_packet("BIN32-ABS.bin", packet)

    def test_header_only(self):
        packet_data = read_packet("BIN32-ABS.bin")
        self._protocol.data_received(packet_data[:2])
        with self.assertRaises(asyncio.queues.QueueEmpty):
            self._queue.get_nowait()
        self._protocol.data_received(packet_data[2:])
        packet = self.expect_packet_recieved()
        assert_packet("BIN32-ABS.bin", packet)

    def test_partial_packet(self):
        packet_data = read_packet("BIN32-ABS.bin")
        self._protocol.data_received(packet_data[:100])
        with self.assertRaises(asyncio.queues.QueueEmpty):
            self._queue.get_nowait()
        self._protocol.data_received(packet_data[100:])
        packet = self.expect_packet_recieved()
        assert_packet("BIN32-ABS.bin", packet)

    def test_time_packet(self):
        packet_data = read_packet("BIN48-NET-TIME_tricky.bin")
        self._protocol.data_received(packet_data)
        packet = self.expect_packet_recieved()
        assert_packet("BIN48-NET-TIME_tricky.bin", packet)

    def test_partial_time_packet(self):
        packet_data = read_packet("BIN48-NET-TIME_tricky.bin")
        self._protocol.data_received(packet_data[: BIN48_NET.size])
        with self.assertRaises(asyncio.queues.QueueEmpty):
            self._queue.get_nowait()
        self._protocol.data_received(packet_data[BIN48_NET.size :])
        packet = self.expect_packet_recieved()
        assert_packet("BIN48-NET-TIME_tricky.bin", packet)

    def test_multiple_packets(self):
        packet_data = read_packets(
            ["BIN32-ABS.bin", "BIN32-NET.bin", "BIN48-NET.bin", "BIN48-NET-TIME.bin"]
        )
        self._protocol.data_received(packet_data)
        packet = self.expect_packet_recieved()
        assert_packet("BIN32-ABS.bin", packet)
        packet = self.expect_packet_recieved()
        assert_packet("BIN32-NET.bin", packet)
        packet = self.expect_packet_recieved()
        assert_packet("BIN48-NET.bin", packet)
        packet = self.expect_packet_recieved()
        assert_packet("BIN48-NET-TIME.bin", packet)

    def test_multiple_packets_with_junk(self):
        self._protocol.data_received(read_packet("BIN32-ABS.bin"))
        self._protocol.data_received(bytes.fromhex("feff05"))
        self._protocol.data_received(read_packet("BIN32-NET.bin"))
        self._protocol.data_received(bytes.fromhex("feff01"))
        self._protocol.data_received(read_packet("BIN48-NET.bin"))
        self._protocol.data_received(bytes.fromhex("23413081afb134870dacea"))
        self._protocol.data_received(read_packet("BIN48-NET-TIME.bin"))
        packet = self.expect_packet_recieved()
        assert_packet("BIN32-ABS.bin", packet)
        packet = self.expect_packet_recieved()
        assert_packet("BIN32-NET.bin", packet)
        packet = self.expect_packet_recieved()
        assert_packet("BIN48-NET.bin", packet)
        packet = self.expect_packet_recieved()
        assert_packet("BIN48-NET-TIME.bin", packet)

    def expect_packet_recieved(self) -> Packet:
        message = self._queue.get_nowait()
        assert isinstance(message, PacketReceivedMessage)
        assert message.protocol is self._protocol
        return message.packet


if __name__ == "__main__":
    unittest.main()
