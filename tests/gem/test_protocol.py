import logging
import sys
import unittest

from siobrultech_protocols.gem.packets import BIN48_NET
from siobrultech_protocols.gem.protocol import PacketProtocol
from tests.gem.packet_test_data import assert_packet, read_packet, read_packets

logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s](%(levelname)s) %(message)s",
)


class TestPacketAccumulator(unittest.TestCase):
    def test_single_packet(self):
        packet_data = read_packet("BIN32-ABS.bin")
        protocol = PacketProtocol()
        protocol.data_received(packet_data)
        packet = protocol.get_packet()
        assert_packet("BIN32-ABS.bin", packet)

    def test_header_only(self):
        packet_data = read_packet("BIN32-ABS.bin")
        protocol = PacketProtocol()
        protocol.data_received(packet_data[:2])
        packet = protocol.get_packet()
        self.assertIsNone(packet)
        protocol.data_received(packet_data[2:])
        packet = protocol.get_packet()
        assert_packet("BIN32-ABS.bin", packet)

    def test_partial_packet(self):
        packet_data = read_packet("BIN32-ABS.bin")
        protocol = PacketProtocol()
        protocol.data_received(packet_data[:100])
        packet = protocol.get_packet()
        self.assertIsNone(packet)
        protocol.data_received(packet_data[100:])
        packet = protocol.get_packet()
        assert_packet("BIN32-ABS.bin", packet)

    def test_time_packet(self):
        packet_data = read_packet("BIN48-NET-TIME_tricky.bin")
        protocol = PacketProtocol()
        protocol.data_received(packet_data)
        packet = protocol.get_packet()
        assert_packet("BIN48-NET-TIME_tricky.bin", packet)

    def test_partial_time_packet(self):
        packet_data = read_packet("BIN48-NET-TIME_tricky.bin")
        protocol = PacketProtocol()
        protocol.data_received(packet_data[: BIN48_NET.size])
        packet = protocol.get_packet()
        self.assertIsNone(packet)
        protocol.data_received(packet_data[BIN48_NET.size :])
        packet = protocol.get_packet()
        assert_packet("BIN48-NET-TIME_tricky.bin", packet)

    def test_multiple_packets(self):
        packet_data = read_packets(
            ["BIN32-ABS.bin", "BIN32-NET.bin", "BIN48-NET.bin", "BIN48-NET-TIME.bin"]
        )
        protocol = PacketProtocol()
        protocol.data_received(packet_data)
        packet = protocol.get_packet()
        assert_packet("BIN32-ABS.bin", packet)
        packet = protocol.get_packet()
        assert_packet("BIN32-NET.bin", packet)
        packet = protocol.get_packet()
        assert_packet("BIN48-NET.bin", packet)
        packet = protocol.get_packet()
        assert_packet("BIN48-NET-TIME.bin", packet)

    def test_multiple_packets_with_junk(self):
        protocol = PacketProtocol()
        protocol.data_received(read_packet("BIN32-ABS.bin"))
        protocol.data_received(bytes.fromhex("feff05"))
        protocol.data_received(read_packet("BIN32-NET.bin"))
        protocol.data_received(bytes.fromhex("feff01"))
        protocol.data_received(read_packet("BIN48-NET.bin"))
        protocol.data_received(bytes.fromhex("23413081afb134870dacea"))
        protocol.data_received(read_packet("BIN48-NET-TIME.bin"))
        packet = protocol.get_packet()
        assert_packet("BIN32-ABS.bin", packet)
        packet = protocol.get_packet()
        assert_packet("BIN32-NET.bin", packet)
        packet = protocol.get_packet()
        assert_packet("BIN48-NET.bin", packet)
        packet = protocol.get_packet()
        assert_packet("BIN48-NET-TIME.bin", packet)


if __name__ == "__main__":
    unittest.main()
