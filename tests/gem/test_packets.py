import unittest

from siobrultech_protocols.gem import packets
from tests.gem.packet_test_data import assert_packet, read_packet


class TestPacketFormats(unittest.TestCase):
    def test_bin32_abs(self):
        check_packet("BIN32-ABS.bin", packets.BIN32_ABS)

    def test_bin32_net(self):
        check_packet("BIN32-NET.bin", packets.BIN32_NET)

    def test_bin48_abs(self):
        check_packet("BIN48-ABS.bin", packets.BIN48_ABS)

    def test_bin48_net(self):
        check_packet("BIN48-NET.bin", packets.BIN48_NET)

    def test_bin48_net_time(self):
        check_packet("BIN48-NET-TIME.bin", packets.BIN48_NET_TIME)

    def test_bin48_net_time_tricky(self):
        """BIN48_NET and BIN48_NET_TIME packets both have the same packet type
        code, so in order to detect the difference you must try to parse as
        BIN48_NET first, and if that fails try BIN48_NET_TIME. However, if
        the parser just checks the checksum and not the footer, it's possible
        for a BIN48_NET_TIME packet to be mistaken for a BIN48_NET. This is
        one such packet."""
        try:
            parse_packet("BIN48-NET-TIME_tricky.bin", packets.BIN48_NET)
            self.fail("Should have thrown")
        except packets.MalformedPacketException:
            pass

        check_packet("BIN48-NET-TIME_tricky.bin", packets.BIN48_NET_TIME)

    def test_short_packet(self):
        packet = read_packet("BIN32-NET.bin")
        with self.assertRaisesRegex(
            packets.MalformedPacketException, "Packet too short."
        ):
            packets.BIN32_NET.parse(packet[:-1])

    def test_packet_with_extra_after(self):
        data = bytearray()
        data.extend(read_packet("BIN32-NET.bin"))
        data.extend(read_packet("BIN32-ABS.bin"))

        packet = packets.BIN32_NET.parse(data)
        assert_packet("BIN32-NET.bin", packet)


class TestPacketDeltaComputation(unittest.TestCase):
    def test_packet_delta_seconds(self):
        packet = parse_packet("BIN32-ABS.bin", packets.BIN32_ABS)
        self.assertEqual(997492, packet.seconds)

        self.assertEqual(997493, packet.delta_seconds(2 ** 24 - 1))
        self.assertEqual(1000000, packet.delta_seconds(2 ** 24 - (1000000 - 997492)))

    def test_packet_delta_pulses(self):
        packet = parse_packet("BIN48-NET-TIME_tricky.bin", packets.BIN48_NET_TIME)

        # All the pulse counts in our packets are 0, so let's fake some out
        packet.pulse_counts = [100, 200, 300, 400]

        self.assertEqual(
            [1100, 1200, 1300, 1400],
            [
                packet.delta_pulse_count(i, 2 ** 24 - 1000)
                for i in range(0, len(packet.pulse_counts))
            ],
        )

    def test_packet_delta_absolute_watt_seconds(self):
        packet = parse_packet("BIN32-ABS.bin", packets.BIN32_ABS)
        self.assertEqual(
            [
                3123664,
                9249700,
                195388151,
                100917236,
                7139112,
                1440,
                4,
                3,
                14645520,
                111396601,
                33259670,
                38296448,
                1108415,
                2184858,
                5191049,
                1,
                71032651,
                60190845,
                47638292,
                12017483,
                36186563,
                14681918,
                69832947,
                37693,
                60941899,
                1685614,
                902,
                799182,
                302590,
                3190972,
                5,
                647375119,
            ],
            packet.absolute_watt_seconds,
        )

        self.assertEqual(
            [
                packet.absolute_watt_seconds[i] + 1000
                for i in range(0, len(packet.absolute_watt_seconds))
            ],
            [
                packet.delta_absolute_watt_seconds(i, 2 ** 40 - 1000)
                for i in range(0, len(packet.absolute_watt_seconds))
            ],
        )

    def test_packet_delta_polarized_watt_seconds(self):
        packet = parse_packet("BIN32-NET.bin", packets.BIN32_NET)

        # Packet didn't have any negative numbers, so let's do some manual ones
        packet.polarized_watt_seconds = [
            -1600 + 100 * i for i in range(0, packet.num_channels)
        ]

        self.assertEqual(
            [
                packet.polarized_watt_seconds[i] + 1000 + 2 ** 39
                for i in range(0, len(packet.polarized_watt_seconds))
            ],
            [
                packet.delta_polarized_watt_seconds(i, 2 ** 39 - 1000)
                for i in range(0, len(packet.polarized_watt_seconds))
            ],
        )


def check_packet(packet_file_name, packet_format):
    packet = parse_packet(packet_file_name, packet_format)

    assert_packet(packet_file_name, packet)


def parse_packet(packet_file_name, packet_format):
    return packet_format.parse(read_packet(packet_file_name))


if __name__ == "__main__":
    unittest.main()
