"""
Packet formats defined in
https://www.brultech.com/software/files/downloadSoft/GEM-PKT_Packet_Format_2_1.pdf
"""
from __future__ import annotations

import codecs
import json
from collections import OrderedDict
from datetime import datetime
from enum import IntEnum, unique
from typing import Any, Dict, List, Optional

from .fields import (
    ByteField,
    ByteOrder,
    BytesField,
    DateTimeField,
    Field,
    FloatingPointArrayField,
    FloatingPointField,
    NumericArrayField,
    NumericField,
    Sign,
)


class MalformedPacketException(Exception):
    pass


class Packet(object):
    def __init__(
        self,
        packet_format: PacketFormat,
        voltage: float,
        absolute_watt_seconds: List[int],
        device_id: int,
        serial_number: int,
        seconds: int,
        pulse_counts: List[int],
        temperatures: List[float],
        polarized_watt_seconds: Optional[List[int]] = None,
        currents: Optional[List[float]] = None,
        time_stamp: Optional[datetime] = None,
        **kwargs: Dict[str, Any],
    ):
        self.packet_format: PacketFormat = packet_format
        self.voltage: float = voltage
        self.absolute_watt_seconds: List[int] = absolute_watt_seconds
        self.polarized_watt_seconds: Optional[List[int]] = polarized_watt_seconds
        self.currents: Optional[List[float]] = currents
        self.device_id: int = device_id
        self.serial_number: int = serial_number
        self.seconds: int = seconds
        self.pulse_counts: List[int] = pulse_counts
        self.temperatures: List[float] = temperatures
        if time_stamp:
            self.time_stamp: datetime = time_stamp
        else:
            self.time_stamp: datetime = datetime.now()

    def __str__(self) -> str:
        return json.dumps(
            {
                "device_id": self.device_id,
                "serial_number": self.serial_number,
                "seconds": self.seconds,
                "voltage": self.voltage,
                "absolute_watt_seconds": self.absolute_watt_seconds,
                "polarized_watt_seconds": self.polarized_watt_seconds,
                "currents": self.currents,
                "pulse_counts": self.pulse_counts,
                "temperatures": self.temperatures,
                "time_stamp": self.time_stamp.isoformat(),
            }
        )

    @property
    def num_channels(self) -> int:
        """The number of channels in the packet given the format.  There may be fewer on the device."""
        return self.packet_format.num_channels

    @property
    def type(self) -> str:
        """The packet format type's name."""
        return self.packet_format.name

    def delta_seconds(self, prev: int) -> int:
        field = self.packet_format.fields["seconds"]
        assert isinstance(field, NumericField)
        return self._delta_value(field, self.seconds, prev)

    def delta_pulse_count(self, index: int, prev: int) -> int:
        field = self.packet_format.fields["pulse_counts"]
        assert isinstance(field, NumericArrayField)
        return self._delta_value(field.elem_field, self.pulse_counts[index], prev)

    def delta_absolute_watt_seconds(self, index: int, prev: int) -> int:
        field = self.packet_format.fields["absolute_watt_seconds"]
        assert isinstance(field, NumericArrayField)
        return self._delta_value(
            field.elem_field, self.absolute_watt_seconds[index], prev
        )

    def delta_polarized_watt_seconds(self, index: int, prev: int) -> int:
        field = self.packet_format.fields["polarized_watt_seconds"]
        assert isinstance(field, NumericArrayField)
        if self.polarized_watt_seconds is not None:
            return self._delta_value(
                field.elem_field, self.polarized_watt_seconds[index], prev
            )
        else:
            return 0

    def _delta_value(self, field: NumericField, cur: int, prev: int) -> int:
        if prev > cur:
            diff = field.max + 1 - prev
            diff += cur
        else:
            diff = cur - prev
        return diff

    @staticmethod
    def _packets_sorted(packet_a: Packet, packet_b: Packet) -> tuple[Packet, Packet]:
        if packet_a.seconds < packet_b.seconds:
            oldest_packet = packet_a
            newest_packet = packet_b
        else:
            oldest_packet = packet_b
            newest_packet = packet_a
        return oldest_packet, newest_packet

    def get_average_power(
        self,
        index: int,
        other_packet: Packet,
    ) -> float:
        oldest_packet, newest_packet = self._packets_sorted(self, other_packet)
        elapsed_seconds = newest_packet.delta_seconds(oldest_packet.seconds)

        # The Brultech devices measure one or two things with their counters:
        #  * Absolute Watt-seconds, which is incoming and outgoing Watt-seconds, combined.
        #  * Polarized Watt-seconds (only when NET metering is enabled), which is just outgoing Watt-seconds.
        #
        # Therefore, in order to compute the average power (Watts) between packets flowing through the point that is
        # being measured, we need to compute two things:
        #  * Produced Watt-seconds, which is just Polarized Watt-seconds.
        #  * Consumed Watt-seconds, which is Absolute Watt-seconds minus Polarized Watt-seconds.
        #
        # Given those two values, the average power is just the (consumed - produced) / elapsed time.  In this way, a
        # negative flow of power occurs if more power was produced than consumed.

        delta_absolute_watt_seconds = newest_packet.delta_absolute_watt_seconds(
            index, oldest_packet.absolute_watt_seconds[index]
        )

        # It is only possible to produce if the given channel has NET metering enabled.
        delta_produced_watt_seconds = (
            newest_packet.delta_polarized_watt_seconds(
                index, oldest_packet.polarized_watt_seconds[index]
            )
            if oldest_packet.polarized_watt_seconds is not None
            and newest_packet.polarized_watt_seconds is not None
            else 0.0
        )

        delta_consumed_watt_seconds = (
            delta_absolute_watt_seconds - delta_produced_watt_seconds
        )

        return (
            delta_consumed_watt_seconds - delta_produced_watt_seconds
        ) / elapsed_seconds

    def get_average_pulse_rate(self, index: int, other_packet: Packet) -> float:
        oldest_packet, newest_packet = self._packets_sorted(self, other_packet)
        elapsed_seconds = newest_packet.delta_seconds(oldest_packet.seconds)

        return (
            newest_packet.delta_pulse_count(index, oldest_packet.pulse_counts[index])
            / elapsed_seconds
        )


@unique
class PacketFormatType(IntEnum):
    BIN48_NET_TIME = 4
    BIN48_NET = 5
    BIN48_ABS = 7
    BIN32_NET = 8
    BIN32_ABS = 9


class PacketFormat(object):
    NUM_PULSE_COUNTERS: int = 4
    NUM_TEMPERATURE_SENSORS: int = 8

    def __init__(
        self,
        name: str,
        type: PacketFormatType,
        num_channels: int,
        has_net_metering: bool = False,
        has_time_stamp: bool = False,
    ):
        self.name: str = name
        self.type: PacketFormatType = type
        self.num_channels: int = num_channels
        self.fields: OrderedDict[str, Field] = OrderedDict()

        self.fields["header"] = NumericField(3, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["voltage"] = FloatingPointField(
            2, ByteOrder.HiToLo, Sign.Unsigned, 10.0
        )
        self.fields["absolute_watt_seconds"] = NumericArrayField(
            num_channels, 5, ByteOrder.LoToHi, Sign.Unsigned
        )
        if has_net_metering:
            self.fields["polarized_watt_seconds"] = NumericArrayField(
                num_channels, 5, ByteOrder.LoToHi, Sign.Unsigned
            )
        self.fields["serial_number"] = NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["reserved"] = ByteField()
        self.fields["device_id"] = NumericField(1, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["currents"] = FloatingPointArrayField(
            num_channels, 2, ByteOrder.LoToHi, Sign.Unsigned, 50.0
        )
        self.fields["seconds"] = NumericField(3, ByteOrder.LoToHi, Sign.Unsigned)
        self.fields["pulse_counts"] = NumericArrayField(
            PacketFormat.NUM_PULSE_COUNTERS, 3, ByteOrder.LoToHi, Sign.Unsigned
        )
        self.fields["temperatures"] = FloatingPointArrayField(
            PacketFormat.NUM_TEMPERATURE_SENSORS,
            2,
            ByteOrder.LoToHi,
            Sign.Signed,
            2.0,
        )
        if num_channels == 32:
            self.fields["spare_bytes"] = BytesField(2)
        if has_time_stamp:
            self.fields["time_stamp"] = DateTimeField()
        self.fields["footer"] = NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["checksum"] = ByteField()

    @property
    def size(self) -> int:
        result = 0
        for value in self.fields.values():
            result += value.size

        return result

    def parse(self, packet: bytes) -> Packet:
        if len(packet) < self.size:
            raise MalformedPacketException(
                "Packet too short. Expected {0} bytes, found {1} bytes.".format(
                    self.size, len(packet)
                )
            )
        _checksum(packet, self.size)

        offset = 0
        args = {
            "packet_format": self,
        }
        for key, value in self.fields.items():
            args[key] = value.read(packet, offset)
            offset += value.size

        if args["footer"] != 0xFFFE:
            raise MalformedPacketException(
                "bad footer {0} in packet: {1}".format(
                    hex(args["footer"]), codecs.encode(packet, "hex")  # type: ignore
                )
            )

        return Packet(**args)  # type: ignore


def _checksum(packet: bytes, size: int):
    checksum = 0
    for i in packet[: size - 1]:
        checksum += i
    checksum = checksum % 256
    if checksum != packet[size - 1]:
        raise MalformedPacketException(
            "bad checksum for packet: {0}".format(codecs.encode(packet[:size], "hex"))
        )


BIN48_NET_TIME = PacketFormat(
    name="BIN48-NET-TIME",
    type=PacketFormatType.BIN48_NET_TIME,
    num_channels=48,
    has_net_metering=True,
    has_time_stamp=True,
)

BIN48_NET = PacketFormat(
    name="BIN48-NET",
    type=PacketFormatType.BIN48_NET,
    num_channels=48,
    has_net_metering=True,
    has_time_stamp=False,
)

BIN48_ABS = PacketFormat(
    name="BIN48-ABS",
    type=PacketFormatType.BIN48_ABS,
    num_channels=48,
    has_net_metering=False,
    has_time_stamp=False,
)

BIN32_NET = PacketFormat(
    name="BIN32-NET",
    type=PacketFormatType.BIN32_NET,
    num_channels=32,
    has_net_metering=True,
    has_time_stamp=False,
)

BIN32_ABS = PacketFormat(
    name="BIN32-ABS",
    type=PacketFormatType.BIN32_ABS,
    num_channels=32,
    has_net_metering=False,
    has_time_stamp=False,
)
