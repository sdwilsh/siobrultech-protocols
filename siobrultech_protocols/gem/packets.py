"""
Packet formats defined in
https://www.brultech.com/software/files/downloadSoft/GEM-PKT_Packet_Format_2_1.pdf
"""
from __future__ import annotations

import codecs
import json
from collections import OrderedDict
from copy import copy
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
        pulse_counts: Optional[List[int]] = None,
        temperatures: Optional[List[float | None]] = None,
        polarized_watt_seconds: Optional[List[int]] = None,
        currents: Optional[List[float]] = None,
        time_stamp: Optional[datetime] = None,
        aux: Optional[List[int]] = None,
        dc_voltage: Optional[int] = None,
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
        self.pulse_counts: List[int] = pulse_counts or []
        self.temperatures: List[float | None] = temperatures or []
        if time_stamp:
            self.time_stamp: datetime = time_stamp
        else:
            self.time_stamp: datetime = datetime.now()
        self.aux: List[int] = aux or []
        self.dc_voltage = dc_voltage

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

    def delta_aux_count(self, index: int, prev: int) -> int:
        field = self.packet_format.fields["aux"]
        assert isinstance(field, NumericArrayField)
        return self._delta_value(field.elem_field, self.aux[index], prev)

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
            (delta_consumed_watt_seconds - delta_produced_watt_seconds)
            / elapsed_seconds
            if elapsed_seconds
            else 0
        )

    def get_average_pulse_rate(self, index: int, other_packet: Packet) -> float:
        oldest_packet, newest_packet = self._packets_sorted(self, other_packet)
        elapsed_seconds = newest_packet.delta_seconds(oldest_packet.seconds)

        return (
            (
                newest_packet.delta_pulse_count(
                    index, oldest_packet.pulse_counts[index]
                )
                / elapsed_seconds
            )
            if elapsed_seconds
            else 0
        )

    def get_average_aux_rate_of_change(self, index: int, other_packet: Packet) -> float:
        oldest_packet, newest_packet = self._packets_sorted(self, other_packet)
        elapsed_seconds = newest_packet.delta_seconds(oldest_packet.seconds)

        return (
            (
                newest_packet.delta_aux_count(index, oldest_packet.aux[index])
                / elapsed_seconds
            )
            if elapsed_seconds
            else 0
        )


@unique
class PacketFormatType(IntEnum):
    ECM_1220 = 1
    ECM_1240 = 3
    BIN48_NET_TIME = 4
    BIN48_NET = 5
    BIN48_ABS = 7
    BIN32_NET = 8
    BIN32_ABS = 9


class PacketFormat(object):
    def __init__(
        self,
        name: str,
        type: PacketFormatType,
        code: int,
        num_channels: int,
    ):
        self.name: str = name
        self.type: PacketFormatType = type
        self.code = code
        self.num_channels: int = num_channels
        self.fields: OrderedDict[str, Field] = OrderedDict()

    @property
    def size(self) -> int:
        result = 0
        for value in self.fields.values():
            result += value.size

        return result

    def parse(self, data: bytes) -> Packet:
        if len(data) < self.size:
            raise MalformedPacketException(
                "Packet too short. Expected {0} bytes, found {1} bytes.".format(
                    self.size, len(data)
                )
            )
        _checksum(data, self.size)

        offset = 0
        args = {
            "packet_format": self,
        }
        for key, value in self.fields.items():
            args[key] = value.read(data, offset)
            offset += value.size

        if args["code"] != self.code:
            raise MalformedPacketException(
                "bad code {0} im packet: {1}".format(
                    args["code"], codecs.encode(data, "hex")
                )
            )

        if args["footer"] != 0xFFFE:
            raise MalformedPacketException(
                "bad footer {0} in packet: {1}".format(
                    hex(args["footer"]), codecs.encode(data, "hex")  # type: ignore
                )
            )

        return Packet(**args)  # type: ignore

    def format(self, packet: Packet) -> bytes:
        result = bytearray()
        for key, field in self.fields.items():
            if key == "footer":
                value = 0xFFFE
            elif key == "header":
                value = 0xFEFF
            elif key == "code":
                value = self.code
            else:
                value = getattr(packet, key) if hasattr(packet, key) else None

            if value is not None:
                field.write(value, result)
            else:
                field.write_padding(result)

        result[-1] = _compute_checksum(result, self.size)
        assert len(result) == self.size

        return bytes(result)


class ECMPacketFormat(PacketFormat):
    def __init__(
        self,
        name: str,
        type: PacketFormatType,
        code: int,
        has_aux_channels: bool = False,
    ):
        super().__init__(name, type, code=code, num_channels=2)

        self.fields["header"] = NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["code"] = NumericField(1, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["voltage"] = FloatingPointField(
            2, ByteOrder.HiToLo, Sign.Unsigned, 10.0
        )
        self.fields["absolute_watt_seconds"] = NumericArrayField(
            self.num_channels, 5, ByteOrder.LoToHi, Sign.Unsigned
        )
        self.fields["polarized_watt_seconds"] = NumericArrayField(
            self.num_channels, 5, ByteOrder.LoToHi, Sign.Unsigned
        )
        self.fields["reserved"] = BytesField(size=4)
        self.fields["serial_number"] = NumericField(2, ByteOrder.LoToHi, Sign.Unsigned)
        self.fields["flag"] = ByteField()
        self.fields["device_id"] = NumericField(1, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["currents"] = FloatingPointArrayField(
            self.num_channels, 2, ByteOrder.LoToHi, Sign.Unsigned, 100.0
        )
        self.fields["seconds"] = NumericField(3, ByteOrder.LoToHi, Sign.Unsigned)
        self.num_aux_channels = 0
        if has_aux_channels:
            self.num_aux_channels = 5
            self.fields["aux"] = NumericArrayField(
                self.num_aux_channels, 4, ByteOrder.LoToHi, Sign.Unsigned
            )
            self.fields["dc_voltage"] = NumericField(2, ByteOrder.LoToHi, Sign.Unsigned)
        self.fields["footer"] = NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["checksum"] = ByteField()


class GEMPacketFormat(PacketFormat):
    NUM_PULSE_COUNTERS: int = 4
    NUM_TEMPERATURE_SENSORS: int = 8

    def __init__(
        self,
        name: str,
        type: PacketFormatType,
        code: int,
        num_channels: int,
        has_net_metering: bool = False,
        has_time_stamp: bool = False,
    ):
        super().__init__(name, type, code=code, num_channels=num_channels)

        self.fields["header"] = NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)
        self.fields["code"] = NumericField(1, ByteOrder.HiToLo, Sign.Unsigned)
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
            GEMPacketFormat.NUM_PULSE_COUNTERS, 3, ByteOrder.LoToHi, Sign.Unsigned
        )
        self.fields["temperatures"] = FloatingPointArrayField(
            GEMPacketFormat.NUM_TEMPERATURE_SENSORS,
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

    def parse(self, data: bytes) -> Packet:
        packet = super().parse(data)
        packet.temperatures = [
            # Above 255 means it wasn't able to read the sensor (though we sometimes also get 0 for that)
            temperature if temperature is not None and temperature <= 255.0 else None
            for temperature in packet.temperatures
        ]
        return packet

    def format(self, packet: Packet) -> bytes:
        packet = copy(packet)
        packet.temperatures = [
            temperature if temperature is not None else 256
            for temperature in packet.temperatures
        ]
        return super().format(packet)


def _compute_checksum(packet: bytes, size: int) -> int:
    checksum = 0
    for i in packet[: size - 1]:
        checksum += i
    checksum = checksum % 256
    return checksum


def _checksum(packet: bytes, size: int) -> None:
    checksum = _compute_checksum(packet, size)
    if checksum != packet[size - 1]:
        raise MalformedPacketException(
            "bad checksum for packet: {0}".format(codecs.encode(packet[:size], "hex"))
        )


BIN48_NET_TIME = GEMPacketFormat(
    name="BIN48-NET-TIME",
    type=PacketFormatType.BIN48_NET_TIME,
    code=5,
    num_channels=48,
    has_net_metering=True,
    has_time_stamp=True,
)

BIN48_NET = GEMPacketFormat(
    name="BIN48-NET",
    type=PacketFormatType.BIN48_NET,
    code=5,
    num_channels=48,
    has_net_metering=True,
    has_time_stamp=False,
)

BIN48_ABS = GEMPacketFormat(
    name="BIN48-ABS",
    type=PacketFormatType.BIN48_ABS,
    code=6,
    num_channels=48,
    has_net_metering=False,
    has_time_stamp=False,
)

BIN32_NET = GEMPacketFormat(
    name="BIN32-NET",
    type=PacketFormatType.BIN32_NET,
    code=7,
    num_channels=32,
    has_net_metering=True,
    has_time_stamp=False,
)

BIN32_ABS = GEMPacketFormat(
    name="BIN32-ABS",
    type=PacketFormatType.BIN32_ABS,
    code=8,
    num_channels=32,
    has_net_metering=False,
    has_time_stamp=False,
)

ECM_1240 = ECMPacketFormat(
    name="ECM-1240", type=PacketFormatType.ECM_1240, code=3, has_aux_channels=True
)

ECM_1220 = ECMPacketFormat(
    name="ECM-1220", type=PacketFormatType.ECM_1220, code=1, has_aux_channels=False
)
