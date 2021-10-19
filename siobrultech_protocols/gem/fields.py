"""
Field types used in
https://www.brultech.com/software/files/downloadSoft/GEM-PKT_Packet_Format_2_1.pdf
"""
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum, unique
from typing import Any, List


@unique
class ByteOrder(Enum):
    # Big-endian (the name comes from the GEM packet format spec)
    HiToLo = 1
    # Little endian (the name comes from the GEM packet format spec)
    LoToHi = 2


@unique
class Sign(Enum):
    Signed = 1
    Unsigned = 2


class Field(ABC):
    def __init__(self, size: int):
        self._size = size

    @property
    def size(self) -> int:
        return self._size

    @abstractmethod
    def read(self, buffer: bytes, offset: int) -> Any:
        """Convert the buffer at the given offset to the proper value."""


class ByteField(Field):
    def __init__(self):
        super().__init__(size=1)

    def read(self, buffer: bytes, offset: int) -> bytes:
        return buffer[offset : offset + self.size]


class BytesField(Field):
    def read(self, buffer: bytes, offset: int) -> bytes:
        return buffer[offset : offset + self.size]


class NumericField(Field):
    def __init__(self, size: int, order: ByteOrder, signed: Sign):
        super().__init__(size=size)
        self.order: ByteOrder = order
        self.signed: Sign = signed

    def read(self, buffer: bytes, offset: int) -> int:
        return _parse(buffer[offset : offset + self.size], self.order, self.signed)

    @property
    def max(self) -> int:
        """The maximum value that can be encoded in this field."""
        bits = 8 * self.size
        if self.signed == Sign.Unsigned:
            return (1 << bits) - 1
        else:
            return (1 << (bits - 1)) - 1


class FloatingPointField(Field):
    def __init__(self, size: int, order: ByteOrder, signed: Sign, divisor: float):
        self.raw_field: NumericField = NumericField(size, order, signed)
        super().__init__(size=self.raw_field.size)
        self.divisor: float = divisor

    def read(self, buffer: bytes, offset: int) -> float:
        return self.raw_field.read(buffer, offset) / self.divisor


class DateTimeField(Field):
    def __init__(self):
        super().__init__(size=6)

    def read(self, buffer: bytes, offset: int) -> datetime:
        year, month, day, hour, minute, second = buffer[offset : offset + self.size]
        return datetime(2000 + year, month, day, hour, minute, second)


class ArrayField(Field):
    def __init__(self, num_elems: int, elem_field: Field):
        super().__init__(size=num_elems * elem_field.size)
        self.elem_field: Field = elem_field
        self.num_elems: int = num_elems

    def read(self, buffer: bytes, offset: int) -> List[Any]:
        return [
            self.elem_field.read(buffer, offset + i * self.elem_field.size)
            for i in range(self.num_elems)
        ]


class FloatingPointArrayField(ArrayField):
    elem_field: FloatingPointField

    def __init__(
        self,
        num_elems: int,
        size: int,
        order: ByteOrder,
        signed: Sign,
        divisor: float,
    ):
        super().__init__(
            num_elems=num_elems,
            elem_field=FloatingPointField(
                size=size, order=order, signed=signed, divisor=divisor
            ),
        )

    def read(self, buffer: bytes, offset: int) -> List[float]:
        return super().read(buffer, offset)


class NumericArrayField(ArrayField):
    elem_field: NumericField

    def __init__(self, num_elems: int, size: int, order: ByteOrder, signed: Sign):
        super().__init__(
            num_elems=num_elems,
            elem_field=NumericField(size=size, order=order, signed=signed),
        )

    def read(self, buffer: bytes, offset: int) -> List[int]:
        return super().read(buffer, offset)

    @property
    def max(self) -> int:
        return self.elem_field.max


def _parse(
    raw_octets: bytes, order: ByteOrder = ByteOrder.HiToLo, signed: Sign = Sign.Unsigned
) -> int:
    """Reads the given octets as a big-endian value. The function name comes
    from how such values are described in the packet format spec."""
    octets = list(raw_octets)
    if len(octets) == 0:
        return 0
    if order == ByteOrder.LoToHi:
        octets.reverse()

    # If this is a signed field (i.e., temperature), the highest-order
    # bit indicates sign. Detect this (and clear the bit so we can
    # compute the magnitude).
    #
    # This isn't documented in the protocol spec, but matches other
    # implementations.
    sign = 1
    if signed == Sign.Signed and (octets[0] & 0x80):
        octets[0] &= ~0x80
        sign = -1

    result = 0
    for octet in octets:
        result = (result << 8) + octet
    return sign * result
