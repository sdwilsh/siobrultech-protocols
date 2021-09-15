"""
Field types used in
https://www.brultech.com/software/files/downloadSoft/GEM-PKT_Packet_Format_2_1.pdf
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Callable, List


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
    def __init__(self, size: int, order_fn: Callable[[bytes], int]):
        super().__init__(size=size)
        self.order_fn = order_fn

    def read(self, buffer: bytes, offset: int) -> int:
        return self.order_fn(buffer[offset : offset + self.size])

    @property
    def max(self) -> int:
        return 2 ** self.size


class FloatingPointField(Field):
    def __init__(self, size: int, order_fn: Callable[[bytes], int], divisor: float):
        self.raw_field = NumericField(size, order_fn)
        super().__init__(size=self.raw_field.size)
        self.divisor = divisor

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
        self.elem_field = elem_field
        self.num_elems = num_elems

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
        order_fn: Callable[[bytes], int],
        divisor: float,
    ):
        super().__init__(
            num_elems=num_elems,
            elem_field=FloatingPointField(
                size=size, order_fn=order_fn, divisor=divisor
            ),
        )

    def read(self, buffer: bytes, offset: int) -> List[float]:
        return super().read(buffer, offset)


class NumericArrayField(ArrayField):
    elem_field: NumericField

    def __init__(self, num_elems: int, size: int, order_fn: Callable[[bytes], int]):
        super().__init__(
            num_elems=num_elems, elem_field=NumericField(size=size, order_fn=order_fn)
        )

    def read(self, buffer: bytes, offset: int) -> List[int]:
        return super().read(buffer, offset)

    @property
    def max(self) -> int:
        return self.elem_field.max


def hi_to_lo(raw_octets: bytes, signed=False):
    """Reads the given octets as a big-endian value. The function name comes
    from how such values are described in the packet format spec."""
    octets = list(raw_octets)
    if len(octets) == 0:
        return 0

    # If this is a signed field (i.e., temperature), the highest-order
    # bit indicates sign. Detect this (and clear the bit so we can
    # compute the magnitude).
    #
    # This isn't documented in the protocol spec, but matches other
    # implementations.
    sign = 1
    if signed and (octets[0] & 0x80):
        octets[0] &= ~0x80
        sign = -1

    result = 0
    for octet in octets:
        result = (result << 8) + octet
    return sign * result


def lo_to_hi(raw_octets: bytes, signed=False):
    """Reads the given octets as a little-endian value. The function name comes
    from how such values are described in the packet format spec."""
    octets = bytearray(raw_octets)
    octets.reverse()
    return hi_to_lo(octets, signed)


def hi_to_lo_signed(octets: bytes):
    """Reads the given octets as a signed big-endian value. The function
    name comes from how such values are described in the packet format
    spec."""
    return hi_to_lo(octets, True)


def lo_to_hi_signed(octets: bytes):
    """Reads the given octets as a signed little-endian value. The
    function name comes from how such values are described in the
    packet format spec."""
    return lo_to_hi(octets, True)
