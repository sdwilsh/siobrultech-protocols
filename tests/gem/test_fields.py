import unittest
from datetime import datetime

from siobrultech_protocols.gem.fields import (
    ArrayField,
    ByteField,
    ByteOrder,
    BytesField,
    DateTimeField,
    FloatingPointArrayField,
    FloatingPointField,
    NumericArrayField,
    NumericField,
    Sign,
)


class TestFieldParsing(unittest.TestCase):
    def testByteFieldRead(self):
        self.assertEqual(b"c", ByteField().read(b"abcdefg", 2))

    def testBytesFieldRead(self):
        self.assertEqual(b"cdef", BytesField(4).read(b"abcdefg", 2))

    def testNumericFieldHiToLoRead(self):
        self.assertEqual(
            1, NumericField(2, ByteOrder.HiToLo, Sign.Unsigned).read(b"\x02\x00\x01", 1)
        )

    def testNumericFieldHiToLoSignedRead(self):
        self.assertEqual(
            -1, NumericField(2, ByteOrder.HiToLo, Sign.Signed).read(b"\x02\x80\x01", 1)
        )

    def testNumericFieldLoToHiRead(self):
        self.assertEqual(
            256,
            NumericField(2, ByteOrder.LoToHi, Sign.Unsigned).read(b"\x02\x00\x01", 1),
        )

    def testNumericFieldLoToHiSignedRead(self):
        self.assertEqual(
            -256,
            NumericField(2, ByteOrder.LoToHi, Sign.Signed).read(b"\x02\x00\x81", 1),
        )

    def testNumericFieldUnsignedMax(self):
        field = NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)
        self.assertEqual(
            field.read(b"\xff\xff", 0),
            field.max,
        )

    def testNumericFieldSignedMax(self):
        field = NumericField(2, ByteOrder.HiToLo, Sign.Signed)
        self.assertEqual(
            field.read(b"\x7f\xff", 0),
            field.max,
        )

    def testFloatingPointFieldRead(self):
        self.assertEqual(
            0.5,
            FloatingPointField(2, ByteOrder.HiToLo, Sign.Unsigned, 2.0).read(
                b"\x02\x00\x01", 1
            ),
        )

    def testFloatingPointFieldReadDiv100(self):
        self.assertEqual(
            1.16,
            FloatingPointField(2, ByteOrder.HiToLo, Sign.Unsigned, 100.0).read(
                b"\x02\x00\x74", 1
            ),
        )

    def testDateTimeFieldRead(self):
        self.assertEqual(
            datetime(2020, 1, 1, 0, 0, 0),
            DateTimeField().read(b"\x02\x14\x01\x01\x00\x00\x00", 1),
        )

    def testArrayFieldRead(self):
        self.assertEqual(
            [1, 2, 3, 4],
            ArrayField(4, NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)).read(
                b"\x05\x00\x01\x00\x02\x00\x03\x00\x04", 1
            ),
        )

    def testNumericArrayFieldRead(self):
        self.assertEqual(
            [1, 2, 3, 4],
            NumericArrayField(4, 2, ByteOrder.HiToLo, Sign.Unsigned).read(
                b"\x05\x00\x01\x00\x02\x00\x03\x00\x04", 1
            ),
        )

    def testFloatingPointArrayFieldRead(self):
        self.assertEqual(
            [0.5, 1.0, 1.5, 2.0],
            FloatingPointArrayField(4, 2, ByteOrder.HiToLo, Sign.Unsigned, 2.0).read(
                b"\x05\x00\x01\x00\x02\x00\x03\x00\x04", 1
            ),
        )


class TestFieldFormatting(unittest.TestCase):
    def setUp(self):
        self._buffer = bytearray()

    def testByteFieldWrite(self):
        ByteField().write(ord("c"), self._buffer)
        self.assertEqual(b"c", self._buffer)

    def testBytesFieldWrite(self):
        BytesField(4).write([ord(char) for char in "cdef"], self._buffer)
        self.assertEqual(b"cdef", self._buffer)

    def testNumericFieldHiToLoWrite(self):
        NumericField(2, ByteOrder.HiToLo, Sign.Signed).write(1, self._buffer)
        self.assertEqual(b"\x00\x01", self._buffer)

    def testNumericFieldHiToLoSignedWrite(self):
        NumericField(2, ByteOrder.HiToLo, Sign.Signed).write(-1, self._buffer)
        self.assertEqual(b"\x80\x01", self._buffer)

    def testNumericFieldLoToHiWrite(self):
        NumericField(2, ByteOrder.LoToHi, Sign.Signed).write(256, self._buffer)
        self.assertEqual(b"\x00\x01", self._buffer)

    def testNumericFieldLoToHiSignedWrite(self):
        NumericField(2, ByteOrder.LoToHi, Sign.Signed).write(-256, self._buffer)
        self.assertEqual(b"\x00\x81", self._buffer)

    def testNumericFieldUnsignedMax(self):
        field = NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)
        field.write(field.max, self._buffer)
        self.assertEqual(b"\xff\xff", self._buffer)

    def testNumericFieldSignedMax(self):
        field = NumericField(2, ByteOrder.HiToLo, Sign.Signed)
        field.write(field.max, self._buffer)
        self.assertEqual(b"\x7f\xff", self._buffer)

    def testFloatingPointFieldWrite(self):
        FloatingPointField(2, ByteOrder.HiToLo, Sign.Unsigned, 2.0).write(
            0.5, self._buffer
        )
        self.assertEqual(b"\x00\x01", self._buffer)

    def testFloatingPointFieldWriteDiv100(self):
        FloatingPointField(2, ByteOrder.HiToLo, Sign.Unsigned, 100.0).write(
            1.16, self._buffer
        )
        self.assertEqual(b"\x00\x74", self._buffer)

    def testDateTimeFieldWrite(self):
        DateTimeField().write(datetime(2020, 1, 1, 0, 0, 0), self._buffer)
        self.assertEqual(b"\x14\x01\x01\x00\x00\x00", self._buffer)

    def testArrayFieldWrite(self):
        ArrayField(4, NumericField(2, ByteOrder.HiToLo, Sign.Unsigned)).write(
            [1, 2, 3, 4], self._buffer
        )
        self.assertEqual(b"\x00\x01\x00\x02\x00\x03\x00\x04", self._buffer)

    def testNumericArrayFieldWrite(self):
        NumericArrayField(4, 2, ByteOrder.HiToLo, Sign.Unsigned).write(
            [1, 2, 3, 4], self._buffer
        )
        self.assertEqual(b"\x00\x01\x00\x02\x00\x03\x00\x04", self._buffer)

    def testFloatingPointArrayFieldWrite(self):
        FloatingPointArrayField(4, 2, ByteOrder.HiToLo, Sign.Unsigned, 2.0).write(
            [0.5, 1.0, 1.5, 2.0], self._buffer
        )
        self.assertEqual(b"\x00\x01\x00\x02\x00\x03\x00\x04", self._buffer)
