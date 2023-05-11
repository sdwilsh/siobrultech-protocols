from __future__ import annotations

import asyncio
import struct
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Callable, Coroutine, Generic, Optional

from siobrultech_protocols.gem.packets import PacketFormatType

from .const import (
    CMD_GET_SERIAL_NUMBER,
    CMD_SET_DATE_AND_TIME,
    CMD_SET_PACKET_FORMAT,
    CMD_SET_PACKET_SEND_INTERVAL,
    CMD_SET_SECONDARY_PACKET_FORMAT,
)
from .protocol import ApiCall, BidirectionalProtocol, R, T

TIMEOUT = timedelta(seconds=15)


@asynccontextmanager
async def call_api(
    api: ApiCall[T, R],
    protocol: BidirectionalProtocol,
    serial_number: Optional[int] = None,
    timeout: timedelta = TIMEOUT,
) -> AsyncIterator[Callable[[T], Coroutine[Any, None, R]]]:
    async def send(arg: T) -> R:
        future = asyncio.get_event_loop().create_future()
        protocol.invoke_api(api, arg, future)
        return await asyncio.wait_for(future, timeout=timeout.total_seconds())

    delay = protocol.begin_api_request()
    try:
        await asyncio.sleep(delay.seconds)
        yield send
    finally:
        protocol.end_api_request()


class GEMAPIStringResponseParser(Generic[R]):
    """Most API responses in the GEM API end with \r\n; this parser waits until it sees a \r\n before attempting to parse."""

    def __init__(self, parser: Callable[[str], R]) -> None:
        self._parser = parser

    def __call__(self, arg: str) -> R | None:
        if not arg.endswith("\r\n"):
            return None

        return self._parser(arg)


def parse_ecm_serial_number_from_settings(binary: bytes) -> int | None:
    """
    Unlike GEM, ECM-1240 doesn't have a specific get-serial-number API. Instead,
    it returns the serial number as part of the device settings response.  This
    parser understands enough of that format to extract the serial number from
    the device settings.
    """
    if len(binary) < 33:
        return None

    # Note: The docs say that the serial number is transmitted big-endian, but
    # my test device is outputting little-endian
    [device_id, serial_number, zero, checksum] = struct.unpack_from(
        "<10xBH18xBB", binary, 0
    )
    actual_sum = sum(binary[:32]) % 256
    if zero != 0 or actual_sum != checksum:
        raise ValueError()

    # Following the GEM convention of just slamming device ID together with serial number
    # to get what the user considers the serial number.
    return int(f"{device_id}{serial_number:05}")


GET_SERIAL_NUMBER = ApiCall[None, int](
    gem_formatter=lambda _: CMD_GET_SERIAL_NUMBER,
    gem_parser=GEMAPIStringResponseParser(lambda response: int(response)),
    ecm_formatter=lambda _: [b"\xfc", b"SET", b"RCV"],
    ecm_parser=parse_ecm_serial_number_from_settings,
)


async def get_serial_number(
    protocol: BidirectionalProtocol, serial_number: Optional[int] = None
) -> int:
    async with call_api(GET_SERIAL_NUMBER, protocol, serial_number) as f:
        return await f(None)


SET_DATE_AND_TIME = ApiCall[datetime, bool](
    gem_formatter=lambda dt: f"{CMD_SET_DATE_AND_TIME}{dt.strftime('%y,%m,%d,%H,%M,%S')}\r",
    gem_parser=GEMAPIStringResponseParser(lambda response: response == "DTM\r\n"),
    ecm_formatter=None,
    ecm_parser=None,
)
SET_PACKET_FORMAT = ApiCall[int, bool](
    gem_formatter=lambda pf: f"{CMD_SET_PACKET_FORMAT}{pf:02}",
    gem_parser=GEMAPIStringResponseParser(lambda response: response == "PKT\r\n"),
    ecm_formatter=None,
    ecm_parser=None,
)
SET_PACKET_SEND_INTERVAL = ApiCall[int, bool](
    gem_formatter=lambda si: f"{CMD_SET_PACKET_SEND_INTERVAL}{si:03}",
    gem_parser=GEMAPIStringResponseParser(lambda response: response == "IVL\r\n"),
    ecm_formatter=lambda si: [b"\xfc", b"SET", b"IV2", bytes([si])],
    ecm_parser=None,
)
SET_SECONDARY_PACKET_FORMAT = ApiCall[int, bool](
    gem_formatter=lambda pf: f"{CMD_SET_SECONDARY_PACKET_FORMAT}{pf:02}",
    gem_parser=GEMAPIStringResponseParser(lambda response: response == "PKF\r\n"),
    ecm_formatter=None,
    ecm_parser=None,
)


async def set_date_and_time(
    protocol: BidirectionalProtocol, time: datetime, serial_number: Optional[int] = None
) -> bool:
    async with call_api(SET_DATE_AND_TIME, protocol, serial_number) as f:
        return await f(time)


async def set_packet_format(
    protocol: BidirectionalProtocol,
    format: PacketFormatType,
    serial_number: Optional[int] = None,
) -> bool:
    async with call_api(SET_PACKET_FORMAT, protocol, serial_number) as f:
        return await f(format)


async def set_packet_send_interval(
    protocol: BidirectionalProtocol,
    send_interval_seconds: int,
    serial_number: Optional[int] = None,
) -> bool:
    if send_interval_seconds < 0 or send_interval_seconds > 256:
        raise ValueError("send_interval must be a postive number no greater than 256")
    async with call_api(SET_PACKET_SEND_INTERVAL, protocol, serial_number) as f:
        return await f(send_interval_seconds)


async def set_secondary_packet_format(
    protocol: BidirectionalProtocol,
    format: PacketFormatType,
    serial_number: Optional[int] = None,
) -> bool:
    async with call_api(SET_SECONDARY_PACKET_FORMAT, protocol, serial_number) as f:
        return await f(format)


async def synchronize_time(
    protocol: BidirectionalProtocol, serial_number: Optional[int] = None
) -> bool:
    """
    Synchronizes the clock on the device to the time on the local device, accounting for the
    time waited for packets to clear.
    """
    time = datetime.now() + protocol.packet_delay_clear_time
    return await set_date_and_time(protocol, time, serial_number)
