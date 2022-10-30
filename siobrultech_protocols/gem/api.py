from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Callable, Coroutine, Generic, Optional, TypeVar

from siobrultech_protocols.gem.packets import PacketFormatType

from .const import (
    CMD_GET_SERIAL_NUMBER,
    CMD_SET_DATE_AND_TIME,
    CMD_SET_PACKET_FORMAT,
    CMD_SET_PACKET_SEND_INTERVAL,
    CMD_SET_SECONDARY_PACKET_FORMAT,
    ESCAPE_SEQUENCE,
    TARGET_SERIAL_NUMBER_PREFIX,
)
from .protocol import BidirectionalProtocol

# Argument type of an ApiCall.
T = TypeVar("T")
# Return type of an ApiCall response parser.
R = TypeVar("R")


class ApiCall(Generic[T, R]):
    """
    Helper class for making API calls with BidirectionalProtocol. There is one instance of
    this class for each supported API call. This class handles the send_api_request and
    receive_api_response parts of driving the protocol, since those are specific to each API
    request type.
    """

    def __init__(self, formatter: Callable[[T], str], parser: Callable[[str], R]):
        """
        Constructs a new ApiCall.

        formatter: given the parameters for the call (if any) as a Python object, formats the request
        parser: given the response from the call as a string, parses it into a Python object
        """
        self._format_request = formatter
        self._parse_response = parser

    def send_request(
        self,
        protocol: BidirectionalProtocol,
        arg: T,
        serial_number: Optional[int] = None,
    ) -> timedelta:
        """
        Send the request using the given protocol and argument.

        Returns the length of time the caller should wait before attempting to receive the response.
        """
        formatted_request = self._format_request(arg)
        if serial_number:
            formatted_request = formatted_request.replace(
                ESCAPE_SEQUENCE,
                f"{TARGET_SERIAL_NUMBER_PREFIX}{serial_number%100000:05}",
            )

        return protocol.send_api_request(formatted_request)

    def receive_response(self, protocol: BidirectionalProtocol) -> R:
        """
        Receive the response. Should be called after send_request, after
        waiting the amount of time indicated in that method's return value.

        Returns the API call response, parsed into an appropriate Python type.
        """
        return self._parse_response(protocol.receive_api_response())


@asynccontextmanager
async def call_api(
    api: ApiCall[T, R],
    protocol: BidirectionalProtocol,
    serial_number: Optional[int] = None,
) -> AsyncIterator[Callable[[T], Coroutine[Any, None, R]]]:
    async def send(arg: T) -> R:
        delay = api.send_request(protocol, arg, serial_number)
        await asyncio.sleep(delay.seconds)

        return api.receive_response(protocol)

    delay = protocol.begin_api_request()
    try:
        await asyncio.sleep(delay.seconds)
        yield send
    finally:
        protocol.end_api_request()


GET_SERIAL_NUMBER = ApiCall[None, int](
    formatter=lambda _: CMD_GET_SERIAL_NUMBER,
    parser=lambda response: int(response),
)


async def get_serial_number(
    protocol: BidirectionalProtocol, serial_number: Optional[int] = None
) -> int:
    async with call_api(GET_SERIAL_NUMBER, protocol, serial_number) as f:
        return await f(None)


SET_DATE_AND_TIME = ApiCall[datetime, bool](
    formatter=lambda dt: f"{CMD_SET_DATE_AND_TIME}{dt.strftime('%y,%m,%d,%H,%M,%S')}\r",
    parser=lambda response: response == "DTM\r\n",
)
SET_PACKET_FORMAT = ApiCall[int, bool](
    formatter=lambda pf: f"{CMD_SET_PACKET_FORMAT}{pf:02}",
    parser=lambda response: response == "PKT\r\n",
)
SET_PACKET_SEND_INTERVAL = ApiCall[int, bool](
    formatter=lambda si: f"{CMD_SET_PACKET_SEND_INTERVAL}{si:03}",
    parser=lambda response: response == "IVL\r\n",
)
SET_SECONDARY_PACKET_FORMAT = ApiCall[int, bool](
    formatter=lambda pf: f"{CMD_SET_SECONDARY_PACKET_FORMAT}{pf:02}",
    parser=lambda response: response == "PKF\r\n",
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
