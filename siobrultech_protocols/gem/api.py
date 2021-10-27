from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Callable, Coroutine, Generic, TypeVar

from .const import CMD_GET_SERIAL_NUMBER, CMD_SET_DATE_AND_TIME
from .protocol import PACKET_DELAY_CLEAR_TIME, BidirectionalProtocol

T = TypeVar("T")
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

    def send_request(self, protocol: BidirectionalProtocol, arg: T) -> timedelta:
        """
        Send the request using the given protocol and argument.

        Returns the length of time the caller should wait before attempting to receive the response.
        """
        return protocol.send_api_request(self._format_request(arg))

    def receive_response(self, protocol: BidirectionalProtocol) -> R:
        """
        Receive the response. Should be called after send_request, after
        waiting the amount of time indicated in that method's return value.

        Returns the API call response, parsed into an appropriate Python type.
        """
        return self._parse_response(protocol.receive_api_response())


@asynccontextmanager
async def call_api(
    api: ApiCall[T, R], protocol: BidirectionalProtocol
) -> AsyncIterator[Callable[[T], Coroutine[Any, None, R]]]:
    async def send(arg: T) -> R:
        delay = api.send_request(protocol, arg)
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


async def get_serial_number(protocol: BidirectionalProtocol) -> int:
    async with call_api(GET_SERIAL_NUMBER, protocol) as f:
        return await f(None)


SET_DATE_AND_TIME = ApiCall[datetime, bool](
    formatter=lambda dt: f"{CMD_SET_DATE_AND_TIME}{dt.strftime('%y,%m,%d,%H,%M,%S')}",
    parser=lambda response: response == "DTM",
)


async def set_date_and_time(protocol: BidirectionalProtocol, time: datetime) -> bool:
    async with call_api(SET_DATE_AND_TIME, protocol) as f:
        return await f(time)


async def synchronize_time(protocol: BidirectionalProtocol) -> bool:
    """
    Synchronizes the clock on the device to the time on the local device, accounting for the
    time waited for packets to clear.
    """
    time = datetime.now() + PACKET_DELAY_CLEAR_TIME
    return await set_date_and_time(protocol, time)
