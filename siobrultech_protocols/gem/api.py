from datetime import timedelta
from typing import Callable, Generic, TypeVar

from .const import CMD_GET_SERIAL_NUMBER
from .protocol import BidirectionalProtocol

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


GET_SERIAL_NUMBER = ApiCall[None, int](
    formatter=lambda _: CMD_GET_SERIAL_NUMBER,
    parser=lambda response: int(response),
)
