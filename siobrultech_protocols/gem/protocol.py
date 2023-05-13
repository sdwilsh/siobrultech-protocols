from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum, unique
from typing import Any, Callable, Deque, Generic, List, Optional, Set, TypeVar, Union

from .const import (
    CMD_DELAY_NEXT_PACKET,
    ESCAPE_SEQUENCE,
    PACKET_DELAY_CLEAR_TIME_DEFAULT,
    TARGET_SERIAL_NUMBER_PREFIX,
)
from .packets import (
    BIN32_ABS,
    BIN32_NET,
    BIN48_ABS,
    BIN48_NET,
    BIN48_NET_TIME,
    ECM_1220,
    ECM_1240,
    MalformedPacketException,
    Packet,
    PacketFormatType,
)

LOG = logging.getLogger(__name__)

PACKET_HEADER = bytes.fromhex("feff")
API_RESPONSE_WAIT_TIME = timedelta(seconds=3)  # Time to wait for an API response


@dataclass(frozen=True)
class PacketProtocolMessage:
    """Base class for messages sent by a PacketProtocol."""

    protocol: PacketProtocol


@dataclass(frozen=True)
class ConnectionMadeMessage(PacketProtocolMessage):
    """Message sent when a new connection has been made to a protocol. Sent once shortly after creation of the protocol instance."""

    pass


@dataclass(frozen=True)
class PacketReceivedMessage(PacketProtocolMessage):
    """Message sent when a packet has been received by the protocol."""

    packet: Packet


@dataclass(frozen=True)
class ConnectionLostMessage(PacketProtocolMessage):
    """Message sent when a protocol loses its connection. exc is the exception that caused the connection to drop, if any."""

    exc: Optional[BaseException]


class PacketProtocol(asyncio.Protocol):
    """Protocol implementation for processing a stream of data packets from a GreenEye Monitor."""

    def __init__(
        self,
        queue: asyncio.Queue[PacketProtocolMessage],
    ):
        """
        Create a new protocol instance.

        Whenever a data packet is received from the GEM, a `Packet` instance will be enqueued to `queue`.
        """
        self._buffer = bytearray()
        self._queue = queue
        self._transport: Optional[asyncio.BaseTransport] = None
        self._packet_type: PacketFormatType | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        LOG.info("%d: Connection opened", id(self))
        assert self._transport is None
        self._transport = transport
        self._queue.put_nowait(ConnectionMadeMessage(protocol=self))

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        if exc is not None:
            LOG.warning("%d: Connection lost due to exception", id(self), exc_info=exc)
        else:
            LOG.info("%d: Connection closed", id(self))
        self._transport = None
        self._queue.put_nowait(ConnectionLostMessage(protocol=self, exc=exc))

    def data_received(self, data: bytes) -> None:
        LOG.debug("%d: Received %d bytes", id(self), len(data))
        self._buffer.extend(data)
        try:
            should_continue = True
            while should_continue:
                should_continue = self._process_buffer()
                self._ensure_transport()
        except Exception:
            LOG.exception("%d: Exception while attempting to parse a packet.", id(self))

    def _process_buffer(self) -> bool:
        """
        Attempts to process one chunk of data in the buffer.
        - If the buffer starts with a complete packet, delivers that packet to the queue and returns True
        - If the buffer starts with an incomplete packet, returns False
        - If the buffer starts with data that is not a packet, removes that data from the buffer, passes it
          to unknown_data_received(), and returns True

        Subclasses override unknown_data_received to process data in the buffer that is not packets (e.g. responses
        to API calls).

        Returns True if another call to _process_buffer might be able to process more of the buffer, False if the caller
        should wait for more data to be added to the buffer before calling again.
        """

        def skip_malformed_packet(msg: str, *args: Any, **kwargs: Any):
            header_index = self._buffer.find(PACKET_HEADER, 1)
            end = header_index if header_index != -1 else len(self._buffer)
            LOG.debug(
                "%d Skipping malformed packet due to " + msg + ". Buffer contents: %s",
                id(self),
                *args,
                self._buffer[0:end],
            )
            del self._buffer[0:end]

        header_index = self._buffer.find(PACKET_HEADER)
        if header_index != 0:
            end = header_index if header_index != -1 else len(self._buffer)
            self.unknown_data_received(self._buffer[0:end])
            del self._buffer[0:end]
            return len(self._buffer) > 0

        if len(self._buffer) < len(PACKET_HEADER) + 1:
            # Not enough length yet
            LOG.debug(
                "%d: Not enough data in buffer yet (%d bytes): %s",
                id(self),
                len(self._buffer),
                self._buffer,
            )
            return False

        format_code = self._buffer[len(PACKET_HEADER)]
        if format_code == 8:
            packet_format = BIN32_ABS
        elif format_code == 7:
            packet_format = BIN32_NET
        elif format_code == 6:
            packet_format = BIN48_ABS
        elif format_code == 5:
            packet_format = BIN48_NET
        elif format_code == 3:
            packet_format = ECM_1240
        elif format_code == 1:
            packet_format = ECM_1220
        else:
            skip_malformed_packet("unknown format code 0x%x", format_code)
            return len(self._buffer) > 0

        if len(self._buffer) < packet_format.size:
            # Not enough length yet
            LOG.debug(
                "%d: Not enough data in buffer yet (%d bytes)",
                id(self),
                len(self._buffer),
            )
            return False

        try:
            packet = None
            try:
                packet = packet_format.parse(self._buffer)
            except MalformedPacketException:
                if packet_format != BIN48_NET:
                    raise

            if packet is None:
                if len(self._buffer) < BIN48_NET_TIME.size:
                    # Not enough length yet
                    LOG.debug(
                        "%d: Not enough data in buffer yet (%d bytes)",
                        id(self),
                        len(self._buffer),
                    )
                    return False

                packet = BIN48_NET_TIME.parse(self._buffer)

            self._packet_type = packet.packet_format.type
            LOG.debug("%d: Parsed one %s packet.", id(self), packet.packet_format.name)
            del self._buffer[0 : packet.packet_format.size]
            self._queue.put_nowait(PacketReceivedMessage(protocol=self, packet=packet))
        except MalformedPacketException as e:
            skip_malformed_packet(e.args[0])

        return len(self._buffer) > 0

    def unknown_data_received(self, data: bytes) -> None:
        LOG.debug(
            "%d: No header found. Discarding junk data: %s",
            id(self),
            data,
        )

    def _ensure_transport(self) -> asyncio.BaseTransport:
        if not self._transport:
            raise EOFError

        return self._transport


@unique
class ProtocolState(Enum):
    RECEIVING_PACKETS = 1  # Receiving packets from the GEM
    SENT_PACKET_DELAY_REQUEST = 2  #  Sent the packet delay request prior to an API request, waiting for any in-flight packets
    SENDING_API_REQUEST = 3  # Sending a multi-part request
    SENT_API_REQUEST = 4  # Sent an API request, waiting for a response
    RECEIVED_API_RESPONSE = 5  # Received an API response, waiting for end call


class ProtocolStateException(Exception):
    def __init__(
        self,
        actual: ProtocolState,
        expected: Union[ProtocolState, Set[ProtocolState]],
        *args: object,
    ) -> None:
        self._actual = actual
        self._expected = expected
        super().__init__(*args)

    def __str__(self) -> str:
        if isinstance(self._expected, set):
            expected = [s.name for s in self._expected]
            if len(expected) > 1:
                expected_str = ", ".join(expected[:-1]) + f", or {expected[-1]}"
            else:
                expected_str = expected[0]
        else:
            expected_str = self._expected.name
        return f"Expected state to be {expected_str}; but got {self._actual.name}!"


# Argument type of an ApiCall.
T = TypeVar("T")
# Return type of an ApiCall response parser.
R = TypeVar("R")


@unique
class ApiType(Enum):
    ECM = 1
    GEM = 2


@dataclass
class ApiCall(Generic[T, R]):
    """
    Helper class for making API calls with BidirectionalProtocol. There is one instance of
    this class for each supported API call. This class handles the send_api_request and
    receive_api_response parts of driving the protocol, since those are specific to each API
    request type.
    """

    def __init__(
        self,
        gem_formatter: Callable[[T], str],
        gem_parser: Callable[[str], R | None] | None,
        ecm_formatter: Callable[[T], List[bytes]] | None,
        ecm_parser: Callable[[bytes], R | None] | None,
    ) -> None:
        """
        Create a new APICall.

        gem_formatter - a callable that, given a parameter of type T, returns the string to send to the GEM to make the API call
        gem_parser - a callable that, given a string, parses it into a value of type R.
                    If there is not enough data to parse yet, it should return None.
                    If there is enough data to parse, but it is malformed, it should raise an Exception.
        ecm_formatter - a callable that, given a parameter of type T, returns the series of bytes chunks to send to the ECM to make the API call
        ecm_parser - a callable that, given a bytes, parses it into a value of type R.
                    If there is not enough data to parse yet, it should return None.
                    If there is enough data to parse, but it is malformed, it should raise an Exception.
        """
        self._gem_formatter = gem_formatter
        self._gem_parser = gem_parser
        self._ecm_formatter = ecm_formatter
        self._ecm_parser = ecm_parser

    def format(
        self,
        api_type: ApiType,
        arg: T,
        serial_number: int | None,
    ) -> List[bytes]:
        if api_type == ApiType.GEM:
            result = self._gem_formatter(arg)
            if serial_number:
                result = result.replace(
                    ESCAPE_SEQUENCE,
                    f"{TARGET_SERIAL_NUMBER_PREFIX}{serial_number%100000:05}",
                )

            return [result.encode()]
        elif api_type == ApiType.ECM:
            assert self._ecm_formatter
            result = self._ecm_formatter(arg)
            return result
        else:
            assert False

    def has_parser(self, api_type: ApiType) -> bool:
        if api_type == ApiType.GEM:
            return self._gem_parser is not None
        elif api_type == ApiType.ECM:
            return self._ecm_parser is not None
        else:
            assert False

    def parse(self, api_type: ApiType, response: bytes) -> R | None:
        if api_type == ApiType.GEM:
            return self._gem_parser(response.decode()) if self._gem_parser else None
        elif api_type == ApiType.ECM:
            return self._ecm_parser(response) if self._ecm_parser else None
        else:
            assert False


class BidirectionalProtocol(PacketProtocol):
    """Protocol implementation for bi-directional communication with a GreenEye Monitor."""

    """
    Create a new BidirectionalProtocol

    The passed in queue contains full packets that have been received.
    The packet_delay_clear_time plus API_RESPONSE_WAIT_TIME must be less than 15 seconds.
    """

    def __init__(
        self,
        queue: asyncio.Queue[PacketProtocolMessage],
        packet_delay_clear_time: timedelta = PACKET_DELAY_CLEAR_TIME_DEFAULT,
        send_packet_delay: bool = True,
        api_type: ApiType | None = None,
    ):
        # Ensure that the clear time and the response wait time fit within the 15 second packet delay interval that is requested.
        assert (packet_delay_clear_time + API_RESPONSE_WAIT_TIME) < timedelta(
            seconds=15
        )

        super().__init__(queue)
        self._api_buffer = bytearray()
        self.send_packet_delay = send_packet_delay
        self._packet_delay_clear_time = packet_delay_clear_time
        self._state = ProtocolState.RECEIVING_PACKETS
        self._api_call: ApiCall[Any, Any] | None = None
        self._api_result: asyncio.Future[Any] | None = None
        self._api_type = api_type
        self._api_requests: Deque[bytes] = deque()

    @property
    def packet_delay_clear_time(self) -> timedelta:
        return self._packet_delay_clear_time

    @property
    def api_type(self) -> ApiType:
        if self._api_type is None:
            if (
                self._packet_type == PacketFormatType.ECM_1220
                or self._packet_type == PacketFormatType.ECM_1240
            ):
                self._api_type = ApiType.ECM
            elif self._packet_type:
                self._api_type = ApiType.GEM

        result = self._api_type
        assert result
        return result

    @api_type.setter
    def api_type(self, type: ApiType) -> None:
        self._api_type = type

    def unknown_data_received(self, data: bytes) -> None:
        if self._state == ProtocolState.SENDING_API_REQUEST:
            # We're in the middle of an ECM API call, which
            # has multiple roundtrips to send all the request chunks
            assert self._api_call
            if data.startswith(b"\xfc"):
                # ECM acks each chunk with \xfc
                if len(self._api_requests) > 0:
                    self._send_next_api_request_chunk()
                else:
                    # No more chunks means that we've now completely sent the request
                    self._state = ProtocolState.SENT_API_REQUEST

                    if self._api_call.has_parser(self.api_type):
                        # This API call is expecting a response, and
                        # the ACK character might be immediately followed
                        # by response data, so we pull off the ACK character
                        # and fall through to the rest of the method,
                        # which then pulls the response from the data
                        data = data[1:]
                    else:
                        # Last ACK of a request with no response
                        self._set_result(result=None)
            else:
                self._set_result(
                    exception=Exception("Bad response from device: {data}")
                )

        if self._state == ProtocolState.SENT_API_REQUEST:
            assert self._api_call is not None
            self._api_buffer.extend(data)

            response = bytes(self._api_buffer)
            LOG.debug("%d: Attempting to parse API response: %s", id(self), response)

            result = self._api_call.parse(self.api_type, response)
            if result:
                if self.api_type == ApiType.ECM:
                    self._ensure_write_transport().write(b"\xfc")
                self._set_result(result=result)
        elif self._state == ProtocolState.RECEIVING_PACKETS:
            super().unknown_data_received(data)

    def begin_api_request(self) -> timedelta:
        """
        Begin the process of sending an API request.

        Calls WriteTransport.write on the associated transport with bytes that need to be sent.

        Returns a timedelta. Callers must wait for that amount of time, then call send_api_request with the actual request.
        """
        self._expect_state(ProtocolState.RECEIVING_PACKETS)

        self._state = ProtocolState.SENT_PACKET_DELAY_REQUEST
        if self.api_type == ApiType.GEM and self.send_packet_delay:
            LOG.debug("%d: Starting API request. Requesting packet delay...", id(self))
            self._ensure_write_transport().write(
                CMD_DELAY_NEXT_PACKET.encode()
            )  # Delay packets for 15 seconds
            return self._packet_delay_clear_time
        else:
            return timedelta(seconds=0)

    def invoke_api(
        self,
        api: ApiCall[T, R],
        arg: T,
        result: asyncio.Future[R],
        serial_number: Optional[int] = None,
    ) -> None:
        """
        Send the given API request, after having called begin_api_request.

        Calls WriteTransport.write on the associated transport with bytes that need to be sent.

        Returns a timedelta. Callers must wait for that amount of time, then call receive_api_response to receive the response.
        """
        self._expect_state(ProtocolState.SENT_PACKET_DELAY_REQUEST)
        assert len(self._api_requests) == 0

        self._api_call = api
        self._api_result = result
        self._api_requests.extend(api.format(self.api_type, arg, serial_number))

        self._send_next_api_request_chunk()

    def _send_next_api_request_chunk(self) -> None:
        assert len(self._api_requests) > 0
        assert self._api_call
        assert self._api_result

        request = self._api_requests.popleft()
        LOG.debug("%d: Sending API request %s...", id(self), request)
        self._ensure_write_transport().write(request)
        self._state = (
            ProtocolState.SENT_API_REQUEST
            if self.api_type == ApiType.GEM
            else ProtocolState.SENDING_API_REQUEST
        )
        if (
            not self._api_call.has_parser(self.api_type)
            and self.api_type == ApiType.GEM
        ):
            # GEM API calls without a response are just a single send and you're done
            # (ECM API calls without a response still have multiple request chunks to send,
            # and even the last chunk is still acked with \xfc, so we don't advance the
            # state for them here)
            assert len(self._api_requests) == 0
            self._set_result(result=None)

    def _set_result(
        self, result: Any | None = None, exception: Exception | None = None
    ) -> None:
        assert (
            self._state == ProtocolState.SENT_API_REQUEST
            or self._state == ProtocolState.SENDING_API_REQUEST
        )
        assert self._api_result
        assert not self._api_result.done()

        if exception is None:
            self._state = ProtocolState.RECEIVED_API_RESPONSE
            self._api_result.set_result(result)
        else:
            assert result is None
            self._api_result.set_exception(exception)
        self._api_result = None
        self._api_call = None

    def end_api_request(self) -> None:
        """
        Ends an API request. Every begin_api_request call must have a matching end_api_request call,
        even if an error occurred in between.
        """
        self._expect_state(
            {
                ProtocolState.RECEIVED_API_RESPONSE,
                ProtocolState.SENDING_API_REQUEST,
                ProtocolState.SENT_API_REQUEST,
                ProtocolState.SENT_PACKET_DELAY_REQUEST,
            }
        )
        self._api_buffer.clear()
        self._api_call = None
        self._api_requests.clear()
        self._api_result = None
        LOG.debug("%d: Ended API request", id(self))
        self._state = ProtocolState.RECEIVING_PACKETS

    def _ensure_write_transport(self) -> asyncio.WriteTransport:
        transport = self._ensure_transport()
        assert isinstance(transport, asyncio.WriteTransport)
        return transport

    def _expect_state(self, expected_state: Union[ProtocolState, Set[ProtocolState]]):
        if not isinstance(expected_state, set):
            expected_state = {expected_state}
        assert len(expected_state) > 0
        if self._state not in expected_state:
            raise ProtocolStateException(actual=self._state, expected=expected_state)
