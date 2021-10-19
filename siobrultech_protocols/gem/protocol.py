from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from enum import Enum, unique
from typing import Any, Optional, TypeVar

from .const import CMD_DELAY_NEXT_PACKET
from .packets import (
    BIN32_ABS,
    BIN32_NET,
    BIN48_ABS,
    BIN48_NET,
    BIN48_NET_TIME,
    MalformedPacketException,
    Packet,
)

LOG = logging.getLogger(__name__)

PACKET_HEADER = bytes.fromhex("feff")
API_RESPONSE_WAIT_TIME = timedelta(seconds=3)  # Time to wait for an API response
PACKET_DELAY_CLEAR_TIME = timedelta(
    seconds=3
)  # Time to wait after a packet delay request so that GEM can finish sending any pending packets


T = TypeVar("T")
R = TypeVar("R")


class PacketProtocol(asyncio.Protocol):
    """Protocol implementation for processing a stream of data packets from a GreenEye Monitor."""

    def __init__(
        self,
        queue: asyncio.Queue[Packet],
    ):
        """
        Create a new protocol instance.

        Whenever a data packet is received from the GEM, a `Packet` instance will be enqueued to `queue`.
        """
        self._buffer = bytearray()
        self._queue = queue
        self._transport: Optional[asyncio.BaseTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport

    def connection_lost(self, exc: Optional[Any]) -> None:
        if exc is not None:
            LOG.warning("Connection lost: {}".format(exc))
        else:
            LOG.info("Connection closed")
        self._transport = None

    def data_received(self, data: bytes) -> None:
        LOG.debug("Received {} bytes".format(len(data)))
        self._buffer.extend(data)
        try:
            packet = self._get_packet()
            while packet is not None:
                self._queue.put_nowait(packet)
                packet = self._get_packet()
        except Exception as e:
            LOG.exception("Exception while attempting to parse a packet.", e)

    def _get_packet(self) -> Optional[Packet]:
        """
        Returns a full packet if available.
        """
        while len(self._buffer) > 0:

            def skip_malformed_packet(msg: str, *args: Any, **kwargs: Any):
                LOG.debug(
                    "Skipping malformed packet due to " + msg + ". Buffer contents: %s",
                    *args,
                    self._buffer,
                )
                del self._buffer[0 : len(PACKET_HEADER)]

            header_index = self._buffer.find(PACKET_HEADER)
            if header_index == -1:
                LOG.debug("No header found. Discarding junk data: %s", self._buffer)
                self._buffer.clear()
                continue
            del self._buffer[0:header_index]

            if len(self._buffer) < len(PACKET_HEADER) + 1:
                # Not enough length yet
                LOG.debug(
                    "Not enough data in buffer yet ({} bytes): {}".format(
                        len(self._buffer), self._buffer
                    )
                )
                return None

            format_code = self._buffer[len(PACKET_HEADER)]
            if format_code == 8:
                packet_format = BIN32_ABS
            elif format_code == 7:
                packet_format = BIN32_NET
            elif format_code == 6:
                packet_format = BIN48_ABS
            elif format_code == 5:
                packet_format = BIN48_NET
            else:
                skip_malformed_packet("unknown format code 0x%x", format_code)
                continue

            if len(self._buffer) < packet_format.size:
                # Not enough length yet
                LOG.debug(
                    "Not enough data in buffer yet ({} bytes)".format(len(self._buffer))
                )
                return None

            try:
                result = None
                try:
                    result = packet_format.parse(self._buffer)
                except MalformedPacketException:
                    if packet_format != BIN48_NET:
                        raise

                if result is None:
                    if len(self._buffer) < BIN48_NET_TIME.size:
                        # Not enough length yet
                        LOG.debug(
                            "Not enough data in buffer yet ({} bytes)".format(
                                len(self._buffer)
                            )
                        )
                        return None

                    result = BIN48_NET_TIME.parse(self._buffer)

                LOG.debug("Parsed one {} packet.".format(result.packet_format.name))
                del self._buffer[0 : result.packet_format.size]
                return result
            except MalformedPacketException as e:
                skip_malformed_packet(e.args[0])

        self._ensure_transport()

    def _ensure_transport(self) -> asyncio.BaseTransport:
        if not self._transport:
            raise EOFError

        return self._transport


@unique
class ProtocolState(Enum):
    RECEIVING_PACKETS = 1  # Receiving packets from the GEM
    SENT_PACKET_DELAY_REQUEST = 2  #  Sent the packet delay request prior to an API request, waiting for any in-flight packets
    SENT_API_REQUEST = 3  # Sent an API request, waiting for a response
    RECEIVED_API_RESPONSE = 4  # Received an API response, waiting for end call


class ProtocolStateException(Exception):
    pass


class BidirectionalProtocol(PacketProtocol):
    """Protocol implementation for bi-directional communication with a GreenEye Monitor."""

    def __init__(self, queue: asyncio.Queue[Packet]):
        super().__init__(queue)
        self._state = ProtocolState.RECEIVING_PACKETS
        self._api_buffer = bytearray()

    def data_received(self, data: bytes) -> None:
        if self._state == ProtocolState.SENT_API_REQUEST:
            self._api_buffer.extend(data)
        else:
            super().data_received(data)

    def begin_api_request(self) -> timedelta:
        """
        Begin the process of sending an API request.

        Calls WriteTransport.write on the associated transport with bytes that need to be sent.

        Returns a timedelta. Callers must wait for that amount of time, then call send_api_request with the actual request.
        """
        self._expect_state(ProtocolState.RECEIVING_PACKETS)

        LOG.debug("Starting API request. Requesting packet delay...")
        self._ensure_write_transport().write(
            CMD_DELAY_NEXT_PACKET.encode()
        )  # Delay packets for 15 seconds
        self._state = ProtocolState.SENT_PACKET_DELAY_REQUEST

        return PACKET_DELAY_CLEAR_TIME

    def send_api_request(self, request: str) -> timedelta:
        """
        Send the given API request, after having called begin_api_request.

        Calls WriteTransport.write on the associated transport with bytes that need to be sent.

        Returns a timedelta. Callers must wait for that amount of time, then call receive_api_response to receive the response.
        """
        self._expect_state(ProtocolState.SENT_PACKET_DELAY_REQUEST)

        LOG.debug(f"Sending API request '{request}'...")
        self._ensure_write_transport().write(request.encode())
        self._state = ProtocolState.SENT_API_REQUEST

        return API_RESPONSE_WAIT_TIME

    def receive_api_response(self) -> str:
        """
        Returns the bytes that were received in response to a call to send_api_request.

        Callers must call end_api_request after this call.
        """
        self._expect_state(ProtocolState.SENT_API_REQUEST)

        response = bytes(self._api_buffer).decode()
        LOG.debug(f"Received API response: '{response}'")
        self._state = ProtocolState.RECEIVED_API_RESPONSE

        return response

    def end_api_request(self) -> None:
        """
        Ends an API request. Every begin_api_request call must have a matching end_api_request call,
        even if an error occurred in between.
        """
        self._expect_state(ProtocolState.RECEIVED_API_RESPONSE)
        self._api_buffer.clear()
        LOG.debug(f"Ended API request")
        self._state = ProtocolState.RECEIVING_PACKETS

    def _ensure_write_transport(self) -> asyncio.WriteTransport:
        transport = self._ensure_transport()
        assert isinstance(transport, asyncio.WriteTransport)
        return transport

    def _expect_state(self, expected_state: ProtocolState):
        if self._state != expected_state:
            raise ProtocolStateException()
