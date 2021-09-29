import asyncio
import logging
from typing import Optional

from .api import CMD_DELAY_NEXT_PACKET, GemApi
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
API_RESPONSE_WAIT_TIME_SECONDS = 3.0  # Time to wait for an API response
PACKET_DELAY_CLEAR_TIME_SECONDS = 3.0  # Time to wait after a packet delay request so that GEM can finish sending any pending packets


class PacketProtocol(asyncio.Protocol):
    def __init__(
        self,
        queue: asyncio.Queue,
    ):
        """
        Create a new protocol instance.

        When a new connection is received from a GEM, a `GemApi` instance will be enqueued to
        `queue` that allows commands to be sent to that GEM. Whenever a data packet is received from
        the remote GEM, a `Packet` instance will be enqueued to `queue`.
        """
        self._buffer = bytearray()
        self._queue = queue
        self._transport: Optional[asyncio.WriteTransport] = None
        self._api_lock = asyncio.Lock()
        self._api_mode = asyncio.BoundedSemaphore(1)

    async def _send_api_command(self, command: str):
        async with self._api_lock:  # One API call at a time, please
            # We're about to send a request on the same channel that the GEM is using to
            # push data packets to us. To minimize confusion, we ask the GEM to delay packets
            # for 15 seconds and give it a few seconds to finish sending any in-progress
            # packets before sending our request.
            LOG.debug("Requesting packet delay...")
            self._ensure_transport().write(
                CMD_DELAY_NEXT_PACKET.encode()
            )  # Delay packets for 15 seconds
            await asyncio.sleep(PACKET_DELAY_CLEAR_TIME_SECONDS)

            async with self._api_mode:
                LOG.debug("Sending API request...")
                self._ensure_transport().write(f"{command}".encode())

                # API calls don't provide a nice consistent framing mechanism, but they
                # are pretty fast. So sleeping a few seconds should generally make sure
                # that we've got a complete response in the buffer, while also not
                # being so long that GEM starts sending packets again.
                await asyncio.sleep(API_RESPONSE_WAIT_TIME_SECONDS)

                result = self._buffer.decode()
                del self._buffer[:]
                LOG.debug("Handled API response")

            return result

    def connection_made(self, transport: asyncio.WriteTransport):
        self._transport = transport
        self._queue.put_nowait(GemApi(self._send_api_command))

    def connection_lost(self, exc):
        if exc is not None:
            LOG.warning("Connection lost: {}".format(exc))
        else:
            LOG.info("Connection closed")
        self._transport = None

    def data_received(self, data: bytes):
        LOG.debug("Received {} bytes".format(len(data)))
        self._buffer.extend(data)
        if not self._in_api_mode():
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

            def skip_malformed_packet(msg, *args, **kwargs):
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

    def _ensure_transport(self) -> asyncio.WriteTransport:
        if not self._transport:
            raise EOFError

        return self._transport

    def _in_api_mode(self) -> bool:
        return self._api_mode.locked()
