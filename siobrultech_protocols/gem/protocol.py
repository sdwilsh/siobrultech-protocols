import asyncio
import logging
from typing import Optional

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


class PacketProtocol(asyncio.Protocol):
    def __init__(self, queue: asyncio.Queue):
        self._buffer = bytearray()
        self._queue = queue
        self._transport: Optional[asyncio.BaseTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport):
        self._transport = transport

    def connection_lost(self, exc):
        if exc is not None:
            LOG.warning("Connection lost: {}".format(exc))
        else:
            LOG.info("Connection closed")
        self._transport = None

    def data_received(self, data: bytes):
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

            def skip_malformed_packet(msg, *args, **kwargs):
                LOG.debug(
                    "Skipping malformed packet due to " + msg + ". Buffer contents: %s",
                    *args,
                    self._buffer
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

        if not self._transport:
            raise EOFError
