from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
from unittest.async_case import IsolatedAsyncioTestCase
from unittest.mock import patch

from siobrultech_protocols.gem.api import (
    GET_SERIAL_NUMBER,
    SET_DATE_AND_TIME,
    SET_PACKET_FORMAT,
    SET_PACKET_SEND_INTERVAL,
    SET_SECONDARY_PACKET_FORMAT,
    ApiCall,
    R,
    T,
    call_api,
    get_serial_number,
    set_date_and_time,
    set_packet_format,
    set_packet_send_interval,
    set_secondary_packet_format,
    synchronize_time,
)
from siobrultech_protocols.gem.packets import PacketFormatType
from siobrultech_protocols.gem.protocol import (
    ApiType,
    BidirectionalProtocol,
    PacketProtocolMessage,
)
from tests.gem.mock_transport import MockRespondingTransport, MockTransport


class TestApi(IsolatedAsyncioTestCase):
    def setUp(self):
        self._queue: asyncio.Queue[PacketProtocolMessage] = asyncio.Queue()
        self._transport = MockTransport()
        self._protocol = BidirectionalProtocol(
            self._queue,
            packet_delay_clear_time=timedelta(seconds=0),
            api_type=ApiType.GEM,
        )
        self._protocol.connection_made(self._transport)

    async def testApiCallWithoutResponse(self):
        call = ApiCall(lambda _: "REQUEST", None, None, None)

        await self.assertCall(call, "REQUEST", None, None, None, None)

    async def testApiCall(self):
        call = ApiCall(lambda _: "REQUEST", lambda response: response, None, None)

        await self.assertCall(
            call, "REQUEST", None, None, "RESPONSE".encode(), "RESPONSE"
        )

    async def testApiCallWithSerialNumber(self):
        call = ApiCall(lambda _: "^^^REQUEST", lambda response: response, None, None)

        await self.assertCall(
            call, "^^^NMB02345REQUEST", None, 1002345, "RESPONSE".encode(), "RESPONSE"
        )

    async def testApiCallIgnored(self):
        call = ApiCall(lambda _: "REQUEST", lambda response: response, None, None)

        async with call_api(call, self._protocol, timeout=timedelta(seconds=0)) as f:
            with self.assertRaises(asyncio.exceptions.TimeoutError):
                await f(None)

    async def testGEMGetSerialNumber(self):
        await self.assertCall(
            GET_SERIAL_NUMBER,
            "^^^RQSSRN",
            None,
            None,
            "1234567\r\n".encode(),
            1234567,
        )

    async def testECMGetSerialNumber(self):
        await self.assertECMCall(
            GET_SERIAL_NUMBER,
            [b"\xfc", b"SET", b"RCV"],
            None,
            None,
            b"\xa7\x04\xa7\x04\xf4\x03\x01\x0c\x04\x0b\x05\x01\xb2\x90\x00\x00\x00\x00\x8d\x8b\x8c\x8b\xce\x00\xff\xff\xff\xff\x05\x80>\x00m",
            545569,
        )

    async def testSetDateTime(self):
        await self.assertCall(
            SET_DATE_AND_TIME,
            "^^^SYSDTM12,08,23,13,30,28\r",
            datetime.fromisoformat("2012-08-23 13:30:28"),
            None,
            "DTM\r\n".encode(),
            True,
        )

    async def testSetPacketFormat(self):
        await self.assertCall(
            SET_PACKET_FORMAT,
            "^^^SYSPKT02",
            2,
            None,
            "PKT\r\n".encode(),
            True,
        )

    async def testGEMSetPacketSendInterval(self):
        await self.assertCall(
            SET_PACKET_SEND_INTERVAL,
            "^^^SYSIVL042",
            42,
            None,
            "IVL\r\n".encode(),
            True,
        )

    async def testECMSetPacketSendInterval(self):
        await self.assertECMCall(
            SET_PACKET_SEND_INTERVAL,
            [b"\xfc", b"SET", b"IV2", bytes([42])],
            42,
            None,
            None,
            None,
        )

    async def testSetSecondaryPacketFormat(self):
        await self.assertCall(
            SET_SECONDARY_PACKET_FORMAT,
            "^^^SYSPKF00",
            0,
            None,
            "PKF\r\n".encode(),
            True,
        )

    async def assertCall(
        self,
        call: ApiCall[T, R],
        request: str,
        arg: T,
        serial_number: Optional[int],
        encoded_response: bytes | None,
        parsed_response: R | None,
    ):
        self._protocol.begin_api_request()
        self._transport.writes.clear()  # Ignore the packet delay
        result = asyncio.get_event_loop().create_future()
        self._protocol.invoke_api(call, arg, result, serial_number)
        self.assertEqual(
            self._transport.writes,
            [request.encode()],
            f"{request.encode()} should be written to the transport",
        )
        if encoded_response is not None:
            self._protocol.data_received(encoded_response)
        result = await asyncio.wait_for(result, 0)
        self.assertEqual(
            result,
            parsed_response,
            f"{parsed_response} should be the parsed value returned",
        )

    async def assertECMCall(
        self,
        call: ApiCall[T, R],
        request: List[bytes],
        arg: T,
        serial_number: Optional[int],
        encoded_response: bytes | None,
        parsed_response: R | None,
    ):
        self._protocol.api_type = ApiType.ECM
        self._transport.writes.clear()
        self._protocol.begin_api_request()
        result = asyncio.get_event_loop().create_future()
        self._protocol.invoke_api(call, arg, result, serial_number)
        for _ in range(0, len(request)):
            self._protocol.data_received(b"\xfc")
        self.assertEqual(
            self._transport.writes,
            request,
            f"{request} should be written to the transport",
        )
        if encoded_response is not None:
            self._transport.writes.clear()
            self._protocol.data_received(encoded_response)
        result = await asyncio.wait_for(result, 0)
        self.assertEqual(
            result,
            parsed_response,
            f"{parsed_response} should be the parsed value returned",
        )
        self._protocol.end_api_request()
        if encoded_response is not None:
            self.assertEqual(
                self._transport.writes,
                [b"\xfc"],
                f"ECM API calls with a response should be acked by the caller",
            )


class TestContextManager(IsolatedAsyncioTestCase):
    def setUp(self):
        self._queue: asyncio.Queue[PacketProtocolMessage] = asyncio.Queue()
        self._transport = MockTransport()
        self._protocol = BidirectionalProtocol(
            self._queue,
            packet_delay_clear_time=timedelta(seconds=0),
            api_type=ApiType.GEM,
        )
        self._protocol.connection_made(self._transport)

    @patch(
        "siobrultech_protocols.gem.protocol.API_RESPONSE_WAIT_TIME",
        timedelta(seconds=0),
    )
    async def testApiCall(self):
        call = ApiCall(lambda _: "REQUEST", lambda response: response, None, None)
        async with call_api(call, self._protocol) as f:
            self.setApiResponse("RESPONSE".encode())
            response = await f(None)
            self.assertEqual(response, "RESPONSE")

    async def testTaskCanceled(self):
        call = ApiCall(lambda _: "REQUEST", lambda response: response, None, None)
        with self.assertRaises(asyncio.CancelledError):
            with patch("asyncio.sleep") as mock_sleep:
                mock_sleep.side_effect = asyncio.CancelledError
                async with call_api(call, self._protocol):
                    raise AssertionError("this should not be reached")

    def setApiResponse(self, ecnoded_response: bytes) -> asyncio.Task[None]:
        async def notify_data_received() -> None:
            self._protocol.data_received(ecnoded_response)

        return asyncio.create_task(
            notify_data_received(), name=f"{__name__}:send_api_resonse"
        )


class TestApiHelpers(IsolatedAsyncioTestCase):
    def setUp(self):
        self._protocol = BidirectionalProtocol(
            asyncio.Queue(),
            packet_delay_clear_time=timedelta(seconds=0),
            api_type=ApiType.GEM,
        )

        patcher_API_RESPONSE_WAIT_TIME = patch(
            "siobrultech_protocols.gem.protocol.API_RESPONSE_WAIT_TIME",
            timedelta(seconds=0),
        )
        patcher_API_RESPONSE_WAIT_TIME.start()
        self.addCleanup(lambda: patcher_API_RESPONSE_WAIT_TIME.stop())

    async def test_get_serial_number(self):
        transport = MockRespondingTransport(self._protocol, "1234567\r\n".encode())
        self._protocol.connection_made(transport)
        serial = await get_serial_number(self._protocol)
        self.assertEqual(serial, 1234567)

    async def test_set_date_and_time(self):
        transport = MockRespondingTransport(self._protocol, "DTM\r\n".encode())
        self._protocol.connection_made(transport)
        success = await set_date_and_time(self._protocol, datetime(2020, 3, 11))
        self.assertTrue(success)

    async def test_set_packet_format(self):
        transport = MockRespondingTransport(self._protocol, "PKT\r\n".encode())
        self._protocol.connection_made(transport)
        success = await set_packet_format(self._protocol, PacketFormatType.BIN32_ABS)
        self.assertTrue(success)

    async def test_set_packet_send_interval(self):
        with self.assertRaises(ValueError):
            await set_packet_send_interval(self._protocol, -1)

        with self.assertRaises(ValueError):
            await set_packet_send_interval(self._protocol, 257)

        transport = MockRespondingTransport(self._protocol, "IVL\r\n".encode())
        self._protocol.connection_made(transport)
        success = await set_packet_send_interval(self._protocol, 42)
        self.assertTrue(success)

    async def test_set_secondary_packet_format(self):
        transport = MockRespondingTransport(self._protocol, "PKF\r\n".encode())
        self._protocol.connection_made(transport)
        success = await set_secondary_packet_format(
            self._protocol, PacketFormatType.BIN32_ABS
        )
        self.assertTrue(success)

    async def test_synchronize_time(self):
        transport = MockRespondingTransport(self._protocol, "DTM\r\n".encode())
        self._protocol.connection_made(transport)
        success = await synchronize_time(self._protocol)
        self.assertTrue(success)
