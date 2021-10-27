from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta
from unittest.async_case import IsolatedAsyncioTestCase
from unittest.mock import patch

import pytest

from siobrultech_protocols.gem.api import (
    GET_SERIAL_NUMBER,
    SET_DATE_AND_TIME,
    ApiCall,
    R,
    T,
    call_api,
)
from siobrultech_protocols.gem.packets import Packet
from siobrultech_protocols.gem.protocol import (
    API_RESPONSE_WAIT_TIME,
    BidirectionalProtocol,
)
from tests.gem.mock_transport import MockTransport


class TestApi(unittest.TestCase):
    def setUp(self):
        self._queue: asyncio.Queue[Packet] = asyncio.Queue()
        self._transport = MockTransport()
        self._protocol = BidirectionalProtocol(self._queue)
        self._protocol.connection_made(self._transport)

        # Put the protocol into a state where it's ready for commands
        # and we can see exactly what is sent
        self._protocol.begin_api_request()
        self._transport.writes.clear()

    def testApiCall(self):
        call = ApiCall(lambda _: "REQUEST", lambda response: response)

        self.assertCall(call, "REQUEST", None, "RESPONSE".encode(), "RESPONSE")

    def testGetSerialNumber(self):
        self.assertCall(
            GET_SERIAL_NUMBER, "^^^RQSSRN", None, "1234567".encode(), 1234567
        )

    def testSetDateTime(self):
        self.assertCall(
            SET_DATE_AND_TIME,
            "^^^SYSDTM12,08,23,13,30,28",
            datetime.fromisoformat("2012-08-23 13:30:28"),
            "DTM".encode(),
            True,
        )

    def assertCall(
        self,
        call: ApiCall[T, R],
        request: str,
        arg: T,
        encoded_response: bytes,
        parsed_response: R,
    ):
        self.assertEqual(call.send_request(self._protocol, arg), API_RESPONSE_WAIT_TIME)
        self.assertEqual(self._transport.writes, [request.encode()])
        self._protocol.data_received(encoded_response)
        self.assertEqual(call.receive_response(self._protocol), parsed_response)


class TestContextManager(IsolatedAsyncioTestCase):
    def setUp(self):
        self._queue: asyncio.Queue[Packet] = asyncio.Queue()
        self._transport = MockTransport()
        self._protocol = BidirectionalProtocol(self._queue)
        self._protocol.connection_made(self._transport)

    @pytest.mark.asyncio
    @patch(
        "siobrultech_protocols.gem.protocol.API_RESPONSE_WAIT_TIME",
        timedelta(seconds=0),
    )
    @patch(
        "siobrultech_protocols.gem.protocol.PACKET_DELAY_CLEAR_TIME",
        timedelta(seconds=0),
    )
    async def testApiCall(self):
        call = ApiCall(lambda _: "REQUEST", lambda response: response)
        async with call_api(call, self._protocol) as f:
            self.setApiResponse("RESPONSE".encode())
            response = await f(None)
            self.assertEqual(response, "RESPONSE")

    @pytest.mark.asyncio
    async def testTaskCanceled(self):
        call = ApiCall(lambda _: "REQUEST", lambda response: response)
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
