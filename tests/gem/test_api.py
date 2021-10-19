import asyncio
import unittest
from typing import TypeVar

from siobrultech_protocols.gem.api import GET_SERIAL_NUMBER, ApiCall
from siobrultech_protocols.gem.protocol import (
    API_RESPONSE_WAIT_TIME,
    BidirectionalProtocol,
)
from tests.gem.mock_transport import MockTransport

T = TypeVar("T")
R = TypeVar("R")


class TestApi(unittest.TestCase):
    def setUp(self):
        self._queue = asyncio.Queue()
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
