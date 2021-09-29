from typing import Awaitable, Callable

_ESCAPE_SEQUENCE = "^^^"
_SYSTEM_PREFIX = _ESCAPE_SEQUENCE + "SYS"
_REQUEST_PREFIX = _ESCAPE_SEQUENCE + "RQS"

CMD_DELAY_NEXT_PACKET = _SYSTEM_PREFIX + "PDL"
CMD_GET_SERIAL_NUMBER = _REQUEST_PREFIX + "SRN"


class GemApi:
    def __init__(self, send_command: Callable[[str], Awaitable[str]]):
        self._send_api_command = send_command

    async def get_serial_number(self) -> int:
        return int(await self._send_api_command(CMD_GET_SERIAL_NUMBER))
