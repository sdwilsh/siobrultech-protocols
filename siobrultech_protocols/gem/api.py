from typing import Awaitable, Callable


class GemApi:
    def __init__(self, send_command: Callable[[str], Awaitable[str]]):
        self._send_api_command = send_command

    async def get_serial_number(self) -> int:
        return int(await self._send_api_command("RQSSRN"))
