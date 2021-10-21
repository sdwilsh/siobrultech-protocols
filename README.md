![Lint](https://github.com/sdwilsh/siobrultech-protocols/workflows/Lint/badge.svg)
![Build](https://github.com/sdwilsh/siobrultech-protocols/workflows/Build/badge.svg)

# What is siobrultech-protocols?

This library is a collection of protcols that decode various packet formats from
[Brultech Research](https://www.brultech.com/).

# What is Sans-I/O?

Sans-I/O is a philosophy for developing protocol processing libraries in which
the library does not do any I/O. Instead, a user of the library is responsible
for transferring blocks of bytes between the socket or pipe and the protocol
library, and for receiving application-level protocol items from and sending
them to the library. This obviously makes a sans-I/O library a little more
difficult to use, but comes with the advantage that the same library can be
used with any I/O and concurrency mechanism: the same library should be usable
in a single-request-at-a-time server, a process-per-request or
thread-per-request blocking server, a server using select/poll and
continuations, or a server using asyncio, Twisted, or any other asynchronous
framework.

See [SansIO](https://sans-io.readthedocs.io/) for more information.

## Installation

```
pip install siobrultech-protocols
```

## Usage

### Receiving data packets

```python
import functools
from siobrultech_protocols.gem.protocols import PacketProtocol

# Queue to get received packets from.
queue = asyncio.Queue()

# Pass this Protocol to whatever receives data from the device.
protocol_factory = functools.partial(PacketProtocol, queue=queue)
```

### Receiving data packets AND sending API commands

If you want to send API commands as well, use a `BidirectionalProtocol` instead of a `PacketProtocol`, and keep track of the protocol instance for each active connection. Then given the `protocol` instance for a given connection, do the API call as follows:

```python
import siobrultech_protocols.gem.api

# Start the API request; do this once for each API call. Each protocol instance can only support one
# API call at a time.
delay = protocol.begin_api_request()
sleep(delay)  # Wait for the specified delay, using whatever mechanism is appropriate for your environment

# Send the API request. This example is for getting the serial number (which has no parameter):
delay = api.GET_SERIAL_NUMBER.send_request(protocol, None)
sleep(delay)

# Parse the response after it has arrived
result = api.GET_SERIAL_NUMBER.receive_response(protocol)

# End the API request
protocol.end_api_request()
```

### Calling API endpoints that aren't supported by this library

The API support in `siobrultech_protocols` is in its infancy. If you want to call an API endpoint for which this library doesn't provide a helper, you can make your own. For example, the following outline could be filled in to support the "get all settings" endpoint; you would use `GET_ALL_SETTINGS` in the same way as `GET_SERIAL_NUMBER` is used above:

```python
from siobrultech_protocols.gem.api import ApiCall

# Define a Python data type for the response. It can be whatever you want; a simple Dict, a custom dataclass, etc.
AllSettings = Dict[str, Any]

def _parse_all_settings(response: str) -> AllSettings:
    # Here you would parse the response into the python type you defined above

GET_ALL_SETTINGS = ApiCall[None, AllSettings](
    formatter=lambda _: "^^^RQSALL", parser=_parse_all_settings
)
```

Take a look at some usage examples from [libraries that use this](https://github.com/sdwilsh/siobrultech-protocols/network/dependents).

## Development

### Setup

```
python3.9 -m venv .venv
source .venv/bin/activate

# Install Requirements
pip install -r requirements.txt

# Install Dev Requirements
pip install -r requirements-dev.txt

# One-Time Install of Commit Hooks
pre-commit install
```

### Testing

Tests are run with `pytest`.
