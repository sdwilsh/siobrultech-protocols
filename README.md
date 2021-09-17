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

```python
import functools
from siobrultech_protocols.gem.protocols import PacketProtocol

# Queue to get recieved packets from.
queue = asyncio.Queue()

# Pass this Protocol to whatever recieves data from the device.
protocol_factory = functools.partial(PacketProtocol, queue=queue)
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
