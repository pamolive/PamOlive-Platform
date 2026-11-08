"""Private native handshake and a display-only boundary, never browser-supplied arguments."""

import asyncio
from collections import deque

from .destination import TransportFailure
from .protocol import Instruction, Parser, ProtocolFailure, validate_input


def _number(value, *, minimum=0, maximum=2**31 - 1):
    try:
        if len(value) > 16 or not value.isascii() or str(int(value)) != value:
            raise ValueError
        number = int(value)
        if not minimum <= number <= maximum:
            raise ValueError
        return number
    except (ValueError, TypeError):
        raise ProtocolFailure("invalid_native_value") from None


class DisplayBoundary:
    """Drop parameter streams before forwarding OR recording their contents."""

    DRAWING = frozenset(
        {
            "arc",
            "cfill",
            "clip",
            "close",
            "copy",
            "cstroke",
            "cursor",
            "curve",
            "dispose",
            "distort",
            "identity",
            "lfill",
            "line",
            "lstroke",
            "move",
            "pop",
            "push",
            "rect",
            "reset",
            "set",
            "shade",
            "start",
            "transfer",
            "transform",
            "png",
            "jpeg",
        }
    )

    def __init__(self):
        self.streams = {}
        self.layers = {}

    def outbound(self, instruction):
        opcode, args = instruction.opcode, instruction.arguments
        if opcode in ("argv", "img"):
            if not args:
                raise ProtocolFailure("invalid_native_stream")
            index = _number(args[0])
            if index in self.streams or len(self.streams) >= 64:
                raise ProtocolFailure("native_stream_limit")
            if opcode == "argv":
                self.streams[index] = "drop"
                return None
            if len(args) != 6 or args[3] not in ("image/png", "image/jpeg"):
                raise ProtocolFailure("native_image_type_not_authorized")
            self.streams[index] = "image"
        elif opcode in ("blob", "end"):
            if not args:
                raise ProtocolFailure("invalid_native_stream")
            index = _number(args[0])
            kind = self.streams.get(index)
            if kind is None:
                raise ProtocolFailure("unknown_native_stream")
            if opcode == "end":
                del self.streams[index]
            if kind == "drop":
                return None
        elif opcode == "size":
            if len(args) != 3:
                raise ProtocolFailure("invalid_native_display")
            layer = _number(args[0], minimum=-(2**31))
            width, height = (_number(value, maximum=8192) for value in args[1:])
            self.layers[layer] = width * height
            if len(self.layers) > 128 or sum(self.layers.values()) > 32 * 1024 * 1024:
                raise ProtocolFailure("native_display_limit")
        elif opcode == "error":
            # Backend errors may quote untrusted server strings or parameters.
            return Instruction("error", ("Connexion distante interrompue.", "512"))
        elif opcode == "mouse":
            # Remote cursor position, not a browser-originated input command.
            if len(args) not in (2, 4):
                raise ProtocolFailure("invalid_native_cursor")
            for value in args[:2]:
                _number(value, maximum=8192)
            if len(args) == 4:
                _number(args[2], maximum=31)
                _number(args[3], maximum=2**53 - 1)
            return Instruction("mouse", args[:2])
        elif opcode in ("ack", "name", "log"):
            return None
        elif opcode not in self.DRAWING | {"sync", "nop", "disconnect"}:
            raise ProtocolFailure("native_instruction_not_authorized")
        if opcode == "dispose" and args:
            self.layers.pop(_number(args[0], minimum=-(2**31)), None)
        return instruction

    def inbound(self, instruction):
        instruction = validate_input(instruction)
        if (
            instruction.opcode == "ack"
            and self.streams.get(int(instruction.arguments[0])) != "image"
        ):
            # Late ACK after end is harmless; no arbitrary stream can be created.
            return None
        return instruction


class NativeSession:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.parser, self.pending = Parser(), deque()
        self.boundary = DisplayBoundary()

    async def send(self, instruction):
        self.writer.write(instruction.encode())
        await self.writer.drain()

    async def receive(self):
        while not self.pending:
            data = await self.reader.read(32768)
            if not data:
                self.parser.finish()
                raise EOFError
            self.pending.extend(self.parser.feed(data))
        return self.pending.popleft()

    async def handshake(self, endpoint, account, target, credentials, width, height):
        async with asyncio.timeout(10):
            await self.send(Instruction("select", (endpoint.protocol,)))
            arguments = await self.receive()
            if arguments.opcode != "args" or len(arguments.arguments) > 256:
                raise TransportFailure("native_handshake_failed")
            names = arguments.arguments
            values = {
                "hostname": target.address,
                "port": str(target.port),
                "width": str(width),
                "height": str(height),
                "dpi": "96",
                "username": account.username,
                "enable-sftp": "false",
                "enable-agent": "false",
                "disable-copy": "true",
                "disable-paste": "true",
                "disable-upload": "true",
                "disable-download": "true",
                "timeout": "8",
                "font-name": "DejaVu Sans Mono",
                "font-size": "12",
                "terminal-type": "xterm-256color",
                "domain": endpoint.domain,
                "security": "nla",
                "ignore-cert": "false",
                "cert-tofu": "false",
                "cert-fingerprints": "sha256:"
                + ":".join(endpoint.certificate_pin[i : i + 2] for i in range(0, 64, 2)),
                "disable-auth": "false",
                "disable-audio": "true",
                "enable-audio-input": "false",
                "enable-drive": "false",
                "enable-printing": "false",
                "enable-touch": "false",
                "enable-wallpaper": "false",
                "resize-method": "display-update",
                "wol-send-packet": "false",
                "sftp-disable-upload": "true",
                "sftp-disable-download": "true",
                "client-name": "PAM-olive",
                "host-key": f"[{target.address}]:{target.port} {endpoint.ssh_host_key}",
                "password": credentials.get("password", ""),
                "private-key": credentials.get("private_key", ""),
            }
            if names and names[0].startswith("VERSION_"):
                values[names[0]] = names[0]
            await self.send(Instruction("size", (str(width), str(height), "96")))
            await self.send(Instruction("audio"))
            await self.send(Instruction("video"))
            await self.send(Instruction("image", ("image/png", "image/jpeg")))
            await self.send(Instruction("connect", tuple(values.get(name, "") for name in names)))
            # Never forward or persist the native connection ID (it allows joins).
            ready = await self.receive()
            if ready.opcode != "ready" or len(ready.arguments) != 1:
                raise TransportFailure("native_handshake_failed")

    async def close(self):
        # Explicitly end the sole Guacamole user before dropping its socket.
        # A bare EOF can leave native cleanup waiting for an input timeout.
        try:
            async with asyncio.timeout(0.5):
                await self.send(Instruction("disconnect"))
        except (OSError, TimeoutError):
            pass
        self.writer.close()
        try:
            async with asyncio.timeout(1):
                await self.writer.wait_closed()
        except (OSError, TimeoutError):
            pass
