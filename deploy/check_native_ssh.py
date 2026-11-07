"""Real native SSH round-trip against a disposable in-process loopback fixture.

No OS account, subprocess shell, external server, database or installed service
is used. This verifies the native transport, not the future HTTP authorization
and WebSocket broker, which must have their own end-to-end release gates.
"""

import asyncio
import secrets
from collections import deque
from contextlib import suppress

import asyncssh

from deploy.check_guacd import inspect_plugins, run_check
from platform_modules.pam.protocol import Instruction, Parser, validate_input


class FixtureServer(asyncssh.SSHServer):
    def __init__(self, state):
        self.state = state

    def begin_auth(self, username):
        self.state["authentication_attempts"] += 1
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        valid = username == "pamolive-fixture" and secrets.compare_digest(
            password, self.state["password"]
        )
        self.state["authenticated"] = valid
        return valid


class NativeClient:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.parser = Parser()
        self.pending = deque()
        self.image_streams = set()

    async def instruction(self):
        while not self.pending:
            data = await self.reader.read(32768)
            if not data:
                self.parser.finish()
                raise EOFError
            self.pending.extend(self.parser.feed(data))
        return self.pending.popleft()

    async def send(self, instruction):
        self.writer.write(instruction.encode())
        await self.writer.drain()

    async def handshake(self, values):
        await self.send(Instruction("select", ("ssh",)))
        arguments = await self.instruction()
        if arguments.opcode != "args":
            raise RuntimeError("Unexpected native SSH handshake")
        names = arguments.arguments
        values = dict(values)
        if names and names[0].startswith("VERSION_"):
            values[names[0]] = names[0]
        for instruction in (
            Instruction("size", ("1280", "720", "96")),
            Instruction("audio"),
            Instruction("video"),
            Instruction("image", ("image/png",)),
            Instruction("connect", tuple(values.get(name, "") for name in names)),
        ):
            await self.send(instruction)

    async def drain_display(self):
        try:
            while True:
                instruction = await self.instruction()
                if instruction.opcode == "sync":
                    await self.send(Instruction("sync", (instruction.arguments[0],)))
                elif instruction.opcode == "img":
                    self.image_streams.add(instruction.arguments[0])
                elif instruction.opcode == "blob":
                    if instruction.arguments[0] in self.image_streams:
                        await self.send(Instruction("ack", (instruction.arguments[0], "OK", "0")))
                elif instruction.opcode == "end":
                    self.image_streams.discard(instruction.arguments[0])
                elif instruction.opcode == "error":
                    return "rejected"
                elif instruction.opcode in ("required", "clipboard", "file"):
                    raise RuntimeError("Native fixture requested forbidden interactive parameters")
                # Native display settings may be advertised through argv. This
                # non-browser test ignores them and never sends argv responses.
        except EOFError:
            return "closed"


async def exercise(engine_port, *, wrong_host_key):
    state = {
        "password": secrets.token_urlsafe(32),
        "authentication_attempts": 0,
        "authenticated": False,
    }
    opened, roundtrip, disconnected = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def terminal(process):
        try:
            opened.set()
            process.stdout.write("PAM-olive isolated native SSH fixture\r\n")
            line = await process.stdin.readline()
            if line.strip() == "pamolive-native-roundtrip":
                roundtrip.set()
            # Do not voluntarily close: verify the native client actually cuts
            # this SSH channel when its Guacamole connection disconnects.
            await process.stdin.read()
        except (asyncssh.Error, BrokenPipeError):
            pass
        finally:
            disconnected.set()

    key = asyncssh.generate_private_key("ssh-ed25519")
    expected = asyncssh.generate_private_key("ssh-ed25519") if wrong_host_key else key
    server = await asyncssh.create_server(
        lambda: FixtureServer(state),
        "127.0.0.1",
        0,
        server_host_keys=[key],
        process_factory=terminal,
    )
    writer = display = None
    try:
        target_port = server.get_port()
        reader, writer = await asyncio.open_connection("127.0.0.1", engine_port)
        client = NativeClient(reader, writer)
        await client.handshake(
            {
                "hostname": "127.0.0.1",
                "port": str(target_port),
                "username": "pamolive-fixture",
                "password": state["password"],
                "host-key": f"[127.0.0.1]:{target_port} "
                + expected.export_public_key().decode().strip(),
                "enable-sftp": "false",
                "enable-agent": "false",
                "disable-copy": "true",
                "disable-paste": "true",
                "font-name": "DejaVu Sans Mono",
                "font-size": "12",
                "terminal-type": "xterm-256color",
                "timeout": "5",
            }
        )
        display = asyncio.create_task(client.drain_display())
        if wrong_host_key:
            result = await asyncio.wait_for(display, timeout=10)
            assert result == "rejected", "Wrong SSH host key must fail closed"
            assert not state["authenticated"]
            assert state["authentication_attempts"] == 0, "Credentials sent before host-key check"
            return
        await asyncio.wait_for(opened.wait(), timeout=10)
        assert state["authenticated"], "Native SSH authentication was not observed on target"
        for character in "pamolive-native-roundtrip":
            for pressed in ("1", "0"):
                instruction = Instruction("key", (str(ord(character)), pressed))
                await client.send(validate_input(instruction))
        await client.send(validate_input(Instruction("key", ("65293", "1"))))
        await client.send(validate_input(Instruction("key", ("65293", "0"))))
        await asyncio.wait_for(roundtrip.wait(), timeout=10)
        await client.send(validate_input(Instruction("disconnect")))
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(disconnected.wait(), timeout=10)
    finally:
        if writer:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
        if display:
            display.cancel()
            with suppress(asyncio.CancelledError, OSError, EOFError):
                await display
        server.close()
        await server.wait_closed()


async def check(engine_port):
    await inspect_plugins(engine_port)
    await exercise(engine_port, wrong_host_key=True)
    await exercise(engine_port, wrong_host_key=False)
    print(
        "Native SSH: wrong host key denied before authentication; valid key and password accepted."
    )
    print("Keyboard round-trip and actual SSH channel disconnect confirmed on loopback fixture.")
    print("This does not validate a production HTTP/WebSocket session broker or RDP login.")


if __name__ == "__main__":
    run_check(check)
