"""Container-only native plugin smoke test; no target or credentials are used."""

import asyncio
import os
import signal
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from platform_modules.pam.protocol import Instruction, Parser


async def plugin_arguments(port, protocol):
    async with asyncio.timeout(10):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(Instruction("select", (protocol,)).encode())
            await writer.drain()
            parser = Parser(max_element=4096, max_instruction=65536)
            while data := await reader.read(4096):
                for instruction in parser.feed(data):
                    if instruction.opcode != "args":
                        raise RuntimeError("Unexpected native handshake")
                    return set(instruction.arguments)
            raise RuntimeError("Native plugin did not report its parameters")
        finally:
            writer.close()
            await writer.wait_closed()


async def inspect_plugins(port):
    for attempt in range(100):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
        else:
            writer.close()
            await writer.wait_closed()
            break
    else:
        raise RuntimeError("Native engine did not become ready")
    ssh = await plugin_arguments(port, "ssh")
    rdp = await plugin_arguments(port, "rdp")
    assert {"hostname", "port", "username", "password", "host-key"} <= ssh
    assert {"hostname", "port", "username", "password", "cert-fingerprints"} <= rdp
    assert {"ignore-cert", "cert-tofu", "security"} <= rdp
    print("SSH and RDP plugins loaded; host-key and certificate pinning parameters present.")
    print("No remote connection, credentials or end-to-end session were tested here.")


def run_check(check=inspect_plugins):
    binary = Path("/opt/pamolive-guac/sbin/guacd")
    if not binary.is_file():
        raise SystemExit("Native engine missing from the application image")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with (
        tempfile.TemporaryDirectory(prefix="pamolive-native-check-") as directory,
        tempfile.TemporaryFile() as log,
    ):
        process = subprocess.Popen(
            [
                str(binary),
                "-f",
                "-b",
                "127.0.0.1",
                "-p",
                str(port),
                "-P",
                str(Path(directory) / "guacd.pid"),
                "-L",
                "error",
            ],
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LD_LIBRARY_PATH": "/opt/pamolive-guac/lib",
                "LANG": "C.UTF-8",
                "HOME": directory,
                "GUACAMOLE_HOME": directory,
            },
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            asyncio.run(check(port))
        except Exception:
            # This test has no targets or credentials. Keep bounded diagnostics
            # for missing libraries/startup failures instead of hiding the cause.
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell() - 4096))
            sys.stderr.write(log.read(4096).decode("utf-8", errors="replace"))
            raise
        finally:
            # Only this smoke test's explicitly created process group is signalled.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


if __name__ == "__main__":
    run_check()
