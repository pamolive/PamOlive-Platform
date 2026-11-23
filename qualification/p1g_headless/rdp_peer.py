"""Private handoff between the synthetic RDP peer and the browser test."""

import asyncio
import json
import os
import re
import signal
import stat
import sys
import time
from pathlib import Path

HOST = "127.0.0.1"
STATE = Path("/run/p1g-rdp")
EVENTS = ("nla_verified", "authenticated", "activated", "key_a", "disconnected")
MAX_EVENTS = 64
FILE_BUDGET = 8192


def read_packet(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        row = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(row.st_mode) or stat.S_IMODE(row.st_mode) != 0o600
            or row.st_uid != os.getuid() or row.st_nlink != 1
            or not 0 < row.st_size <= FILE_BUDGET
        ):
            raise ValueError("rdp_peer_state_file")
        raw = stream.read(FILE_BUDGET + 1)
    if len(raw) != row.st_size:
        raise ValueError("rdp_peer_state_size")
    return json.loads(raw)


def publish(root, filename, packet):
    raw = json.dumps(packet, separators=(",", ":")).encode("ascii")
    if not 0 < len(raw) <= FILE_BUDGET:
        raise ValueError("rdp_peer_state_size")
    pending = root / (filename + ".next")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        if stream.write(raw) != len(raw):
            raise ValueError("rdp_peer_state_write")
    os.replace(pending, root / filename)


def connection_events(rows, *, required=EVENTS):
    if type(rows) is not list or len(rows) > MAX_EVENTS:
        raise ValueError("rdp_peer_event_budget")
    connection = None
    history = []
    for row in rows:
        if (
            type(row) is not dict or set(row) != {"event", "connection"}
            or row["event"] not in EVENTS or type(row["connection"]) is not int
            or not 1 <= row["connection"] < 2**31
        ):
            raise ValueError("rdp_peer_event_shape")
        if connection is None:
            connection = row["connection"]
        if row["connection"] != connection:
            raise ValueError("rdp_peer_multiple_connections")
        history.append(row["event"])
    return connection if tuple(history) == required else None


class Peer:
    username = "fixture"
    domain = "FIXTURE"
    host = HOST

    def __init__(self, state):
        self.state = state
        packet = self.wait_packet("ready.json")
        if (
            type(packet) is not dict or set(packet) != {"port", "pin", "password"}
            or type(packet["port"]) is not int or not 1024 <= packet["port"] <= 65535
            or type(packet["pin"]) is not str or type(packet["password"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", packet["pin"])
            or not re.fullmatch(r"[A-Za-z0-9_-]{32}", packet["password"])
        ):
            raise ValueError("rdp_peer_ready_shape")
        self.port, self.pin, self.password = packet["port"], packet["pin"], packet["password"]

    def wait_packet(self, name):
        until = time.monotonic() + 15
        while time.monotonic() < until:
            try:
                return read_packet(self.state / name)
            except FileNotFoundError:
                time.sleep(0.05)
        raise ValueError("rdp_peer_state_timeout")

    def wait(self, required):
        until = time.monotonic() + 12
        while time.monotonic() < until:
            observed = self.current(required)
            if observed is not None:
                return observed
            time.sleep(0.05)
        raise ValueError("rdp_peer_event_timeout")

    def current(self, required):
        return connection_events(read_packet(self.state / "events.json"), required=required)


async def serve():
    sys.path.insert(0, "/app")
    from tests.fixtures.rdp import RDPFixture

    stop = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    async with RDPFixture() as fixture:
        publish(STATE, "events.json", [])
        publish(STATE, "ready.json", {
            "port": fixture.port, "pin": fixture.pin, "password": fixture.password,
        })
        previous = 0
        async with asyncio.timeout(710):
            while not stop.is_set():
                if fixture.process.returncode is not None or len(fixture.events) > MAX_EVENTS:
                    raise ValueError("rdp_peer_fixture_refused")
                if len(fixture.events) != previous:
                    previous = len(fixture.events)
                    rows = [event for event in fixture.events if event["event"] in EVENTS]
                    connection_events(rows)
                    publish(STATE, "events.json", rows)
                await asyncio.sleep(0.025)


if __name__ == "__main__":
    if len(sys.argv) != 1 or os.getuid() <= 0:
        raise SystemExit(42)
    os.umask(0o077)
    asyncio.run(serve())
