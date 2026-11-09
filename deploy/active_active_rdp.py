"""CI-only RDP peer and scoped database probes for two application instances."""

import asyncio
import json
import os
import socket as sockets
import sys
from contextlib import asynccontextmanager
from uuid import UUID

from websockets.exceptions import ConnectionClosed

from platform_modules.pam.protocol import Instruction, Parser
from tests.fixtures.paint import PaintProof
from tests.fixtures.rdp import HA_PORT, RDPFixture, isolated_bind

from .active_active_fixture import require_test_database
from .active_active_ssh import (
    WEB_A,
    WEB_B,
    FixtureError,
    emit,
    launch,
    post,
    prepare,
    require,
    socket,
    state,
    submit_ticket,
)

TARGET = "ha-rdp-fixture"
PHASE = "setup"


def input_json():
    return json.loads(sys.stdin.readline(8192))


async def acknowledge(expected):
    actual = await asyncio.to_thread(sys.stdin.readline, 128)
    require(actual.strip() == expected, "Missing or invalid host acknowledgement.")


async def send_keepalives(websocket):
    """Match Guacamole.Client 1.6's browser keepalive, not synthetic keyboard input."""
    try:
        while True:
            await asyncio.sleep(5)
            await websocket.send(Instruction("nop", ()).encode().decode())
    except ConnectionClosed:
        pass


@asynccontextmanager
async def relay(node, config, session):
    async with socket(node, config, session) as websocket:
        await submit_ticket(websocket, config)
        display = asyncio.Event()
        pixels = PaintProof()

        async def drain():
            parser = Parser()
            try:
                async for frame in websocket:
                    for item in parser.feed(frame.encode()):
                        pixels.observe(item)
                        if item.opcode == "sync":
                            response = Instruction("sync", (item.arguments[0],))
                            display.set()
                        elif item.opcode == "blob":
                            response = Instruction("ack", (item.arguments[0], "", "0"))
                        else:
                            continue
                        await websocket.send(response.encode().decode())
            except ConnectionClosed:
                pass

        worker = asyncio.create_task(drain())
        keepalives = asyncio.create_task(send_keepalives(websocket))
        try:
            yield websocket, display, pixels, worker
        finally:
            keepalives.cancel()
            await asyncio.gather(keepalives, return_exceptions=True)
            await websocket.close()
            await worker


async def keyboard(fixture, relay_state, connection, *, key="a"):
    websocket, _, pixels, worker = relay_state
    if key == "b":
        pixels.expect((80, 107, 215))
    after = len(fixture.events)
    for pressed in ("1", "0"):
        await websocket.send(Instruction("key", (str(ord(key)), pressed)).encode().decode())
    await fixture.wait(f"key_{key}", timeout=8, connection=connection, after=after)
    await pixels.wait(worker)


async def confirmed(fixture, relay_state, after):
    authentication = await fixture.wait("authenticated", after=after, timeout=18)
    identifier = authentication["connection"]
    await fixture.wait("nla_verified", connection=identifier, after=after)
    await fixture.wait("activated", connection=identifier, after=after)
    await asyncio.wait_for(relay_state[1].wait(), 12)
    await keyboard(fixture, relay_state, identifier)
    return identifier


async def peer():
    global PHASE
    require(os.environ.get("PAMOLIVE_HA_RDP_PEER") == "1", "Missing isolated test marker.")
    address = isolated_bind(sockets.gethostbyname(TARGET))
    require(
        {item[4][0] for item in sockets.getaddrinfo(TARGET, HA_PORT, type=sockets.SOCK_STREAM)}
        == {address},
        "The target alias must resolve to a single private IPv4.",
    )
    async with RDPFixture(ha_bind=address) as fixture:
        # This line is consumed by the orchestration process, never displayed.
        emit("ready", pin=fixture.pin, password=fixture.password)
        data = await asyncio.to_thread(input_json)
        session, csrf = data["session"], data["csrf"]
        intent_a, intent_b = UUID(data["intent_a"]), UUID(data["intent_b"])
        PHASE = "first pinned NLA session and replay refusal"
        aid, cfg_a = await asyncio.to_thread(launch, WEB_A, intent_a, session, csrf)
        async with relay(WEB_A, cfg_a, session) as a:
            first = await confirmed(fixture, a, 0)
            after = len(fixture.events)
            async with socket(WEB_B, cfg_a, session) as replay:
                await submit_ticket(replay, cfg_a)
                await asyncio.wait_for(replay.wait_closed(), 10)
            require(
                not any(item["event"] == "authenticated" for item in fixture.events[after:]),
                "Replay established another native RDP session.",
            )
            PHASE = "second independent pinned NLA session"
            bid, cfg_b = await asyncio.to_thread(launch, WEB_B, intent_b, session, csrf)
            async with relay(WEB_B, cfg_b, session) as b:
                second = await confirmed(fixture, b, after)
                require(first != second, "Both nodes must have distinct RDP sessions.")
                emit("both-active", a=str(aid), b=str(bid))
                await acknowledge("both-recorded")
                PHASE = "cross-node RDP stop"
                status, _ = await asyncio.to_thread(
                    post, WEB_B, f"/pam/connections/{aid}/stop/", session, csrf
                )
                require(status == 302, "Node B did not accept the stop command.")
                await asyncio.wait_for(a[0].wait_closed(), 12)
                await fixture.wait("disconnected", connection=first, timeout=12)
                PHASE = "new node A RDP relay"
                after = len(fixture.events)
                cid, cfg_c = await asyncio.to_thread(launch, WEB_A, intent_a, session, csrf)
                async with relay(WEB_A, cfg_c, session) as c:
                    third = await confirmed(fixture, c, after)
                    require(third not in (first, second), "The reopened relay reused a peer.")
                    emit("kill-node-a", a=str(aid), b=str(bid), c=str(cid))
                    await acknowledge("node-a-killed")
                    PHASE = "surviving RDP input and lost peer closure"
                    await asyncio.wait_for(c[0].wait_closed(), 12)
                    await fixture.wait("disconnected", connection=third, timeout=12)
                    await keyboard(fixture, b, second, key="b")
                    emit("surviving", b=str(bid), c=str(cid))
                    await acknowledge("orphan-verified")
        emit("complete")


def database(action):
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()
    require_test_database()
    data = input_json()
    if action == "prepare":
        organization, intent_a, intent_b = prepare(
            data["run"],
            data["pin"],
            data["password"],
            protocol="rdp",
            hostname=TARGET,
            port=HA_PORT,
        )
        emit(
            "prepared",
            organization=str(organization),
            intent_a=str(intent_a),
            intent_b=str(intent_b),
        )
    else:
        keys = data["keys"]
        require(isinstance(keys, list) and 0 < len(keys) <= 3, "Invalid relay scope.")
        organization = UUID(data["organization"])
        emit("state", relays={key: state(organization, UUID(key)) for key in keys})


def main():
    try:
        (action,) = sys.argv[1:]
        if action == "peer":
            asyncio.run(peer())
        else:
            require(action in ("prepare", "state"), "Unknown fixture operation.")
            database(action)
    except Exception as error:
        emit(
            "failed",
            phase=PHASE,
            error=str(error) if isinstance(error, FixtureError) else type(error).__name__,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
