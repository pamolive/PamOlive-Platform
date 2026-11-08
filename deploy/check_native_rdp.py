"""Test-image-only NLA, native certificate pin and display/keyboard release gate."""

import asyncio
from types import SimpleNamespace

from deploy.check_guacd import inspect_plugins, run_check
from platform_modules.pam.native import NativeSession
from platform_modules.pam.protocol import Instruction, ProtocolFailure
from tests.fixtures.paint import PaintProof
from tests.fixtures.rdp import RDPFixture


async def exercise(engine_port, *, wrong_pin=False, wrong_password=False):
    async with RDPFixture() as fixture:
        reader, writer = await asyncio.open_connection("127.0.0.1", engine_port)
        native = NativeSession(reader, writer)
        endpoint = SimpleNamespace(
            protocol="rdp",
            domain="FIXTURE",
            ssh_host_key="",
            certificate_pin="00" * 32 if wrong_pin else fixture.pin,
        )
        target = SimpleNamespace(address="127.0.0.1", port=fixture.port)
        instructions = []
        pixels = PaintProof()

        async def display():
            try:
                while True:
                    instruction = await native.receive()
                    try:
                        result = native.boundary.outbound(instruction)
                    except ProtocolFailure as error:
                        raise RuntimeError(
                            f"Native display boundary rejected opcode {instruction.opcode} "
                            f"with {len(instruction.arguments)} arguments"
                        ) from error
                    if result:
                        instructions.append(result)
                        pixels.observe(result)
                    if instruction.opcode == "sync":
                        await native.send(Instruction("sync", (instruction.arguments[0],)))
                    elif instruction.opcode == "blob":
                        await native.send(Instruction("ack", (instruction.arguments[0], "", "0")))
                    elif instruction.opcode == "error":
                        return "denied"
            except EOFError:
                return "closed"

        task = None
        try:
            await native.handshake(
                endpoint,
                SimpleNamespace(username="fixture"),
                target,
                {"password": "wrong-fixture-password" if wrong_password else fixture.password},
                1024,
                768,
            )
            task = asyncio.create_task(display())
            await fixture.wait("peer_ready")
            if wrong_pin or wrong_password:
                assert await asyncio.wait_for(task, timeout=12) == "denied"
                assert not any(value["event"] == "authenticated" for value in fixture.events)
                return
            await fixture.wait("nla_verified")
            authenticated = await fixture.wait("authenticated")
            await fixture.wait("activated")
            for pressed in ("1", "0"):
                await native.send(Instruction("key", ("97", pressed)))
            await fixture.wait("key_a", timeout=5)
            await pixels.wait(task)
            assert any(item.opcode in ("rect", "cfill", "img", "png") for item in instructions)
            await native.close()
            await fixture.wait("disconnected", connection=authenticated["connection"], timeout=6)
        finally:
            await native.close()
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


async def check(engine_port):
    await inspect_plugins(engine_port)
    await exercise(engine_port, wrong_pin=True)
    await exercise(engine_port, wrong_password=True)
    await exercise(engine_port)
    print("Native RDP: wrong pin and password denied; NLA, display and keyboard confirmed.")
    print("Actual peer disconnect observed; no OS user, shell or external server was used.")


if __name__ == "__main__":
    run_check(check)
