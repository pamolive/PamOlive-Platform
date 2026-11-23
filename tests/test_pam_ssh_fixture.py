"""Loopback integration tests for the shared native SSH fixture."""

import asyncio
from unittest import IsolatedAsyncioTestCase

import asyncssh

from .fixtures.ssh import INPUT, REPLY, WELCOME, SSHFixture


def connect(peer, **authentication):
    host = f"[{peer.host}]:{peer.port}"
    trust = asyncssh.import_known_hosts(f"{host} {peer.host_key}")
    return asyncssh.connect(
        peer.host, peer.port, username=peer.username, known_hosts=trust, config=None,
        agent_path=None, client_keys=authentication.pop("client_keys", None), **authentication,
    )


class SSHFixtureTests(IsolatedAsyncioTestCase):
    async def test_both_auth_modes_confirm_the_terminal_and_its_transport(self):
        for key_auth in (False, True):
            with self.subTest(key_auth=key_auth):
                async with asyncio.timeout(6), SSHFixture(key_auth=key_auth) as peer:
                    auth = ({"client_keys": [asyncssh.import_private_key(peer.private_key)]}
                            if key_auth else {"password": peer.password})
                    async with connect(peer, **auth) as primary:
                        command = await primary.run("fixture-only-command", check=False)
                        self.assertEqual(command.exit_status, 1)
                        self.assertFalse(peer.opened.is_set())
                        process = await primary.create_process()
                        self.assertEqual((await process.stdout.readline()).strip(), WELCOME)
                        self.assertTrue(peer.opened.is_set())
                        process.stdin.write(INPUT + "\n")
                        await process.stdin.drain()
                        self.assertEqual((await process.stdout.readline()).strip(), REPLY)
                        self.assertTrue(peer.echoed.is_set())
                        async with connect(peer, **auth):
                            pass
                        self.assertFalse(peer.lost.is_set())
                    await peer.lost.wait()

    async def test_cleanup_closes_the_listener_and_an_idle_authenticated_client(self):
        async with asyncio.timeout(6):
            async with SSHFixture() as peer:
                client = await connect(peer, password=peer.password)
                self.assertFalse(peer.opened.is_set())
                self.assertFalse(peer.lost.is_set())
            await client.wait_closed()
            self.assertFalse(peer.lost.is_set())
            with self.assertRaises(OSError):
                await connect(peer, password=peer.password)

    async def test_cleanup_does_not_count_as_an_observed_terminal_disconnect(self):
        async with asyncio.timeout(6):
            async with SSHFixture() as peer:
                client = await connect(peer, password=peer.password)
                process = await client.create_process()
                self.assertEqual((await process.stdout.readline()).strip(), WELCOME)
                self.assertTrue(peer.opened.is_set())
            await client.wait_closed()
            self.assertFalse(peer.lost.is_set())
