"""Owned loopback SSH peer for PAM integration tests, with no OS login or shell."""

import asyncio
import secrets
import threading
from concurrent.futures import Future
from contextlib import suppress

import asyncssh

INPUT = "native-broker-proof"
WELCOME = "PAM-olive actual WebSocket SSH fixture"
REPLY = "Round-trip confirmed"


class SSHFixture:
    host = "127.0.0.1"
    username = "fixture"

    def __init__(self, *, key_auth=False):
        self.opened, self.echoed, self.lost = asyncio.Event(), asyncio.Event(), asyncio.Event()
        self.password = secrets.token_urlsafe(24)
        self._host_key = asyncssh.generate_private_key("ssh-ed25519")
        self._account_key = asyncssh.generate_private_key("ssh-ed25519") if key_auth else None
        self._connections = set()
        self._terminal_connection = None
        self._closing = False
        self.process = None

    @property
    def host_key(self):
        return self._host_key.export_public_key().decode()

    @property
    def private_key(self):
        if self._account_key is not None:
            return self._account_key.export_private_key("openssh").decode()
        return None

    async def __aenter__(self):
        self._listener = await asyncssh.create_server(
            lambda: _Peer(self), self.host, 0, server_host_keys=[self._host_key],
            process_factory=self._terminal, config=None, agent_forwarding=False,
            x11_forwarding=False, kbdint_auth=False,
        )
        self.port = self._listener.get_port()
        return self

    async def __aexit__(self, *_):
        self._closing = True
        self._listener.close()
        connections = tuple(self._connections)
        for connection in connections:
            connection.abort()
        async with asyncio.timeout(5):
            await asyncio.gather(self._listener.wait_closed(),
                                 *(connection.wait_closed() for connection in connections))

    async def _terminal(self, process):
        if self.process is not None or process.command is not None or process.subsystem is not None:
            process.exit(1)
            return
        self.process = process
        self._terminal_connection = process.channel.get_connection()
        self.opened.set()
        process.stdout.write(WELCOME + "\r\n")
        if (await process.stdin.readline()).strip() == INPUT:
            process.stdout.write(REPLY + "\r\n")
            self.echoed.set()
        while await process.stdin.read(4096):
            pass


class ThreadedSSHFixture:
    """Own the SSH peer from a synchronous browser case on a separate loop."""

    def __init__(self):
        self._started = Future()
        self._worker = threading.Thread(target=self._run, name="pamolive-test-ssh", daemon=True)
        self._error = None

    def __enter__(self):
        self._worker.start()
        try:
            self.peer = self._started.result(timeout=5)
        except BaseException:
            self.close()
            raise
        return self

    def _run(self):
        try:
            asyncio.run(self._serve())
        except BaseException as error:
            self._error = error
            if not self._started.done():
                self._started.set_exception(error)

    async def _serve(self):
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        async with SSHFixture() as peer:
            self._started.set_result(peer)
            await self._stop.wait()

    def wait(self, signal, timeout=8):
        event = {"opened": self.peer.opened, "echoed": self.peer.echoed, "lost": self.peer.lost}[
            signal
        ]
        if not self._worker.is_alive():
            raise RuntimeError("Test SSH peer already stopped")
        pending = asyncio.run_coroutine_threadsafe(event.wait(), self._loop)
        try:
            pending.result(timeout)
        finally:
            pending.cancel()

    def close(self):
        if self._worker.is_alive() and hasattr(self, "_stop"):
            with suppress(RuntimeError):
                self._loop.call_soon_threadsafe(self._stop.set)
        self._worker.join(6)
        if self._worker.is_alive():
            raise RuntimeError("Test SSH peer did not shut down")
        if self._error is not None and self._started.done() and not self._started.exception():
            raise RuntimeError("Test SSH peer failed while running") from self._error

    def __exit__(self, *_):
        self.close()


class _Peer(asyncssh.SSHServer):
    def __init__(self, fixture):
        self.fixture = fixture

    def connection_made(self, conn):
        self.connection = conn
        self.fixture._connections.add(conn)
        if self.fixture._closing:
            conn.abort()

    def connection_lost(self, exc):
        self.fixture._connections.discard(self.connection)
        if not self.fixture._closing and self.connection is self.fixture._terminal_connection:
            self.fixture.lost.set()

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return self.fixture._account_key is None

    def public_key_auth_supported(self):
        return self.fixture._account_key is not None

    def validate_password(self, username, password):
        return self.password_auth_supported() and username == self.fixture.username and (
            secrets.compare_digest(password.encode(), self.fixture.password.encode())
        )

    def validate_public_key(self, username, key):
        account_key = self.fixture._account_key
        return account_key is not None and username == self.fixture.username and (
            key.public_data == account_key.public_data
        )
