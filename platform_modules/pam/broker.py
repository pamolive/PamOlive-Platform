"""Same-origin ASGI relay. Authority and durable capture fail closed."""

import asyncio
import json
import logging
import re
import time
from http.cookies import SimpleCookie

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, close_old_connections, connections

from platform_core.models import Organization
from platform_core.security import throttle

from .context import check_websocket_origin
from .destination import TransportFailure
from .native import NativeSession
from .probe import probe_rdp, probe_ssh
from .protocol import Instruction, Parser, ProtocolFailure
from .sessions import (
    append_recording,
    check_session,
    check_startup_session,
    claim_session,
    endpoint_credentials,
    finish_session,
    session_actor,
)

logger = logging.getLogger(__name__)
DATABASE_DEADLINE_SECONDS = 4


class DatabaseDeadlineExceeded(TimeoutError):
    """Database execution or its local queue exceeded the unchanged relay deadline."""


def operation_name(function):
    name = getattr(function, "__name__", "unknown")
    return (
        name
        if isinstance(name, str) and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,79}", name)
        else "unknown"
    )


async def database(function, *args, **kwargs):
    def call():
        close_old_connections()
        try:
            return function(*args, **kwargs)
        except DatabaseError as error:
            code = getattr(error.__cause__, "sqlstate", None)
            code = (
                code if isinstance(code, str) and re.fullmatch(r"[A-Z0-9]{5}", code) else "unknown"
            )
            # SQL, exception messages, parameters and connection strings can contain secrets.
            logger.error(
                "PAM database unavailable: operation=%s sqlstate=%s", operation_name(function), code
            )
            raise
        finally:
            connections.close_all()

    deadline = asyncio.timeout(DATABASE_DEADLINE_SECONDS)
    try:
        async with deadline:
            return await sync_to_async(call, thread_sensitive=False)()
    except TimeoutError:
        if not deadline.expired():
            raise
        logger.error(
            "PAM database deadline exceeded: phase=operation operation=%s",
            operation_name(function),
        )
        raise DatabaseDeadlineExceeded from None


def admission(session_key):
    actor = session_actor(session_key)
    if throttle(f"pam-relay-attempt\x00{actor.pk}", failure=True):
        raise PermissionDenied
    return actor


class Relay:
    def __init__(self, connection_id, scope, receive, send):
        self.connection_id, self.scope = connection_id, scope
        self.receive, self.send = receive, send
        self.native = None
        self.organization = self.owner = None
        self.session_key = self.client_ip = ""
        self.started = time.monotonic()
        self.tasks = []
        self.database_lock = asyncio.Lock()

    async def state(self, function, *args, **kwargs):
        # One relay must not make its heartbeat, startup and capture transactions
        # compete for its own row. PostgreSQL locks/fencing still coordinate other
        # actors and instances. Waiting for this local queue shares the same deadline.
        deadline = asyncio.timeout(DATABASE_DEADLINE_SECONDS)
        acquired = False
        try:
            async with deadline:
                async with self.database_lock:
                    acquired = True
                    return await database(function, *args, **kwargs)
        except TimeoutError:
            if not deadline.expired():
                raise
            logger.error(
                "PAM database deadline exceeded: phase=%s operation=%s",
                "state" if acquired else "queue",
                operation_name(function),
            )
            raise DatabaseDeadlineExceeded from None

    async def monitor(self):
        while True:
            await self.state(
                check_session,
                self.connection_id,
                self.organization,
                self.owner,
                session_key=self.session_key,
                client_ip=self.client_ip,
            )
            await asyncio.sleep(1)

    async def start(self, width, height):
        item = await self.state(
            check_startup_session,
            self.connection_id,
            self.organization,
            self.owner,
            session_key=self.session_key,
            client_ip=self.client_ip,
        )
        endpoint = item.endpoint
        if endpoint.protocol == "ssh":
            target = await probe_ssh(endpoint.hostname, endpoint.port, endpoint.ssh_host_key)
        else:
            target = await probe_rdp(endpoint.hostname, endpoint.port, endpoint.certificate_pin)
        # A revision, role, session or contract may have changed during the network probe.
        item = await self.state(
            check_startup_session,
            self.connection_id,
            self.organization,
            self.owner,
            session_key=self.session_key,
            client_ip=self.client_ip,
        )
        credentials = endpoint_credentials(item)
        async with asyncio.timeout(3):
            reader, writer = await asyncio.open_connection("127.0.0.1", settings.PAM_GUACD_PORT)
        self.native = NativeSession(reader, writer)
        await self.native.handshake(
            item.endpoint, item.lease.intent.account, target, credentials, width, height
        )
        del credentials
        await self.state(
            check_session,
            self.connection_id,
            self.organization,
            self.owner,
            session_key=self.session_key,
            client_ip=self.client_ip,
            target_snapshot={
                "protocol": endpoint.protocol,
                "hostname": endpoint.hostname,
                "address": target.address,
                "port": target.port,
                "fingerprint": target.fingerprint,
                "resource_id": str(item.lease.intent.resource_id),
                "account_id": str(item.lease.intent.account_id),
                "revision": item.endpoint_revision,
            },
        )

    async def input(self):
        parser = Parser(max_element=256, max_instruction=2048, max_elements=8)
        window, frames, instructions = time.monotonic(), 0, 0
        while True:
            event = await self.receive()
            if event["type"] == "websocket.disconnect":
                return "client_closed"
            if event["type"] != "websocket.receive" or event.get("text") is None:
                raise ProtocolFailure("text_frames_required")
            data = event["text"].encode("utf-8", errors="strict")
            if time.monotonic() - window >= 1:
                window, frames, instructions = time.monotonic(), 0, 0
            frames += 1
            if frames > 256 or len(data) > 65536:
                raise ProtocolFailure("input_rate_exceeded")
            for instruction in parser.feed(data):
                instructions += 1
                if instructions > 2048:
                    raise ProtocolFailure("input_rate_exceeded")
                allowed = self.native.boundary.inbound(instruction)
                if allowed:
                    await self.native.send(allowed)
                    if allowed.opcode == "disconnect":
                        return "client_closed"

    async def flush(self, batch):
        elapsed = max(0, int((time.monotonic() - self.started) * 1000))
        for offset in range(0, len(batch), 65536):
            await self.state(
                append_recording,
                self.connection_id,
                self.organization,
                self.owner,
                bytes(batch[offset : offset + 65536]),
                elapsed,
            )
        # No display data is forwarded until its encrypted chunks are committed.
        await self.send({"type": "websocket.send", "text": bytes(batch).decode("utf-8")})

    async def output(self):
        batch, deadline = bytearray(), time.monotonic() + 0.05
        while True:
            try:
                instruction = await asyncio.wait_for(
                    self.native.receive(), timeout=max(0.001, deadline - time.monotonic())
                )
            except TimeoutError:
                if batch:
                    await self.flush(batch)
                    batch.clear()
                deadline = time.monotonic() + 0.05
                continue
            except EOFError:
                if batch:
                    await self.flush(batch)
                return "native_closed"
            dropped_stream = (
                instruction.opcode == "blob"
                and instruction.arguments
                and self.native.boundary.streams.get(int(instruction.arguments[0])) == "drop"
            )
            forwarded = self.native.boundary.outbound(instruction)
            if dropped_stream:
                await self.native.send(Instruction("ack", (instruction.arguments[0], "", "0")))
            if forwarded:
                batch.extend(forwarded.encode())
            if len(batch) >= 65536 or time.monotonic() >= deadline:
                if batch:
                    await self.flush(batch)
                    batch.clear()
                deadline = time.monotonic() + 0.05
            if instruction.opcode in ("error", "disconnect"):
                if batch:
                    await self.flush(batch)
                return "native_error" if instruction.opcode == "error" else "native_closed"

    async def race(self, tasks):
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception():
                raise task.exception()
        values = [task.result() for task in done]
        return "native_error" if "native_error" in values else values[0]

    async def run(self):
        accepted = False
        reason, complete = "relay_failed", False
        try:
            headers, self.client_ip = check_websocket_origin(self.scope)
            cookies = SimpleCookie()
            if len(headers.get("cookie", "")) > 8192:
                raise PermissionDenied
            cookies.load(headers.get("cookie", ""))
            cookie = cookies.get(settings.SESSION_COOKIE_NAME)
            self.session_key = cookie.value if cookie else ""
            actor = await database(admission, self.session_key)
            if (await self.receive())["type"] != "websocket.connect":
                raise PermissionDenied
            await self.send({"type": "websocket.accept", "subprotocol": "guacamole"})
            accepted = True
            event = await asyncio.wait_for(self.receive(), timeout=5)
            if event["type"] != "websocket.receive" or not event.get("text"):
                raise PermissionDenied
            if len(event["text"]) > 1024:
                raise PermissionDenied
            message = json.loads(event["text"])
            if not isinstance(message, dict) or set(message) != {"ticket", "width", "height"}:
                raise PermissionDenied
            width, height = message["width"], message["height"]
            if (
                type(width) is not int
                or type(height) is not int
                or not 320 <= width <= 3840
                or not 200 <= height <= 2160
            ):
                raise PermissionDenied
            _, organization_id, self.owner = await database(
                claim_session,
                self.connection_id,
                actor=actor,
                session_key=self.session_key,
                client_ip=self.client_ip,
                ticket=message["ticket"],
                instance_id=settings.PAM_INSTANCE_ID,
            )
            self.organization = await database(Organization.objects.get, pk=organization_id)
            monitor = asyncio.create_task(self.monitor())
            start = asyncio.create_task(self.start(width, height))
            self.tasks.extend([monitor, start])
            await self.race([start, monitor])
            incoming, outgoing = (
                asyncio.create_task(self.input()),
                asyncio.create_task(self.output()),
            )
            self.tasks.extend([incoming, outgoing])
            reason = await self.race([monitor, incoming, outgoing])
            complete = reason in ("native_closed", "client_closed")
        except asyncio.CancelledError:
            reason = "relay_shutdown"
            raise
        except PermissionDenied:
            reason = "authority_lost"
        except (ProtocolFailure, TransportFailure) as error:
            reason = str(error)
            complete = False
        except (DatabaseError, DatabaseDeadlineExceeded):
            reason = "database_unavailable"
        except (OSError, EOFError, TimeoutError, ValueError, ValidationError):
            reason = "relay_failed"
        except Exception as error:
            # Do not log exception values/locals: libraries may quote credentials.
            logger.error("PAM relay failure class: %s", type(error).__name__)
            reason = "relay_failed"
        finally:
            # Cut the real transport first, before any potentially slow evidence write.
            if self.native:
                await self.native.close()
            for task in self.tasks:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            if self.owner and self.organization:
                try:
                    await asyncio.shield(
                        database(
                            finish_session,
                            self.connection_id,
                            self.organization,
                            self.owner,
                            reason=reason,
                            complete=complete,
                        )
                    )
                except Exception:
                    # The durable reaper marks an orphan capture incomplete later.
                    logger.error("PAM relay finalization deferred to orphan reaper")
            try:
                if accepted:
                    await self.send({"type": "websocket.close", "code": 1000 if complete else 4403})
                else:
                    await self.send({"type": "websocket.close", "code": 4403})
            except (OSError, RuntimeError):
                pass
