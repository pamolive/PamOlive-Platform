"""Mandatory image gate: real WebSocket → broker → guacd → disposable SSH server."""

import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path
from unittest import skipUnless

import asyncssh
import pyotp
import uvicorn
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import Client, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from platform_core.authorization import recent_authentication
from platform_core.models import (
    AccountSecurity,
    ModuleActivation,
    Organization,
    OrganizationMembership,
)
from platform_core.security import cipher
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.approvals.services import decide
from platform_modules.identity.models import ExternalAccount, Identity, Resource
from platform_modules.pam.models import (
    RecordingChunk,
    RelayConnection,
    SessionEndpoint,
    SessionLease,
)
from platform_modules.pam.protocol import Instruction, Parser
from platform_modules.pam.recordings import issue_recording_grant, recording_page

BINARY = Path("/opt/pamolive-guac/sbin/guacd")


def unused_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


@skipUnless(BINARY.is_file() or os.environ.get("PAM_REQUIRE_NATIVE"), "native image gate")
class NativeRelayTests(TransactionTestCase):
    def setUp(self):
        self.assertTrue(BINARY.is_file(), "PAM_REQUIRE_NATIVE cannot silently skip this gate")
        self.directory = tempfile.TemporaryDirectory(prefix="pamolive-relay-e2e-")
        self.log = tempfile.TemporaryFile()
        self.native_port, self.web_port = unused_port(), unused_port()
        self.native = subprocess.Popen(
            [
                str(BINARY),
                "-f",
                "-b",
                "127.0.0.1",
                "-l",
                str(self.native_port),
                "-p",
                self.directory.name + "/guacd.pid",
                "-L",
                "error",
            ],
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LD_LIBRARY_PATH": "/opt/pamolive-guac/lib",
                "HOME": self.directory.name,
            },
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.overrides = override_settings(
            ALLOWED_HOSTS=["127.0.0.1", "testserver"],
            PAM_PUBLIC_ORIGIN="",
            PAM_TRUSTED_PROXY_NETWORKS=(),
            PAM_GUACD_PORT=self.native_port,
        )
        self.overrides.enable()
        self.server = uvicorn.Server(
            uvicorn.Config(
                "config.asgi:application",
                host="127.0.0.1",
                port=self.web_port,
                log_level="critical",
                proxy_headers=False,
                ws_max_size=65536,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.started:
                try:
                    with socket.create_connection(("127.0.0.1", self.native_port), timeout=0.1):
                        break
                except OSError:
                    pass
            time.sleep(0.02)
        else:
            self.fail("Native/ASGI fixture did not start")
        self.org = Organization.objects.create(key="relay", name="Relay test organization")
        self.actor = get_user_model().objects.create_user("operator", password="test-only-password")
        self.reviewer = get_user_model().objects.create_superuser("reviewer", password=None)
        OrganizationMembership.objects.create(
            organization=self.org, account=self.actor, role="operator"
        )
        AccountSecurity.objects.create(
            account=self.actor,
            encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
        )
        ModuleActivation.objects.bulk_create(
            [
                ModuleActivation(
                    organization=self.org, module_key=module, version="test", enabled=True
                )
                for module in ("identity", "access", "approvals", "pam")
            ]
        )
        with organization_context(self.org):
            self.identity = Identity.objects.create(
                organization=self.org, name="Person", kind="human"
            )
            self.resource = Resource.objects.create(
                organization=self.org, name="Fixture", kind="server"
            )
            self.account = ExternalAccount.objects.create(
                organization=self.org,
                identity=self.identity,
                username="fixture",
                system="Fixture",
                kind="privileged",
            )
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.actor)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        self.session_key = session.session_key

    def tearDown(self):
        self.server.should_exit = True
        self.thread.join(timeout=10)
        try:
            os.killpg(self.native.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.native.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.native.pid, signal.SIGKILL)
            self.native.wait(timeout=5)
        self.log.close()
        self.directory.cleanup()
        self.overrides.disable()

    def create_launch(self, host_key, target_port, private_key=None):
        with organization_context(self.org):
            endpoint = SessionEndpoint.objects.create(
                organization=self.org,
                resource=self.resource,
                account=self.account,
                name="SSH fixture",
                protocol="ssh",
                hostname="127.0.0.1",
                port=target_port,
                auth_method="private_key" if private_key else "password",
                encrypted_secret=cipher()
                .encrypt(
                    json.dumps(
                        {"private_key": private_key}
                        if private_key
                        else {"password": "fixture-secret"}
                    ).encode()
                )
                .decode(),
                ssh_host_key=host_key,
                enabled=True,
                verified_revision=1,
                tested_at=timezone.now(),
            )
            intent = AccessIntent.objects.create(
                organization=self.org,
                identity=self.identity,
                account=self.account,
                resource=self.resource,
                method="SSH",
                reason="Fixture test",
                fulfillment="pam",
                starts_at=timezone.now() - timedelta(seconds=15),
                ends_at=timezone.now() + timedelta(hours=1),
                requested_by=self.actor,
            )
            decide(
                intent.pk,
                actor=self.reviewer,
                organization=self.org,
                approved=True,
                comment="Independent native fixture approval",
            )
        self.client.get(reverse("pam-home"))
        token = self.client.cookies[settings.CSRF_COOKIE_NAME].value
        response = self.client.post(
            reverse("pam-launch", args=[intent.pk]), {"csrfmiddlewaretoken": token}
        )
        self.assertEqual(response.status_code, 200, response.content[:1000])
        match = re.search(
            rb'<script id="pam-player-config" type="application/json">(.*?)</script>',
            response.content,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        self.assertNotIn(b"fixture-secret", response.content)
        config = json.loads(match[1])
        return endpoint.pk, intent.pk, config

    async def test_real_websocket_roundtrip_recording_and_logout_disconnect(self):
        await self.exercise("logout")

    async def test_expired_lease_cuts_the_real_ssh_connection(self):
        await self.exercise("expiry")

    async def test_disabled_endpoint_cuts_the_real_ssh_connection(self):
        await self.exercise("disabled")

    async def test_forbidden_browser_arguments_cut_the_real_ssh_connection(self):
        await self.exercise("forbidden")

    async def test_recording_quota_cuts_the_real_ssh_connection(self):
        await self.exercise("quota")

    async def test_private_key_authentication_and_logout_disconnect(self):
        await self.exercise("logout", private_key=True)

    async def exercise(self, termination, private_key=False):
        opened, echoed, lost = asyncio.Event(), asyncio.Event(), asyncio.Event()
        processes = []
        account_key = asyncssh.generate_private_key("ssh-ed25519") if private_key else None

        class SSH(asyncssh.SSHServer):
            authenticated = False

            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return not private_key

            def public_key_auth_supported(self):
                return private_key

            def validate_public_key(self, username, key):
                self.authenticated = (
                    username == "fixture" and key.public_data == account_key.public_data
                )
                return self.authenticated

            def validate_password(self, username, password):
                self.authenticated = username == "fixture" and password == "fixture-secret"
                return self.authenticated

            def connection_lost(self, error):
                if self.authenticated:
                    lost.set()

        async def terminal(process):
            processes.append(process)
            opened.set()
            process.stdout.write("PAM-olive actual WebSocket SSH fixture\r\n")
            if (await process.stdin.readline()).strip() == "native-broker-proof":
                process.stdout.write("Round-trip confirmed\r\n")
                echoed.set()
            await process.stdin.read()

        key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(
            SSH, "127.0.0.1", 0, server_host_keys=[key], process_factory=terminal
        )
        target_port = server.get_port()
        try:
            with override_settings(
                PAM_ALLOWED_HOSTS={f"127.0.0.1:{target_port}"},
                PAM_ALLOWED_NETWORKS=("127.0.0.0/8",),
            ):
                endpoint_id, _, config = await sync_to_async(self.create_launch)(
                    key.export_public_key().decode(),
                    target_port,
                    account_key.export_private_key("openssh").decode() if account_key else None,
                )
                async with connect(
                    f"ws://127.0.0.1:{self.web_port}" + config["websocket_path"],
                    proxy=None,
                    origin=f"http://127.0.0.1:{self.web_port}",
                    subprotocols=["guacamole"],
                    additional_headers={
                        "Cookie": f"{settings.SESSION_COOKIE_NAME}={self.session_key}"
                    },
                    max_size=4 * 1024 * 1024,
                ) as websocket:
                    await websocket.send(
                        json.dumps({"ticket": config["ticket"], "width": 1280, "height": 720})
                    )
                    parser, received = Parser(), []

                    async def display():
                        try:
                            async for frame in websocket:
                                for instruction in parser.feed(frame.encode()):
                                    self.assertNotIn(
                                        instruction.opcode,
                                        ("argv", "required", "ready", "clipboard", "file"),
                                    )
                                    received.append(instruction)
                                    if instruction.opcode == "sync":
                                        await websocket.send(
                                            Instruction("sync", (instruction.arguments[0],))
                                            .encode()
                                            .decode()
                                        )
                                    elif instruction.opcode == "blob":
                                        await websocket.send(
                                            Instruction(
                                                "ack", (instruction.arguments[0], "OK", "0")
                                            )
                                            .encode()
                                            .decode()
                                        )
                        except ConnectionClosed:
                            pass

                    drain = asyncio.create_task(display())
                    try:
                        await asyncio.wait_for(opened.wait(), timeout=10)

                        # MFA freshness expiring during a session must NOT cut or challenge it.
                        def expire_mfa_only():
                            session = Session.objects.get(session_key=self.session_key)
                            data = session.get_decoded()
                            data["mfa_verified_at"] = time.time() - 3600
                            from django.contrib.sessions.backends.db import SessionStore

                            store = SessionStore(session_key=self.session_key)
                            store.update(data)
                            store.save()

                        await sync_to_async(expire_mfa_only)()
                        await asyncio.sleep(1.2)
                        for char in "native-broker-proof":
                            for pressed in ("1", "0"):
                                await websocket.send(
                                    Instruction("key", (str(ord(char)), pressed)).encode().decode()
                                )
                        for pressed in ("1", "0"):
                            await websocket.send(
                                Instruction("key", ("65293", pressed)).encode().decode()
                            )
                        await asyncio.wait_for(echoed.wait(), timeout=5)

                        def revoke():
                            with organization_context(self.org):
                                if termination == "logout":
                                    Session.objects.filter(session_key=self.session_key).delete()
                                elif termination == "expiry":
                                    SessionLease.objects.update(expires_at=timezone.now())
                                elif termination == "disabled":
                                    SessionEndpoint.objects.filter(pk=endpoint_id).update(
                                        enabled=False
                                    )

                        with override_settings(
                            PAM_MAX_RECORDING_BYTES=(
                                1 if termination == "quota" else settings.PAM_MAX_RECORDING_BYTES
                            )
                        ):
                            await sync_to_async(revoke)()
                            if termination == "forbidden":
                                await websocket.send(
                                    Instruction("connect", ("browser-chosen-target",))
                                    .encode()
                                    .decode()
                                )
                            elif termination == "quota":
                                processes[0].stdout.write("capture quota test\r\n" * 100)
                            await asyncio.wait_for(lost.wait(), timeout=6)
                            await asyncio.wait_for(drain, timeout=6)
                    finally:
                        drain.cancel()
                        await asyncio.gather(drain, return_exceptions=True)
                self.assertTrue(any(instruction.opcode == "sync" for instruction in received))
                connection_id = config["websocket_path"].split("/")[3]

                def verify_recording():
                    with organization_context(self.org):
                        item = RelayConnection.objects.get(pk=connection_id)
                        self.assertEqual(
                            item.end_reason,
                            {
                                "forbidden": "input_not_authorized",
                                "quota": "recording_quota_exceeded",
                            }.get(termination, "authority_lost"),
                        )
                        self.assertIsNotNone(item.ended_at)
                        self.assertGreater(item.recording_bytes, 0)
                        for chunk in RecordingChunk.objects.filter(connection=item):
                            payload = cipher().decrypt(bytes(chunk.encrypted_payload))
                            self.assertNotIn(b"fixture-secret", payload)
                            self.assertNotIn(b"PRIVATE KEY", payload)
                            self.assertNotIn(b"4.argv", payload)
                        # Re-authenticate for playback, never during the transport.
                        self.client.force_login(self.actor)
                        with recent_authentication(self.actor, self.org, time.time()):
                            grant = issue_recording_grant(
                                item, self.actor, self.client.session.session_key
                            )
                        sequence, previous, total = 0, "", 0
                        while True:
                            payloads, sequence, previous = recording_page(
                                item.pk,
                                self.org,
                                self.client.session.session_key,
                                grant,
                                sequence,
                                previous,
                            )
                            total += sum(map(len, payloads))
                            if not payloads:
                                break
                        self.assertEqual(total, item.recording_bytes)

                await sync_to_async(verify_recording)()
        finally:
            server.close()
            await server.wait_closed()
