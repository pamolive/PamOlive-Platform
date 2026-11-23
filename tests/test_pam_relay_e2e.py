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
from unittest.mock import patch

import pyotp
import uvicorn
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError, OperationalError
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
from platform_modules.access.services import create_record
from platform_modules.approvals.services import decide
from platform_modules.identity.bindings import current_binding, revoke_binding
from platform_modules.identity.models import ExternalAccount, Identity, Resource
from platform_modules.pam.models import (
    RecordingChunk,
    RelayConnection,
    SessionEndpoint,
    SessionLease,
)
from platform_modules.pam.protocol import Instruction, Parser
from platform_modules.pam.recordings import issue_recording_grant, recording_page
from platform_modules.pam.trust import launch_payload

from .fixtures.ssh import INPUT, SSHFixture
from .pam_trust_fixtures import TrustFixture
from .person_fixtures import bind_person

BINARY = Path("/opt/pamolive-guac/sbin/guacd")
STARTUP_STATUSES = {"pending", "connecting", "active", "ended", "failed", "expired"}
STARTUP_REASONS = {
    "authority_lost",
    "database_unavailable",
    "native_closed",
    "native_error",
    "native_handshake_failed",
    "relay_failed",
    "relay_shutdown",
    "session_credentials_unavailable",
    "ssh_host_key_mismatch",
    "ssh_identity_probe_failed",
    "stop_requested",
}


def unused_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


async def ssh_open_failure(opened, display, *, timeout=10):
    """Distinguish an early relay close from the SSH server failing to open a shell."""
    opening = asyncio.create_task(opened.wait())
    try:
        done, _ = await asyncio.wait(
            (opening, display), timeout=timeout, return_when=asyncio.FIRST_COMPLETED
        )
        if opening in done or opened.is_set():
            return None
        if display in done:
            display.result()
            return "websocket_closed_before_ssh"
        return "ssh_open_deadline"
    finally:
        opening.cancel()
        await asyncio.gather(opening, return_exceptions=True)


@skipUnless(BINARY.is_file() or os.environ.get("PAM_REQUIRE_NATIVE"), "native image gate")
class RelayHarness(TransactionTestCase):
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
                "LD_LIBRARY_PATH": "/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib",
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
            bind_person(
                self.actor,
                organization=self.org,
                administrator=self.reviewer,
                identity=self.identity,
            )
            self.reviewer_binding = bind_person(
                self.reviewer, organization=self.org, administrator=self.reviewer, role="reviewer"
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

    def make_endpoint(
        self, host_key, target_port, private_key, protocol, certificate_pin, password
    ):
        from platform_modules.pam.target_binding import credential_seal

        endpoint = SessionEndpoint(
            organization=self.org,
            resource=self.resource,
            account=self.account,
            name=f"{protocol.upper()} fixture",
            protocol=protocol,
            hostname="127.0.0.1",
            port=target_port,
            auth_method="private_key" if private_key else "password",
            encrypted_secret=cipher()
            .encrypt(
                json.dumps(
                    {"private_key": private_key} if private_key else {"password": password}
                ).encode()
            )
            .decode(),
            ssh_host_key=host_key if protocol == "ssh" else "",
            certificate_pin=certificate_pin,
            domain="FIXTURE" if protocol == "rdp" else "",
            enabled=True,
            verified_revision=1,
            tested_at=timezone.now(),
        )
        endpoint.credential_seal = credential_seal(endpoint, self.account)
        endpoint.save()
        return endpoint

    def create_launch(
        self,
        host_key,
        target_port,
        private_key=None,
        *,
        protocol="ssh",
        certificate_pin="",
        password="fixture-secret",
        shared=False,
    ):
        with (
            organization_context(self.org),
            recent_authentication(self.actor, self.org, time.time()),
        ):
            if shared:
                self.shared_owner = Identity.objects.create(
                    organization=self.org, name="Shared service fixture", kind="service"
                )
                self.account.identity, self.account.kind = self.shared_owner, "service"
                self.account.state_revision += 1
                self.account.save(update_fields=["identity", "kind", "state_revision"])
            endpoint = self.make_endpoint(
                host_key, target_port, private_key, protocol, certificate_pin, password
            )
            self.trust = TrustFixture(
                self,
                self.org,
                [endpoint],
                [
                    (self.actor, self.identity, ["requester"]),
                    (self.reviewer, self.reviewer_binding.identity, ["reviewer", "sponsor"]),
                ],
            )
            with self.trust.personal_action(self.actor):
                intent = create_record(
                    "intent",
                    {
                        "identity": self.identity,
                        "account": self.account,
                        "resource": self.resource,
                        "method": protocol.upper(),
                        "reason": "Fixture test",
                        "fulfillment": "pam",
                        "starts_at": timezone.now() - timedelta(seconds=15),
                        "ends_at": timezone.now() + timedelta(hours=1),
                    },
                    actor=self.actor,
                    organization=self.org,
                )
            with (
                recent_authentication(self.reviewer, self.org, time.time()),
                self.trust.personal_action(self.reviewer),
            ):
                decide(
                    intent.pk,
                    actor=self.reviewer,
                    organization=self.org,
                    approved=True,
                    comment="Independent native fixture approval",
                )
        self.client.get(reverse("pam-home"))
        token = self.client.cookies[settings.CSRF_COOKIE_NAME].value
        browser = self.trust.request(self.actor)
        browser.session = self.client.session
        proof = self.trust.proof(self.actor, "launch", launch_payload(intent), request=browser)
        response = self.client.post(
            reverse("pam-launch", args=[intent.pk]),
            {"csrfmiddlewaretoken": token, "_pam_trust_proof": proof},
        )
        self.assertEqual(response.status_code, 200, response.content[:1000])
        match = re.search(
            rb'<script id="pam-player-config" type="application/json">(.*?)</script>',
            response.content,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        self.assertNotIn(password.encode(), response.content)
        config = json.loads(match[1])
        return endpoint.pk, intent.pk, config

    def recording_grant(self, item, revoked_binding=False):
        if revoked_binding:
            self.client.force_login(self.actor)
            with (
                recent_authentication(self.actor, self.org, time.time()),
                self.assertRaises(PermissionDenied),
            ):
                issue_recording_grant(item, self.actor, self.client.session.session_key)
        reader = self.reviewer if revoked_binding else self.actor
        self.client.force_login(reader)
        with recent_authentication(reader, self.org, time.time()):
            return issue_recording_grant(item, reader, self.client.session.session_key)


class NativeRelayTests(RelayHarness):
    async def test_person_uses_shared_service_account_without_becoming_its_owner(self):
        await self.exercise("logout", shared=True)

    async def test_person_link_revocation_cuts_shared_ssh_but_preserves_service(self):
        await self.exercise("binding_revoked", shared=True)

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

    async def test_database_failure_cuts_the_real_ssh_connection_without_claiming_revocation(self):
        await self.exercise("database_failure")

    async def test_startup_and_monitor_do_not_compete_for_their_own_database_row(self):
        from platform_modules.pam import sessions

        original = sessions._check_authority
        delayed = threading.Event()

        def slow_authority(item, **kwargs):
            # check_session already holds the relay row. Without local ordering,
            # the second startup/monitor query exceeds its unchanged 1s lock timeout.
            if item.status == "connecting" and not delayed.is_set():
                delayed.set()
                time.sleep(1.25)
            return original(item, **kwargs)

        with patch("platform_modules.pam.sessions._check_authority", side_effect=slow_authority):
            await self.exercise("logout")
        self.assertTrue(delayed.is_set())

    async def startup_observation(self, connection_id, websocket):
        def snapshot():
            with organization_context(self.org):
                return (
                    RelayConnection.objects.filter(pk=connection_id)
                    .values_list("status", "end_reason")
                    .first()
                )

        try:
            row = await asyncio.wait_for(sync_to_async(snapshot)(), timeout=1)
        except (DatabaseError, TimeoutError):
            state, reason = "unavailable", "unknown"
        else:
            if row is None:
                state, reason = "missing", "unknown"
            else:
                state, reason = row
                state = state if state in STARTUP_STATUSES else "other"
                reason = reason if reason in STARTUP_REASONS else "other" if reason else "none"
        return (
            f"state={state} reason={reason} websocket_code={websocket.close_code} "
            f"guacd_exit={self.native.poll()}"
        )

    async def exercise(self, termination, private_key=False, shared=False):
        async with SSHFixture(key_auth=private_key) as peer:
            with override_settings(
                PAM_ALLOWED_HOSTS={f"{peer.host}:{peer.port}"},
                PAM_ALLOWED_NETWORKS=("127.0.0.0/8",),
            ):
                endpoint_id, _, config = await sync_to_async(self.create_launch)(
                    peer.host_key,
                    peer.port,
                    peer.private_key,
                    password=peer.password,
                    shared=shared,
                )
                connection_id = config["websocket_path"].split("/")[3]
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
                        failure = await ssh_open_failure(peer.opened, drain)
                        if failure is not None:
                            observation = await self.startup_observation(connection_id, websocket)
                            self.fail(f"Native relay startup failed: {failure} {observation}")

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
                        for char in INPUT:
                            for pressed in ("1", "0"):
                                await websocket.send(
                                    Instruction("key", (str(ord(char)), pressed)).encode().decode()
                                )
                        for pressed in ("1", "0"):
                            await websocket.send(
                                Instruction("key", ("65293", pressed)).encode().decode()
                            )
                        await asyncio.wait_for(peer.echoed.wait(), timeout=5)

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
                                elif termination == "binding_revoked":
                                    binding = current_binding(self.actor, organization=self.org)
                                    with recent_authentication(
                                        self.reviewer, self.org, time.time()
                                    ):
                                        revoke_binding(
                                            binding.pk,
                                            actor=self.reviewer,
                                            organization=self.org,
                                            reason="Fixture person revoked",
                                        )

                        with override_settings(
                            PAM_MAX_RECORDING_BYTES=(
                                1 if termination == "quota" else settings.PAM_MAX_RECORDING_BYTES
                            )
                        ):
                            from contextlib import nullcontext

                            failure = (
                                patch(
                                    "platform_modules.pam.broker.check_session",
                                    side_effect=OperationalError("fixture-secret-never-log"),
                                )
                                if termination == "database_failure"
                                else nullcontext()
                            )
                            with failure:
                                await sync_to_async(revoke)()
                                if termination == "forbidden":
                                    await websocket.send(
                                        Instruction("connect", ("browser-chosen-target",))
                                        .encode()
                                        .decode()
                                    )
                                elif termination == "quota":
                                    peer.process.stdout.write("capture quota test\r\n" * 100)
                                await asyncio.wait_for(peer.lost.wait(), timeout=6)
                                await asyncio.wait_for(drain, timeout=6)
                    finally:
                        drain.cancel()
                        await asyncio.gather(drain, return_exceptions=True)
                self.assertTrue(any(instruction.opcode == "sync" for instruction in received))

                def verify_recording():
                    with organization_context(self.org):
                        item = RelayConnection.objects.get(pk=connection_id)
                        self.assertEqual(
                            item.end_reason,
                            {
                                "forbidden": "input_not_authorized",
                                "quota": "recording_quota_exceeded",
                                "database_failure": "database_unavailable",
                            }.get(termination, "authority_lost"),
                        )
                        self.assertIsNotNone(item.ended_at)
                        if termination == "database_failure":
                            self.assertFalse(item.recording_complete)
                        self.assertGreater(item.recording_bytes, 0)
                        for chunk in RecordingChunk.objects.filter(connection=item):
                            payload = cipher().decrypt(bytes(chunk.encrypted_payload))
                            self.assertNotIn(b"fixture-secret", payload)
                            self.assertFalse(
                                peer.password.encode() in payload, "Fixture password in recording"
                            )
                            self.assertNotIn(b"PRIVATE KEY", payload)
                            self.assertNotIn(b"4.argv", payload)
                        # Re-authenticate for playback, never during the transport.
                        if shared:
                            self.account.refresh_from_db()
                            self.assertTrue(self.account.active)
                            self.assertEqual(self.account.identity_id, self.shared_owner.pk)
                            self.assertEqual(
                                item.authority_snapshot["identity_id"], str(self.identity.pk)
                            )
                            self.assertEqual(
                                item.authority_snapshot["account_owner_identity_id"],
                                str(self.shared_owner.pk),
                            )
                        grant = self.recording_grant(item, termination == "binding_revoked")
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
