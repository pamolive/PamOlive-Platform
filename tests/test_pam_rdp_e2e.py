"""RDP release gate: actual CredSSP peer, WebSocket relay and encrypted capture."""

import asyncio
import json
import os
import time
from collections import Counter
from unittest import skipUnless

import pyotp
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import override_settings
from django.utils import timezone
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity
from platform_core.security import cipher
from platform_core.tenancy import organization_context
from platform_modules.identity.bindings import current_binding, revoke_binding
from platform_modules.pam.models import RelayConnection, SessionEndpoint, SessionLease
from platform_modules.pam.protocol import Instruction, Parser
from platform_modules.pam.recordings import recording_page
from platform_modules.pam.sessions import configure_endpoint, probe_endpoint, set_endpoint_enabled
from tests.fixtures.paint import PaintProof
from tests.fixtures.rdp import BINARY as RDP_BINARY
from tests.fixtures.rdp import RDPFixture
from tests.test_pam_relay_e2e import RelayHarness


@skipUnless(RDP_BINARY.is_file() or os.environ.get("PAM_REQUIRE_RDP"), "RDP test-image gate")
class NativeRDPRelayTests(RelayHarness):
    def setUp(self):
        self.assertTrue(RDP_BINARY.is_file(), "PAM_REQUIRE_RDP cannot silently skip its peer")
        super().setUp()
        self.assertIn(
            "rdp", settings.PAM_SESSION_PROTOCOLS, "Published RDP must actually be enabled"
        )
        AccountSecurity.objects.get_or_create(
            account=self.reviewer,
            defaults={
                "encrypted_secret": cipher().encrypt(pyotp.random_base32().encode()).decode()
            },
        )

    def make_endpoint(
        self, host_key, target_port, private_key, protocol, certificate_pin, password
    ):
        if self.mode == "pin":
            # An adversarial stale/misconfigured endpoint must fail again at launch.
            return super().make_endpoint(
                host_key, target_port, private_key, protocol, certificate_pin, password
            )
        with recent_authentication(self.reviewer, self.org, time.time()):
            endpoint = configure_endpoint(
                actor=self.reviewer,
                organization=self.org,
                name="Validated RDP fixture",
                resource=self.resource,
                account=self.account,
                protocol="rdp",
                hostname="127.0.0.1",
                port=target_port,
                domain="FIXTURE",
                auth_method="password",
                password=password,
                rdp_pin=certificate_pin,
            )
            verified, code = probe_endpoint(endpoint.pk, actor=self.reviewer, organization=self.org)
            self.assertTrue(verified, code)
            set_endpoint_enabled(
                endpoint.pk, actor=self.reviewer, organization=self.org, enabled=True
            )
        endpoint.refresh_from_db()
        return endpoint

    async def test_rdp_mfa_expiry_does_not_interrupt_but_logout_does(self):
        await self.exercise("logout")

    async def test_rdp_person_uses_shared_service_account(self):
        await self.exercise("logout", shared=True)

    async def test_rdp_person_link_revocation_cuts_transport_not_service_account(self):
        await self.exercise("binding_revoked", shared=True)

    async def test_rdp_expired_lease_cuts_the_actual_connection(self):
        await self.exercise("expiry")

    async def test_rdp_endpoint_disable_cuts_the_actual_connection(self):
        await self.exercise("disabled")

    async def test_rdp_server_redirection_is_rejected_before_any_new_tcp_connection(self):
        await self.exercise("redirect")

    async def test_rdp_wrong_server_pin_sends_no_account_credentials(self):
        await self.exercise("pin")

    async def test_rdp_wrong_password_never_authenticates(self):
        await self.exercise("password")

    async def exercise(self, mode, shared=False):
        self.mode = mode
        config = None
        received = []
        async with RDPFixture(redirect=mode == "redirect") as peer:
            trap_connections = []

            async def trap(reader, writer):
                trap_connections.append(True)
                writer.close()
                await writer.wait_closed()

            trap_server = await asyncio.start_server(trap, "127.0.0.2", peer.port)
            try:
                with override_settings(
                    PAM_ALLOWED_HOSTS={f"127.0.0.1:{peer.port}"},
                    PAM_ALLOWED_NETWORKS=("127.0.0.1/32",),
                ):
                    endpoint_id, _, config = await sync_to_async(self.create_launch)(
                        "",
                        peer.port,
                        protocol="rdp",
                        certificate_pin="00" * 32 if mode == "pin" else peer.pin,
                        password="incorrect-test-password" if mode == "password" else peer.password,
                        shared=shared,
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
                        received = []
                        pixels = PaintProof()

                        async def display():
                            parser = Parser()
                            try:
                                async for frame in websocket:
                                    self.assertNotIn(peer.password, frame)
                                    for instruction in parser.feed(frame.encode()):
                                        self.assertNotIn(
                                            instruction.opcode,
                                            ("argv", "ready", "required", "clipboard", "file"),
                                        )
                                        received.append(instruction)
                                        pixels.observe(instruction)
                                        if instruction.opcode == "sync":
                                            await websocket.send(
                                                Instruction("sync", (instruction.arguments[0],))
                                                .encode()
                                                .decode()
                                            )
                                        elif instruction.opcode == "blob":
                                            await websocket.send(
                                                Instruction(
                                                    "ack", (instruction.arguments[0], "", "0")
                                                )
                                                .encode()
                                                .decode()
                                            )
                            except ConnectionClosed:
                                pass

                        drain = asyncio.create_task(display())
                        try:
                            if mode in ("pin", "password"):
                                await asyncio.wait_for(drain, timeout=15)
                                self.assertFalse(
                                    any(item["event"] == "authenticated" for item in peer.events)
                                )
                            else:
                                await peer.wait("nla_verified")
                                authenticated = await peer.wait("authenticated")
                                await peer.wait("activated")
                                if mode == "redirect":
                                    await peer.wait("redirect_sent")
                                else:

                                    def expire_mfa():
                                        session = SessionStore(session_key=self.session_key)
                                        session["mfa_verified_at"] = time.time() - 3600
                                        session.save()

                                    await sync_to_async(expire_mfa)()
                                    await asyncio.sleep(1.2)
                                    for pressed in ("1", "0"):
                                        await websocket.send(
                                            Instruction("key", ("97", pressed)).encode().decode()
                                        )
                                    await peer.wait("key_a", timeout=5)
                                    await pixels.wait(drain)

                                    def revoke():
                                        with organization_context(self.org):
                                            if mode == "logout":
                                                Session.objects.filter(
                                                    session_key=self.session_key
                                                ).delete()
                                            elif mode == "expiry":
                                                SessionLease.objects.update(
                                                    expires_at=timezone.now()
                                                )
                                            elif mode == "disabled":
                                                SessionEndpoint.objects.filter(
                                                    pk=endpoint_id
                                                ).update(enabled=False)
                                            elif mode == "binding_revoked":
                                                binding = current_binding(
                                                    self.actor, organization=self.org
                                                )
                                                with recent_authentication(
                                                    self.reviewer, self.org, time.time()
                                                ):
                                                    revoke_binding(
                                                        binding.pk,
                                                        actor=self.reviewer,
                                                        organization=self.org,
                                                        reason="Fixture person revoked",
                                                    )

                                    await sync_to_async(revoke)()
                                await peer.wait(
                                    "disconnected",
                                    connection=authenticated["connection"],
                                    timeout=6,
                                )
                                await asyncio.wait_for(drain, timeout=6)
                        finally:
                            drain.cancel()
                            await asyncio.gather(drain, return_exceptions=True)
                    connection_id = config["websocket_path"].split("/")[3]

                    def verify_capture():
                        with organization_context(self.org):
                            item = RelayConnection.objects.get(pk=connection_id)
                            self.assertIsNotNone(item.ended_at)
                            if mode == "pin":
                                self.assertEqual(item.end_reason, "rdp_certificate_mismatch")
                                self.assertEqual(item.recording_bytes, 0)
                                return
                            if mode in ("password", "redirect"):
                                self.assertEqual(item.end_reason, "native_error")
                            else:
                                self.assertEqual(item.end_reason, "authority_lost")
                                self.assertGreater(item.recording_bytes, 0)
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
                            grant = self.recording_grant(item, mode == "binding_revoked")
                            total, sequence, previous = 0, 0, ""
                            recorded_parser, recorded_pixels = Parser(), PaintProof()
                            while True:
                                chunks, sequence, previous = recording_page(
                                    item.pk,
                                    self.org,
                                    self.client.session.session_key,
                                    grant,
                                    sequence,
                                    previous,
                                )
                                for chunk in chunks:
                                    self.assertNotIn(peer.password.encode(), chunk)
                                    self.assertNotIn(b"4.argv", chunk)
                                    for instruction in recorded_parser.feed(chunk):
                                        self.assertNotEqual(instruction.opcode, "argv")
                                        recorded_pixels.observe(instruction)
                                total += sum(map(len, chunks))
                                if not chunks:
                                    break
                            self.assertEqual(total, item.recording_bytes)
                            if mode not in ("password", "redirect"):
                                self.assertTrue(recorded_pixels.matches)

                    await sync_to_async(verify_capture)()
                    self.assertEqual(trap_connections, [], "RDP attempted an unauthorized target")
                    if mode == "redirect":
                        self.log.seek(0)
                        self.assertIn(b"PAMOLIVE_RDP_REDIRECTION_DENIED", self.log.read())
                    elif mode not in ("pin", "password"):
                        self.assertTrue(
                            any(item.opcode in ("rect", "cfill", "img") for item in received)
                        )
            except BaseException:
                # Only synthetic fixture IDs/statuses/opcodes: never credentials or frame data.
                diagnostic = {
                    "mode": mode,
                    "peer_events": [
                        {"event": item.get("event"), "connection": item.get("connection")}
                        for item in peer.events
                    ],
                    "display_opcodes": dict(Counter(item.opcode for item in received)),
                    "native_error_codes": [
                        item.arguments[-1]
                        for item in received
                        if item.opcode == "error"
                        and item.arguments
                        and item.arguments[-1].isdecimal()
                    ],
                }
                self.log.seek(0, os.SEEK_END)
                self.log.seek(max(0, self.log.tell() - 2048))
                native_tail = self.log.read(2048).decode("utf-8", errors="replace")
                diagnostic["synthetic_native_log_tail"] = native_tail.replace(
                    peer.password, "[redacted]"
                ).replace("incorrect-test-password", "[redacted]")
                if config:
                    connection_id = config["websocket_path"].split("/")[3]

                    def snapshot():
                        with organization_context(self.org):
                            return (
                                RelayConnection.objects.filter(pk=connection_id)
                                .values(
                                    "status",
                                    "end_reason",
                                    "recording_bytes",
                                    "recording_chunks",
                                    "connected_at",
                                    "ended_at",
                                    "expires_at",
                                    "endpoint__enabled",
                                    "lease__status",
                                    "lease__expires_at",
                                    "lease__intent__status",
                                )
                                .first()
                            )

                    try:
                        diagnostic["relay"] = await sync_to_async(snapshot)()
                    except Exception as error:
                        diagnostic["snapshot_error_class"] = type(error).__name__
                print("RDP_TEST_DIAGNOSTIC " + json.dumps(diagnostic, default=str, sort_keys=True))
                raise
            finally:
                trap_server.close()
                await trap_server.wait_closed()
