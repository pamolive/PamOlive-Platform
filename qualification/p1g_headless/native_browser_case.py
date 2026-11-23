"""P1-G browser acceptance for one synthetic SSH session and administrative stop."""

import os
import re
from uuid import UUID

from django.conf import settings
from django.test import override_settings
from django.urls import reverse

from platform_core.audit import verify_chain
from platform_core.models import AuditEvent
from platform_modules.pam import trust
from platform_modules.pam.models import RelayConnection, SessionEndpoint
from platform_modules.pam.sessions import browser_hash
from qualification.p1g_headless import lab_support as support
from qualification.p1g_headless.browser_case import FACTS, TLS, P1GBrowser
from tests.fixtures.asgi import TLSASGIServer
from tests.fixtures.guacd import guacd_fixture
from tests.fixtures.ssh import INPUT, ThreadedSSHFixture

CAPTURE_LIMIT = 2 * 1024**2


class NativeSSHBrowser(P1GBrowser):
    @classmethod
    def _start_server_thread(cls):
        support.guard(os.environ)
        cls.server_thread = cls.enterClassContext(
            TLSASGIServer(TLS["server_certificate"], TLS["server_key"])
        )

    def setUp(self):
        self.ssh = self.enterContext(ThreadedSSHFixture())
        peer = self.ssh.peer
        native_port, _ = self.enterContext(guacd_fixture(owned_by_worker=True))
        self.enterContext(override_settings(
            PAM_ALLOWED_HOSTS={f"{peer.host}:{peer.port}"},
            PAM_ALLOWED_NETWORKS=("127.0.0.1/32",),
            PAM_GUACD_PORT=native_port,
            PAM_MAX_RECORDING_BYTES=CAPTURE_LIMIT,
            PAM_TRUSTED_PROXY_NETWORKS=(),
        ))
        super().setUp()
        self.enterContext(override_settings(PAM_PUBLIC_ORIGIN=self.origin))
        self.wss_pattern = support.relay_socket_pattern(self.origin)

    def _endpoint(self):
        peer = self.ssh.peer
        self.account.username = peer.username
        self.account.save(update_fields=["username"])
        response = self._post(self.admin_browser, reverse("pam-endpoint-create"), {
            "name": "Synthetic P1-G SSH peer",
            "resource": self.resource.pk,
            "account": self.account.pk,
            "protocol": "ssh",
            "hostname": peer.host,
            "port": peer.port,
            "auth_method": "password",
            "password": peer.password,
            "host_key": peer.host_key,
        })
        self.assertEqual(response.status_code, 302)
        endpoint = SessionEndpoint.objects.get(organization=self.org, account=self.account)
        for action in ("test", "enable"):
            response = self._post(
                self.admin_browser, reverse("pam-endpoint-action", args=[endpoint.pk, action]), {},
            )
            self.assertEqual(response.status_code, 302)
        endpoint.refresh_from_db()
        self.assertTrue(endpoint.enabled)
        self.assertEqual(endpoint.verified_revision, endpoint.revision)
        self.assertEqual(endpoint.ssh_host_key, peer.host_key.strip())
        return endpoint

    def install_websocket_policy(self, context):
        def deny_socket(socket):
            self.denied.append("unexpected_socket_in_native_UI")
            socket.close()

        # Leave matching sockets on the real browser/server route. Never proxy
        # the first frame carrying the short-lived relay capability through a hook.
        context.route_web_socket(re.compile(r"^(?!" + self.wss_pattern + r"$).*$"), deny_socket)

    def after_approval(self, browser, pages, intent):
        from playwright.sync_api import expect

        self.phase("native_SSH_launch_from_existing_approved_intent")
        page = pages[0]
        self.goto(page, "pam-home")
        action = reverse("pam-launch", args=[intent.pk])
        page.locator(f'form[action="{action}"] button').click()
        self.trust.checkpoint()
        with page.expect_websocket(
            lambda socket: re.fullmatch(self.wss_pattern, socket.url) is not None, timeout=20000,
        ) as upgrade:
            with page.expect_navigation(wait_until="domcontentloaded", timeout=20000):
                page.locator('#pam-trust-form button[type="submit"]').click()
        socket = upgrade.value
        connection_id = UUID(re.fullmatch(self.wss_pattern, socket.url)[1])
        expect(page.locator("#pam-state")).to_have_text(
            "Relais ouvert — affichage enregistré", timeout=15000,
        )
        self.ssh.wait("opened")
        relay = RelayConnection.unscoped.get(
            pk=connection_id, organization=self.org, lease__intent=intent, endpoint=self.endpoint,
            opened_by=self.operator, status="active",
        )
        self.assertIsNotNone(relay.connected_at)
        self.assertTrue(trust.verify_launch(intent, relay.authority_snapshot["pam_trust_launch"]))
        cookies = page.context.cookies(self.origin)
        session = next(cookie["value"] for cookie in cookies
                       if cookie["name"] == settings.SESSION_COOKIE_NAME)
        self.assertTrue(relay.browser_session_hash == browser_hash(session))
        self.assert_target_secret_absent(page.content().encode())
        page.locator("#pam-display").focus()
        for key in INPUT:
            page.keyboard.press(key)
        page.keyboard.press("Enter")
        self.ssh.wait("echoed")
        FACTS["native_PAM_transport_observed"] = True
        FACTS["observed_UI_phases"].append("approved_intent_to_same_SSH_connection_and_keyboard")

        self.phase("native_SSH_stop_and_capture")
        details = page.context.new_page()
        details.on("pageerror", lambda error: self.errors.append("pageerror"))
        self.goto(details, "pam-connection", relay.pk)
        stop = reverse("pam-stop", args=[relay.pk])
        with socket.expect_event("close", timeout=15000):
            with details.expect_navigation(wait_until="domcontentloaded", timeout=12000):
                details.locator(f'form[action="{stop}"] button').click()
        self.ssh.wait("lost")
        expect(page.locator("#pam-state")).to_have_text(
            "Relais fermé — consultez la fiche pour le motif et la capture.", timeout=10000,
        )
        self.assertTrue(page.locator("#pam-close").is_disabled())
        relay.refresh_from_db()
        self.assertEqual((relay.status, relay.end_reason), ("ended", "stop_requested"))
        self.assertIsNotNone(relay.stop_requested_at)
        self.assertLessEqual(relay.stop_requested_at, relay.ended_at)
        self.assertFalse(relay.recording_complete)
        self.assertTrue(AuditEvent.objects.filter(
            organization=self.org, actor=self.operator, object_id=str(relay.pk),
            action="pam.relay.stop_requested.v1",
        ).exists())
        self.assertTrue(0 < relay.recording_bytes <= CAPTURE_LIMIT)
        self.assertEqual(self._business_counts(), (1, 2, 1, 1))
        self.verify_capture(details, relay)
        details.close()
        FACTS["observed_UI_phases"].append("same_relay_stop_WSS_SSH_and_verified_partial_capture")

    def assert_target_secret_absent(self, content):
        self.assertFalse(self.ssh.peer.password.encode() in content, "Target credential exposed")

    def verify_capture(self, page, relay):
        self.goto(page, "pam-connection", relay.pk)
        data = self.origin + reverse("pam-recording-data", args=[relay.pk])
        recording = reverse("pam-recording", args=[relay.pk])
        with page.expect_response(lambda response: response.url == data, timeout=15000) as capture:
            page.locator(f'form[action="{recording}"] button').click()
        response = capture.value
        self.assertEqual(response.status, 200)
        body = response.body()
        self.assertEqual(len(body), relay.recording_bytes)
        self.assert_target_secret_absent(body)
        self.assertFalse(b"4.argv" in body, "Sensitive arguments in capture")
        page.get_by_text("Capture vérifiée", exact=False).wait_for(timeout=10000)
        self.assertTrue(page.locator("#pam-play").is_enabled())
        self.assertTrue(AuditEvent.objects.filter(
            organization=self.org, object_id=str(relay.pk), action="pam.recording.viewed.v1",
        ).exists())
        self.assertTrue(verify_chain(self.org))
