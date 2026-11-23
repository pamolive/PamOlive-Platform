"""P1-G browser acceptance for synthetic native sessions and administrative stop."""

import os
import re
from uuid import UUID

import asyncssh
from django.conf import settings
from django.test import override_settings
from django.urls import reverse

from platform_core.audit import verify_chain
from platform_core.models import AuditEvent
from platform_modules.pam import trust
from platform_modules.pam.models import RelayConnection, SessionEndpoint
from platform_modules.pam.sessions import browser_hash
from qualification.p1g_headless import lab_support as support
from qualification.p1g_headless import rdp_peer
from qualification.p1g_headless.browser_case import FACTS, TLS, P1GBrowser
from tests.fixtures.asgi import TLSASGIServer
from tests.fixtures.guacd import guacd_fixture
from tests.fixtures.ssh import INPUT, ThreadedSSHFixture

CAPTURE_LIMIT = 2 * 1024**2


class NativePAMBrowser(P1GBrowser):
    @classmethod
    def _start_server_thread(cls):
        support.guard(os.environ, native_lab="isolated_guacd_port" in TLS)
        cls.server_thread = cls.enterClassContext(
            TLSASGIServer(TLS["server_certificate"], TLS["server_key"])
        )

    def setUp(self):
        self.peer = self.make_peer()
        native_port = TLS.get("isolated_guacd_port")
        if native_port is None:
            native_port, _ = self.enterContext(guacd_fixture(owned_by_worker=True))
        self.enterContext(override_settings(
            PAM_ALLOWED_HOSTS={f"{self.peer.host}:{self.peer.port}"},
            PAM_ALLOWED_NETWORKS=("127.0.0.1/32",),
            PAM_GUACD_PORT=native_port,
            PAM_MAX_RECORDING_BYTES=CAPTURE_LIMIT,
            PAM_TRUSTED_PROXY_NETWORKS=(),
        ))
        super().setUp()
        self.enterContext(override_settings(PAM_PUBLIC_ORIGIN=self.origin))
        self.wss_pattern = support.relay_socket_pattern(self.origin)

    def _endpoint(self):
        peer = self.peer
        self.account.username = peer.username
        self.account.save(update_fields=["username"])
        response = self._post(self.admin_browser, reverse("pam-endpoint-create"), {
            "name": f"Synthetic P1-G {self.protocol.upper()} peer",
            "resource": self.resource.pk,
            "account": self.account.pk,
            "protocol": self.protocol,
            "hostname": peer.host,
            "port": peer.port,
            "auth_method": "password",
            "password": peer.password,
            **self.endpoint_pin(),
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
        self.check_endpoint_pin(endpoint)
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

        self.phase(f"native_{self.protocol.upper()}_launch_from_existing_approved_intent")
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
        self.observe_open(page)
        relay = RelayConnection.unscoped.get(
            pk=connection_id, organization=self.org, lease__intent=intent, endpoint=self.endpoint,
            opened_by=self.operator, status="active",
        )
        self.assertIsNotNone(relay.connected_at)
        self.assertEqual(relay.target_snapshot["protocol"], self.protocol)
        self.assertEqual(relay.target_snapshot["address"], self.peer.host)
        self.assertEqual(relay.target_snapshot["port"], self.peer.port)
        self.check_target_fingerprint(relay)
        self.assertTrue(trust.verify_launch(intent, relay.authority_snapshot["pam_trust_launch"]))
        cookies = page.context.cookies(self.origin)
        session = next(cookie["value"] for cookie in cookies
                       if cookie["name"] == settings.SESSION_COOKIE_NAME)
        self.assertTrue(relay.browser_session_hash == browser_hash(session))
        self.assert_target_secret_absent(page.content().encode())
        self.observe_keyboard(page)
        FACTS["native_PAM_transport_observed"] = True
        transport = self.protocol.upper()
        FACTS["observed_UI_phases"].append(
            f"approved_intent_to_same_{transport}_connection_and_keyboard"
        )

        self.phase(f"native_{transport}_stop_and_capture")
        details = page.context.new_page()
        details.on("pageerror", lambda error: self.errors.append("pageerror"))
        self.goto(details, "pam-connection", relay.pk)
        stop = reverse("pam-stop", args=[relay.pk])
        with socket.expect_event("close", timeout=15000):
            with details.expect_navigation(wait_until="domcontentloaded", timeout=12000):
                self.check_before_stop()
                details.locator(f'form[action="{stop}"] button').click()
        self.observe_disconnect()
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
        FACTS["observed_UI_phases"].append(
            f"same_relay_stop_WSS_{transport}_and_verified_partial_capture"
        )

    def check_before_stop(self):
        """Protocol-specific proof that the same remote session is still open."""

    def assert_target_secret_absent(self, content):
        self.assertFalse(self.peer.password.encode() in content, "Target credential exposed")

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


class NativeSSHBrowser(NativePAMBrowser):
    protocol = "ssh"

    def make_peer(self):
        self.ssh = self.enterContext(ThreadedSSHFixture())
        return self.ssh.peer

    def endpoint_pin(self):
        return {"host_key": self.peer.host_key}

    def check_endpoint_pin(self, endpoint):
        self.assertEqual(endpoint.ssh_host_key, self.peer.host_key.strip())

    def check_target_fingerprint(self, relay):
        expected = asyncssh.import_public_key(self.peer.host_key).get_fingerprint("sha256")
        self.assertEqual(relay.target_snapshot["fingerprint"], expected)

    def observe_open(self, page):
        self.ssh.wait("opened")

    def observe_keyboard(self, page):
        page.locator("#pam-display").focus()
        for key in INPUT:
            page.keyboard.press(key)
        page.keyboard.press("Enter")
        self.ssh.wait("echoed")

    def observe_disconnect(self):
        self.ssh.wait("lost")


class NativeRDPBrowser(NativePAMBrowser):
    protocol = "rdp"
    request_method = "RDP"

    def make_peer(self):
        return rdp_peer.Peer(TLS["isolated_rdp_state"])

    def endpoint_pin(self):
        return {"rdp_pin": self.peer.pin, "domain": self.peer.domain}

    def check_endpoint_pin(self, endpoint):
        self.assertEqual(endpoint.certificate_pin, self.peer.pin)
        self.assertEqual(endpoint.domain, self.peer.domain)

    def check_target_fingerprint(self, relay):
        self.assertEqual(relay.target_snapshot["fingerprint"], "sha256:" + self.peer.pin)

    def observe_paint(self, page, color):
        page.wait_for_function(
            """expected => Array.from(document.querySelectorAll('#pam-display canvas')).some(
              canvas => canvas.width >= 24 && canvas.height >= 24 && (() => {
                const data = canvas.getContext('2d').getImageData(16, 16, 8, 8).data;
                return Array.from({length: 64}, (_, index) => index * 4).filter(
                  offset => data[offset + 3] === 255 &&
                    expected.every((value, channel) => Math.abs(value - data[offset+channel]) <= 8)
                ).length >= 48;
              })()
            )""",
            arg=list(color), timeout=10000,
        )

    def observe_open(self, page):
        self.rdp_connection = self.peer.wait(rdp_peer.EVENTS[:3])
        self.observe_paint(page, (40, 65, 46))

    def observe_keyboard(self, page):
        page.locator("#pam-display").focus()
        self.assertEqual(self.peer.current(rdp_peer.EVENTS[:3]), self.rdp_connection)
        page.keyboard.press("a")
        self.assertEqual(self.peer.wait(rdp_peer.EVENTS[:4]), self.rdp_connection)
        self.observe_paint(page, (187, 216, 88))
        FACTS["native_RDP_display_and_NLA_observed"] = True

    def check_before_stop(self):
        self.assertEqual(self.peer.current(rdp_peer.EVENTS[:4]), self.rdp_connection)

    def observe_disconnect(self):
        self.assertEqual(self.peer.wait(rdp_peer.EVENTS), self.rdp_connection)
