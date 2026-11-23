"""One explicit live UI increment; no native-session or full-P1G admission."""

import importlib.metadata
import json
import os
import ssl
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import override_settings
from django.test.testcases import LiveServerThread
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.models import AccountSecurity, AuditEvent, ModuleActivation
from platform_core.security import cipher
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.access.observe_demo import create_observe_demo
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.governance.policy import approval_requirements
from platform_modules.identity.models import Grant, Identity
from platform_modules.pam import trust
from platform_modules.pam.models import RelayConnection, SessionLease
from platform_modules.pam.trust_auth import verify_authorization_evidence
from platform_modules.recertification.models import Review
from qualification.p1g_headless import lab_support as support
from tests import test_identity_pam_journey as fixture

FACTS = {
    "phase": "not_started",
    "browser_sandbox": None,
    "browser_E2E_executed": False,
    "full_P1G_qualified": False,
    "target_system_contacted": False,
    "UP_UV_simulation": "Chromium CDP virtual authenticator, not hardware/humans",
    "observed_UI_phases": [],
    "SDK_cleanup_completed": False,
    "all_OS_descendants_reaped_claimed": False,
    "single_intent_end_to_end": False,
    "native_PAM_transport_observed": False,
    "real_provider_effect_proved": False,
}
TLS = {}


def browser_target():
    if "isolated_chrome" in TLS:
        binary = TLS["isolated_chrome"]
        return binary, support.tool_pin(binary, root_owner=False)
    return support.chrome_target(Path(__file__).resolve().parents[2], mode=TLS["browser_mode"])


class TLSLiveServer(LiveServerThread):
    def _create_server(self, connections_override=None):
        server = super()._create_server(connections_override)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(TLS["server_certificate"], TLS["server_key"])
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.base_environ["HTTPS"] = "on"
            return server
        except BaseException:
            server.server_close()
            raise


@override_settings(
    ALLOWED_HOSTS=[support.HOST, "127.0.0.1"],
    PAM_ALLOWED_HOSTS={"ssh.example.test:22"},
    SECURE_SSL_REDIRECT=True,
    SESSION_COOKIE_SECURE=True,
    CSRF_COOKIE_SECURE=True,
)
class P1GBrowser(StaticLiveServerTestCase):
    host = "127.0.0.1"
    server_thread_class = TLSLiveServer
    # Reuse the existing real HTTP password/TOTP/binding/endpoint ceremonies only
    # to PREPARE data. Browser login/enrollment/actions below are independently UI-driven.
    _actor = fixture.IdentityPamJourneyTests._actor
    _get = fixture.IdentityPamJourneyTests._get
    _post = fixture.IdentityPamJourneyTests._post
    _switch = fixture.IdentityPamJourneyTests._switch
    _bind = fixture.IdentityPamJourneyTests._bind
    _endpoint = fixture.IdentityPamJourneyTests._endpoint
    _no_target_secret = fixture.IdentityPamJourneyTests._no_target_secret

    def _enroll_authenticator(self, actor, browser):
        # Defer enrollment to the real page JS/Chromium ceremony, never Python VirtualAuthenticator.
        pass

    def _business_counts(self):
        return tuple(
            model.unscoped.filter(organization=self.org).count()
            for model in (AccessIntent, ApprovalDecision, SessionLease, RelayConnection)
        )

    def setUp(self):
        self.assertFalse(get_user_model().objects.exists())
        self.demo = create_observe_demo()
        demo_actor = get_user_model().objects.get(username="observe-demo-operator")
        demo_actor.set_password(fixture.PASSWORD)
        demo_actor.save(update_fields=["password"])
        self.demo_reviewer = get_user_model().objects.get(username="observe-demo-reviewer")
        self.demo_reviewer.set_password(fixture.PASSWORD)
        self.demo_reviewer.save(update_fields=["password"])
        fixture.IdentityPamJourneyTests.setUp(self)
        self.origin = f"https://{support.HOST}:{self.server_thread.port}"
        settings = override_settings(
            PAM_TRUST_ORIGIN=self.origin, CSRF_TRUSTED_ORIGINS=[self.origin]
        )
        settings.enable()
        self.addCleanup(settings.disable)
        with organization_context(self.other):
            self.foreign = Identity.objects.create(
                organization=self.other, name="Synthetic foreign sentinel", kind="human"
            )
        self.contexts, self.errors, self.denied = [], [], []

    def phase(self, name):
        FACTS["phase"] = name

    def visible(self, page, text):
        page.get_by_text(text, exact=False).first.wait_for(state="visible", timeout=10000)
        self.assertNotIn(fixture.TARGET_PASSWORD, page.content(), "target_secret_in_DOM")

    def goto(self, page, name, *args):
        response = page.goto(self.origin + reverse(name, args=args), timeout=15000)
        self.assertEqual(response.status, 200)
        self.assertTrue(page.evaluate("window.isSecureContext"))
        self.assertNotIn(fixture.TARGET_PASSWORD, page.content(), "target_secret_in_DOM")
        return response

    def totp(self, actor):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            profile = AccountSecurity.objects.get(account=actor)
            if int(time.time()) // 30 > profile.last_counter and time.time() % 30 <= 27:
                secret = cipher().decrypt(profile.encrypted_secret.encode()).decode()
                return pyotp.TOTP(secret).now()
            time.sleep(0.1)
        self.fail("fresh_totp_counter_unavailable")

    def login(self, browser, actor, org, *, mfa=True):
        context = browser.new_context(ignore_https_errors=False, service_workers="block")
        self.contexts.append(context)

        def route(item):
            if support.same_origin(item.request.url, self.origin):
                item.continue_()
            else:
                self.denied.append("application_request_outside_origin")
                item.abort()

        context.route("**/*", route)

        self.install_websocket_policy(context)
        page = context.new_page()
        page.on("pageerror", lambda error: self.errors.append("pageerror"))
        self.goto(page, "login")
        page.locator('[name="username"]').fill(actor.username)
        page.locator('[name="password"]').fill(fixture.PASSWORD)
        if mfa:
            page.locator('[name="otp"]').fill(self.totp(actor))
        with page.expect_navigation(wait_until="domcontentloaded", timeout=15000):
            page.locator('form button[type="submit"]').click()
        switch = page.locator('form[action="' + reverse("organization-switch") + '"]')
        switch.locator('select[name="organization"]').select_option(str(org.pk))
        with page.expect_navigation(wait_until="domcontentloaded", timeout=15000):
            switch.locator("button").click()
        return context, page

    def install_websocket_policy(self, context):
        """Native follow-up overrides this only in its owned, isolated fixture network."""

        def deny_socket(socket):
            self.denied.append("unexpected_WebSocket_in_non_session_increment")
            socket.close()

        context.route_web_socket("**/*", deny_socket)

    def enroll(self, context, page, actor):
        self.trust.checkpoint()
        client = context.new_cdp_session(page)
        client.send("WebAuthn.enable")
        client.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }
            },
        )
        self.goto(page, "pam-trust-enrollment")
        page.locator('#pam-trust-form button[type="submit"]').click()
        page.locator("#pam-trust-enrollment-result").wait_for(state="visible", timeout=20000)
        receipt = json.loads(page.locator("#pam-trust-enrollment-json").inner_text())
        self.assertEqual(self._business_counts(), (0, 0, 0, 0))
        person = self.trust.people[actor.pk]
        self.trust.update(lambda body: body["persons"][person]["authenticators"].append(receipt))
        # The virtual device stays in this page until context.close; no private-key export/CDP seed.

    def confirm(self, page):
        self.trust.checkpoint()
        self.assertNotIn(fixture.TARGET_PASSWORD, page.content(), "target_secret_in_DOM")
        page.locator('#pam-trust-form button[type="submit"]').wait_for(state="visible")
        with page.expect_navigation(wait_until="domcontentloaded", timeout=20000):
            page.locator('#pam-trust-form button[type="submit"]').click()
        self.assertNotIn(fixture.TARGET_PASSWORD, page.content(), "target_secret_in_DOM")

    def request(self, page):
        self.phase("identity360_request_JS")
        self.goto(page, "identity360-detail", self.person.pk)
        before = self._business_counts()
        page.get_by_role("link", name="Demander un accès", exact=True).click()
        self.assertEqual(self._business_counts(), before)
        form = page.locator("#record-form")
        for name, pk in (
            ("identity", self.person.pk),
            ("account", self.account.pk),
            ("resource", self.resource.pk),
        ):
            form.locator(f'[name="{name}"]').select_option(str(pk))
        form.locator('[name="method"]').fill("SSH")
        form.locator('[name="fulfillment"]').select_option("pam")
        form.locator('[name="reason"]').fill("Synthetic browser bounded maintenance")
        form.locator('[name="reference"]').fill("P1G-BROWSER-SYNTHETIC")
        now = timezone.localtime()
        for name, value in (
            ("starts_at", now - timedelta(minutes=1)),
            ("ends_at", now + timedelta(minutes=15)),
        ):
            form.locator(f'[name="{name}"]').fill(value.strftime("%Y-%m-%dT%H:%M"))
        page.get_by_role("button", name="Enregistrer", exact=True).click()
        self.assertEqual(self._business_counts(), before)
        self.confirm(page)
        intent = AccessIntent.objects.get(organization=self.org, requested_by=self.operator)
        self.assertEqual(intent.status, "pending")
        self.assertTrue(
            verify_authorization_evidence(
                intent.pam_trust["request"],
                actor=self.operator,
                organization=self.org,
                action="request",
                payload=trust.request_payload(intent, intent.pam_trust["policy"]),
            )
        )
        FACTS["observed_UI_phases"].append("Identity360_form_to_signed_request")
        return intent

    def votes(self, pages, intent):
        self.phase("two_independent_fixture_people_JS_votes")
        for index, page in enumerate(pages):
            self.goto(page, "approvals-home")
            form = page.locator('form[action="' + reverse("intent-decide", args=[intent.pk]) + '"]')
            form.locator('[name="comment"]').fill("Synthetic browser review of exact scope")
            form.locator('button[name="decision"][value="approve"]').click()
            self.confirm(page)
            intent.refresh_from_db()
            self.assertEqual(intent.status, "pending" if index == 0 else "approved")
            self.assertEqual(approval_requirements(intent)["approved"], index + 1)
            self.assertFalse(SessionLease.unscoped.filter(organization=self.org).exists())
        self.assertTrue(all(trust.verified_vote(intent, vote) for vote in intent.decisions.all()))
        FACTS["observed_UI_phases"].append("two_UI_votes_verified_by_existing_P0")

    def negative_boundaries(self, page, intent):
        self.phase("UI_refusals")
        before = self._business_counts()
        response = page.goto(self.origin + reverse("identity360-detail", args=[self.foreign.pk]))
        self.assertEqual(response.status, 404)
        self.assertNotIn(self.foreign.name, page.content())
        response = page.goto(
            self.origin
            + reverse("identity360-detail", args=["00000000-0000-4000-8000-000000000001"])
        )
        self.assertEqual(response.status, 404)
        with organization_context(self.org):
            deleted = Identity.objects.create(
                organization=self.org, name="Synthetic deleted UI sentinel", kind="human"
            )
            deleted_id = deleted.pk
            deleted.delete()
        response = page.goto(self.origin + reverse("identity360-detail", args=[deleted_id]))
        self.assertEqual(response.status, 404)
        self.person.status = "suspended"
        self.person.save(update_fields=["status"])
        try:
            self.goto(page, "identity360-detail", self.person.pk)
            self.assertEqual(
                page.get_by_role("link", name="Demander un accès", exact=True).count(), 0
            )
            response = page.goto(
                self.origin
                + reverse("record-create", args=["intent"])
                + "?identity="
                + str(self.person.pk)
            )
            self.assertEqual(response.status, 404)
        finally:
            self.person.status = "active"
            self.person.save(update_fields=["status"])
        active = ModuleActivation.objects.get(organization=self.org, module_key="access")
        active.enabled = False
        active.save(update_fields=["enabled"])
        try:
            response = page.goto(self.origin + reverse("record-create", args=["intent"]))
            self.assertEqual(response.status, 403)
        finally:
            active.enabled = True
            active.save(update_fields=["enabled"])
        self.operator.is_active = False
        self.operator.save(update_fields=["is_active"])
        try:
            response = page.goto(self.origin + reverse("access-contract-detail", args=[intent.pk]))
            self.assertIn(response.status, (200, 403))
            self.assertTrue(
                page.locator('[name="username"]').is_visible() or response.status == 403
            )
        finally:
            self.operator.is_active = True
            self.operator.save(update_fields=["is_active"])
        self.assertEqual(self._business_counts(), before)
        FACTS["observed_UI_phases"].append("foreign_disabled_module_inactive_user_refused")

    def historical_observe_UI(self, browser):
        self.phase("PC483_PC991_recorded_fixture_UI")
        actor = get_user_model().objects.get(username="observe-demo-operator")
        org = self.demo["organizations"][0]
        from platform_core.models import Organization

        _, page = self.login(browser, actor, Organization.objects.get(pk=org["id"]), mfa=False)
        for story in org["observations"][:2]:
            self.goto(page, "observe-detail", story["event_id"])
            self.visible(page, "Parcours de l’observation")
            self.visible(page, "vérifiée : oui")
        self.goto(page, "access-contract-detail", org["intent_id"])
        self.visible(page, "remove_membership")
        self.visible(page, "ne certifie pas l’état actuel du fournisseur")
        FACTS["observed_UI_phases"].append(
            "PC483_PC991_observation_evaluation_recorded_withdrawal_UI"
        )
        FACTS["Observe_fixture"] = {
            "transport": "in_memory",
            "browser_provisioning_executed": False,
            "browser_withdrawal_clicked": False,
        }

    def revoke_local_right_UI(self, browser):
        """Real grant-review UI act on a NEW local fixture grant, never provider proof."""
        from platform_core.models import Organization

        self.phase("local_grant_review_revocation_UI")
        demo = self.demo["organizations"][0]
        organization = Organization.objects.get(pk=demo["id"])
        with organization_context(organization):
            existing = AccessIntent.objects.get(pk=demo["intent_id"])
            grant = Grant.objects.create(
                organization=organization,
                identity=existing.identity,
                account=existing.account,
                resource=existing.resource,
                entitlement="Synthetic UI-only local right",
                justification="No remote provisioning",
                valid_from=timezone.now(),
                expires_at=timezone.now() + timedelta(minutes=15),
            )
            _, page = self.login(browser, self.demo_reviewer, organization)
            self.goto(page, "recertification-home")
            form = page.locator('form:has(input[name="due_at"])')
            form.locator('[name="name"]').fill("Synthetic UI frozen-cohort review")
            form.locator('[name="due_at"]').fill(
                (timezone.localtime() + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M")
            )
            form.locator('[name="owner"]').select_option(str(self.demo_reviewer.pk))
            with page.expect_navigation(wait_until="domcontentloaded", timeout=15000):
                form.get_by_role("button", name="Créer la campagne", exact=True).click()
            review = Review.objects.get(
                grant=grant, campaign__name="Synthetic UI frozen-cohort review"
            )
            decision = page.locator(
                'form[action="' + reverse("grant-review", args=[review.pk]) + '"]'
            )
            decision.locator('[name="comment"]').fill("Synthetic actual local revocation via UI")
            with page.expect_navigation(wait_until="domcontentloaded", timeout=15000):
                decision.get_by_role("button", name="Retirer le droit", exact=True).click()
            grant.refresh_from_db()
            review.refresh_from_db()
            self.assertEqual(grant.status, "revoked")
            self.assertIsNotNone(grant.revoked_at)
            self.assertEqual(review.decision, "revoke")
            self.visible(page, "Preuve de décision vérifiée.")
            self.assertTrue(verify_chain(organization))
        FACTS["observed_UI_phases"].append("new_local_grant_frozen_review_and_revocation_UI")
        FACTS["local_revocation"] = {"UI_act_observed": True, "provider_effect_proved": False}

    def after_approval(self, browser, pages, intent):
        """Extension seam: later native case overrides this, not request/auth/vote methods."""
        self.goto(pages[0], "access-contract-detail", intent.pk)
        self.visible(pages[0], "Un bail local ne prouve pas")
        self.assertEqual(self._business_counts(), (1, 2, 0, 0))
        self.goto(pages[0], "audit-log")
        self.visible(pages[0], "access.intent.created.v1")
        self.assertTrue(verify_chain(self.org))
        self.assertEqual(
            AuditEvent.objects.filter(
                organization=self.org, action="approvals.intent.decided.v1"
            ).count(),
            2,
        )

    def test_synthetic_JS_increment(self):
        from playwright.sync_api import sync_playwright

        self.phase("browser_launch")
        self.assertEqual(importlib.metadata.version("playwright"), support.SDK_VERSION)
        node = Path(
            importlib.metadata.distribution("playwright").locate_file("playwright/driver/node")
        )
        node_before = support.playwright_node_pin(node)
        FACTS["SDK_Node_tool"] = node_before
        binary, before = browser_target()
        self.assertEqual(before, TLS["browser_binary_pin"])
        clean_env = {
            "HOME": TLS["browser_home"],
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        with patch.dict(os.environ, clean_env, clear=True):
            playwright = sync_playwright().start()
        browser = None
        try:
            browser = playwright.chromium.launch(
                executable_path=str(binary),
                headless=True,
                chromium_sandbox=True,
                timeout=30000,
                env=clean_env,
                args=["--host-resolver-rules=MAP pam.example.test 127.0.0.1"],
            )
            self.assertRegex(browser.version, r"^[0-9]{1,3}(\.[0-9]{1,5}){3}$")
            self.assertGreaterEqual(int(browser.version.split(".", 1)[0]), 146)
            if TLS["browser_mode"] == "test-bundle-v3":
                self.assertEqual(browser.version, support.BUNDLE_BROWSER_VERSION)
            if "isolated_chrome" in TLS:
                self.assertEqual(browser.version, TLS["isolated_chrome_version"])
            FACTS["browser_version"] = browser.version
            FACTS["browser_tool"] = before
            self.phase("active_browser_sandbox")
            FACTS["browser_sandbox"] = support.observe_browser_sandbox(
                browser, binary, namespace_only="isolated_chrome" in TLS
            )
            pages = []
            for actor in [self.operator, *(actor for actor, _ in self.reviewers)]:
                self.phase("UI_password_TOTP_and_enrollment")
                context, page = self.login(browser, actor, self.org)
                self.enroll(context, page, actor)
                pages.append(page)
            intent = self.request(pages[0])
            self.votes(pages[1:], intent)
            self.after_approval(browser, pages, intent)
            self.negative_boundaries(pages[0], intent)
            self.historical_observe_UI(browser)
            self.revoke_local_right_UI(browser)
            self.assertEqual(self.errors, [])
            self.assertEqual(self.denied, [])
            final_binary, final_pin = browser_target()
            self.assertEqual(final_binary, binary)
            self.assertEqual(final_pin, before)
            FACTS["browser_E2E_executed"] = True
        finally:
            cleanup_errors = []
            for context in self.contexts:
                try:
                    context.close()
                except Exception:
                    cleanup_errors.append("context_close_unknown")
            if browser is not None:
                try:
                    browser.close()
                    self.assertFalse(browser.is_connected())
                except Exception:
                    cleanup_errors.append("browser_close_unknown")
            try:
                playwright.stop()
                self.assertEqual(
                    support.playwright_node_pin(node), node_before
                )
            except Exception:
                cleanup_errors.append("driver_stop_unknown")
            FACTS["SDK_cleanup_completed"] = not cleanup_errors
            self.assertEqual(cleanup_errors, [], "SDK_cleanup_unknown")
        self.phase("completed_increment_full_P1G_still_open")
