"""Synthetic HTTP continuity; a pending ticket is not a native or browser session."""

import hashlib
import json
import secrets
from datetime import timedelta
from html.parser import HTMLParser
from unittest.mock import AsyncMock, patch

import asyncssh
import pyotp
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.models import AuditEvent, ModuleActivation, Organization, OrganizationMembership
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessEvent, AccessIntent
from platform_modules.access.provenance import verify_provenance_receipt
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.connectors.services import create_source
from platform_modules.governance.policy import approval_requirements
from platform_modules.identity.models import (
    ExternalAccount,
    Identity,
    LoginIdentityBinding,
    Resource,
)
from platform_modules.pam import trust
from platform_modules.pam.mandates import decision_signature, scope_hash
from platform_modules.pam.models import (
    PAMTrustAuthorization,
    RelayConnection,
    SessionEndpoint,
    SessionLease,
)
from platform_modules.pam.probe import ProbeResult
from platform_modules.pam.services import open_lease
from platform_modules.pam.sessions import authority_seal, browser_hash, revoke_mandate
from platform_modules.pam.target_binding import target_scope
from platform_modules.pam.trust_auth import verify_authorization_evidence

from .pam_trust_fixtures import TrustFixture, VirtualAuthenticator

PASSWORD = secrets.token_urlsafe(32)
TARGET_PASSWORD = secrets.token_urlsafe(32)
HOST = "pam.example.test"
ORIGIN = "https://" + HOST


def ingest_collector_observation(test, intent, external_id):
    with organization_context(test.org):
        install_module("connectors", actor=test.admin, organization=test.org)
        source, token = create_source(
            "Synthetic peer observer", actor=test.admin, organization=test.org,
        )
        response = test.client.post(
            reverse("api-events"),
            {
                "external_id": external_id,
                "identity": str(intent.identity_id),
                "account": str(intent.account_id),
                "resource": str(intent.resource_id),
                "method": intent.method,
                "privilege": intent.privilege,
                "action": "synthetic.native_session_observed",
                "domain": "pam",
                "result": "success",
                "occurred_at": timezone.now().isoformat(),
            },
            content_type="application/json", secure=True, HTTP_HOST=HOST,
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        test.assertEqual(response.status_code, 201)
        event = AccessEvent.objects.get(pk=response.json()["event_id"], collector_source=source)
        test.assertTrue(verify_provenance_receipt(event.provenance_receipt))
        evaluation = event.evaluations.get()
        test.assertTrue(verify_evaluation(evaluation))
        test.assertEqual(evaluation.intent_id, intent.pk)
        test.assertEqual(evaluation.verdict, "expected")
        return event.pk


class _Page(HTMLParser):
    def __init__(self, response):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.scripts = [], [], {}
        self.script = None
        self.feed(response.content.decode())

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "form" and attrs.get("method", "get").lower() == "post":
            self.forms.append(attrs.get("action", ""))
        if tag == "script":
            self.script = attrs.get("id")

    def handle_data(self, data):
        if self.script:
            self.scripts[self.script] = self.scripts.get(self.script, "") + data

    def handle_endtag(self, tag):
        if tag == "script":
            self.script = None


@override_settings(
    ALLOWED_HOSTS=[HOST],
    PAM_ALLOWED_HOSTS={"ssh.example.test:22"},
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
)
class IdentityPamJourneyTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(key="p1g-pam", name="Synthetic PAM journey")
        self.other = Organization.objects.create(key="p1g-other", name="Synthetic other tenant")
        self.context = organization_context(self.org)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        for organization in (self.org, self.other):
            ModuleActivation.objects.bulk_create(
                [
                    ModuleActivation(
                        organization=organization, module_key=module, version="test", enabled=True
                    )
                    for module in ("identity", "access", "approvals", "pam")
                ]
            )
        self.admin, self.admin_browser = self._actor("administrator", "admin")
        self.operator, self.browser = self._actor("operator", "operator")
        self.reviewers = [self._actor(f"reviewer-{number}", "reviewer") for number in (1, 2)]
        self.identities = {}
        for actor in (self.operator, *(actor for actor, _ in self.reviewers)):
            self.identities[actor.pk] = self._bind(actor)
        self.person = self.identities[self.operator.pk]
        self.owner = Identity.objects.create(
            organization=self.org, name="Synthetic technical owner", kind="service"
        )
        self.account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.owner,
            username="synthetic-maintenance",
            system="Synthetic SSH target",
            kind="privileged",
        )
        self.resource = Resource.objects.create(
            organization=self.org, name="Synthetic P1G server", kind="server"
        )
        self.endpoint = self._endpoint()
        self.trust = TrustFixture(
            self,
            self.org,
            [self.endpoint],
            [(self.operator, self.person, ["requester"])]
            + [(actor, self.identities[actor.pk], ["reviewer"]) for actor, _ in self.reviewers],
            auto_enroll=False,
        )
        self.trust.update(
            lambda body: body["targets"][str(self.endpoint.pk)].update(min_reviewers=2)
        )
        for actor, browser in [(self.operator, self.browser), *self.reviewers]:
            self._enroll_authenticator(actor, browser)
        self.assertEqual(self._business_counts(), (0, 0, 0, 0))

    def _get(self, browser, path):
        response = browser.get(path, secure=True)
        self._no_target_secret(response)
        return response

    def _post(self, browser, path, fields, *, json_body=False):
        kwargs = {
            "secure": True,
            "HTTP_X_CSRFTOKEN": browser.cookies[settings.CSRF_COOKIE_NAME].value,
        }
        if json_body:
            kwargs["content_type"] = "application/json"
            fields = json.dumps(fields)
        response = browser.post(path, fields, **kwargs)
        self._no_target_secret(response)
        return response

    def _no_target_secret(self, response):
        # Keep a failure diagnostic from printing the synthetic credential itself.
        self.assertFalse(TARGET_PASSWORD.encode() in response.content, "Target secret in response")

    def _actor(self, name, role):
        actor = get_user_model().objects.create_user("p1g-" + name, password=PASSWORD)
        self.assertFalse(actor.is_superuser)
        for organization in (self.org, self.other):
            OrganizationMembership.objects.create(
                organization=organization, account=actor, role=role
            )
        browser = Client(enforce_csrf_checks=True, HTTP_HOST=HOST, HTTP_ORIGIN=ORIGIN)
        self.assertEqual(self._get(browser, reverse("login")).status_code, 200)
        response = self._post(
            browser,
            reverse("login"),
            {
                "username": actor.username,
                "password": PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(browser.session["_auth_user_id"], str(actor.pk))
        self._switch(browser, self.org)
        page = self._get(browser, reverse("account-security"))
        self.assertFalse(page.context["enabled"])
        code = pyotp.TOTP(page.context["secret"]).now()
        response = self._post(
            browser,
            reverse("account-security"),
            {
                "password": PASSWORD,
                "code": code,
                "freshness_minutes": 5,
            },
        )
        self.assertTemplateUsed(response, "security/resume.html")
        self.assertIn("mfa_verified_at", browser.session)
        return actor, browser

    def _switch(self, browser, organization):
        response = self._post(
            browser,
            reverse("organization-switch"),
            {
                "organization": str(organization.pk),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(browser.session["organization_id"], str(organization.pk))

    def _bind(self, actor):
        identity = Identity.objects.create(
            organization=self.org, name="Synthetic person " + actor.username, kind="human"
        )
        response = self._post(
            self.admin_browser,
            reverse("identity-login-bindings"),
            {
                "login_account": actor.pk,
                "identity": identity.pk,
                "verification_reference": "Synthetic explicit person reference",
            },
        )
        self.assertEqual(response.status_code, 302)
        binding = LoginIdentityBinding.objects.get(login_account=actor, revoked_at=None)
        self.assertEqual(binding.identity_id, identity.pk)
        return identity

    def _endpoint(self):
        host_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        response = self._post(
            self.admin_browser,
            reverse("pam-endpoint-create"),
            {
                "name": "Synthetic preconfigured SSH endpoint",
                "resource": self.resource.pk,
                "account": self.account.pk,
                "protocol": "ssh",
                "hostname": "ssh.example.test",
                "port": 22,
                "auth_method": "password",
                "password": TARGET_PASSWORD,
                "host_key": host_key,
            },
        )
        self.assertEqual(response.status_code, 302)
        endpoint = SessionEndpoint.objects.get(account=self.account)
        # Only the pre-authentication network probe is synthetic; no socket is opened.
        result = ProbeResult(
            "ssh", "ssh.example.test", 22, "192.0.2.17", "SHA256:synthetic", timezone.now()
        )
        with patch(
            "platform_modules.pam.sessions.probe_ssh", AsyncMock(return_value=result)
        ) as probe:
            response = self._post(
                self.admin_browser, reverse("pam-endpoint-action", args=[endpoint.pk, "test"]), {}
            )
        self.assertEqual(response.status_code, 302)
        # CharField strips the trailing newline from the submitted public key.
        self.assertEqual(endpoint.ssh_host_key, host_key.strip())
        probe.assert_awaited_once_with("ssh.example.test", 22, endpoint.ssh_host_key)
        response = self._post(
            self.admin_browser, reverse("pam-endpoint-action", args=[endpoint.pk, "enable"]), {}
        )
        self.assertEqual(response.status_code, 302)
        endpoint.refresh_from_db()
        self.assertTrue(endpoint.enabled)
        self.assertEqual(endpoint.verified_revision, endpoint.revision)
        return endpoint

    def _enroll_authenticator(self, actor, browser):
        path = reverse("pam-trust-enrollment")
        self.assertEqual(self._get(browser, path).status_code, 200)
        device = VirtualAuthenticator()
        start = self._post(browser, path, {"operation": "begin"}, json_body=True)
        self.assertEqual(start.status_code, 200)
        start = start.json()
        possession = self._post(
            browser,
            path,
            {
                "operation": "register",
                "challenge": start["challenge"],
                "credential": device.response(start, registration=True),
            },
            json_body=True,
        )
        self.assertEqual(possession.status_code, 200)
        possession = possession.json()
        finish = self._post(
            browser,
            path,
            {
                "operation": "finish",
                "enrollment": possession["enrollment"],
                "credential": device.response(possession),
            },
            json_body=True,
        )
        self.assertEqual(finish.status_code, 200)
        # Possession alone cannot authorize an action before independent publication.
        refused = self._post(
            browser,
            reverse("pam-trust-action"),
            {
                "operation": "begin",
                "action": "request" if actor == self.operator else "approve",
                "payload": {"synthetic": "unpublished-key-probe"},
            },
            json_body=True,
        )
        self.assertEqual(refused.status_code, 403)
        receipt = finish.json()
        person = self.trust.people[actor.pk]
        self.trust.update(lambda body: body["persons"][person]["authenticators"].append(receipt))
        self.trust.authenticators[actor.pk] = device

    def _business_counts(self):
        return tuple(
            model.unscoped.count()
            for model in (
                AccessIntent,
                ApprovalDecision,
                SessionLease,
                RelayConnection,
            )
        )

    def _fields(self):
        now = timezone.now()
        return {
            "identity": str(self.person.pk),
            "account": str(self.account.pk),
            "resource": str(self.resource.pk),
            "method": "SSH",
            "fulfillment": "pam",
            "reason": "Synthetic bounded privileged maintenance",
            "reference": "P1G-SYNTHETIC",
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "ends_at": (now + timedelta(minutes=15)).isoformat(),
        }

    def _entry(self):
        before = self._business_counts()
        profile = self._get(self.browser, reverse("identity360-detail", args=[self.person.pk]))
        self.assertEqual(profile.status_code, 200)
        path = reverse("record-create", args=["intent"]) + "?identity=" + str(self.person.pk)
        self.assertIn(path, _Page(profile).links)
        form = self._get(self.browser, path)
        self.assertEqual(form.status_code, 200)
        self.assertEqual(form.context["form"].initial, {"identity": self.person.pk})
        self.assertEqual(self._business_counts(), before)
        return path

    def _begin(self, browser, path, fields):
        before = self._business_counts()
        response = self._post(browser, path, fields)
        self.assertTemplateUsed(response, "pam/trust_action.html")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(self._business_counts(), before)
        return json.loads(_Page(response).scripts["pam-trust-ceremony"])

    def _finish(self, browser, ceremony):
        actor_id = int(browser.session["_auth_user_id"])
        return self._post(
            browser,
            reverse("pam-trust-action"),
            {
                "operation": "finish",
                "challenge": ceremony["challenge"],
                "credential": self.trust.authenticators[actor_id].response(ceremony),
            },
            json_body=True,
        )

    def _resume(self, browser, verified):
        path = verified["resume"]["path"]
        self.assertTrue(path.startswith("/") and not path.startswith("//"))
        fields = {}
        for key, value in verified["resume"]["fields"]:
            self.assertNotIn(key, ("csrfmiddlewaretoken", "_pam_trust_proof"))
            fields.setdefault(key, []).append(value)
        fields["_pam_trust_proof"] = verified["proof"]
        return self._post(browser, path, fields)

    def _signed_post(self, browser, path, fields):
        ceremony = self._begin(browser, path, fields)
        finished = self._finish(browser, ceremony)
        self.assertEqual(finished.status_code, 200)
        verified = finished.json()
        self.assertEqual(verified["resume"]["path"], path.split("?", 1)[0])
        self.assertEqual(
            verified["resume"]["fields"], [[key, str(value)] for key, value in fields.items()]
        )
        response = self._resume(browser, verified)
        proof = PAMTrustAuthorization.unscoped.get(pk=verified["authorization"])
        self.assertIsNotNone(proof.consumed_at)
        return response

    def _request(self):
        path = self._entry()
        response = self._signed_post(self.browser, path, self._fields())
        self.assertEqual(response.status_code, 302)
        intent = AccessIntent.objects.get(requested_by=self.operator)
        self.assertEqual(intent.status, "pending")
        self.assertEqual(intent.requester_binding.identity_id, self.person.pk)
        self.assertEqual(intent.account.identity_id, self.owner.pk)
        self.assertEqual(intent.pam_destination, target_scope(self.endpoint, self.account))
        self._verify_request(intent)
        return intent

    def _verify_request(self, intent):
        self.assertTrue(
            verify_authorization_evidence(
                intent.pam_trust["request"],
                actor=self.operator,
                organization=self.org,
                action="request",
                payload=trust.request_payload(intent, intent.pam_trust["policy"]),
            )
        )

    def _vote(self, reviewer, intent):
        actor, browser = reviewer
        response = self._signed_post(
            browser,
            reverse("intent-decide", args=[intent.pk]),
            {
                "decision": "approve",
                "comment": "Synthetic review of the exact target and scope",
            },
        )
        self.assertEqual(response.status_code, 302)
        decision = intent.decisions.get(reviewer=actor)
        self.assertEqual(decision.scope_hash, scope_hash(intent))
        self.assertEqual(decision.signature, decision_signature(decision))
        self.assertTrue(trust.verified_vote(intent, decision))
        intent.refresh_from_db()

    def _approved(self):
        intent = self._request()
        for reviewer in self.reviewers:
            self._vote(reviewer, intent)
        self.assertEqual(intent.status, "approved")
        self.assertTrue(approval_requirements(intent)["complete"])
        return intent

    def _contract(self, intent):
        path = reverse("access-contract-detail", args=[intent.pk])
        profile = self._get(self.browser, reverse("identity360-detail", args=[self.person.pk]))
        self.assertIn(path, _Page(profile).links)
        response = self._get(self.browser, path)
        self.assertEqual(response.status_code, 200)
        exported = self._get(self.browser, reverse("access-contract-export", args=[intent.pk]))
        self.assertEqual(exported.status_code, 200)
        contract = exported.json()
        self.assertEqual(contract["intention"]["id"], str(intent.pk))
        self.assertEqual(contract["intention"]["identity_id"], str(self.person.pk))
        self.assertEqual(contract["observations"]["items"], [])
        self.assertEqual(len(contract["approval_decisions"]["items"]), 2)
        return contract

    def test_identity360_signed_request_votes_ticket_stop_and_audit(self):
        entry = self._entry()
        rejected = self.browser.post(entry, self._fields(), secure=True)
        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(self._business_counts(), (0, 0, 0, 0))
        # A shared account is chosen on POST, never smuggled into an ownership GET hint.
        rejected = self._get(self.browser, entry + "&account=" + str(self.account.pk))
        self.assertEqual(rejected.status_code, 404)
        intent = self._request()
        self._vote(self.reviewers[0], intent)
        self.assertEqual(intent.status, "pending")
        self.assertEqual(approval_requirements(intent)["approved"], 1)
        self.assertFalse(SessionLease.objects.exists())
        self._vote(self.reviewers[1], intent)
        self.assertEqual(intent.status, "approved")
        page = self._get(self.browser, reverse("pam-home"))
        launch = reverse("pam-launch", args=[intent.pk])
        self.assertIn(launch, _Page(page).forms)
        response = self._signed_post(self.browser, launch, {})
        self.assertTemplateUsed(response, "pam/session.html")
        relay = RelayConnection.objects.get(lease__intent=intent)
        self.assertEqual(relay.status, "pending")
        self.assertIsNone(relay.connected_at)
        self.assertEqual(relay.recording_bytes, 0)
        self.assertEqual(relay.opened_by_id, self.operator.pk)
        self.assertEqual(relay.endpoint_id, self.endpoint.pk)
        self.assertEqual(relay.browser_session_hash, browser_hash(self.browser.session.session_key))
        self.assertEqual(relay.authority_seal, authority_seal(relay))
        self.assertEqual(relay.authority_snapshot["mandate_scope_hash"], scope_hash(intent))
        self.assertTrue(trust.verify_launch(intent, relay.authority_snapshot["pam_trust_launch"]))
        player = response.context["player"]
        self.assertEqual(relay.ticket_hash, hashlib.sha256(player["ticket"].encode()).hexdigest())
        self.assertEqual(player["websocket_path"], f"/ws/pam/{relay.pk}/")
        contract = self._contract(intent)
        sessions = contract["pam_sessions"]["items"]
        self.assertTrue(any(row.get("connection_id") == str(relay.pk) for row in sessions))
        self.assertTrue(any(row["assurance"] == "local_lease_not_remote_login" for row in sessions))
        detail = self._get(self.browser, reverse("pam-connection", args=[relay.pk]))
        self.assertEqual(detail.status_code, 200)
        stop = reverse("pam-stop", args=[relay.pk])
        self.assertIn(stop, _Page(detail).forms)
        stopped = self._post(self.browser, stop, {})
        self.assertEqual(stopped.status_code, 302)
        relay.refresh_from_db()
        self.assertEqual((relay.status, relay.end_reason), ("ended", "stop_requested"))
        self.assertIsNotNone(relay.stop_requested_at)
        self.assertEqual(relay.ticket_hash, "")
        after = self._contract(intent)
        self.assertTrue(
            any(
                row.get("connection_id") == str(relay.pk) and row["state"] == "ended"
                for row in after["pam_sessions"]["items"]
            )
        )
        self.account.refresh_from_db()
        self.assertTrue(self.account.active)
        self.assertEqual(self.account.identity_id, self.owner.pk)
        actions = list(
            AuditEvent.objects.filter(organization=self.org).values_list("action", flat=True)
        )
        for action, count in {
            "access.intent.created.v1": 1,
            "approvals.intent.decided.v1": 2,
            "pam.lease.opened.v1": 1,
            "pam.relay.authorized.v1": 1,
            "pam.relay.stop_requested.v1": 1,
            "pam.relay.ended.v1": 1,
        }.items():
            self.assertEqual(actions.count(action), count)
        events = AuditEvent.objects.filter(organization=self.org)
        for action, object_id in (
            ("access.intent.created.v1", intent.pk),
            ("pam.lease.opened.v1", relay.lease_id),
            ("pam.relay.authorized.v1", relay.pk),
            ("pam.relay.stop_requested.v1", relay.pk),
            ("pam.relay.ended.v1", relay.pk),
        ):
            self.assertEqual(
                events.get(action=action, object_id=str(object_id)).actor_id, self.operator.pk
            )
        for decision in intent.decisions.all():
            event = events.get(action="approvals.intent.decided.v1", object_id=str(decision.pk))
            self.assertEqual(event.actor_id, decision.reviewer_id)
            self.assertEqual(event.metadata["intent_id"], str(intent.pk))
        self.assertEqual(self._get(self.browser, reverse("audit-log")).status_code, 200)
        self.assertTrue(verify_chain(self.org))

    def test_withdraw_from_the_same_contract_invalidates_ticket_and_preserves_proofs(self):
        intent = self._approved()
        launch = reverse("pam-launch", args=[intent.pk])
        self.assertTemplateUsed(self._signed_post(self.browser, launch, {}), "pam/session.html")
        relay = RelayConnection.objects.get(lease__intent=intent)
        self.assertTrue(relay.ticket_hash)
        self.assertEqual(relay.status, "pending")
        observation = ingest_collector_observation(self, intent, "synthetic-withdrawal")
        other_intent = AccessIntent.objects.create(
            organization=self.org, identity=self.person, account=self.account,
            resource=self.resource, requested_by=self.operator, method="SSH", fulfillment="pam",
            status="approved", reason="Unrelated synthetic mandate",
            starts_at=intent.starts_at, ends_at=intent.ends_at,
        )
        other_lease = SessionLease.objects.create(
            organization=self.org, intent=other_intent, opened_by=self.operator,
            expires_at=other_intent.ends_at,
        )
        path = reverse("pam-mandate-revoke", args=[intent.pk])
        contract = reverse("access-contract-detail", args=[intent.pk])
        self.assertIn(path, _Page(self._get(self.browser, contract)).forms)
        self.assertEqual(self._get(self.browser, path).status_code, 405)
        self.assertEqual(self.browser.post(path, secure=True).status_code, 403)

        # The requester's normal session can give up its own authority.
        session = self.browser.session
        session.pop("mfa_verified_at", None)
        session.save()
        membership = OrganizationMembership.objects.get(
            organization=self.org, account=self.operator
        )
        membership.role = "auditor"
        membership.save(update_fields=["role"])
        try:
            self.assertIn(path, _Page(self._get(self.browser, contract)).forms)
            self.assertRedirects(
                self._post(self.browser, path, {}), contract, fetch_redirect_response=False
            )
        finally:
            membership.role = "operator"
            membership.save(update_fields=["role"])
        intent.refresh_from_db()
        relay.refresh_from_db()
        self.assertEqual(intent.status, "revoked")
        self.assertIsNotNone(intent.revoked_at)
        self.assertEqual((relay.lease.status, relay.lease.ended_at), ("revoked", intent.revoked_at))
        self.assertEqual((relay.status, relay.end_reason), ("ended", "stop_requested"))
        self.assertEqual(relay.ticket_hash, "")
        self.assertEqual(relay.stop_requested_at, intent.revoked_at)

        other_intent.refresh_from_db()
        other_lease.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual((other_intent.status, other_lease.status), ("approved", "active"))
        self.assertTrue(self.account.active)
        self._verify_request(intent)
        self.assertTrue(all(trust.verified_vote(intent, row) for row in intent.decisions.all()))
        self.assertTrue(trust.verify_launch(intent, relay.authority_snapshot["pam_trust_launch"]))
        with self.assertRaises(ValidationError):
            open_lease(intent.pk, actor=self.operator, organization=self.org)
        self.assertNotIn(path, _Page(self._get(self.browser, contract)).forms)
        self.assertEqual(self._post(self.browser, path, {}).status_code, 302)
        revoked_at = intent.revoked_at
        intent.refresh_from_db()
        self.assertEqual(intent.revoked_at, revoked_at)
        history = AuditEvent.objects.get(action="pam.mandate.revoked.v1", object_id=str(intent.pk))
        self.assertEqual(history.actor_id, self.operator.pk)
        self.assertEqual(history.metadata, {"leases_revoked": 1, "relay_stop_requests": 1})
        self.assertTrue(verify_chain(self.org))
        exported = self._get(
            self.browser, reverse("access-contract-export", args=[intent.pk])
        ).json()
        self.assertEqual(exported["intention"]["status"], "revoked")
        self.assertEqual(len(exported["approval_decisions"]["items"]), 2)
        self.assertEqual(len(exported["observations"]["items"]), 1)
        self.assertEqual(exported["observations"]["items"][0]["id"], str(observation))
        self.assertTrue(exported["observations"]["items"][0]["provenance_verified"])

    def test_administrative_withdrawal_requires_recent_mfa_in_the_same_organization(self):
        intent = self._approved()
        path = reverse("pam-mandate-revoke", args=[intent.pk])
        other_operator, other_browser = self._actor("other-operator", "operator")
        self.assertEqual(self._post(other_browser, path, {}).status_code, 403)
        self.assertEqual(self._post(self.reviewers[0][1], path, {}).status_code, 403)
        with self.assertRaises(PermissionDenied):
            revoke_mandate(intent.pk, actor=other_operator, organization=self.org)
        with self.assertRaises(PermissionDenied):
            revoke_mandate(intent.pk, actor=self.admin, organization=self.org)

        self._switch(self.browser, self.other)
        self.assertEqual(self._post(self.browser, path, {}).status_code, 404)
        self._switch(self.browser, self.org)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "approved")
        self.assertFalse(AuditEvent.objects.filter(action="pam.mandate.revoked.v1").exists())

        session = self.admin_browser.session
        previous_mfa = session.pop("mfa_verified_at")
        session.save()
        challenge = self._post(self.admin_browser, path, {})
        self.assertRedirects(challenge, reverse("account-security"), fetch_redirect_response=False)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "approved")
        session = self.admin_browser.session
        session["mfa_verified_at"] = previous_mfa
        session.save()
        response = self._post(self.admin_browser, path, {})
        self.assertEqual(response.status_code, 302)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "revoked")
        event = AuditEvent.objects.get(action="pam.mandate.revoked.v1", object_id=str(intent.pk))
        self.assertEqual(event.actor_id, self.admin.pk)

    def test_ceremony_resume_and_foreign_object_reads_stay_in_selected_tenant(self):
        path = self._entry()
        ceremony = self._begin(self.browser, path, self._fields())
        self._switch(self.browser, self.other)
        self.assertEqual(self._finish(self.browser, ceremony).status_code, 403)
        self._switch(self.browser, self.org)
        finished = self._finish(self.browser, ceremony)
        self.assertEqual(finished.status_code, 200)
        self._switch(self.browser, self.other)
        refused = self._resume(self.browser, finished.json())
        self.assertEqual(refused.status_code, 200)  # Foreign model choices are invalid.
        self.assertFalse(refused.context["form"].is_valid())
        self.assertNotContains(refused, self.person.name)
        self.assertNotContains(refused, self.resource.name)
        self.assertEqual(self._business_counts(), (0, 0, 0, 0))
        self._switch(self.browser, self.org)
        self.assertEqual(self._resume(self.browser, finished.json()).status_code, 302)
        intent = AccessIntent.objects.get(requested_by=self.operator)
        self._switch(self.browser, self.other)
        for route, args in (
            ("identity360-detail", [self.person.pk]),
            ("record-detail", ["intent", intent.pk]),
            ("access-contract-detail", [intent.pk]),
        ):
            self.assertEqual(self._get(self.browser, reverse(route, args=args)).status_code, 404)
        _, reviewer_browser = self.reviewers[0]
        self._switch(reviewer_browser, self.other)
        response = self._post(
            reviewer_browser,
            reverse("intent-decide", args=[intent.pk]),
            {
                "decision": "approve",
                "comment": "Synthetic foreign tenant attempt",
            },
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._business_counts(), (1, 0, 0, 0))

    def test_tenant_controlled_reviewer_cannot_complete_independent_quorum(self):
        controlled, browser = self._actor("tenant-controlled-reviewer", "reviewer")
        self._bind(controlled)
        intent = self._request()
        self._vote(self.reviewers[0], intent)
        response = self._post(
            browser,
            reverse("intent-decide", args=[intent.pk]),
            {
                "decision": "approve",
                "comment": "Synthetic tenant-controlled extra vote",
            },
        )
        self.assertEqual(response.status_code, 403)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        self.assertEqual(intent.decisions.count(), 1)
        response = self._post(self.browser, reverse("pam-launch", args=[intent.pk]), {})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._business_counts(), (1, 1, 0, 0))
        self._vote(self.reviewers[1], intent)
        self.assertEqual(intent.status, "approved")

    def test_credential_revoked_after_challenge_cannot_finish_or_create_mandate(self):
        path = self._entry()
        fields = self._fields()
        ceremony = self._begin(self.browser, path, fields)
        person = self.trust.people[self.operator.pk]
        self.trust.update(
            lambda body: body["persons"][person]["authenticators"][0].update(active=False)
        )
        response = self._finish(self.browser, ceremony)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("proof", response.json())
        self.assertEqual(self._post(self.browser, path, fields).status_code, 403)
        self.assertEqual(self._business_counts(), (0, 0, 0, 0))

    def test_binding_revoked_after_approval_blocks_launch_and_preserves_signed_history(self):
        intent = self._approved()
        original = intent.pam_trust.copy()
        decisions = list(intent.decisions.order_by("pk").values_list("pk", "signature"))
        response = self._post(
            self.admin_browser,
            reverse("identity-binding-revoke", args=[intent.requester_binding_id]),
            {"reason": "Synthetic withdrawal before launch"},
        )
        self.assertEqual(response.status_code, 302)
        intent.refresh_from_db()
        self.assertEqual(intent.status, "revoked")
        response = self._post(self.browser, reverse("pam-launch", args=[intent.pk]), {})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._business_counts(), (1, 2, 0, 0))
        self.assertEqual(intent.pam_trust, original)
        self.assertEqual(
            list(intent.decisions.order_by("pk").values_list("pk", "signature")), decisions
        )
        self._verify_request(intent)
        for decision in intent.decisions.all():
            self.assertTrue(trust.verified_vote(intent, decision))
        self.assertEqual(self._contract(intent)["intention"]["status"], "revoked")
        self.account.refresh_from_db()
        self.assertTrue(self.account.active)
        self.assertEqual(self.account.identity_id, self.owner.pk)
        self.assertTrue(verify_chain(self.org))
