"""P0-4 regressions derived from the original synthetic attack reproduction.

No real collector, remote destination, key or production database is involved.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest import skipUnless

import pyotp
from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, connections, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.models import AuditEvent, ModuleActivation, Organization, OrganizationMembership
from platform_core.tenancy import organization_context
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessEvent
from platform_modules.connectors.models import EventSource
from platform_modules.connectors.services import create_source
from platform_modules.identity.models import Credential, ExternalAccount, Identity, Resource

PASSWORD = "P0-4-synthetic-local-disposable-password!72"


class ProvenanceSecurityOracles:
    """Invariants that failed before the approved P0-4 correction."""

    def assert_independent_authorities(self, manual_event, collector_response):
        """Desired: manual entry cannot reserve an authenticated collector's event ID."""
        self.assertEqual(collector_response.status_code, 201)
        self.assertNotEqual(collector_response.json()["event_id"], str(manual_event.pk))

    def assert_divergent_replay_conflict(self, response):
        """Desired: same authority/external ID with different facts produces a conflict."""
        self.assertEqual(response.status_code, 409)


class EventProvenanceFixture(ProvenanceSecurityOracles):
    def setUp(self):
        super().setUp()
        users = get_user_model()
        self.admin = users.objects.create_user("p04-synthetic-admin", password=PASSWORD)
        self.operator = users.objects.create_user("p04-synthetic-operator", password=PASSWORD)
        self.org = Organization.objects.create(key="p04-synthetic", name="P04 Synthetic")
        self.other = Organization.objects.create(key="p04-other", name="Other Synthetic")
        for actor, role in ((self.admin, "admin"), (self.operator, "operator")):
            OrganizationMembership.objects.create(organization=self.org, account=actor, role=role)
        OrganizationMembership.objects.create(
            organization=self.other, account=self.admin, role="admin"
        )
        for organization in (self.org, self.other):
            for key in ("identity", "access", "connectors"):
                ModuleActivation.objects.create(
                    organization=organization, module_key=key, version="synthetic", enabled=True
                )
        self.context = organization_context(self.org)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.identity = Identity.objects.create(
            organization=self.org, name="Synthetic actor", kind="human"
        )
        self.resource = Resource.objects.create(
            organization=self.org, name="Synthetic privileged server", kind="server"
        )
        self.account = ExternalAccount.objects.create(
            organization=self.org, identity=self.identity, username="synthetic-root",
            system="synthetic-server", kind="privileged",
        )
        self.source, self.token = create_source(
            "Synthetic authenticated collector", actor=self.admin, organization=self.org
        )
        with organization_context(self.other):
            self.foreign_source, self.foreign_token = create_source(
                "Other synthetic collector", actor=self.admin, organization=self.other
            )
        self.browser = Client()
        response = self.browser.post(
            reverse("login"), {"username": self.operator.username, "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.browser.session["_auth_user_id"], str(self.operator.pk))
        enrollment = self.browser.get(reverse("account-security"))
        self.assertFalse(enrollment.context["enabled"])
        enrolled = self.browser.post(
            reverse("account-security"),
            {"password": PASSWORD, "code": pyotp.TOTP(enrollment.context["secret"]).now(),
             "freshness_minutes": 5},
        )
        self.assertTemplateUsed(enrolled, "security/resume.html")
        self.assertIn("mfa_verified_at", self.browser.session)
        self.assertFalse(self.operator.is_superuser)

    def payload(self, external_id="synthetic-event-1", **changes):
        return {
            "external_id": external_id,
            "occurred_at": (timezone.now() - timedelta(minutes=1)).isoformat(),
            "identity": str(self.identity.pk), "account": str(self.account.pk),
            "resource": str(self.resource.pk), "method": "SSH", "action": "session.start",
            "location": "synthetic-origin", "privilege": "root", "result": "failure",
            "evidence": "synthetic-authenticated-log", "domain": "pam",
            "credential_observation": "identifier_only", **changes,
        }

    def api(self, payload, *, token=None, browser=None):
        return (browser or Client()).post(
            reverse("api-events"), json.dumps(payload), content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + (self.token if token is None else token),
        )

    def manual(self, payload, *, source=None, browser=None):
        response = (browser or self.browser).post(
            reverse("record-create", args=["event"]),
            {**payload, "source": str(source or self.source.pk)},
        )
        self.assertEqual(response.status_code, 302, response.content)
        event_id = response["Location"].rstrip("/").rsplit("/", 1)[-1]
        return AccessEvent.unscoped.get(pk=event_id)

    def receipt(self, event):
        return AuditEvent.objects.get(
            action="access.event.received.v1", object_id=str(event.pk)
        )


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class EventProvenanceReproductionTests(EventProvenanceFixture, TestCase):
    def test_manual_http_entry_cannot_preempt_authenticated_observation(self):
        """An operator with a source UUID cannot reserve the collector's identifier."""
        genuine = self.payload()
        forged = self.manual({**genuine, "result": "success", "evidence": "synthetic-forgery"})
        received = self.api(genuine)
        self.assert_independent_authorities(forged, received)
        self.assertEqual(AccessEvent.objects.count(), 2)
        authentic = AccessEvent.objects.get(pk=received.json()["event_id"])
        self.assertEqual(authentic.provenance_channel, "collector")
        self.assertEqual(authentic.collector_source_id, self.source.pk)
        self.assertEqual(authentic.result, "failure")
        self.assertEqual(self.receipt(authentic).actor_id, None)
        forged.refresh_from_db()
        self.assertEqual(forged.provenance_channel, "manual")
        self.assertEqual(forged.manual_actor_id, self.operator.pk)
        self.assertEqual(forged.result, "success")
        self.assertEqual(forged.evidence, "synthetic-forgery")
        self.assertEqual(self.receipt(forged).actor_id, self.operator.pk)
        self.assertTrue(verify_evaluation(forged.evaluations.get()))
        self.assertTrue(verify_chain(self.org))
        exported = self.browser.get(reverse("event-export", args=[forged.pk]))
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.json()["source"], str(self.source.pk))
        self.assertTrue(exported.json()["evaluation"]["proof_verified"])
        self.assertEqual(exported.json()["provenance"]["channel"], "manual")

    def test_late_authentic_delivery_remains_independent_of_manual_event(self):
        """Desired: delivery delay must not allow an operator to consume the collector namespace."""
        genuine = self.payload(occurred_at=(timezone.now() - timedelta(days=45)).isoformat())
        forged = self.manual({**genuine, "action": "synthetic.sanitized", "result": "success"})
        first_id = None
        for attempt in range(3):
            response = self.api(genuine)
            self.assertEqual(response.status_code, 201 if attempt == 0 else 200)
            self.assertNotEqual(response.json()["event_id"], str(forged.pk))
            first_id = first_id or response.json()["event_id"]
            self.assertEqual(response.json()["event_id"], first_id)
        self.assertEqual(forged.evaluations.count(), 1)
        self.assertEqual(self.receipt(forged).actor_id, self.operator.pk)
        self.assertEqual(AccessEvent.objects.count(), 2)

    def test_later_manual_entry_cannot_adopt_authenticated_event(self):
        genuine = self.payload()
        created = self.api(genuine)
        self.assertEqual(created.status_code, 201)
        current = AccessEvent.objects.get(pk=created.json()["event_id"])
        manual = self.manual({**genuine, "result": "success", "evidence": "synthetic-later-lie"})
        self.assertNotEqual(manual.pk, current.pk)
        manual.refresh_from_db()
        self.assertEqual(manual.result, "success")
        self.assertEqual(manual.evidence, "synthetic-later-lie")
        self.assertEqual(self.receipt(manual).actor_id, self.operator.pk)
        self.assertEqual(AccessEvent.objects.count(), 2)

    def test_exact_authenticated_replay_is_idempotent(self):
        """Existing protection to preserve: exact delivery repeats create no extra event/audit."""
        payload = self.payload()
        first = self.api(payload)
        self.assertEqual(first.status_code, 201)
        audit_count = AuditEvent.objects.count()
        repeated = self.api(payload)
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json(), {"event_id": first.json()["event_id"], "created": False})
        self.assertEqual(AuditEvent.objects.count(), audit_count)
        self.assertEqual(AccessEvent.objects.count(), 1)

    def test_existing_two_authenticated_collectors_can_use_the_same_external_id(self):
        second, token = create_source(
            "Second synthetic authenticated collector", actor=self.admin, organization=self.org
        )
        payload = self.payload()
        first_response, second_response = self.api(payload), self.api(payload, token=token)
        self.assertEqual(first_response.status_code, 201)
        self.assertEqual(second_response.status_code, 201)
        self.assertNotEqual(first_response.json()["event_id"], second_response.json()["event_id"])
        self.assertEqual(
            set(AccessEvent.objects.values_list("source", flat=True)),
            {str(self.source.pk), str(second.pk)},
        )

    def test_divergent_authenticated_replay_is_an_audited_conflict(self):
        payload = self.payload()
        first = self.api(payload)
        self.assertEqual(first.status_code, 201)
        audit_count = AuditEvent.objects.count()
        repeated = self.api({**payload, "result": "success", "action": "session.other"})
        self.assert_divergent_replay_conflict(repeated)
        self.assertEqual(repeated.json()["event_id"], first.json()["event_id"])
        self.assertGreater(AuditEvent.objects.count(), audit_count)
        self.assertTrue(AuditEvent.objects.filter(action="access.event.conflict.v1").exists())
        self.assertEqual(AccessEvent.objects.get().result, "failure")

    def test_existing_api_authentication_source_override_and_foreign_reference_guards(self):
        payload = self.payload()
        self.assertEqual(self.api(payload, token="synthetic-wrong-token").status_code, 401)
        self.assertEqual(
            self.api({**payload, "source": str(self.foreign_source.pk)}).status_code, 400
        )
        foreign_identity = Identity.objects.create(
            organization=self.other, name="Other actor", kind="human"
        )
        self.assertEqual(
            self.api({**payload, "identity": str(foreign_identity.pk)}).status_code, 400
        )
        self.assertFalse(AccessEvent.objects.exists())
        EventSource.objects.filter(pk=self.source.pk).update(active=False)
        self.assertEqual(self.api(payload).status_code, 401)

    def test_existing_organization_scope_prevents_poisoning_a_foreign_collector(self):
        payload = self.payload()
        forged = self.manual(payload, source=self.foreign_source.pk)
        foreign_payload = {
            key: value for key, value in payload.items()
            if key not in {"identity", "account", "resource"}
        }
        response = self.api(foreign_payload, token=self.foreign_token)
        self.assertEqual(response.status_code, 201)
        other = AccessEvent.unscoped.get(pk=response.json()["event_id"])
        self.assertNotEqual(other.pk, forged.pk)
        self.assertEqual(other.organization_id, self.other.pk)
        self.assertEqual(forged.organization_id, self.org.pk)
        self.assertEqual(other.source, forged.source)
        self.assertEqual(other.external_id, forged.external_id)

    def test_existing_managed_source_namespace_is_reserved(self):
        for source in ("managed:teamviewer", "  MANAGED:teamviewer"):
            response = self.browser.post(
                reverse("record-create", args=["event"]), {**self.payload(), "source": source}
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(AccessEvent.objects.exists())

    def test_manual_impersonation_does_not_obtain_certificate_possession_challenge(self):
        """Existing stronger path uses the actor-less ingestion audit, not the UUID alone."""
        credential = Credential.objects.create(
            organization=self.org, identity=self.identity, resource=self.resource,
            name="Synthetic certificate reference", kind="certificate", fingerprint="a" * 64,
        )
        payload = self.payload(domain="certificate", credential=str(credential.pk), method="TLS")
        forged = self.manual(payload)
        authentic = self.api(payload)
        self.assertEqual(authentic.status_code, 201)
        self.assertNotEqual(authentic.json()["event_id"], str(forged.pk))
        denied = Client().post(
            reverse("certificate-challenge", args=[forged.pk]), "{}", secure=True,
            content_type="application/json", HTTP_AUTHORIZATION="Bearer " + self.token,
        )
        self.assertEqual(denied.status_code, 404)
        accepted = Client().post(
            reverse("certificate-challenge", args=[authentic.json()["event_id"]]), "{}",
            secure=True, content_type="application/json", HTTP_AUTHORIZATION="Bearer " + self.token,
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertIn("challenge", accepted.json())


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row locks require PostgreSQL")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class EventProvenanceConcurrencyTests(EventProvenanceFixture, TransactionTestCase):
    def test_manual_transaction_cannot_discard_waiting_authenticated_delivery(self):
        """Two connections still serialize, but their authorities remain separate."""
        genuine = self.payload()
        ready, release, api_started = Event(), Event(), Event()
        collector_pid = []
        cookies = self.browser.cookies.copy()

        def manual_worker():
            close_old_connections()
            browser = Client()
            browser.cookies = cookies
            try:
                with transaction.atomic():
                    Organization.objects.select_for_update().get(pk=self.org.pk)
                    forged = self.manual({**genuine, "result": "success"}, browser=browser)
                    ready.set()
                    if not release.wait(10):
                        raise AssertionError("Synthetic concurrency release timed out")
                return str(forged.pk)
            finally:
                connections.close_all()

        def authenticated_worker():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    collector_pid.append(cursor.fetchone()[0])
                api_started.set()
                response = self.api(genuine)
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            manual = pool.submit(manual_worker)
            try:
                self.assertTrue(ready.wait(10))
                authentic = pool.submit(authenticated_worker)
                self.assertTrue(api_started.wait(5))
                observed_lock = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s",
                            [collector_pid[0]],
                        )
                        row = cursor.fetchone()
                    if row and row[0] == "Lock":
                        observed_lock = True
                        break
                    Event().wait(0.02)
                self.assertTrue(observed_lock, "Collector must wait on the held organization lock")
            finally:
                release.set()
            event_id = manual.result(timeout=10)
            status, result = authentic.result(timeout=10)
        self.assertEqual(status, 201)
        self.assertNotEqual(result["event_id"], event_id)
        self.assertEqual(result["created"], True)
        self.assertEqual(AccessEvent.objects.get(pk=event_id).result, "success")
        self.assertEqual(AccessEvent.objects.get(pk=result["event_id"]).result, "failure")
        self.assertEqual(AccessEvent.objects.count(), 2)

    def test_concurrent_divergent_authenticated_events_report_conflict(self):
        start = Barrier(3)
        payload = self.payload()

        def deliver(result):
            close_old_connections()
            try:
                start.wait(timeout=5)
                response = self.api({**payload, "result": result})
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.submit(deliver, "success"), pool.submit(deliver, "failure")
            start.wait(timeout=5)
            responses = [first.result(timeout=10), second.result(timeout=10)]
        self.assertEqual(sorted(status for status, _ in responses), [201, 409])
        self.assertEqual(len({response["event_id"] for _, response in responses}), 1)
        self.assertEqual(AccessEvent.objects.count(), 1)
