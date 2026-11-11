"""P0-4 API and service boundary tests using only synthetic local principals."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.models import AuditEvent, Organization
from platform_modules.access.models import AccessEvent, AccessEventConflict, AccessEventQuota
from platform_modules.access.provenance import verify_provenance_receipt
from platform_modules.access.services import ingest_event
from platform_modules.connectors.models import EventSource
from platform_modules.connectors.services import source_from_token

from .test_event_provenance_reproduction import EventProvenanceFixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class EventProvenanceAppSecTests(EventProvenanceFixture, TestCase):
    def test_service_rejects_ambiguous_or_caller_supplied_authority(self):
        with self.assertRaises(ValidationError):
            ingest_event({}, organization=self.org, actor=self.operator, source=self.source)
        with self.assertRaises(ValidationError):
            ingest_event({}, organization=self.org)
        with self.assertRaises(ValidationError):
            ingest_event(
                {"provenance_channel": "collector"},
                organization=self.org,
                actor=self.operator,
            )
        with self.assertRaisesMessage(ValidationError, "authentifiée par jeton"):
            self.source._authenticated_token_hash = self.source.token_hash
            ingest_event({}, organization=self.org, source=self.source)
        self.assertFalse(AccessEvent.objects.exists())

    def test_api_rejects_duplicate_json_keys_and_nonfinite_numbers(self):
        payload = self.payload()
        raw = json.dumps(payload)[:-1] + ',"external_id":"synthetic-duplicate"}'
        invalid = [raw, json.dumps({**payload, "evidence": float("nan")})]
        for body in invalid:
            response = Client().post(
                reverse("api-events"), body, content_type="application/json",
                HTTP_AUTHORIZATION="Bearer " + self.token,
            )
            self.assertEqual(response.status_code, 400)
        self.assertFalse(AccessEvent.objects.exists())

    def test_source_rotation_preserves_identity_but_revokes_old_credential(self):
        payload = self.payload()
        first = self.api(payload)
        self.assertEqual(first.status_code, 201)
        stale = source_from_token(self.token)
        replacement = "synthetic-replacement-token-for-p04"
        EventSource.unscoped.filter(pk=self.source.pk).update(
            token_hash=hashlib.sha256(replacement.encode()).hexdigest()
        )
        with self.assertRaises(ValidationError):
            ingest_event({}, organization=self.org, source=stale, source_token=self.token)
        self.assertEqual(self.api(payload).status_code, 401)
        repeated = self.api(payload, token=replacement)
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json()["event_id"], first.json()["event_id"])
        self.assertEqual(AccessEvent.objects.count(), 1)

    def test_source_revocation_is_rechecked_after_preliminary_authentication(self):
        stale = source_from_token(self.token)
        EventSource.unscoped.filter(pk=self.source.pk).update(active=False)
        with self.assertRaises(ValidationError):
            ingest_event({}, organization=self.org, source=stale, source_token=self.token)
        self.assertEqual(self.api(self.payload()).status_code, 401)
        self.assertFalse(AccessEvent.objects.exists())

    def test_exact_replay_and_divergent_replay_have_distinct_responses(self):
        payload = self.payload()
        first = self.api(payload)
        self.assertEqual(first.status_code, 201)
        same = self.api(payload)
        self.assertEqual(same.status_code, 200)
        self.assertEqual(same.json()["event_id"], first.json()["event_id"])
        divergent = self.api({**payload, "result": "success"})
        self.assertEqual(divergent.status_code, 409)
        self.assertEqual(divergent.json()["event_id"], first.json()["event_id"])
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(AccessEvent.objects.get().result, "failure")
        conflict = AccessEventConflict.objects.get()
        self.assertEqual(str(conflict.event_id), first.json()["event_id"])
        self.assertEqual(conflict.audit.action, "access.event.conflict.v1")
        self.assertEqual(
            AuditEvent.objects.filter(action="access.event.conflict.v1").count(), 1
        )

    def test_sql_tampered_existing_facts_are_never_acknowledged_as_exact_replay(self):
        payload = self.payload()
        first = self.api(payload)
        self.assertEqual(first.status_code, 201)
        event = AccessEvent.objects.get(pk=first.json()["event_id"])
        self.assertTrue(verify_provenance_receipt(event.provenance_receipt))
        if connection.vendor == "postgresql":
            # The pre-existing append-only proof trigger already rejects every
            # UPDATE of an event in PostgreSQL. SQLite still exercises the V8
            # verifier's fail-closed response to externally altered facts.
            with self.assertRaises(DatabaseError), transaction.atomic():
                AccessEvent.objects.filter(pk=event.pk).update(action="synthetic.sql.tamper")
            self.assertTrue(verify_provenance_receipt(event.provenance_receipt))
            self.assertEqual(self.api(payload).status_code, 200)
            return
        AccessEvent.objects.filter(pk=event.pk).update(action="synthetic.sql.tamper")
        event.refresh_from_db()
        self.assertFalse(verify_provenance_receipt(event.provenance_receipt))
        for _ in range(2):
            replay = self.api(payload)
            self.assertEqual(replay.status_code, 409)
            self.assertEqual(replay.json()["error"], "event_integrity_failed")
        self.assertEqual(
            AuditEvent.objects.filter(
                action="access.event.integrity_failed.v1", object_id=str(event.pk)
            ).count(),
            1,
        )
        self.assertFalse(AccessEventConflict.objects.exists())

    def test_manual_same_actor_and_id_divergence_is_visible_conflict(self):
        payload = self.payload()
        original = self.manual(payload, source="synthetic-manual-not-a-collector")
        response = self.browser.post(
            reverse("record-create", args=["event"]),
            {**payload, "source": "synthetic-manual-not-a-collector", "result": "success"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(AccessEvent.objects.get().pk, original.pk)
        self.assertEqual(AccessEventConflict.objects.get().event_id, original.pk)

    def test_conflict_evidence_is_bounded_under_many_distinct_payloads(self):
        payload = self.payload()
        self.assertEqual(self.api(payload).status_code, 201)
        for number in range(20):
            response = self.api({**payload, "evidence": f"synthetic-divergence-{number}"})
            self.assertEqual(response.status_code, 409)
        self.assertEqual(AccessEventConflict.objects.count(), 17)
        self.assertEqual(
            AccessEventConflict.objects.get(attempted_digest="").count, 4
        )
        self.assertEqual(
            AuditEvent.objects.filter(action="access.event.conflict.v1").count(), 17
        )
        self.assertEqual(AccessEvent.objects.count(), 1)

    @override_settings(PAMOLIVE_EVENT_COLLECTOR_DAILY_LIMIT=1)
    def test_collector_storage_quota_is_durable_and_exact_replay_remains_idempotent(self):
        first_payload = self.payload()
        first = self.api(first_payload)
        self.assertEqual(first.status_code, 201)
        refused = self.api(self.payload(external_id="synthetic-event-2"))
        self.assertEqual(refused.status_code, 429)
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(self.api(first_payload).status_code, 200)
        quota = AccessEventQuota.objects.get(channel="collector")
        self.assertEqual((quota.accepted_count, quota.denied_count), (1, 1))
        self.assertIsNotNone(quota.first_denial_audit_id)

    @override_settings(PAMOLIVE_EVENT_COLLECTOR_DAILY_ATTEMPT_LIMIT=1)
    def test_attempt_quota_bounds_replay_pressure_and_audits_first_refusal(self):
        payload = self.payload()
        self.assertEqual(self.api(payload).status_code, 201)
        self.assertEqual(self.api(payload).status_code, 429)
        quota = AccessEventQuota.objects.get(channel="collector")
        self.assertEqual((quota.accepted_count, quota.attempt_count, quota.denied_count), (1, 2, 1))
        self.assertEqual(quota.first_denial_audit.action, "access.event.quota_denied.v1")
        self.assertEqual(AccessEvent.objects.count(), 1)

    @override_settings(PAMOLIVE_EVENT_COLLECTOR_DAILY_ATTEMPT_LIMIT=1)
    def test_invalid_future_events_consume_persistent_attempt_budget(self):
        invalid = self.payload(
            occurred_at=(timezone.now() + timedelta(hours=1)).isoformat()
        )
        self.assertEqual(self.api(invalid).status_code, 400)
        self.assertEqual(self.api(invalid).status_code, 429)
        quota = AccessEventQuota.objects.get(channel="collector")
        self.assertEqual((quota.attempt_count, quota.denied_count), (2, 1))
        self.assertFalse(AccessEvent.objects.exists())

    def test_export_reports_server_receipt_separately_from_remote_truth(self):
        created = self.api(self.payload())
        self.assertEqual(created.status_code, 201)
        exported = self.browser.get(reverse("event-export", args=[created.json()["event_id"]]))
        self.assertEqual(exported.status_code, 200)
        provenance = exported.json()["provenance"]
        self.assertEqual(provenance["channel"], "collector")
        self.assertEqual(provenance["principal_id"], str(self.source.pk))
        self.assertTrue(provenance["receipt_verified"])
        self.assertFalse(provenance["remote_telemetry_verified"])

        with patch(
            "platform_modules.access.provenance_status.verify_provenance_receipt",
            return_value=False,
        ):
            unverified = self.browser.get(
                reverse("event-export", args=[created.json()["event_id"]])
            )
        self.assertEqual(unverified.status_code, 200)
        body = unverified.json()
        self.assertFalse(body["provenance"]["receipt_verified"])
        self.assertEqual(body["provenance"]["origin_claim"], "invalid_provenance")
        self.assertEqual(body["facts"]["identity_attribution"], "unverified_collector_claim")
        self.assertFalse(body["evaluation"]["provenance_verified"])
        self.assertEqual(body["business_context"]["state"], "no_verified_intent_match")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row locks require PostgreSQL")
@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class EventProvenanceRevocationRaceTests(EventProvenanceFixture, TransactionTestCase):
    def test_revocation_committed_while_ingest_waits_on_org_lock_is_enforced(self):
        stale = source_from_token(self.token)
        worker_started = Event()

        def ingest_after_preliminary_authentication():
            close_old_connections()
            worker_started.set()
            try:
                ingest_event({}, organization=self.org, source=stale, source_token=self.token)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.pk)
                EventSource.unscoped.filter(pk=self.source.pk).update(active=False)
                waiting = pool.submit(ingest_after_preliminary_authentication)
                self.assertTrue(worker_started.wait(5))
                self.assertFalse(waiting.done())
            with self.assertRaisesMessage(ValidationError, "révoqué"):
                waiting.result(timeout=10)
        self.assertFalse(AccessEvent.objects.exists())
