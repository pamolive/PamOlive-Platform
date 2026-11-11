"""P0-4 cryptographic and canonicalization contracts for V8 receipts."""

from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone as django_timezone

from platform_core.audit import record
from platform_core.models import ModuleActivation, Organization
from platform_core.tenancy import organization_context
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessEvent
from platform_modules.access.provenance import (
    FACTS_SCHEMA,
    create_provenance_receipt,
    event_facts_digest,
    verify_provenance_receipt,
)
from platform_modules.access.services import evaluate_event
from platform_modules.connectors.models import EventSource


def synthetic_event(**changes):
    facts = {
        "organization_id": uuid4(),
        "source": "synthetic-source",
        "external_id": "case-SYNTHETIC-001",
        "occurred_at": datetime(2026, 11, 11, 9, 5, 6, 123456, tzinfo=UTC),
        "ended_at": None,
        "identity_id": uuid4(),
        "account_id": None,
        "resource_id": uuid4(),
        "credential_id": None,
        "method": "SSH",
        "action": "session.start",
        "location": "synthetic-local",
        "privilege": "root",
        "result": "failure",
        "contract_id": None,
        "country_code": "",
        "evidence": "synthetic evidence only",
        "domain": "pam",
        "network_switch_id": None,
        "network_port": "",
        "network_vlan": "",
        "credential_observation": "identifier_only",
        "id": uuid4(),
        "received_at": datetime.now(UTC),
    }
    facts.update(changes)
    return SimpleNamespace(**facts)


class EventFactsV8Tests(SimpleTestCase):
    def test_equivalent_timezones_have_the_same_digest(self):
        event = synthetic_event()
        shifted = synthetic_event(**vars(event))
        shifted.occurred_at = event.occurred_at.astimezone(timezone(timedelta(hours=2)))
        self.assertEqual(event_facts_digest(event), event_facts_digest(shifted))
        self.assertEqual(event_facts_digest(event)[0], FACTS_SCHEMA)

    def test_server_generated_event_id_and_receipt_time_do_not_change_content(self):
        event = synthetic_event()
        retry = synthetic_event(**vars(event))
        retry.id = uuid4()
        retry.received_at += timedelta(days=2)
        self.assertEqual(event_facts_digest(event), event_facts_digest(retry))

    def test_divergent_facts_change_digest(self):
        event = synthetic_event()
        changed = synthetic_event(**vars(event))
        changed.result = "success"
        self.assertNotEqual(event_facts_digest(event), event_facts_digest(changed))

    def test_naive_timestamp_and_nonfinite_value_are_rejected(self):
        with self.assertRaises(ValidationError):
            event_facts_digest(synthetic_event(occurred_at=datetime(2026, 11, 11, 9, 5)))
        with self.assertRaises(ValidationError):
            event_facts_digest(synthetic_event(location=float("nan")))


class ProvenanceReceiptV8Tests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(key="p04-crypto", name="P04 crypto fixture")
        self.actor = get_user_model().objects.create_user("p04-crypto-actor")
        self.scope = organization_context(self.org)
        self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)

    def _event_and_receipt(self, *, collector=False):
        source = None
        if collector:
            source = EventSource.objects.create(
                organization=self.org,
                name="Synthetic receipt collector",
                token_hash="a" * 64,
            )
        event = AccessEvent(
            organization=self.org,
            source=str(source.pk) if source else "synthetic-manual-label",
            external_id="synthetic-receipt-1",
            occurred_at=django_timezone.now(),
            method="SSH",
            action="session.start",
            provenance_channel="collector" if collector else "manual",
            collector_source=source,
            manual_actor=None if collector else self.actor,
        )
        event.facts_schema, event.facts_digest = event_facts_digest(event)
        event.full_clean()
        event.save()
        audit = record(
            action="access.event.received.v1",
            summary="Synthetic V8 acceptance",
            actor=None if collector else self.actor,
            organization=self.org,
            target=event,
        )
        receipt = create_provenance_receipt(
            event, audit, credential_fingerprint=source.token_hash if source else ""
        )
        return event, receipt, source

    def test_manual_receipt_verifies_and_detects_tampered_facts(self):
        event, receipt, _ = self._event_and_receipt()
        self.assertTrue(verify_provenance_receipt(receipt))
        event.result = "failure"
        self.assertFalse(verify_provenance_receipt(receipt))

    def test_collector_receipt_survives_token_rotation_but_not_channel_change(self):
        event, receipt, source = self._event_and_receipt(collector=True)
        self.assertTrue(verify_provenance_receipt(receipt))
        EventSource.objects.filter(pk=source.pk).update(token_hash="b" * 64)
        self.assertTrue(verify_provenance_receipt(receipt))
        receipt.channel = "manual"
        self.assertFalse(verify_provenance_receipt(receipt))
        self.assertEqual(event.collector_source_id, source.pk)

    def test_signing_key_fallback_verifies_old_receipt(self):
        old = "synthetic-p04-old-signing-key-01234567890123456789"
        new = "synthetic-p04-new-signing-key-01234567890123456789"
        with override_settings(SECRET_KEY=old):
            _, receipt, _ = self._event_and_receipt()
            self.assertTrue(verify_provenance_receipt(receipt))
        with override_settings(SECRET_KEY=new, PAMOLIVE_EVIDENCE_VERIFICATION_KEYS=[old]):
            self.assertTrue(verify_provenance_receipt(receipt))
        with override_settings(SECRET_KEY=new, PAMOLIVE_EVIDENCE_VERIFICATION_KEYS=[]):
            self.assertFalse(verify_provenance_receipt(receipt))

    def test_invalid_audit_or_fingerprint_cannot_be_sealed(self):
        event, receipt, _ = self._event_and_receipt()
        self.assertTrue(verify_provenance_receipt(receipt))
        receipt.audit.action = "unrelated.audit.v1"
        self.assertFalse(verify_provenance_receipt(receipt))
        receipt.audit.action = "access.event.received.v1"
        with self.assertRaises(ValidationError):
            create_provenance_receipt(event, receipt.audit, credential_fingerprint="a" * 64)

    def test_v7_evaluation_remains_verifiable_with_historical_signing_key(self):
        for module_key in ("identity", "access"):
            ModuleActivation.objects.create(
                organization=self.org, module_key=module_key, version="synthetic", enabled=True
            )
        event, _, _ = self._event_and_receipt()
        old = "synthetic-p04-old-v7-key-012345678901234567890123"
        new = "synthetic-p04-new-v7-key-012345678901234567890123"
        with override_settings(SECRET_KEY=old):
            evaluation = evaluate_event(event, organization=self.org)
            self.assertTrue(verify_evaluation(evaluation))
        with override_settings(SECRET_KEY=new, PAMOLIVE_EVIDENCE_VERIFICATION_KEYS=[old]):
            self.assertTrue(verify_evaluation(evaluation))
        with override_settings(SECRET_KEY=new, PAMOLIVE_EVIDENCE_VERIFICATION_KEYS=[]):
            self.assertFalse(verify_evaluation(evaluation))
