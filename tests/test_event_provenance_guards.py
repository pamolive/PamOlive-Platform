"""SQL boundaries complement application validation for P0-4 provenance."""

from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.utils import timezone

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvent
from platform_modules.access.provenance import (
    create_provenance_receipt,
    event_facts_digest,
    verify_provenance_receipt,
)
from platform_modules.connectors.models import EventSource


class ProvenanceDatabaseGuardsTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(key="p04-db-guard", name="P04 DB Guard")
        self.actor = get_user_model().objects.create_user("p04-db-actor")
        self.context = organization_context(self.org)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)

    def event(self, **changes):
        event = AccessEvent(
            organization=self.org,
            source="synthetic-manual",
            external_id="synthetic-event",
            provenance_channel="manual",
            manual_actor=self.actor,
            occurred_at=timezone.now(),
            method="SSH",
            action="session.start",
            **changes,
        )
        event.facts_schema, event.facts_digest = event_facts_digest(event)
        return event

    def test_bulk_insert_cannot_create_new_legacy_unknown_event(self):
        legacy = AccessEvent(
            organization=self.org,
            source="synthetic-legacy",
            external_id="synthetic-event",
            provenance_channel="legacy_unknown",
            occurred_at=timezone.now(),
            method="SSH",
            action="session.start",
        )
        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessEvent.objects.bulk_create([legacy])
        self.assertFalse(AccessEvent.objects.exists())

    def test_provenance_and_receipt_cannot_be_updated_through_queryset(self):
        event = self.event()
        event.full_clean()
        event.save()
        audit = record(
            organization=self.org, actor=self.actor, target=event,
            action="access.event.received.v1", summary="Synthetic event",
        )
        receipt = create_provenance_receipt(event, audit)
        self.assertTrue(verify_provenance_receipt(receipt))
        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessEvent.objects.filter(pk=event.pk).update(source="changed")
        with self.assertRaises(DatabaseError), transaction.atomic():
            type(receipt).objects.filter(pk=receipt.pk).update(signature="0" * 64)
        receipt.refresh_from_db()
        self.assertTrue(verify_provenance_receipt(receipt))

    @skipUnless(connection.vendor == "postgresql", "Composite tenant FK requires PostgreSQL")
    def test_raw_collector_reference_cannot_cross_organizations(self):
        other = Organization.objects.create(key="p04-db-other", name="P04 DB Other")
        with organization_context(other):
            foreign = EventSource.objects.create(
                organization=other, name="Foreign synthetic source", token_hash="f" * 64
            )
        event = AccessEvent(
            organization=self.org,
            source=str(foreign.pk),
            external_id="synthetic-foreign",
            provenance_channel="collector",
            collector_source=foreign,
            occurred_at=timezone.now(),
            method="SSH",
            action="session.start",
        )
        event.facts_schema, event.facts_digest = event_facts_digest(event)
        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessEvent.objects.bulk_create([event])
