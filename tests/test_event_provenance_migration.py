"""P0-4 upgrade preserves untrusted history and removes the old global key."""

from datetime import timedelta

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone


class EventProvenanceMigrationTests(TransactionTestCase):
    migrate_from = ("access", "0014_accessintent_pam_trust")
    migrate_to = ("access", "0016_provenance_database_guards")

    def test_historical_event_remains_unknown_and_can_coexist_with_collector(self):
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        try:
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            Organization = old_apps.get_model("platform_core", "Organization")
            AccessEvent = old_apps.get_model("access", "AccessEvent")
            org = Organization.objects.create(key="p04-migration", name="P04 Migration")
            old = AccessEvent.objects.create(
                organization=org,
                source="synthetic-collector-uuid",
                external_id="same-remote-id",
                occurred_at=timezone.now() - timedelta(minutes=1),
                method="SSH",
                action="session.start",
            )
        finally:
            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])

        from platform_core.models import Organization
        from platform_core.tenancy import organization_context
        from platform_modules.access.models import AccessEvent
        from platform_modules.access.provenance import event_facts_digest
        from platform_modules.connectors.models import EventSource

        org = Organization.objects.get(key="p04-migration")
        with organization_context(org):
            historical = AccessEvent.objects.get(pk=old.pk)
            self.assertEqual(historical.provenance_channel, "legacy_unknown")
            self.assertIsNone(historical.collector_source_id)
            self.assertIsNone(historical.manual_actor_id)
            self.assertEqual(historical.facts_schema, "")
            self.assertEqual(historical.facts_digest, "")
            self.assertEqual(historical.source, "synthetic-collector-uuid")

            source = EventSource.objects.create(
                organization=org, name="Synthetic collector", token_hash="1" * 64
            )
            newer = AccessEvent(
                organization=org,
                source=historical.source,
                external_id=historical.external_id,
                provenance_channel="collector",
                collector_source=source,
                occurred_at=historical.occurred_at,
                method="SSH",
                action="session.start",
            )
            newer.facts_schema, newer.facts_digest = event_facts_digest(newer)
            newer.full_clean()
            newer.save()
            self.assertNotEqual(newer.pk, historical.pk)
            self.assertEqual(AccessEvent.objects.count(), 2)
        with self.assertRaisesRegex(RuntimeError, "explicit reconciliation"):
            MigrationExecutor(connection).migrate([self.migrate_from])
        self.assertTrue(AccessEvent.unscoped.filter(pk=newer.pk).exists())

    def test_quota_evidence_alone_blocks_unsafe_rollback(self):
        from platform_core.models import Organization
        from platform_modules.access.models import AccessEventQuota

        org = Organization.objects.create(key="p04-quota-only", name="P04 Quota Only")
        quota = AccessEventQuota.unscoped.create(
            organization=org, channel="manual", principal_key="synthetic-actor",
            day=timezone.localdate(), attempt_count=1,
        )
        with self.assertRaisesRegex(RuntimeError, "explicit reconciliation"):
            MigrationExecutor(connection).migrate([self.migrate_from])
        self.assertTrue(AccessEventQuota.unscoped.filter(pk=quota.pk).exists())
