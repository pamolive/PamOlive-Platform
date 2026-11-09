import json
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, timedelta
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import close_old_connections, connection, connections, transaction
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from platform_core import event_backfill
from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication, require_recent_authentication
from platform_core.events import process_events, publish_domain_event
from platform_core.extensions.manifest import PERIODIC_TOPIC, ExtensionError, ModuleManifest
from platform_core.management.commands.runjobs import refill
from platform_core.models import (
    AccountSecurity,
    EventAttempt,
    EventDelivery,
    ExtensionDeployment,
    ModuleActivation,
    ModuleEvent,
    Organization,
)
from platform_core.periodic_signals import enqueue_periodic_signals
from platform_core.tenancy import current_organization, organization_context

from .extension_fixtures import SOURCE


class WorkerRotationTests(SimpleTestCase):
    def test_early_organizations_cannot_starve_the_rest_or_duplicate_pending_work(self):
        organizations = [SimpleNamespace(pk=i) for i in range(8)]
        pending = {}
        executor = Mock()
        queue = refill(executor, pending, organizations, deque())
        self.assertEqual(list(pending), [0, 1, 2, 3])
        for key in (1, 2, 3):
            pending.pop(key)
        active = organizations[0:5] + organizations[6:]
        queue = refill(executor, pending, active, queue)
        self.assertEqual(list(pending), [0, 4, 6, 7])
        self.assertNotIn(5, queue)
        self.assertEqual(executor.submit.call_count, 7)


class PeriodicSignalTests(TransactionTestCase):
    def setUp(self):
        self.actor = get_user_model().objects.create_superuser("periodic-admin")
        AccountSecurity.objects.create(account=self.actor, encrypted_secret="fixture-enabled")
        self.org = Organization.objects.create(key="periodic-a", name="A")
        self.other = Organization.objects.create(key="periodic-b", name="B")
        self.slot = (
            (timezone.now() - timedelta(days=1))
            .astimezone(UTC)
            .replace(minute=0, second=0, microsecond=0)
        )
        self.now = self.slot + timedelta(minutes=1)
        source = SOURCE / "pamolive_ext_notes/manifest.json"
        self.manifest_source = json.loads(source.read_bytes())
        self.rule = {
            "name": "refresh_v1",
            "handler": "pamolive_ext_notes.events.record_receipt",
            "interval_minutes": 60,
        }
        manifest = ModuleManifest.from_dict(self.manifest_data())
        self.release = SimpleNamespace(
            manifest=manifest, release_hash="a" * 64, manifest_hash="b" * 64, wheel_sha256="c" * 64
        )
        ExtensionDeployment.objects.create(
            module_key=manifest.key,
            version=manifest.version,
            release_hash=self.release.release_hash,
            manifest_hash=self.release.manifest_hash,
            wheel_hash=self.release.wheel_sha256,
            delivered_at=self.slot - timedelta(hours=1),
            delivered_by=self.actor,
        )
        for org in (self.org, self.other):
            ModuleActivation.objects.create(
                organization=org, module_key="identity", version="0.1.0", enabled=True
            )
        self.activation = ModuleActivation.objects.create(
            organization=self.org,
            module_key=manifest.key,
            version=manifest.version,
            release_hash=self.release.release_hash,
            enabled=True,
        )
        self.set_activation_time(self.slot - timedelta(hours=1))
        extension_settings = override_settings(PAMOLIVE_EXTENSIONS=(self.release,))
        extension_settings.enable()
        self.addCleanup(extension_settings.disable)
        clock = patch("platform_core.periodic_signals.database_clock", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

    def set_activation_time(self, stamp):
        ModuleActivation.objects.filter(pk=self.activation.pk).update(updated_at=stamp)

    def manifest_data(self):
        return {**self.manifest_source, "api_version": "3", "periodic_signals": [self.rule.copy()]}

    def test_old_manifest_stays_byte_equivalent_and_v3_rule_is_bounded(self):
        self.assertEqual(
            ModuleManifest.from_dict(self.manifest_source).to_dict(), self.manifest_source
        )
        self.assertEqual(self.release.manifest.to_dict(), self.manifest_data())
        for change in (
            {"handler": "os.system"},
            {"name": "identity_receipt_v1"},
            {"interval_minutes": 1},
            {"interval_minutes": True},
            {"payload": {"function": "run"}},
        ):
            data = self.manifest_data()
            data["periodic_signals"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ExtensionError):
                ModuleManifest.from_dict(data)
        data = self.manifest_data()
        data["consumed_events"] = [
            {**data["consumed_events"][0], "topic": PERIODIC_TOPIC},
        ]
        with self.assertRaises(ExtensionError):
            ModuleManifest.from_dict(data)

    def test_organization_and_current_slot_are_exact_and_no_mfa_is_inherited(self):
        self.assertEqual(enqueue_periodic_signals(self.other), 0)
        self.assertEqual(enqueue_periodic_signals(self.org), 1)
        self.assertEqual(enqueue_periodic_signals(self.org), 0)
        with organization_context(self.org):
            event = ModuleEvent.objects.get()
            recipient = EventDelivery.objects.get()
            self.assertIsNone(event.actor_account_id)
            self.assertEqual(event.payload["slot_utc"], self.slot.isoformat())
            self.assertEqual(event.topic, PERIODIC_TOPIC)
            self.assertEqual(recipient.consumer, self.release.manifest.key)
            choices = event_backfill.choices(self.org)
            self.assertFalse(any("refresh_v1" in key for key, _ in choices))

        def handle(envelope):
            self.assertEqual(envelope.organization_id, str(self.org.pk))
            self.assertEqual(current_organization(), self.org)
            with self.assertRaises(PermissionDenied):
                require_recent_authentication(self.actor, self.org)
            with self.assertRaises(TypeError):
                envelope.payload["name"] = "altered"

        with (
            recent_authentication(self.actor, self.org, time.time()),
            patch("platform_core.events.import_string", return_value=handle) as importer,
        ):
            self.assertEqual(process_events(self.other), 0)
            self.assertEqual(process_events(self.org), 1)
            self.assertEqual(process_events(self.org), 0)
            importer.assert_called_once_with(self.rule["handler"])
        with organization_context(self.org):
            self.assertEqual(EventAttempt.objects.get().outcome, "delivered")
        self.assertTrue(verify_chain(self.org))

    def test_late_or_newly_activated_slots_are_not_replayed(self):
        self.set_activation_time(self.now)
        self.assertEqual(enqueue_periodic_signals(self.org), 0)
        self.set_activation_time(self.slot - timedelta(hours=1))
        self.now = self.slot + timedelta(minutes=10)
        self.assertEqual(enqueue_periodic_signals(self.org), 0)
        self.now = self.slot + timedelta(hours=3, minutes=1)
        self.assertEqual(enqueue_periodic_signals(self.org), 1)
        with organization_context(self.org):
            self.assertEqual(
                ModuleEvent.objects.get().payload["slot_utc"],
                (self.slot + timedelta(hours=3)).isoformat(),
            )

    def test_expired_or_reactivated_window_never_invokes_handler(self):
        self.assertEqual(enqueue_periodic_signals(self.org), 1)
        ModuleActivation.objects.filter(pk=self.activation.pk).update(enabled=False)
        with patch("platform_core.events.import_string") as importer:
            self.assertEqual(process_events(self.org), 0)
            ModuleActivation.objects.filter(pk=self.activation.pk).update(
                enabled=True, updated_at=self.now
            )
            self.assertEqual(process_events(self.org), 1)
            self.now = self.slot + timedelta(hours=1, minutes=1)
            self.assertEqual(enqueue_periodic_signals(self.org), 1)
            self.now += timedelta(minutes=9)
            self.assertEqual(process_events(self.org), 1)
            importer.assert_not_called()
        with organization_context(self.org):
            self.assertEqual(EventAttempt.objects.filter(outcome="expired").count(), 2)

    def test_scheduler_rollback_does_not_leave_unpaired_fact_and_topic_is_reserved(self):
        with self.assertRaises(RuntimeError), transaction.atomic():
            self.assertEqual(enqueue_periodic_signals(self.org), 1)
            raise RuntimeError("rollback")
        with organization_context(self.org):
            self.assertFalse(ModuleEvent.objects.exists())
            self.assertFalse(EventDelivery.objects.exists())
            with self.assertRaises(ValidationError):
                publish_domain_event(
                    organization=self.org, emitter="core", topic=PERIODIC_TOPIC, payload={}
                )
        self.assertEqual(enqueue_periodic_signals(self.org), 1)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL organization lock")
    def test_two_scheduler_processes_emit_only_one_signed_recipient(self):
        def schedule(_):
            close_old_connections()
            try:
                return enqueue_periodic_signals(Organization.objects.get(pk=self.org.pk))
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(pool.map(schedule, range(2)), [0, 1])
        with organization_context(self.org):
            self.assertEqual(ModuleEvent.objects.count(), 1)
            self.assertEqual(EventDelivery.objects.count(), 1)
