import copy
import io
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core import event_backfill
from platform_core.audit import record, verify_chain
from platform_core.authorization import recent_authentication, require_recent_authentication
from platform_core.events import payload_bytes, process_events
from platform_core.extensions import api
from platform_core.extensions.manifest import ExtensionError, ModuleManifest
from platform_core.models import (
    AccountSecurity,
    AuditEvent,
    EventAttempt,
    EventDelivery,
    ExtensionDeployment,
    ModuleActivation,
    ModuleEvent,
    Organization,
    OrganizationMembership,
)
from platform_core.tenancy import current_organization, organization_context
from platform_modules.access.services import create_record, revoke_identity
from platform_modules.identity.models import Identity

from .extension_fixtures import SOURCE


class ModuleEventTests(TransactionTestCase):
    def setUp(self):
        self.actor = get_user_model().objects.create_superuser("event-admin")
        AccountSecurity.objects.create(account=self.actor, encrypted_secret="fixture-enabled")
        self.org = Organization.objects.create(key="module-events-a", name="A")
        self.other = Organization.objects.create(key="module-events-b", name="B")
        self.manifest = ModuleManifest.from_dict(
            json.loads((SOURCE / "pamolive_ext_notes/manifest.json").read_bytes())
        )
        self.release = SimpleNamespace(
            manifest=self.manifest,
            release_hash="a" * 64,
            manifest_hash="b" * 64,
            wheel_sha256="c" * 64,
        )
        self.settings = override_settings(PAMOLIVE_EXTENSIONS=(self.release,))
        self.settings.enable()
        self.addCleanup(self.settings.disable)
        ExtensionDeployment.objects.create(
            module_key="example_notes",
            version=self.manifest.version,
            release_hash="a" * 64,
            manifest_hash="b" * 64,
            wheel_hash="c" * 64,
            delivered_at=timezone.now(),
            delivered_by=self.actor,
        )
        for org in (self.org, self.other):
            ModuleActivation.objects.create(
                organization=org, module_key="identity", version="0.1.0", enabled=True
            )
        self.activation = ModuleActivation.objects.create(
            organization=self.org,
            module_key="example_notes",
            version=self.manifest.version,
            release_hash=self.release.release_hash,
            enabled=True,
        )
        self.context = organization_context(self.org)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)

    def publish(self):
        with recent_authentication(self.actor, self.org, time.time()):
            return api.publish_event(
                actor=self.actor,
                organization=self.org,
                topic="example_notes.note.created.v1",
                payload={"note_id": "fixture"},
            )

    def project(self, event):
        self.assertEqual(event.organization_id, str(current_organization().pk))
        Identity.objects.create(
            organization=current_organization(), kind="machine", name="Projection"
        )

    def historic_identity(self):
        self.activation.enabled = False
        self.activation.save(update_fields=["enabled"])
        identity = create_record(
            "identity",
            {"name": "Historical person", "kind": "human"},
            actor=self.actor,
            organization=self.org,
        )
        self.activation.enabled = True
        self.activation.save(update_fields=["enabled"])
        return ModuleEvent.objects.get(aggregate_id=str(identity.pk))

    def backfill_scope(self):
        end = timezone.now()
        return dict(
            actor=self.actor,
            organization=self.org,
            selected="example_notes:identity_receipt_v1",
            start=end - timedelta(days=1),
            end=end,
        )

    def test_historical_backfill_is_reviewed_audited_and_delivered_once_without_mfa(self):
        historic = self.historic_identity()
        create_record(
            "identity",
            {"name": "Already queued person", "kind": "human"},
            actor=self.actor,
            organization=self.org,
        )
        with organization_context(self.other):
            create_record(
                "identity",
                {"name": "Foreign person", "kind": "human"},
                actor=self.actor,
                organization=self.other,
            )
        original = EventDelivery.objects.get()
        before = ModuleEvent.objects.count()
        arguments = self.backfill_scope()
        with recent_authentication(self.actor, self.org, time.time()):
            plan, token = event_backfill.preview(**arguments)
            self.assertEqual(plan["ready"], 1)
            self.assertEqual([row["state"] for row in plan["rows"]], ["ready", "existing"])
            self.assertEqual(EventDelivery.objects.count(), 1)
            self.assertEqual(event_backfill.submit(**arguments, token=token), 1)
            with self.assertRaisesMessage(ValidationError, "périmètre a changé"):
                event_backfill.submit(**arguments, token=token)
        self.assertEqual(ModuleEvent.objects.count(), before)
        self.assertEqual(EventDelivery.unscoped.filter(organization=self.other).count(), 0)
        queued = EventDelivery.objects.get(event=historic)
        original.refresh_from_db()
        self.assertEqual(original.attempts, 0)
        self.assertEqual(queued.status, "pending")
        review = AuditEvent.objects.get(action="core.module_event.backfill_requested.v1")
        self.assertEqual(review.actor, self.actor)
        self.assertEqual(
            review.metadata["recipients"], [{"event": str(historic.pk), "delivery": str(queued.pk)}]
        )

        def consume(envelope):
            self.assertEqual(envelope.organization_id, str(self.org.pk))
            with self.assertRaises(PermissionDenied):
                require_recent_authentication(self.actor, self.org)
            self.project(envelope)

        with recent_authentication(self.actor, self.org, time.time()):
            with patch("platform_core.events.import_string", return_value=consume):
                self.assertEqual(process_events(self.org), 2)
                self.assertEqual(process_events(self.org), 0)
        self.assertEqual(EventAttempt.objects.get(delivery=queued).outcome, "delivered")
        self.assertEqual(Identity.objects.filter(name="Projection").count(), 2)
        self.assertTrue(verify_chain(self.org))

    def test_backfill_refuses_an_expired_foreign_or_changed_preview(self):
        self.historic_identity()
        arguments = self.backfill_scope()
        other_actor = get_user_model().objects.create_superuser("second-admin")
        AccountSecurity.objects.create(account=other_actor, encrypted_secret="fixture-enabled")
        with self.assertRaises(PermissionDenied):
            event_backfill.preview(**arguments)
        with recent_authentication(self.actor, self.org, time.time()):
            plan, token = event_backfill.preview(**arguments)
            with patch.object(signing.TimestampSigner, "timestamp", return_value="1"):
                _, expired = event_backfill.preview(**arguments)
            with self.assertRaisesMessage(ValidationError, "aperçu n’est plus valide"):
                event_backfill.submit(**arguments, token=expired)
            shifted = {**arguments, "start": arguments["start"] + timedelta(minutes=1)}
            with self.assertRaisesMessage(ValidationError, "périmètre a changé"):
                event_backfill.submit(**shifted, token=token)
        with recent_authentication(other_actor, self.org, time.time()):
            with self.assertRaisesMessage(ValidationError, "périmètre a changé"):
                event_backfill.submit(**{**arguments, "actor": other_actor}, token=token)
        with (
            organization_context(self.other),
            recent_authentication(self.actor, self.other, time.time()),
        ):
            with self.assertRaises(PermissionDenied):
                event_backfill.submit(**arguments, token=token)
        self.assertEqual(plan["ready"], 1)
        self.assertFalse(EventDelivery.objects.exists())

    def test_backfill_never_rewrites_a_prior_contract(self):
        old = create_record(
            "identity",
            {"name": "Old release", "kind": "human"},
            actor=self.actor,
            organization=self.org,
        )
        first = EventDelivery.objects.get(event__aggregate_id=str(old.pk))
        historical = self.historic_identity()
        # Simulate installing a separately admitted version which keeps the logical
        # subscriber's name but changes its handler contract.
        self.release.manifest = replace(
            self.manifest,
            consumed_events=tuple(
                replace(item, handler=item.handler + "_changed")
                if item.name == "identity_receipt_v1"
                else item
                for item in self.manifest.consumed_events
            ),
        )
        self.release.release_hash = "e" * 64
        ExtensionDeployment.objects.filter(module_key="example_notes").update(
            release_hash=self.release.release_hash
        )
        self.activation.release_hash = self.release.release_hash
        self.activation.save(update_fields=["release_hash"])
        arguments = self.backfill_scope()
        with recent_authentication(self.actor, self.org, time.time()):
            plan, token = event_backfill.preview(**arguments)
            self.assertEqual([row["state"] for row in plan["rows"]], ["old_contract", "ready"])
            self.assertEqual(event_backfill.submit(**arguments, token=token), 1)
        reloaded = EventDelivery.objects.get(pk=first.pk)
        self.assertEqual(reloaded.signature, first.signature)
        self.assertEqual(reloaded.contract_hash, first.contract_hash)
        self.assertNotEqual(
            EventDelivery.objects.get(event=historical).contract_hash, first.contract_hash
        )

    def test_backfill_rejects_invalid_evidence_and_refuses_truncated_batches(self):
        self.historic_identity()
        self.historic_identity()
        arguments = self.backfill_scope()
        with recent_authentication(self.actor, self.org, time.time()):
            with patch.object(event_backfill, "LIMIT", 1):
                plan, token = event_backfill.preview(**arguments)
                self.assertTrue(plan["truncated"])
                with self.assertRaisesMessage(ValidationError, "ne peut pas être mis en file"):
                    event_backfill.submit(**arguments, token=token)
            with patch.object(event_backfill, "event_is_valid", return_value=False):
                plan, token = event_backfill.preview(**arguments)
                self.assertTrue(plan["blocked"])
                with self.assertRaisesMessage(ValidationError, "ne peut pas être mis en file"):
                    event_backfill.submit(**arguments, token=token)
        self.assertFalse(EventDelivery.objects.exists())

    def test_backfill_ui_requires_admin_and_mfa_and_never_discloses_event_payload(self):
        self.historic_identity()
        args = self.backfill_scope()
        fields = {key: str(args[key]) for key in ("selected", "start", "end")}
        url = reverse("module-event-backfill")
        self.assertEqual(self.client.get(url).status_code, 302)
        operator = get_user_model().objects.create_user("backfill-operator")
        OrganizationMembership.objects.create(
            organization=self.org, account=operator, role="operator"
        )
        self.client.force_login(operator)
        self.assertEqual(self.client.get(url).status_code, 403)
        self.client.force_login(self.actor)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session.save()
        self.assertEqual(self.client.post(url, dict(fields, command="preview")).status_code, 302)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.post(url, dict(fields, command="preview"))
        self.assertContains(response, "Confirmer la mise en file")
        self.assertNotContains(response, "Historical person")
        self.assertIn("no-store", response["Cache-Control"])
        token = response.context["form"].data["token"]
        result = self.client.post(url, dict(fields, command="submit", token=token))
        self.assertRedirects(result, reverse("system-status"), fetch_redirect_response=False)
        self.assertEqual(EventDelivery.objects.count(), 1)

    def test_publisher_enforces_declared_topic_mfa_delivery_and_tenant(self):
        with self.assertRaises(PermissionDenied):
            api.publish_event(
                actor=self.actor,
                organization=self.org,
                topic="example_notes.note.created.v1",
                payload={},
            )
        for topic in ("other.secret.created.v1", "example_notes.unknown.created.v1"):
            with self.subTest(topic=topic), self.assertRaises(PermissionDenied):
                api.publish_event(actor=self.actor, organization=self.org, topic=topic, payload={})
        with recent_authentication(self.actor, self.org, time.time()):
            with self.assertRaises(PermissionDenied):
                api.publish_event(
                    actor=self.actor,
                    organization=self.other,
                    topic="example_notes.note.created.v1",
                    payload={},
                )
        self.assertFalse(ModuleEvent.objects.exists())

    def test_publication_and_recipient_rollback_with_business_transaction(self):
        with self.assertRaises(RuntimeError), transaction.atomic():
            self.publish()
            raise RuntimeError("abort business transaction")
        self.assertEqual(ModuleEvent.objects.count(), 0)
        self.assertEqual(EventDelivery.objects.count(), 0)
        self.assertTrue(verify_chain(self.org))

    def test_real_identity_creation_publishes_only_to_active_organization(self):
        identity = create_record(
            "identity", {"name": "Person", "kind": "human"}, actor=self.actor, organization=self.org
        )
        event = ModuleEvent.objects.get()
        self.assertEqual(event.payload["identity_id"], str(identity.pk))
        self.assertEqual(EventDelivery.objects.get().handler_name, "identity_receipt_v1")
        with organization_context(self.other):
            create_record(
                "identity",
                {"name": "Other", "kind": "human"},
                actor=self.actor,
                organization=self.other,
            )
            self.assertEqual(ModuleEvent.objects.count(), 1)
            self.assertEqual(EventDelivery.objects.count(), 0)
        self.assertEqual(EventDelivery.objects.count(), 1)

    def test_departure_publishes_one_fact_not_an_external_execution_claim(self):
        identity = Identity.objects.create(organization=self.org, kind="human", name="Leaver")
        for _ in range(2):
            revoke_identity(
                identity.pk, actor=self.actor, organization=self.org, reason="Contract end"
            )
        event = ModuleEvent.objects.get(topic="identity.identity.departed.v1")
        self.assertEqual(event.payload, {"identity_id": str(identity.pk), "status": "departed"})
        self.assertNotIn("external_execution", event.payload)

    def test_operator_status_and_cli_are_scoped_without_exposing_payload(self):
        self.publish()
        self.client.force_login(self.actor)
        response = self.client.get(reverse("system-status"))
        self.assertContains(response, "Notifications entre modules")
        self.assertContains(response, "example_notes.note.created.v1")
        self.assertNotContains(response, "note_id")
        output = io.StringIO()
        call_command("pamolive_events", "status", organization=self.other.key, stdout=output)
        self.assertEqual(json.loads(output.getvalue())["deliveries"], [])

    def test_consumer_commits_once_and_gets_immutable_notification_without_mfa(self):
        self.publish()

        def handler(event):
            with self.assertRaises(TypeError):
                event.payload["note_id"] = "mutated"
            with self.assertRaises(PermissionDenied):
                require_recent_authentication(self.actor, self.org)
            self.project(event)

        with recent_authentication(self.actor, self.org, time.time()):
            with patch("platform_core.events.import_string", return_value=handler) as imported:
                self.assertEqual(process_events(self.org), 1)
                self.assertEqual(process_events(self.org), 0)
            require_recent_authentication(self.actor, self.org)
        imported.assert_called_once_with("pamolive_ext_notes.events.record_receipt")
        self.assertEqual(Identity.objects.filter(name="Projection").count(), 1)
        self.assertEqual(EventAttempt.objects.get().outcome, "delivered")
        self.assertTrue(verify_chain(self.org))

    def test_failure_rolls_back_local_effects_and_retries_with_bounded_attempts(self):
        self.publish()

        def fail(event):
            self.project(event)
            raise RuntimeError("do-not-persist-private-exception-text")

        with patch("platform_core.events.import_string", return_value=fail):
            for number in range(1, 6):
                self.assertEqual(process_events(self.org), 1)
                delivery = EventDelivery.objects.get()
                self.assertEqual(delivery.attempts, number)
                self.assertFalse(Identity.objects.exists())
                if number < 5:
                    self.assertEqual(process_events(self.org), 0)
                    EventDelivery.objects.update(available_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(EventDelivery.objects.get().status, "dead")
        self.assertEqual(EventAttempt.objects.count(), 5)
        self.assertTrue(
            all(attempt.error_code == "RuntimeError" for attempt in EventAttempt.objects.all())
        )
        self.assertNotIn(
            "private-exception", json.dumps(list(AuditEvent.objects.values("metadata")))
        )

    def test_commit_failure_does_not_leave_effect_without_delivery_receipt(self):
        self.publish()
        original = record

        def fail_completion(**kwargs):
            if kwargs["action"] == "core.module_event.processed.v1":
                raise RuntimeError("simulated failure before commit")
            return original(**kwargs)

        with patch("platform_core.events.import_string", return_value=self.project):
            with patch("platform_core.events.record", side_effect=fail_completion):
                with self.assertRaises(RuntimeError):
                    process_events(self.org)
            self.assertFalse(Identity.objects.exists())
            self.assertFalse(EventAttempt.objects.exists())
            self.assertEqual(EventDelivery.objects.get().attempts, 0)
            self.assertEqual(process_events(self.org), 1)
        self.assertEqual(Identity.objects.count(), 1)

    def test_disabled_release_pauses_and_preserves_queued_delivery(self):
        self.publish()
        self.activation.enabled = False
        self.activation.save()
        with patch("platform_core.events.import_string") as imported:
            self.assertEqual(process_events(self.org), 0)
        imported.assert_not_called()
        self.assertEqual(EventDelivery.objects.get().attempts, 0)
        self.activation.enabled = True
        self.activation.release_hash = "d" * 64
        self.activation.save()
        self.assertEqual(process_events(self.org), 0)
        self.activation.release_hash = self.release.release_hash
        self.activation.save()
        with patch("platform_core.events.import_string", return_value=self.project):
            self.assertEqual(process_events(self.org), 1)

    def test_changed_consumer_contract_never_loads_old_queued_handler(self):
        self.publish()
        changed = replace(self.manifest.consumed_events[1], handler="pamolive_ext_notes.events.new")
        self.release.manifest = replace(self.manifest, consumed_events=(changed,))
        with patch("platform_core.events.import_string") as imported:
            self.assertEqual(process_events(self.org), 0)
        imported.assert_not_called()

    def test_forged_envelope_or_recipient_is_quarantined_without_import(self):
        for signer in ("event_signature", "delivery_signature"):
            with patch("platform_core.events." + signer, return_value="0" * 64):
                self.publish()
        with patch("platform_core.events.import_string") as imported:
            self.assertEqual(process_events(self.org), 2)
        imported.assert_not_called()
        self.assertEqual(EventDelivery.objects.filter(status="invalid").count(), 2)
        self.assertFalse(Identity.objects.exists())

    def test_scope_and_evidence_cannot_be_mutated_through_orm(self):
        event = self.publish()
        for action in (
            lambda: ModuleEvent.objects.update(payload={}),
            lambda: ModuleEvent.objects.all().delete(),
            lambda: EventDelivery.objects.update(consumer="different"),
            lambda: EventDelivery.objects.all().delete(),
        ):
            with self.assertRaises(ValidationError):
                action()
        event.topic = "other.secret.created.v1"
        with self.assertRaises(ValidationError):
            event.save()

    def test_payload_contract_refuses_non_json_excess_depth_and_oversized_data(self):
        for payload in (
            ["not-object"],
            {"number": float("nan")},
            {"bad": object()},
            {"big": "x" * 8193},
            {1: "non-string-key"},
        ):
            with self.subTest(payload=type(payload)), self.assertRaises(ValidationError):
                payload_bytes(payload)
        self.assertEqual(
            json.loads(payload_bytes({"nested": [True, None, 42]})), {"nested": [True, None, 42]}
        )

    def test_signed_numeric_payload_survives_a_real_database_round_trip(self):
        with recent_authentication(self.actor, self.org, time.time()):
            event = api.publish_event(
                actor=self.actor,
                organization=self.org,
                topic="example_notes.note.created.v1",
                payload={"zero": -0.0, "large": 1e15, "fraction": 0.125, "tiny": 1e-20},
            )
        event.refresh_from_db()
        self.assertIs(type(event.payload["zero"]), int)
        self.assertIs(type(event.payload["large"]), int)
        with patch("platform_core.events.import_string", return_value=self.project):
            self.assertEqual(process_events(self.org), 1)
        self.assertEqual(EventDelivery.objects.get().status, "delivered")

    def test_manifest_v1_hash_representation_and_v2_closed_handler_contract(self):
        old = copy.deepcopy(self.manifest.to_dict())
        old.pop("emitted_events")
        old.pop("consumed_events")
        old["api_version"] = "1"
        self.assertEqual(ModuleManifest.from_dict(old).to_dict(), old)
        for change in (
            {"handler": "os.system"},
            {"topic": "identity.*"},
            {"name": "arbitrary-job"},
        ):
            data = self.manifest.to_dict()
            data["consumed_events"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ExtensionError):
                ModuleManifest.from_dict(data)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL row locking")
    def test_two_workers_commit_one_effect_for_one_recipient(self):
        self.publish()

        def worker():
            close_old_connections()
            try:
                return process_events(Organization.objects.get(pk=self.org.pk), limit=1)
            finally:
                connections.close_all()

        with patch("platform_core.events.import_string", return_value=self.project):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: worker(), range(2)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(Identity.objects.count(), 1)
        self.assertEqual(EventAttempt.objects.count(), 1)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL organization lock")
    def test_concurrent_backfill_confirmations_create_only_one_recipient_and_audit(self):
        self.historic_identity()
        arguments = self.backfill_scope()
        with recent_authentication(self.actor, self.org, time.time()):
            _, token = event_backfill.preview(**arguments)

        def submit():
            close_old_connections()
            try:
                with (
                    organization_context(self.org),
                    recent_authentication(self.actor, self.org, time.time()),
                ):
                    return event_backfill.submit(**arguments, token=token)
            except ValidationError:
                return 0
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: submit(), range(2)))
        self.assertCountEqual(results, [0, 1])
        self.assertEqual(EventDelivery.objects.count(), 1)
        self.assertEqual(
            AuditEvent.objects.filter(action="core.module_event.backfill_requested.v1").count(), 1
        )

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL immutable and tenant guards")
    def test_raw_sql_cannot_rewrite_event_or_recipient_scope(self):
        event = self.publish()
        delivery = EventDelivery.objects.get()
        for statement, values in (
            ("UPDATE platform_core_moduleevent SET payload='{}' WHERE id=%s", [event.pk]),
            ("DELETE FROM platform_core_eventdelivery WHERE id=%s", [delivery.pk]),
            ("UPDATE platform_core_eventdelivery SET consumer='other' WHERE id=%s", [delivery.pk]),
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(DatabaseError),
                transaction.atomic(),
            ):
                with connection.cursor() as cursor:
                    cursor.execute(statement, values)
        invalid = EventDelivery(
            organization=self.other,
            event=event,
            consumer="other",
            handler_name="other_v1",
            contract_hash="0" * 64,
            signature="0" * 64,
            available_at=timezone.now(),
        )
        with self.assertRaises(DatabaseError), transaction.atomic():
            EventDelivery.unscoped.bulk_create([invalid])
