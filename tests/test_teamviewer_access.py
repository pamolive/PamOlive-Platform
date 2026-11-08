import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import Client, TransactionTestCase, override_settings
from django.urls import reverse

from platform_core.audit import record, verify_chain
from platform_core.models import AuditEvent, ModuleActivation
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessEvaluation, AccessEvent, AccessIntent
from platform_modules.access.observations import (
    EVENT_FACT_FIELDS,
    ObservationContext,
    observation_context,
    register_provider,
)
from platform_modules.access.services import evaluate_event, ingest_event
from platform_modules.connectors.teamviewer_access import (
    SOURCE,
    normalize_sessions,
    process_access_observations,
    verify_observation,
)
from platform_modules.connectors.teamviewer_access_models import (
    TeamViewerAccessCursor,
    TeamViewerAccessObservation,
)
from platform_modules.connectors.teamviewer_restoration import verify_evidence
from platform_modules.connectors.teamviewer_sessions import index_sessions
from platform_modules.identity.models import ExternalAccount, Identity, Resource
from platform_modules.intelligence.coverage import event_timeline
from platform_modules.intelligence.projection import graph_for_identity
from tests.test_teamviewer_collection import TeamViewerFixture, TeamViewerFixtureData
from tests.test_teamviewer_sessions import SessionFixtureData


class TeamViewerAccessTests(SessionFixtureData, TeamViewerFixture):
    def setUp(self):
        super().setUp()
        self.make_source()
        self.before = self.source.started_at - timedelta(hours=1)
        with patch("django.utils.timezone.now", return_value=self.before):
            self.person = Identity.objects.create(
                organization=self.org, name="Intervenant attesté", kind="human"
            )
            self.owner = Identity.objects.create(
                organization=self.org, name="Compte de service", kind="service"
            )
        self.account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.owner,
            username="shared-tv",
            system="TeamViewer",
            kind="service",
        )
        self.device = Resource.objects.create(
            organization=self.org, name="Observed workstation", kind="device"
        )
        self.sighting = self.read()
        index_sessions(self.org)

    def assign_all(self, sighting=None):
        sighting = sighting or self.sighting
        for kind, target in (
            ("actor", self.person),
            ("account", self.account),
            ("device", self.device),
        ):
            self.assign(sighting, kind, target)

    def intent(self, **changes):
        with patch("django.utils.timezone.now", return_value=self.before):
            return AccessIntent.objects.create(
                **(
                    dict(
                        organization=self.org,
                        identity=self.person,
                        account=self.account,
                        resource=self.device,
                        method="TeamViewer",
                        reason="Maintenance déclarée",
                        reference="CHG-OBS-1",
                        starts_at=self.source.started_at,
                        ends_at=self.source.ended_at,
                        approved_at=self.before,
                        status="approved",
                        requested_by=self.admin,
                    )
                    | changes
                )
            )

    def event(self):
        return AccessEvent.objects.get(source=SOURCE)

    def latest(self):
        return AccessEvaluation.objects.select_related("audit", "event", "intent").latest(
            "evaluated_at"
        )

    def test_unresolved_source_is_recorded_without_invented_identity_or_resource(self):
        self.assertEqual(normalize_sessions(self.org), 1)
        event = self.event()
        self.assertIsNone(event.identity_id)
        self.assertIsNone(event.account_id)
        self.assertIsNone(event.resource_id)
        self.assertEqual(event.result, "reported_completed")
        self.assertEqual(event.occurred_at, self.source.started_at)
        self.assertEqual(event.ended_at, self.source.ended_at)
        self.assertEqual(event.received_at, self.sighting.report.observed_at)
        self.assertEqual(self.latest().verdict, "unknown")
        link = TeamViewerAccessObservation.objects.get()
        self.assertTrue(verify_observation(link))
        self.assertTrue(verify_evaluation(self.latest()))
        self.assertTrue(verify_chain(self.org))

    def test_explicit_assignments_explain_scope_without_rewriting_source_or_claiming_authentication(
        self,
    ):
        normalize_sessions(self.org)
        original = AccessEvent.objects.values().get()
        initial = self.latest()
        self.assign_all()
        intent = self.intent()
        normalize_sessions(self.org)
        evaluation = self.latest()
        self.assertEqual(evaluation.verdict, "expected")
        self.assertEqual(evaluation.intent_id, intent.pk)
        self.assertEqual(AccessEvent.objects.values().get(), original)
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(AccessEvaluation.objects.count(), 2)
        semantic = evaluation.context["semantic"]
        self.assertEqual(semantic["attribution"]["actor"]["target"], str(self.person.pk))
        self.assertNotEqual(semantic["attribution"]["actor"]["target"], str(self.owner.pk))
        self.assertFalse(semantic["actor_inferred_from_owner"])
        self.assertIn("administrative_attestation", semantic["actor_provenance"])
        self.assertTrue(
            any("attestation administrative" in item["detail"] for item in evaluation.findings)
        )
        self.assertTrue(verify_evaluation(initial))
        self.assertTrue(verify_evaluation(evaluation))

    def test_missing_privilege_is_unknown_but_known_wrong_target_is_a_deviation(self):
        self.assign_all()
        intent = self.intent(privilege="Administrator")
        normalize_sessions(self.org)
        self.assertEqual(self.latest().verdict, "unknown")
        self.assertTrue(any(item["code"] == "scope_telemetry" for item in self.latest().findings))
        other = Resource.objects.create(
            organization=self.org, name="Different endpoint", kind="device"
        )
        # A new intention on another known target cannot explain the observed machine.
        AccessIntent.objects.filter(pk=intent.pk).update(status="denied")
        self.intent(resource=other, privilege="Administrator")
        evaluation = evaluate_event(self.event(), organization=self.org)
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(any(item["code"] == "scope" for item in evaluation.findings))

    def test_unresolved_account_does_not_become_expected_via_an_unconstrained_intent(self):
        self.assign(self.sighting, "actor", self.person)
        self.assign(self.sighting, "device", self.device)
        self.intent(account=None)
        normalize_sessions(self.org)
        self.assertEqual(self.latest().verdict, "unknown")
        self.assertTrue(
            any(
                item["code"] == "teamviewer_attribution" and item["state"] == "unknown"
                for item in self.latest().findings
            )
        )

    def test_repeated_reads_keep_one_event_and_do_not_append_identical_interpretations(self):
        self.assign_all()
        self.intent()
        normalize_sessions(self.org)
        before = self.latest()
        self.read()
        index_sessions(self.org)
        normalize_sessions(self.org)
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(AccessEvaluation.objects.count(), 1)
        self.assertEqual(self.latest().context_hash, before.context_hash)
        self.read(replace(self.source, notes="A corrected unverified note"))
        index_sessions(self.org)
        normalize_sessions(self.org)
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(AccessEvaluation.objects.count(), 2)

    def test_identical_reread_does_not_duplicate_analysis_when_collector_order_changes(self):
        self.assign_all()
        other_collector = self.save(self.draft(name="Another collector", collect_notes=True))
        witness = self.read(collector=other_collector)
        self.assign_all(witness)
        index_sessions(self.org)
        self.intent()
        normalize_sessions(self.org)
        first = self.latest()
        self.read()
        index_sessions(self.org)
        normalize_sessions(self.org)
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(AccessEvaluation.objects.count(), 1)
        self.assertEqual(self.latest().context_hash, first.context_hash)

    def test_mapping_correction_appends_analysis_and_marks_old_view_stale_until_processed(self):
        self.assign_all()
        self.intent()
        normalize_sessions(self.org)
        old = self.latest()
        original = AccessEvent.objects.values().get()
        other = Identity.objects.create(
            organization=self.org, name="Corrected operator", kind="human"
        )
        self.assign(self.sighting, "actor", other)
        client = self.browser_client()
        page = client.get(reverse("record-detail", args=["event", self.event().pk]))
        self.assertTrue(page.context["interpretation_stale"])
        self.assertIsNone(page.context["evaluation"])
        self.assertContains(page, "Analyse historique conservée")
        exported = client.get(reverse("event-export", args=[self.event().pk])).json()
        self.assertIsNone(exported["facts"]["identity_id"])
        self.assertEqual(exported["interpretation"]["identity_id"], str(other.pk))
        self.assertTrue(exported["evaluation"]["current_interpretation_differs"])
        normalize_sessions(self.org)
        self.assertEqual(AccessEvent.objects.values().get(), original)
        self.assertEqual(AccessEvaluation.objects.count(), 2)
        old.refresh_from_db()
        self.assertEqual(old.verdict, "expected")
        self.assertEqual(
            old.context["semantic"]["attribution"]["actor"]["target"], str(self.person.pk)
        )
        self.assertTrue(verify_evaluation(old))

    def test_structural_conflict_prevents_reusing_a_previously_expected_conclusion(self):
        self.assign_all()
        self.intent()
        normalize_sessions(self.org)
        self.read(replace(self.source, device_ref="different-source-device"))
        index_sessions(self.org)
        normalize_sessions(self.org)
        result = self.latest()
        self.assertEqual(result.verdict, "unknown")
        self.assertEqual(result.context["semantic"]["source_state"], "conflict")
        self.assertIsNone(result.intent_id)
        self.assertEqual(AccessEvent.objects.count(), 1)

    def test_managed_namespace_is_reserved_and_preexisting_events_are_not_adopted(self):
        data = dict(
            source=SOURCE,
            external_id=self.source.id,
            occurred_at=self.source.started_at,
            method="TeamViewer",
            action="remote_session",
            resource=self.device,
        )
        with self.assertRaises(ValidationError):
            ingest_event(data, organization=self.org, actor=self.admin)
        fake = AccessEvent.objects.create(organization=self.org, **data)
        original = AccessEvent.objects.values().get()
        normalize_sessions(self.org)
        self.assertFalse(TeamViewerAccessObservation.objects.exists())
        self.assertEqual(AccessEvent.objects.values().get(), original)
        issue = AuditEvent.objects.filter(action="connectors.teamviewer.access.refused.v1").get()
        self.assertEqual(issue.metadata["code"], "managed_source_collision")
        self.assertTrue(observation_context(fake, organization=self.org).blocked)
        self.assertEqual(evaluate_event(fake, organization=self.org).verdict, "unknown")
        normalize_sessions(self.org)
        self.assertEqual(AuditEvent.objects.filter(action=issue.action).count(), 1)

    def test_module_revocation_and_foreign_context_fail_closed_without_deleting_history(self):
        self.assign_all()
        normalize_sessions(self.org)
        event = self.event()
        with organization_context(self.other), self.assertRaises(PermissionDenied):
            observation_context(event, organization=self.org)
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        self.assertTrue(observation_context(event, organization=self.org).blocked)
        self.assertEqual(evaluate_event(event, organization=self.org).verdict, "unknown")
        self.assertEqual(process_access_observations(self.org), 0)
        self.assertEqual(AccessEvent.objects.count(), 1)

    def test_signature_tampering_and_wrong_key_reject_source_and_evaluation_proofs(self):
        normalize_sessions(self.org)
        evaluation = self.latest()
        evaluation.findings.append(dict(code="forged", state="confirmed"))
        self.assertFalse(verify_evaluation(evaluation))
        with override_settings(SECRET_KEY="wrong-test-key"):
            self.assertFalse(verify_evaluation(self.latest()))
            self.assertTrue(observation_context(self.event(), organization=self.org).blocked)
            with self.assertRaises(RuntimeError):
                verify_evidence()

    def test_new_evaluation_seal_binds_every_current_source_field(self):
        normalize_sessions(self.org)
        event = self.event()
        self.assertEqual(
            set(EVENT_FACT_FIELDS), {field.attname for field in event._meta.concrete_fields}
        )
        evaluation = self.latest()
        evaluation.event.evidence = "forged-source-reference"
        self.assertFalse(verify_evaluation(evaluation))
        evaluation = self.latest()
        evaluation.event.occurred_at += timedelta(microseconds=1)
        self.assertFalse(verify_evaluation(evaluation))

    def test_unsigned_legacy_shape_is_history_not_a_current_verified_conclusion(self):
        normalize_sessions(self.org)
        legacy = AccessEvaluation.objects.create(
            organization=self.org,
            event=self.event(),
            rule_version="access-context/6",
            verdict="expected",
            findings=[],
        )
        self.assertFalse(verify_evaluation(legacy))
        self.assertTrue(verify_evaluation(legacy, allow_legacy=True))
        normalize_sessions(self.org)
        self.assertEqual(self.latest().rule_version, "access-context/7")
        self.assertTrue(verify_evaluation(self.latest()))

    def test_evaluation_reloads_canonical_source_instead_of_trusting_modified_python_objects(self):
        self.assign_all()
        self.intent()
        normalize_sessions(self.org)
        event = self.event()
        before = AccessEvent.objects.values().get()
        event.source = "untrusted-local-override"
        event.identity = self.owner
        event.resource = self.device
        evaluation = evaluate_event(event, organization=self.org)
        self.assertTrue(verify_evaluation(evaluation))
        self.assertEqual(
            evaluation.context["semantic"]["attribution"]["actor"]["target"], str(self.person.pk)
        )
        self.assertEqual(AccessEvent.objects.values().get(), before)

    def test_observation_adapter_cannot_rewrite_source_method_or_privilege(self):
        from copy import copy

        from platform_modules.access.observations import _providers

        event = AccessEvent.objects.create(
            organization=self.org,
            source="managed:fixture",
            external_id="adapter-fixture",
            occurred_at=self.source.started_at,
            method="TeamViewer",
            action="remote_session",
        )

        def invalid_adapter(source, *, organization):
            changed = copy(source)
            changed.privilege = "Administrator"
            return ObservationContext(changed, dict(semantic=dict(state="forged")))

        with patch.dict(_providers):
            register_provider(
                key="fixture",
                module="connectors",
                resolve=invalid_adapter,
                related=lambda identity, limit: ([], False),
            )
            context = observation_context(event, organization=self.org)
        self.assertTrue(context.blocked)
        self.assertEqual(context.event.privilege, "")

    def test_signed_cursor_scans_fairly_and_a_broken_cache_does_not_supply_authority(self):
        self.read(replace(self.source, id=str(uuid.uuid4())))
        self.read(replace(self.source, id=str(uuid.uuid4())))
        index_sessions(self.org)
        for _ in range(3):
            normalize_sessions(self.org, limit=1)
        self.assertEqual(AccessEvent.objects.count(), 3)
        self.assertEqual(AccessEvaluation.objects.count(), 3)
        TeamViewerAccessCursor.objects.update(
            last_session_id=uuid.UUID(int=2**128 - 1), signature="broken"
        )
        normalize_sessions(self.org, limit=1)
        self.assertEqual(AccessEvaluation.objects.count(), 3)
        self.assertTrue(verify_chain(self.org))

    def test_graph_and_timeline_use_verified_attribution_not_raw_owner_inference(self):
        install_module("intelligence", actor=self.admin, organization=self.org)
        self.assign_all()
        self.intent()
        normalize_sessions(self.org)
        graph = graph_for_identity(self.person, at=self.source.ended_at + timedelta(seconds=1))
        self.assertTrue(any(edge["relation"] == "observed-on" for edge in graph["edges"]))
        owner_graph = graph_for_identity(self.owner, at=self.source.ended_at + timedelta(seconds=1))
        owner_node = f"identity:{self.owner.pk}"
        self.assertFalse(
            any(
                edge["source"] == owner_node and edge["relation"] == "observed-on"
                for edge in owner_graph["edges"]
            )
        )
        rows, _ = event_timeline(
            AccessEvent.objects.all(),
            self.source.started_at - timedelta(seconds=1),
            self.source.ended_at + timedelta(seconds=1),
        )
        self.assertEqual(rows[0]["event"].identity_id, self.person.pk)
        self.assertEqual(rows[0]["event"].resource_id, self.device.pk)
        self.assertIsNone(self.event().identity_id)

    def browser_client(self):
        client = Client()
        client.force_login(self.admin)
        session = client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()
        return client

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL normalization and evaluation guards")
    def test_database_refuses_rewriting_links_and_v7_evaluations_without_proof(self):
        normalize_sessions(self.org)
        for table in ("connectors_teamvieweraccessobservation", "access_accessevaluation"):
            with (
                self.assertRaises(DatabaseError),
                transaction.atomic(),
                connection.cursor() as cursor,
            ):
                cursor.execute(f"UPDATE {table} SET signature='forged'")
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "INSERT INTO access_accessevaluation "
                "(id, verdict, rule_version, findings, evaluated_at, organization_id, event_id, "
                "context, context_hash, signature) VALUES (%s, 'expected', 'access-context/7', "
                "'[]', CURRENT_TIMESTAMP, %s, %s, '{}', '', '')",
                [uuid.uuid4(), self.org.pk, self.event().pk],
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23514")

    @skipUnless(
        connection.vendor == "postgresql", "PostgreSQL exact source and audit tenant guards"
    )
    def test_database_rejects_unmanaged_source_and_foreign_audit_links(self):
        from platform_modules.connectors.teamviewer_session_models import TeamViewerSession

        session = TeamViewerSession.objects.get()
        event = AccessEvent.objects.create(
            organization=self.org,
            source="ordinary-fixture",
            external_id=self.source.id,
            occurred_at=self.source.started_at,
            ended_at=self.source.ended_at,
            method="TeamViewer",
            action="remote_session",
        )
        audit = record(organization=self.org, action="fixture.source", summary="Constraint fixture")
        insert = (
            "INSERT INTO connectors_teamvieweraccessobservation "
            "(id, organization_id, session_id, event_id, audit_id, registered_at, signature) "
            "VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP, %s)"
        )
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                insert, [uuid.uuid4(), self.org.pk, session.pk, event.pk, audit.pk, "a" * 64]
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23514")
        canonical = AccessEvent.objects.create(
            organization=self.org,
            source=SOURCE,
            external_id=self.source.id,
            occurred_at=self.source.started_at,
            ended_at=self.source.ended_at,
            method="TeamViewer",
            action="remote_session",
        )
        foreign = record(organization=self.other, action="fixture.foreign", summary="Other tenant")
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                insert, [uuid.uuid4(), self.org.pk, session.pk, canonical.pk, foreign.pk, "a" * 64]
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23503")
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "INSERT INTO access_accessevaluation "
                "(id, organization_id, event_id, audit_id, verdict, rule_version, findings, "
                "context, context_hash, signature, evaluated_at) "
                "VALUES (%s, %s, %s, %s, 'expected', 'access-context/7', '[]', '{}', "
                "%s, %s, CURRENT_TIMESTAMP)",
                [uuid.uuid4(), self.org.pk, canonical.pk, foreign.pk, "b" * 64, "a" * 64],
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23503")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL concurrent normalization")
@override_settings(CONNECTOR_ALLOWED_HOSTS=["webapi.teamviewer.com:443"])
class TeamViewerNormalizationRaceTests(
    SessionFixtureData, TeamViewerFixtureData, TransactionTestCase
):
    def setUp(self):
        self.setUpTestData()
        super().setUp()
        self.make_source()
        self.read()
        index_sessions(self.org)

    def test_two_workers_create_one_event_and_one_initial_analysis(self):
        barrier = Barrier(2)

        def run(_):
            close_old_connections()
            try:
                barrier.wait(10)
                return normalize_sessions(self.org)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(run, range(2))), [1, 1])
        self.assertEqual(AccessEvent.objects.count(), 1)
        self.assertEqual(TeamViewerAccessObservation.objects.count(), 1)
        self.assertEqual(AccessEvaluation.objects.count(), 1)
        self.assertTrue(verify_evaluation(AccessEvaluation.objects.get()))
        self.assertTrue(verify_chain(self.org))
