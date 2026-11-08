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
from django.utils import timezone

from platform_core.audit import record, verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import ModuleActivation, OrganizationMembership
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.connectors.teamviewer import ConnectionReport, ReportPage
from platform_modules.connectors.teamviewer_ingestion import process_collectors
from platform_modules.connectors.teamviewer_mapping import publish_mapping
from platform_modules.connectors.teamviewer_mapping_models import TeamViewerSighting
from platform_modules.connectors.teamviewer_models import TeamViewerReport, TeamViewerRun
from platform_modules.connectors.teamviewer_restoration import verify_evidence
from platform_modules.connectors.teamviewer_session_models import (
    TeamViewerSession,
    TeamViewerSessionEvidence,
)
from platform_modules.connectors.teamviewer_sessions import (
    index_sessions,
    process_sessions,
    resolve_session,
    verify_session,
    verify_session_evidence,
)
from platform_modules.identity.models import ExternalAccount, Identity, Resource
from tests.test_teamviewer_collection import TeamViewerFixture, TeamViewerFixtureData


class SessionFixtureData:
    def make_source(self):
        self.collector = self.save(self.draft(collect_notes=True))
        end = timezone.now().replace(microsecond=0) - timedelta(minutes=1)
        self.source = ConnectionReport(
            "54d71d96-c9dd-4539-8ca9-866dcb2480df",
            "u-session",
            "d-session",
            end - timedelta(minutes=20),
            end,
            "First note",
        )

    def read(self, source=None, collector=None):
        collector = collector or self.collector
        source = source or self.source
        self.enable(collector)
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
            return_value=ReportPage((source,), None, source.ended_at, True),
        ):
            process_collectors(self.org, limit=1)
        return (
            TeamViewerSighting.objects.filter(collector=collector)
            .select_related("run__audit", "report")
            .latest("run__audit__sequence")
        )

    def assign(self, sighting, kind, target=None, *, withdrawn=False):
        with recent_authentication(self.admin, self.org, time.time()):
            return publish_mapping(
                actor=self.admin,
                organization=self.org,
                collector_id=sighting.collector_id,
                sighting_id=sighting.pk,
                kind=kind,
                remote_ref=sighting.report.device_ref
                if kind == "device"
                else sighting.report.account_ref,
                target=target,
                withdrawn=withdrawn,
                valid_from=self.source.started_at,
                valid_until=self.source.ended_at,
                verification_reference="Administrative assignment fixture",
            )


class TeamViewerSessionTests(SessionFixtureData, TeamViewerFixture):
    def setUp(self):
        super().setUp()
        self.make_source()
        self.owner = Identity.objects.create(
            organization=self.org, name="Service owner", kind="service"
        )
        self.actor = Identity.objects.create(
            organization=self.org, name="Actual operator", kind="human"
        )
        self.device = Resource.objects.create(organization=self.org, name="Endpoint", kind="device")
        self.account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.owner,
            username="Shared support",
            system="TeamViewer",
            kind="service",
        )

    def session(self):
        return TeamViewerSession.objects.select_related(
            "audit", "origin__run__audit", "origin__report"
        ).get()

    def resolve(self):
        return resolve_session(self.session(), organization=self.org)

    def assign_all(self, sighting):
        for kind, target in (
            ("account", self.account),
            ("actor", self.actor),
            ("device", self.device),
        ):
            self.assign(sighting, kind, target)

    def test_index_is_bounded_idempotent_and_preserves_raw_data(self):
        self.read()
        before = dict(
            reports=list(TeamViewerReport.objects.values()),
            runs=list(TeamViewerRun.objects.values()),
            sightings=list(TeamViewerSighting.objects.values()),
        )
        self.assertEqual(index_sessions(self.org, limit=1), 1)
        self.assertEqual(index_sessions(self.org, limit=1), 0)
        session = self.session()
        self.assertTrue(verify_session(session))
        link = TeamViewerSessionEvidence.objects.select_related(
            "audit",
            "session__audit",
            "session__origin__run__audit",
            "session__origin__report",
            "sighting__run__audit",
            "sighting__report",
        ).get()
        self.assertTrue(verify_session_evidence(link))
        self.assertEqual(
            before,
            dict(
                reports=list(TeamViewerReport.objects.values()),
                runs=list(TeamViewerRun.objects.values()),
                sightings=list(TeamViewerSighting.objects.values()),
            ),
        )
        self.assertTrue(verify_chain(self.org))
        self.assertEqual(self.resolve().state, "unresolved")
        self.assertEqual(self.resolve().observations, 1)
        for invalid in (0, 101, True, "1"):
            with self.assertRaises(ValueError):
                index_sessions(self.org, limit=invalid)

    def test_note_corrections_and_return_to_prior_content_keep_one_session(self):
        sighting = self.read()
        self.assign_all(sighting)
        self.read(replace(self.source, notes="Corrected note"))
        self.read(self.source)
        self.assertEqual(index_sessions(self.org), 3)
        self.assertEqual(TeamViewerSession.objects.count(), 1)
        self.assertEqual(TeamViewerReport.objects.count(), 2)
        result = self.resolve()
        self.assertEqual(result.state, "resolved")
        self.assertEqual(result.observations, 3)
        self.assertEqual(len(result.variants), 2)
        self.assertEqual(result.dimensions["actor"].target.pk, self.actor.pk)
        self.assertNotEqual(result.dimensions["actor"].target.pk, self.owner.pk)
        self.assertIsNone(result.facts["remote_os_privilege"])
        self.assertIsNone(result.facts["observed_location"])

    def test_multiple_collectors_require_independent_attestations_not_reuse(self):
        first = self.read()
        self.assign_all(first)
        second_collector = self.save(self.draft(name="Second collector", collect_notes=True))
        second = self.read(collector=second_collector)
        index_sessions(self.org)
        self.assertEqual(TeamViewerSession.objects.count(), 1)
        self.assertEqual(self.resolve().dimensions["actor"].state, "partial")
        self.assign_all(second)
        self.assertEqual(self.resolve().state, "resolved")
        replacement = Identity.objects.create(
            organization=self.org, name="Another operator", kind="human"
        )
        self.assign(second, "actor", replacement)
        result = self.resolve()
        self.assertEqual(result.dimensions["actor"].state, "ambiguous")
        self.assertIsNone(result.dimensions["actor"].target)
        self.assertEqual(result.dimensions["device"].target.pk, self.device.pk)

    def test_token_rotation_does_not_inherit_the_previous_scope_mapping(self):
        first = self.read()
        self.assign_all(first)
        capsule = self.draft(
            collector_id=self.collector.pk, collect_notes=True, token="fixture-replaced-token"
        )
        self.collector = self.save(capsule, collector_id=self.collector.pk)
        second = self.read()
        index_sessions(self.org)
        self.assertEqual(TeamViewerSession.objects.count(), 1)
        self.assertEqual(TeamViewerReport.objects.count(), 1)
        self.assertEqual(self.resolve().dimensions["actor"].state, "partial")
        self.assign_all(second)
        self.assertEqual(self.resolve().state, "resolved")
        self.assign(second, "actor", withdrawn=True)
        self.assertEqual(self.resolve().dimensions["actor"].state, "ambiguous")

    def test_structural_source_changes_are_conflicts_not_new_physical_sessions(self):
        first = self.read()
        self.assign_all(first)
        changed = (
            replace(self.source, account_ref="different-operator"),
            replace(self.source, device_ref="different-device"),
            replace(self.source, started_at=self.source.started_at - timedelta(seconds=1)),
            replace(self.source, ended_at=self.source.ended_at + timedelta(seconds=1)),
        )
        for report in changed:
            self.read(report)
        index_sessions(self.org)
        result = self.resolve()
        self.assertEqual(TeamViewerSession.objects.count(), 1)
        self.assertEqual(result.state, "conflict")
        self.assertIsNone(result.facts)
        self.assertTrue(all(value.target is None for value in result.dimensions.values()))
        self.assertEqual(len(result.variants), 5)

    def test_missing_source_references_are_unknown_not_evidence_of_conflicting_ids(self):
        first = self.read()
        self.assign_all(first)
        self.read(replace(self.source, account_ref="", device_ref=""))
        index_sessions(self.org)
        result = self.resolve()
        self.assertEqual(result.state, "unresolved")
        self.assertIsNotNone(result.facts)
        self.assertTrue(all(value.target is None for value in result.dimensions.values()))

    def test_repeated_identical_reads_do_not_consume_variant_budget(self):
        self.read()
        self.read()
        self.read()
        index_sessions(self.org)
        with patch("platform_modules.connectors.teamviewer_sessions.MAX_VARIANTS", 1):
            result = self.resolve()
        self.assertEqual(result.state, "unresolved")
        self.assertEqual(result.observations, 3)
        self.assertEqual(len(result.variants), 1)
        self.read(replace(self.source, notes="Another semantic version"))
        index_sessions(self.org)
        with patch("platform_modules.connectors.teamviewer_sessions.MAX_VARIANTS", 1):
            result = self.resolve()
        self.assertEqual(result.state, "limit")
        self.assertIsNone(result.facts)

    def test_disabled_collector_history_remains_readable_and_mapping_never_reactivates_identity(
        self,
    ):
        sighting = self.read()
        self.assign_all(sighting)
        index_sessions(self.org)
        self.enable(self.collector, False)
        Identity.objects.filter(pk=self.actor.pk).update(status="departed")
        result = self.resolve()
        self.assertEqual(result.dimensions["actor"].target.status, "departed")
        self.actor.refresh_from_db()
        self.assertEqual(self.actor.status, "departed")

    def test_proofs_reject_wrong_keys_and_modified_session_or_link(self):
        self.read()
        index_sessions(self.org)
        session = self.session()
        with override_settings(SECRET_KEY="wrong-fixture-key"):
            self.assertFalse(verify_session(session))
            self.assertEqual(self.resolve().state, "invalid")
            with self.assertRaises(RuntimeError):
                verify_evidence()
        session.remote_id = uuid.uuid4()
        self.assertFalse(verify_session(session))
        evidence = TeamViewerSessionEvidence.objects.select_related(
            "audit",
            "session__audit",
            "session__origin__run__audit",
            "session__origin__report",
            "sighting__run__audit",
            "sighting__report",
        ).get()
        evidence.signature = "x" * 64
        self.assertFalse(verify_session_evidence(evidence))

    def test_restore_verifies_all_links_even_when_current_view_deduplicates_reads(self):
        for _ in range(3):
            self.read()
        before = verify_evidence()
        index_sessions(self.org)
        after = verify_evidence()
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1] - before[1], 4)
        self.assertTrue(verify_chain(self.org))

    def test_module_disabled_or_wrong_tenant_denies_processing_and_resolution(self):
        self.read()
        index_sessions(self.org)
        with organization_context(self.other), self.assertRaises(PermissionDenied):
            resolve_session(self.session_for_other_context(), organization=self.org)
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        self.assertEqual(process_sessions(self.org), 0)
        with self.assertRaises(PermissionDenied):
            self.resolve()

    def session_for_other_context(self):
        return TeamViewerSession.unscoped.get(organization=self.org)

    def test_same_provider_session_identifier_is_never_merged_across_organizations(self):
        self.read()
        index_sessions(self.org)
        first = self.session()
        OrganizationMembership.objects.create(
            organization=self.other, account=self.other_admin, role="admin"
        )
        with organization_context(self.other):
            for key in ("identity", "access", "approvals", "connectors"):
                install_module(key, actor=self.other_admin, organization=self.other)
            with (
                patch.object(self, "org", self.other),
                patch.object(self, "admin", self.other_admin),
            ):
                self.make_source()
                self.read()
                index_sessions(self.org)
                second = self.session()
                self.assertNotEqual(first.pk, second.pk)
                self.assertEqual(first.remote_id, second.remote_id)
                self.assertEqual(TeamViewerSession.objects.count(), 1)
        self.assertEqual(TeamViewerSession.objects.count(), 1)
        self.assertEqual(TeamViewerSession.unscoped.count(), 2)

    def test_invalid_source_aborts_index_without_creating_partial_session_or_audit(self):
        self.read()
        self.org.refresh_from_db()
        head = self.org.audit_sequence
        with patch(
            "platform_modules.connectors.teamviewer_sessions.verify_run", return_value=False
        ):
            with self.assertRaises(ValidationError):
                index_sessions(self.org)
            with self.assertLogs(
                "platform_modules.connectors.teamviewer_sessions", level="WARNING"
            ):
                self.assertEqual(process_sessions(self.org), 0)
        self.assertFalse(TeamViewerSession.objects.exists())
        self.assertFalse(TeamViewerSessionEvidence.objects.exists())
        self.org.refresh_from_db()
        self.assertEqual(self.org.audit_sequence, head)
        self.assertTrue(verify_chain(self.org))

    def test_native_session_pages_require_personal_mfa_and_current_org(self):
        self.read()
        index_sessions(self.org)
        client = Client()
        client.force_login(self.admin)
        session = client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()
        url = reverse("teamviewer-session", args=[self.session().pk])
        self.assertContains(
            client.get(reverse("teamviewer-sessions")), "Sessions TeamViewer regroupées"
        )
        page = client.get(url)
        self.assertContains(page, "Session TeamViewer")
        self.assertEqual(page["Cache-Control"], "no-store")
        self.assertContains(page, "reste à livrer")
        session = client.session
        session["mfa_verified_at"] = 0
        session.save()
        self.assertRedirects(
            client.get(url), reverse("account-security"), fetch_redirect_response=False
        )
        self.assertEqual(
            client.get(reverse("teamviewer-session", args=[uuid.uuid4()])).status_code, 404
        )

    def test_orm_evidence_is_immutable(self):
        self.read()
        index_sessions(self.org)
        for model in (TeamViewerSession, TeamViewerSessionEvidence):
            item = model.objects.get()
            with self.assertRaises(ValidationError):
                item.save()
            with self.assertRaises(ValidationError):
                item.delete()
            with self.assertRaises(ValidationError):
                model.objects.update(signature="modified")

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL source and tenant guards")
    def test_sql_scope_source_and_immutable_guards(self):
        self.read()
        index_sessions(self.org)
        session = self.session()
        for model in (TeamViewerSession, TeamViewerSessionEvidence):
            for operation in (
                f"UPDATE {model._meta.db_table} SET signature='modified'",
                f"DELETE FROM {model._meta.db_table}",
            ):
                with (
                    self.assertRaises(DatabaseError),
                    transaction.atomic(),
                    connection.cursor() as cursor,
                ):
                    cursor.execute(operation)
        # Reuse the raw INSERT harness, not ORM validation; new IDs/audits avoid
        # uniqueness violations masking the source-scope guard under test.
        from tests.test_teamviewer_mapping import TeamViewerMappingTests

        audit = record(organization=self.org, action="fixture", summary="Constraint fixture")
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "INSERT INTO connectors_teamviewersession "
                "(id, remote_id, registered_at, signature, audit_id, organization_id, origin_id) "
                "SELECT %s, %s, registered_at, signature, %s, organization_id, origin_id "
                "FROM connectors_teamviewersession WHERE id=%s",
                [uuid.uuid4(), uuid.uuid4(), audit.pk, session.pk],
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23514")
        # Use a fresh source ID and origin to avoid unique constraints masking a
        # different-organization audit relation. The source trigger must pass first.
        new_source = replace(self.source, id=str(uuid.uuid4()))
        witness = self.read(new_source)
        foreign_audit = record(organization=self.other, action="fixture", summary="Foreign fixture")
        TeamViewerMappingTests.assert_bad_insert(
            self,
            TeamViewerSession,
            session.pk,
            dict(
                id=uuid.uuid4(),
                remote_id=uuid.UUID(new_source.id),
                origin_id=witness.pk,
                audit_id=foreign_audit.pk,
            ),
        )

        link = TeamViewerSessionEvidence.objects.get()
        another_audit = record(organization=self.org, action="fixture", summary="Second constraint")
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "INSERT INTO connectors_teamviewersessionevidence "
                "(id, registered_at, signature, audit_id, organization_id, "
                "session_id, sighting_id) "
                "SELECT %s, registered_at, signature, %s, organization_id, session_id, %s "
                "FROM connectors_teamviewersessionevidence WHERE id=%s",
                [uuid.uuid4(), another_audit.pk, witness.pk, link.pk],
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23514")

    def test_pending_observations_prevent_premature_session_resolution(self):
        first = self.read()
        self.assign_all(first)
        index_sessions(self.org)
        self.assertEqual(self.resolve().state, "resolved")
        self.read(replace(self.source, device_ref="changed-while-index-is-pending"))
        pending = self.resolve()
        self.assertEqual(pending.state, "pending")
        self.assertIsNone(pending.facts)
        self.assertTrue(all(value.target is None for value in pending.dimensions.values()))
        index_sessions(self.org)
        self.assertEqual(self.resolve().state, "conflict")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL concurrent physical session indexing")
@override_settings(CONNECTOR_ALLOWED_HOSTS=["webapi.teamviewer.com:443"])
class TeamViewerSessionRaceTests(SessionFixtureData, TeamViewerFixtureData, TransactionTestCase):
    def setUp(self):
        self.setUpTestData()
        super().setUp()
        self.make_source()
        self.read()

    def test_two_indexers_do_not_duplicate_session_or_observation(self):
        barrier = Barrier(2)

        def run(_):
            close_old_connections()
            try:
                barrier.wait(10)
                return index_sessions(self.org)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(run, range(2))), [0, 1])
        self.assertEqual(TeamViewerSession.objects.count(), 1)
        self.assertEqual(TeamViewerSessionEvidence.objects.count(), 1)
        self.assertTrue(verify_session(TeamViewerSession.objects.get()))
        self.assertTrue(verify_chain(self.org))
