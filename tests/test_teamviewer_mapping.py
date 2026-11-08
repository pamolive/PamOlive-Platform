import time
import uuid
from concurrent.futures import ThreadPoolExecutor
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
from platform_core.models import Organization, OrganizationMembership
from platform_core.tenancy import organization_context
from platform_modules.connectors.teamviewer import ConnectionReport, ReportPage
from platform_modules.connectors.teamviewer_ingestion import process_collectors
from platform_modules.connectors.teamviewer_mapping import (
    publish_mapping,
    resolve_sighting,
    verify_mapping,
)
from platform_modules.connectors.teamviewer_mapping_models import (
    TeamViewerMapping,
    TeamViewerSighting,
)
from platform_modules.connectors.teamviewer_models import TeamViewerReport, TeamViewerRun
from platform_modules.connectors.teamviewer_restoration import verify_evidence
from platform_modules.connectors.teamviewer_sightings import backfill_sightings, verify_sighting
from platform_modules.identity.models import ExternalAccount, Identity, Resource
from tests.test_teamviewer_collection import TeamViewerFixture, TeamViewerFixtureData

DEFAULT_TARGET = object()


class TeamViewerMappingTests(TeamViewerFixture):
    def setUp(self):
        super().setUp()
        self.collector = self.enable(self.save())
        self.end = timezone.now().replace(microsecond=0) - timedelta(minutes=1)
        self.begin = self.end - timedelta(minutes=30)
        self.person = Identity.objects.create(organization=self.org, name="Operator", kind="human")
        self.service = Identity.objects.create(
            organization=self.org, name="Service owner", kind="service"
        )
        self.account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.service,
            username="support-shared",
            system="TeamViewer",
            kind="service",
        )
        self.device = Resource.objects.create(
            organization=self.org, name="Workstation", kind="device"
        )
        source = ConnectionReport(
            "fdceff76-9eaf-4479-a077-e7aedff53236",
            "u123",
            "d456",
            self.begin,
            self.end,
            "A note is not a ticket",
        )
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
            return_value=ReportPage((source,), None, source.ended_at, True),
        ):
            process_collectors(self.org)
        self.sighting = TeamViewerSighting.objects.select_related("run__audit", "report").get()

    def publish(self, kind="actor", target=DEFAULT_TARGET, **changes):
        values = dict(
            actor=self.admin,
            organization=self.org,
            collector_id=self.collector.pk,
            kind=kind,
            remote_ref="d456" if kind == "device" else "u123",
            valid_from=self.begin,
            valid_until=self.end,
            verification_reference="ASSIGNMENT-verified-42",
            target={"actor": self.person, "account": self.account, "device": self.device}[kind]
            if target is DEFAULT_TARGET
            else target,
            sighting_id=self.sighting.pk,
        )
        values.update(changes)
        with recent_authentication(self.admin, self.org, time.time()):
            return publish_mapping(**values)

    def resolved(self, sighting=None):
        return resolve_sighting(sighting or self.sighting, organization=self.org)

    def test_observation_links_exact_run_revision_and_signature(self):
        self.assertTrue(verify_sighting(self.sighting))
        self.assertEqual(self.sighting.run.revision, self.collector.revision)
        self.assertEqual(self.sighting.run.config_hash, self.collector.config_hash)
        self.sighting.report_id = None
        self.assertFalse(verify_sighting(self.sighting))

    def test_unknown_ids_stay_unmapped_and_account_owner_is_never_actor(self):
        result = self.resolved()
        self.assertEqual(result["actor"].state, "unmapped")
        self.publish(kind="account")
        self.publish(kind="device")
        result = self.resolved()
        self.assertEqual(result["account"].target.pk, self.account.pk)
        self.assertEqual(result["device"].target.pk, self.device.pk)
        self.assertIsNone(result["actor"].target)
        self.assertFalse(result["actor_inferred_from_owner"])
        self.assertIsNone(result["remote_os_privilege"])
        self.assertEqual(result["normalized_access_events"], 0)

    def test_explicit_actor_assignment_is_independent_of_account_ownership(self):
        account = self.publish(kind="account")
        actor = self.publish()
        result = self.resolved()
        self.assertEqual(result["actor"].target.pk, self.person.pk)
        self.assertNotEqual(result["actor"].target.pk, self.account.identity_id)
        self.assertEqual(
            result["actor_provenance"], "explicit_mapping_attestation_not_authentication_proof"
        )
        self.assertTrue(verify_mapping(account))
        self.assertTrue(verify_mapping(actor))
        self.assertTrue(verify_chain(self.org))

    def test_service_requires_role_recent_mfa_and_matching_tenant_context(self):
        values = dict(
            actor=self.admin,
            organization=self.org,
            collector_id=self.collector.pk,
            kind="actor",
            remote_ref="u123",
            target=self.person,
            valid_from=self.begin,
            verification_reference="proof",
        )
        with self.assertRaises(PermissionDenied):
            publish_mapping(**values)
        with (
            organization_context(self.other),
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            publish_mapping(**values)
        OrganizationMembership.objects.filter(organization=self.org, account=self.admin).update(
            role="operator"
        )
        with (
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            publish_mapping(**values)
        self.assertFalse(TeamViewerMapping.objects.exists())

    def test_windows_account_door_wrong_target_type_and_foreign_target_are_rejected(self):
        windows = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.person,
            username="administrator",
            system="Windows",
            kind="privileged",
        )
        door = Resource.objects.create(organization=self.org, name="Door", kind="door")
        with organization_context(self.other):
            foreign = Identity.objects.create(organization=self.other, name="Foreign", kind="human")
        for kind, target in (
            ("account", windows),
            ("device", door),
            ("actor", self.account),
            ("actor", foreign),
        ):
            with self.subTest(kind=kind), self.assertRaises(ValidationError):
                self.publish(kind=kind, target=target)
        self.assertFalse(TeamViewerMapping.objects.exists())

    def test_correction_and_withdrawal_append_without_rewriting_reports_or_statements(self):
        original = self.publish()
        report_before = TeamViewerReport.objects.values().get()
        before = TeamViewerMapping.objects.values().get(pk=original.pk)
        second = Identity.objects.create(
            organization=self.org, name="Corrected attribution", kind="human"
        )
        corrected = self.publish(target=second)
        self.assertEqual(corrected.sequence, 2)
        self.assertEqual(self.resolved()["actor"].target.pk, second.pk)
        self.publish(target=None, withdrawn=True)
        self.assertEqual(self.resolved()["actor"].state, "withdrawn")
        self.assertEqual(TeamViewerMapping.objects.values().get(pk=original.pk), before)
        self.assertEqual(TeamViewerReport.objects.values().get(), report_before)

    def test_changes_during_session_never_assign_a_single_actor_to_the_whole_period(self):
        self.publish()
        other = Identity.objects.create(organization=self.org, name="Other operator", kind="human")
        self.publish(
            target=other,
            valid_from=self.begin + timedelta(minutes=10),
            valid_until=self.begin + timedelta(minutes=20),
        )
        result = self.resolved()["actor"]
        self.assertEqual(result.state, "ambiguous")
        self.assertIsNone(result.target)
        self.assertEqual(len(result.segments), 3)
        self.assertEqual(result.segments[0]["target"], result.segments[2]["target"])
        self.assertNotEqual(result.segments[0]["target"], result.segments[1]["target"])

    def test_partial_window_and_exact_half_open_boundaries(self):
        self.publish(valid_until=self.begin + timedelta(minutes=15))
        self.assertEqual(self.resolved()["actor"].state, "partial")
        self.publish(valid_from=self.begin + timedelta(minutes=15))
        self.assertEqual(self.resolved()["actor"].state, "mapped")
        self.assertEqual(len(self.resolved()["actor"].statements), 2)
        self.publish(
            valid_from=self.end,
            valid_until=self.end + timedelta(hours=1),
            withdrawn=True,
            target=None,
        )
        self.assertEqual(self.resolved()["actor"].state, "mapped")

    def test_revision_fence_prevents_new_token_configuration_reusing_old_mapping(self):
        original = self.publish()
        self.collector = self.enable(
            self.save(
                self.draft(collector_id=self.collector.pk, token="another-company-fixture-token"),
                collector_id=self.collector.pk,
            )
        )
        source = ConnectionReport(
            str(self.sighting.report.remote_id),
            "u123",
            "d456",
            self.begin,
            self.end,
            "A note is not a ticket",
        )
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
            return_value=ReportPage((source,), None, source.ended_at, True),
        ):
            process_collectors(self.org)
        new = TeamViewerSighting.objects.select_related("run__audit", "report").latest(
            "run__audit__sequence"
        )
        self.assertEqual(TeamViewerReport.objects.count(), 1)
        self.assertEqual(new.run.revision, 2)
        self.assertEqual(self.resolved(new)["actor"].state, "unmapped")
        self.assertEqual(self.resolved()["actor"].target.pk, self.person.pk)
        statement = self.publish(sighting_id=new.pk)
        self.assertEqual(statement.source_revision, 2)
        self.assertEqual(original.source_revision, 1)
        self.assertEqual(self.resolved(new)["actor"].target.pk, self.person.pk)

    def test_changed_target_classification_needs_review_but_new_statement_can_correct_it(self):
        first = self.publish(kind="device")
        Resource.objects.filter(pk=self.device.pk).update(kind="door")
        self.assertFalse(verify_mapping(first))
        self.assertTrue(verify_mapping(first, check_target=False))
        self.assertEqual(self.resolved()["device"].state, "invalid")
        new = Resource.objects.create(organization=self.org, name="Correct endpoint", kind="server")
        self.publish(kind="device", target=new)
        self.assertEqual(self.resolved()["device"].target.pk, new.pk)

    def test_invalid_inputs_and_audit_failure_never_publish_partial_statement(self):
        for changes in (
            dict(valid_from=self.begin.replace(tzinfo=None)),
            dict(valid_until=self.begin),
            dict(remote_ref=" u123 "),
            dict(verification_reference=""),
            dict(withdrawn=True),
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.publish(**changes)
        with (
            patch(
                "platform_modules.connectors.teamviewer_mapping.record",
                side_effect=ValidationError("fixture"),
            ),
            self.assertRaises(ValidationError),
        ):
            self.publish()
        self.assertFalse(TeamViewerMapping.objects.exists())

    def test_tampered_signatures_or_mfa_proofs_are_not_resolved(self):
        item = self.publish()
        for field, value in (
            ("signature", "x" * 64),
            ("mfa_window_minutes", 0),
            ("mfa_verified_at", item.published_at + timedelta(seconds=1)),
            ("source_config_hash", "f" * 64),
        ):
            original = getattr(item, field)
            setattr(item, field, value)
            self.assertFalse(verify_mapping(item))
            setattr(item, field, original)
        with override_settings(SECRET_KEY="wrong-signing-key"), self.assertRaises(ValidationError):
            self.resolved()

    def test_evidence_cannot_be_rewritten_or_deleted_by_orm(self):
        mapping = self.publish()
        for item in (mapping, self.sighting):
            with self.assertRaises(ValidationError):
                item.save()
            with self.assertRaises(ValidationError):
                item.delete()
            with self.assertRaises(ValidationError):
                type(item).objects.filter(pk=item.pk).update(signature="fake")

    def test_offline_restore_verifies_sightings_and_mapping_proofs(self):
        self.publish()
        encrypted, signed = verify_evidence()
        self.assertEqual(encrypted, 1)
        self.assertGreaterEqual(signed, 6)

    def test_nhi_attribution_is_explicit_and_does_not_require_a_human_owner(self):
        self.publish(target=self.service)
        self.assertEqual(self.resolved()["actor"].target.kind, "service")
        self.assertEqual(self.resolved()["actor"].target.pk, self.service.pk)

    def test_retired_identity_can_be_mapped_for_historical_observation_without_reactivation(self):
        Identity.objects.filter(pk=self.person.pk).update(status="departed")
        self.publish()
        self.assertEqual(self.resolved()["actor"].target.status, "departed")
        self.person.refresh_from_db()
        self.assertEqual(self.person.status, "departed")

    def test_too_many_partial_statements_stay_unknown_but_one_new_full_attestation_recovers(self):
        for offset in range(65):
            self.publish(
                valid_from=self.begin + timedelta(seconds=offset),
                valid_until=self.begin + timedelta(seconds=offset + 1),
            )
        self.assertEqual(self.resolved()["actor"].state, "limit")
        self.publish()
        self.assertEqual(self.resolved()["actor"].state, "mapped")

    def browser_client(self, fresh=True):
        client = Client()
        client.force_login(self.admin)
        session = client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time() if fresh else 0
        session.save()
        return client

    def test_native_form_publishes_mapping_and_report_preview_uses_it(self):
        client = self.browser_client()
        url = reverse("teamviewer-mapping-new", args=[self.collector.pk, "actor"])
        page = client.get(url, {"sighting": str(self.sighting.pk)})
        self.assertContains(page, "Publier cette attestation datée")
        self.assertEqual(page.context["form"].initial["remote_ref"], "u123")
        result = client.post(
            url,
            dict(
                source_sighting=str(self.sighting.pk),
                remote_ref="u123",
                target=str(self.person.pk),
                valid_from=self.begin.isoformat(),
                valid_until=self.end.isoformat(),
                verification_reference="HUMAN-verified-13",
            ),
        )
        self.assertRedirects(result, reverse("teamviewer-mappings", args=[self.collector.pk]))
        page = client.get(reverse("teamviewer-report", args=[self.sighting.report_id]))
        self.assertContains(page, "Résolution explicite des identifiants")
        actor = next(item for item in page.context["preview"] if item["kind"] == "actor")
        self.assertEqual(actor["result"].target.pk, self.person.pk)
        self.assertContains(page, "ne crée pas encore d’événement d’accès corrélé")
        self.assertEqual(page["Cache-Control"], "no-store")

    def test_native_post_mfa_challenge_preserves_action_without_publishing(self):
        client = self.browser_client(fresh=False)
        url = reverse("teamviewer-mapping-new", args=[self.collector.pk, "actor"])
        result = client.post(
            url,
            dict(
                remote_ref="u123",
                target=str(self.person.pk),
                valid_from=self.begin.isoformat(),
                verification_reference="pending",
            ),
        )
        self.assertRedirects(result, reverse("account-security"), fetch_redirect_response=False)
        self.assertFalse(TeamViewerMapping.objects.exists())
        self.assertIn("post_mfa_action", client.session)

    def test_native_source_scope_and_invalid_paths_are_closed(self):
        client = self.browser_client()
        for url in (
            reverse("teamviewer-mapping-new", args=[self.collector.pk, "unknown"]),
            reverse("teamviewer-mappings", args=[uuid.uuid4()]),
        ):
            self.assertEqual(client.get(url).status_code, 404)
        url = reverse("teamviewer-report", args=[self.sighting.report_id])
        self.assertEqual(client.get(url, {"sighting": "invalid"}).status_code, 404)
        self.assertEqual(client.get(url, {"sighting": str(uuid.uuid4())}).status_code, 404)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL composite source and tenant keys")
    def test_database_rejects_foreign_mapping_target_and_mixed_collector_sighting(self):
        mapping = self.publish()
        with organization_context(self.other):
            foreign = Identity.objects.create(organization=self.other, name="Foreign", kind="human")
        audit = record(
            organization=self.org,
            actor=self.admin,
            action="fixture.mapping.sql",
            summary="Constraint fixture",
        )
        overrides = dict(id=uuid.uuid4(), identity_id=foreign.pk, audit_id=audit.pk, sequence=2)
        self.assert_bad_insert(TeamViewerMapping, mapping.pk, overrides)
        second = self.save()
        self.enable(second)
        source = ConnectionReport(str(uuid.uuid4()), "u123", "d456", self.begin, self.end, "")
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
            return_value=ReportPage((source,), None, source.ended_at, True),
        ):
            process_collectors(self.org)
        report = TeamViewerReport.objects.get(collector=second)
        self.assert_bad_insert(
            TeamViewerSighting, self.sighting.pk, dict(id=uuid.uuid4(), report_id=report.pk)
        )

    def assert_bad_insert(self, model, source_id, overrides):
        quote = connection.ops.quote_name
        columns = [field.attname for field in model._meta.concrete_fields]
        values, expressions = [], []
        for column in columns:
            expressions.append("%s" if column in overrides else quote(column))
            if column in overrides:
                values.append(overrides[column])
        values.append(source_id)
        sql = (
            f"INSERT INTO {quote(model._meta.db_table)} ({', '.join(map(quote, columns))}) "
            f"SELECT {', '.join(expressions)} FROM {quote(model._meta.db_table)} WHERE id = %s"
        )
        with self.assertRaises(DatabaseError) as raised:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(sql, values)
        self.assertEqual(raised.exception.__cause__.sqlstate, "23503")

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL evidence guards")
    def test_sql_cannot_update_or_delete_mapping_and_sighting(self):
        self.publish()
        for table in ("connectors_teamviewermapping", "connectors_teamviewersighting"):
            for sql in (f"UPDATE {table} SET signature = 'fake'", f"DELETE FROM {table}"):
                with (
                    self.subTest(sql=sql),
                    self.assertRaises(DatabaseError),
                    transaction.atomic(),
                    connection.cursor() as cursor,
                ):
                    cursor.execute(sql)

    def test_sighting_backfill_does_not_change_original_report_or_run(self):
        report_before = TeamViewerReport.objects.values().get()
        # Simulate a pre-0005 run by suppressing only the derived link creation.
        source = ConnectionReport(
            "784d38ed-f3d1-4f29-b7b3-1f4223b3192d", "u123", "d456", self.begin, self.end, ""
        )
        self.enable(self.collector)
        with (
            patch("platform_modules.connectors.teamviewer_sightings._retain_sightings"),
            patch(
                "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
                return_value=ReportPage((source,), None, source.ended_at, True),
            ),
        ):
            process_collectors(self.org)
        run = TeamViewerRun.objects.latest("audit__sequence")
        run_before = TeamViewerRun.objects.values().get(pk=run.pk)
        self.assertFalse(TeamViewerSighting.objects.filter(run=run).exists())
        self.assertEqual(backfill_sightings(self.org), 1)
        self.assertEqual(backfill_sightings(self.org), 0)
        link = TeamViewerSighting.objects.select_related("run__audit", "report").get(run=run)
        self.assertTrue(verify_sighting(link))
        self.assertEqual(TeamViewerRun.objects.values().get(pk=run.pk), run_before)
        self.assertEqual(
            TeamViewerReport.objects.values().get(pk=self.sighting.report_id), report_before
        )


@skipUnless(connection.vendor == "postgresql", "PostgreSQL concurrent mapping publication")
@override_settings(CONNECTOR_ALLOWED_HOSTS=["webapi.teamviewer.com:443"])
class TeamViewerMappingRaceTests(TeamViewerFixtureData, TransactionTestCase):
    def setUp(self):
        self.setUpTestData()
        super().setUp()
        self.collector = self.save()
        self.person = Identity.objects.create(
            organization=self.org, name="Concurrent actor", kind="human"
        )

    def test_concurrent_attestations_receive_distinct_monotonic_revisions(self):
        barrier = Barrier(2)

        def publish(number):
            close_old_connections()
            try:
                with (
                    organization_context(self.org),
                    recent_authentication(self.admin, self.org, time.time()),
                ):
                    barrier.wait(10)
                    item = publish_mapping(
                        actor=self.admin,
                        organization=self.org,
                        collector_id=self.collector.pk,
                        kind="actor",
                        remote_ref="u-race",
                        target=self.person,
                        valid_from=self.start,
                        verification_reference=f"Concurrent attestation {number}",
                    )
                    return item.sequence
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(publish, range(2)))
        self.assertEqual(sorted(results), [1, 2])
        self.assertEqual(TeamViewerMapping.objects.count(), 2)
        self.assertTrue(
            all(
                verify_mapping(item)
                for item in TeamViewerMapping.objects.select_related("audit", "collector")
            )
        )
        self.assertTrue(verify_chain(self.org))

    def test_resolution_holds_the_publication_lock_for_all_three_dimensions(self):
        self.enable(self.collector)
        end = timezone.now() - timedelta(minutes=1)
        source = ConnectionReport(
            str(uuid.uuid4()), "u-race", "d-race", end - timedelta(minutes=5), end, ""
        )
        with patch(
            "platform_modules.connectors.teamviewer.TeamViewerClient.read_page",
            return_value=ReportPage((source,), None, source.ended_at, True),
        ):
            process_collectors(self.org)
        sighting = TeamViewerSighting.objects.select_related("run__audit", "report").get()

        def can_lock_organization():
            close_old_connections()
            try:
                with transaction.atomic():
                    Organization.objects.select_for_update(nowait=True).get(pk=self.org.pk)
                return True
            except DatabaseError as error:
                self.assertEqual(error.__cause__.sqlstate, "55P03")
                return False
            finally:
                connections.close_all()

        from platform_modules.connectors.teamviewer_mapping import _resolve

        checked = []
        with ThreadPoolExecutor(max_workers=1) as pool:
            self.assertTrue(pool.submit(can_lock_organization).result(timeout=10))

            def resolve_dimension(*args):
                checked.append(args[1])
                self.assertFalse(pool.submit(can_lock_organization).result(timeout=10))
                return _resolve(*args)

            with patch(
                "platform_modules.connectors.teamviewer_mapping._resolve",
                side_effect=resolve_dimension,
            ):
                resolve_sighting(sighting, organization=self.org)
            self.assertTrue(pool.submit(can_lock_organization).result(timeout=10))
        self.assertEqual(checked, ["account", "actor", "device"])
