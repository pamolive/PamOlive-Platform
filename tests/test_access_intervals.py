"""Completed observations are not authorized only at their first or last instant."""

import json
from datetime import UTC, datetime, time, timedelta
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import record, verify_chain
from platform_core.models import ModuleActivation, Organization
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvaluation, AccessEvent, AccessIntent
from platform_modules.access.services import ingest_event, reevaluate_event
from platform_modules.access.temporal import MAX_SEGMENTS
from platform_modules.connectors.models import EventSource
from platform_modules.connectors.services import create_source
from platform_modules.governance.models import (
    ApprovalPolicyRevision,
    ContractParticipant,
    ContractRevision,
    ContractScope,
    SeparationRule,
    Supplier,
    SupplierContract,
)
from platform_modules.identity.models import (
    Credential,
    ExternalAccount,
    Grant,
    Identity,
    IdentityStateChange,
    Resource,
)
from platform_modules.intelligence.coverage import event_timeline
from platform_modules.intelligence.models import (
    CollectionReport,
    CollectionScope,
    ContextLink,
    GraphNode,
    NetworkPlacement,
)
from platform_modules.intelligence.projection import investigate
from tests.test_extension_upgrade import historical_targets


class AccessIntervalTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.start = datetime(2026, 1, 5, 10, tzinfo=UTC)
        cls.end = cls.start + timedelta(minutes=30)
        cls.before = cls.start - timedelta(days=1)
        cls.admin = get_user_model().objects.create_superuser("interval-admin")
        cls.org = Organization.objects.create(key="interval-one", name="Interval one")
        cls.other = Organization.objects.create(key="interval-two", name="Interval two")
        ModuleActivation.objects.bulk_create(
            [
                ModuleActivation(organization=cls.org, module_key=key, version="test", enabled=True)
                for key in (
                    "identity",
                    "access",
                    "approvals",
                    "connectors",
                    "governance",
                    "intelligence",
                )
            ]
        )
        with organization_context(cls.org):
            with patch("django.utils.timezone.now", return_value=cls.before):
                cls.person = Identity.objects.create(
                    organization=cls.org, name="Intervenante", kind="human"
                )
            cls.resource = Resource.objects.create(
                organization=cls.org, name="Workstation", kind="device"
            )
            cls.account = ExternalAccount.objects.create(
                organization=cls.org, identity=cls.person, username="operator", system="TeamViewer"
            )

    def setUp(self):
        context = organization_context(self.org)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def intent(self, **changes):
        with patch("django.utils.timezone.now", return_value=self.before):
            return AccessIntent.objects.create(
                **(
                    dict(
                        organization=self.org,
                        identity=self.person,
                        account=self.account,
                        resource=self.resource,
                        method="TeamViewer",
                        privilege="support",
                        reason="Intervention déclarée",
                        reference="CHG-interval",
                        starts_at=self.start,
                        ends_at=self.end,
                        requested_by=self.admin,
                        status="approved",
                        approved_at=self.before,
                    )
                    | changes
                )
            )

    def grant(self, **changes):
        with patch("django.utils.timezone.now", return_value=self.before):
            return Grant.objects.create(
                **(
                    dict(
                        organization=self.org,
                        identity=self.person,
                        account=self.account,
                        resource=self.resource,
                        entitlement="support",
                        justification="Support duty",
                        valid_from=self.before,
                        method="TeamViewer",
                        status="active",
                    )
                    | changes
                )
            )

    def observed(self, **changes):
        return ingest_event(
            dict(
                source="interval-fixture",
                external_id=str(AccessEvent.objects.count()),
                occurred_at=self.start,
                ended_at=self.end,
                identity=self.person,
                account=self.account,
                resource=self.resource,
                method="TeamViewer",
                privilege="support",
                domain="remote",
                action="session.completed",
            )
            | changes,
            organization=self.org,
            actor=self.admin,
        )[0]

    def evaluation(self, event):
        return event.evaluations.latest("evaluated_at")

    def contract(self, **changes):
        supplier = Supplier.objects.create(organization=self.org, name="Supplier")
        contract = SupplierContract.objects.create(
            organization=self.org, supplier=supplier, name="Contract", reference="SUP-1"
        )
        revision = self.revision(contract, 1, self.before, **changes)
        ContractParticipant.objects.create(
            organization=self.org,
            contract=contract,
            identity=self.person,
            valid_from=self.before,
            valid_until=self.start + timedelta(days=4),
            registered_by=self.admin,
        )
        return contract, revision

    def revision(self, contract, sequence, effective, **changes):
        revision = ContractRevision.objects.create(
            **(
                dict(
                    organization=self.org,
                    contract=contract,
                    sequence=sequence,
                    effective_at=effective,
                    starts_at=self.before,
                    ends_at=self.start + timedelta(days=4),
                    sponsor=self.admin,
                    timezone_name="UTC",
                    weekdays=list(range(7)),
                    daily_start=time(0),
                    daily_end=time(0),
                    allowed_methods=["TeamViewer"],
                    allowed_countries=[],
                    physical_allowed=False,
                    require_reference=False,
                    published_by=self.admin,
                    authorization_at=effective,
                )
                | changes
            )
        )
        ContractScope.objects.create(
            organization=self.org,
            revision=revision,
            resource=self.resource,
            privilege="support",
            locations=[],
        )
        return revision

    def test_one_authorization_covers_the_whole_half_open_session(self):
        intent = self.intent()
        event = self.observed()
        evaluation = self.evaluation(event)
        self.assertEqual(evaluation.verdict, "expected")
        self.assertEqual(evaluation.intent_id, intent.pk)
        self.assertEqual(evaluation.rule_version, "access-context/7")
        intervals = [item for item in evaluation.findings if item["code"] == "observed_interval"]
        self.assertEqual(len(intervals), 1)
        self.assertTrue(verify_chain(self.org))

    def test_grant_expiring_inside_session_does_not_justify_its_remainder(self):
        middle = self.start + timedelta(minutes=15)
        self.grant(expires_at=middle)
        evaluation = self.evaluation(self.observed())
        self.assertEqual(evaluation.verdict, "unknown")
        unknown = [item for item in evaluation.findings if item["state"] == "unknown"]
        self.assertTrue(any(item.get("interval_start") == middle.isoformat() for item in unknown))

    def test_adjacent_grants_cover_period_without_an_artificial_endpoint_gap(self):
        middle = self.start + timedelta(minutes=15)
        self.grant(expires_at=middle)
        self.grant(valid_from=middle, expires_at=self.end)
        evaluation = self.evaluation(self.observed())
        self.assertEqual(evaluation.verdict, "expected")
        self.assertIsNone(evaluation.intent_id)

    def test_late_approval_is_not_retroactive_for_first_half(self):
        middle = self.start + timedelta(minutes=15)
        self.intent(approved_at=middle)
        evaluation = self.evaluation(self.observed())
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertIsNone(evaluation.intent_id)
        self.assertTrue(
            any(
                item.get("interval_start") == self.start.isoformat() and item["state"] == "unknown"
                for item in evaluation.findings
            )
        )

    def test_revoked_intent_only_justifies_activity_before_its_revocation(self):
        self.intent(status="revoked", revoked_at=self.start + timedelta(minutes=10))
        self.assertEqual(self.evaluation(self.observed()).verdict, "unknown")

    def test_two_distinct_intents_are_explained_per_segment_not_as_one_global_match(self):
        middle = self.start + timedelta(minutes=15)
        first = self.intent(ends_at=middle)
        second = self.intent(starts_at=middle, reference="CHG-second")
        evaluation = self.evaluation(self.observed())
        self.assertEqual(evaluation.verdict, "expected")
        self.assertIsNone(evaluation.intent_id)
        proofs = {item["evidence"] for item in evaluation.findings if item["code"] == "intent"}
        self.assertEqual(proofs, {str(first.pk), str(second.pk)})
        rows, _ = event_timeline(AccessEvent.objects.all(), self.start, self.end)
        self.assertTrue(rows[0]["reference_complete"])
        self.assertIn("CHG-second", rows[0]["reference"])
        results, _, _ = investigate(
            "events-without-reference", at=self.end, start=self.start, end=self.end
        )
        self.assertEqual(results, [])

    def test_partial_ticket_context_is_not_hidden_by_one_referenced_segment(self):
        middle = self.start + timedelta(minutes=15)
        self.intent(ends_at=middle)
        self.intent(starts_at=middle, reference="")
        self.observed()
        rows, _ = event_timeline(AccessEvent.objects.all(), self.start, self.end)
        self.assertFalse(rows[0]["reference_complete"])
        self.assertIn("CHG-interval", rows[0]["reference"])
        results, _, _ = investigate(
            "events-without-reference", at=self.end, start=self.start, end=self.end
        )
        self.assertEqual(len(results), 1)

    def test_timeline_keeps_overlap_and_measures_receipt_delay_after_session_end(self):
        self.intent()
        with patch("django.utils.timezone.now", return_value=self.end + timedelta(minutes=1)):
            event = self.observed()
        rows, limited = event_timeline(
            AccessEvent.objects.all(),
            self.start + timedelta(minutes=20),
            self.end + timedelta(minutes=1),
        )
        self.assertFalse(limited)
        self.assertEqual([row["event"].pk for row in rows], [event.pk])
        self.assertFalse(rows[0]["arrived_late"])
        self.assertEqual(rows[0]["delay_seconds"], 60)
        rows, _ = event_timeline(
            AccessEvent.objects.all(), self.end, self.end + timedelta(minutes=1)
        )
        self.assertEqual(rows, [])

    def test_inactive_middle_is_detected_even_when_start_and_end_are_active(self):
        self.intent()
        for offset, old, new in ((10, "active", "suspended"), (20, "suspended", "active")):
            IdentityStateChange.objects.create(
                organization=self.org,
                identity=self.person,
                previous_status=old,
                next_status=new,
                effective_at=self.start + timedelta(minutes=offset),
            )
        evaluation = self.evaluation(self.observed())
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(
            any(
                item["code"] == "lifecycle"
                and item.get("interval_start") == (self.start + timedelta(minutes=10)).isoformat()
                for item in evaluation.findings
            )
        )

    def test_contract_calendar_checks_internal_overnight_gap_not_just_endpoints(self):
        end = self.start + timedelta(days=1)
        contract, _ = self.contract(daily_start=time(9), daily_end=time(17))
        self.intent(contract=contract, ends_at=end)
        evaluation = self.evaluation(self.observed(ended_at=end))
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(
            any(
                item["code"] == "contract_schedule" and item["state"] == "deviation"
                for item in evaluation.findings
            )
        )

    def test_contract_revision_restricting_only_middle_cannot_be_missed(self):
        contract, _ = self.contract()
        self.revision(contract, 2, self.start + timedelta(minutes=10), allowed_methods=["SSH"])
        self.revision(contract, 3, self.start + timedelta(minutes=20))
        self.intent(contract=contract)
        evaluation = self.evaluation(self.observed())
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(
            any(
                item["code"] == "contract_method" and item["state"] == "deviation"
                for item in evaluation.findings
            )
        )

    def test_separation_conflict_existing_only_in_middle_is_detected(self):
        self.intent()
        other_resource = Resource.objects.create(
            organization=self.org, name="Payments", kind="application"
        )
        self.grant(
            resource=other_resource,
            entitlement="approve",
            valid_from=self.start + timedelta(minutes=10),
            expires_at=self.start + timedelta(minutes=20),
        )
        SeparationRule.objects.create(
            organization=self.org,
            name="Support/payment conflict",
            left_resource=self.resource,
            left_entitlement="support",
            right_resource=other_resource,
            right_entitlement="approve",
            effective_at=self.before,
            published_by=self.admin,
        )
        evaluation = self.evaluation(self.observed())
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(
            any(
                item["code"] == "separation_of_duties" and item["state"] == "deviation"
                for item in evaluation.findings
            )
        )

    def test_certificate_expiry_inside_interval_is_not_treated_as_valid_throughout(self):
        self.intent()
        certificate = Credential.objects.create(
            organization=self.org,
            identity=self.person,
            resource=self.resource,
            name="Public cert reference",
            kind="certificate",
            fingerprint="not-a-secret",
            expires_at=self.start + timedelta(minutes=15),
            registered_at=self.before,
        )
        evaluation = self.evaluation(self.observed(credential=certificate))
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(any(item["code"] == "credential_expired" for item in evaluation.findings))

    def test_unknown_historical_lifecycle_is_not_mislabeled_departed(self):
        with patch("django.utils.timezone.now", return_value=self.end + timedelta(days=1)):
            later = Identity.objects.create(
                organization=self.org, name="Registered later", kind="human"
            )
        evaluation = self.evaluation(self.observed(identity=later, account=None))
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertFalse(
            any(
                item["code"] == "lifecycle" and item["state"] == "deviation"
                for item in evaluation.findings
            )
        )

    def test_expected_certificate_host_change_only_in_middle_is_detected(self):
        self.intent(method="TLS", privilege="")
        certificate = Credential.objects.create(
            organization=self.org,
            identity=self.person,
            name="Public reference",
            kind="certificate",
            fingerprint="public",
            registered_at=self.before,
        )
        other = Resource.objects.create(organization=self.org, name="Other host", kind="server")
        source = GraphNode.objects.create(
            organization=self.org, kind="credential", credential=certificate
        )
        targets = [
            GraphNode.objects.create(organization=self.org, kind="resource", resource=resource)
            for resource in (self.resource, other)
        ]
        windows = [
            (self.before, self.start + timedelta(minutes=10), targets[0]),
            (self.start + timedelta(minutes=10), self.start + timedelta(minutes=20), targets[1]),
            (self.start + timedelta(minutes=20), None, targets[0]),
        ]
        with patch("django.utils.timezone.now", return_value=self.before):
            for start, end, target in windows:
                ContextLink.objects.create(
                    organization=self.org,
                    source=source,
                    target=target,
                    relation="expected-on",
                    evidence="Explicit host schedule",
                    confidence="verified",
                    valid_from=start,
                    valid_until=end,
                    published_by=self.admin,
                )
        evaluation = self.evaluation(
            self.observed(credential=certificate, method="TLS", privilege="", domain="certificate")
        )
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(
            any(
                item["code"] == "credential_host" and item["state"] == "deviation"
                for item in evaluation.findings
            )
        )

    def test_expected_network_placement_change_in_middle_is_detected(self):
        with patch("django.utils.timezone.now", return_value=self.before):
            machine = Identity.objects.create(organization=self.org, name="Machine", kind="machine")
        self.intent(identity=machine, account=None, method="802.1X", privilege="")
        switches = [
            Resource.objects.create(organization=self.org, name=name, kind="network")
            for name in ("Switch A", "Switch B")
        ]
        windows = [
            (self.before, self.start + timedelta(minutes=10), switches[0]),
            (self.start + timedelta(minutes=10), self.start + timedelta(minutes=20), switches[1]),
            (self.start + timedelta(minutes=20), None, switches[0]),
        ]
        with patch("django.utils.timezone.now", return_value=self.before):
            for start, end, switch in windows:
                NetworkPlacement.objects.create(
                    organization=self.org,
                    identity=machine,
                    switch=switch,
                    port="1",
                    vlan="10",
                    evidence="Explicit placement schedule",
                    valid_from=start,
                    valid_until=end,
                    published_by=self.admin,
                )
        evaluation = self.evaluation(
            self.observed(
                identity=machine,
                account=None,
                method="802.1X",
                privilege="",
                domain="network",
                network_switch=switches[0],
                network_port="1",
                network_vlan="10",
            )
        )
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertTrue(
            any(
                item["code"] == "network_placement" and item["state"] == "deviation"
                for item in evaluation.findings
            )
        )

    def test_clock_uncertainty_also_checks_temporary_grant_expiration(self):
        self.grant(expires_at=self.end)
        source = EventSource.objects.create(
            organization=self.org, name="Grant clock", token_hash="e" * 64
        )
        scope = CollectionScope.objects.create(
            organization=self.org,
            source=source,
            domain="remote",
            effective_at=self.before,
            published_by=self.admin,
        )
        CollectionReport.objects.create(
            organization=self.org,
            scope=scope,
            external_id="grant-clock",
            sequence=1,
            covered_from=self.before,
            covered_until=self.end + timedelta(days=1),
            state="complete",
            clock_uncertainty_seconds=2,
        )
        evaluation = self.evaluation(self.observed(source=str(source.pk)))
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertTrue(any(item["code"] == "time_boundary" for item in evaluation.findings))

    def test_temporal_limits_retain_fact_but_never_claim_global_conformity(self):
        self.intent(ends_at=self.start + timedelta(days=40))
        long_event = self.observed(ended_at=self.start + timedelta(days=32))
        self.assertEqual(self.evaluation(long_event).verdict, "unknown")
        for offset in range(MAX_SEGMENTS + 1):
            IdentityStateChange.objects.create(
                organization=self.org,
                identity=self.person,
                previous_status="active",
                next_status="active",
                effective_at=self.start + timedelta(seconds=offset + 1),
            )
        event = self.observed()
        evaluation = self.evaluation(event)
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertEqual(evaluation.findings[0]["code"], "interval_boundary_limit")
        self.assertEqual(AccessEvent.objects.count(), 2)

    def test_foreign_policy_boundaries_do_not_affect_this_organization(self):
        self.intent()
        ApprovalPolicyRevision.objects.bulk_create(
            [
                ApprovalPolicyRevision(
                    organization=self.other,
                    sequence=offset + 1,
                    effective_at=self.start + timedelta(seconds=offset + 1),
                    published_by=self.admin,
                )
                for offset in range(MAX_SEGMENTS + 1)
            ]
        )
        self.assertEqual(self.evaluation(self.observed()).verdict, "expected")

    def test_clock_uncertainty_covers_observed_end_and_half_open_equality(self):
        self.intent()
        source = EventSource.objects.create(
            organization=self.org, name="Clock fixture", token_hash="f" * 64
        )
        scope = CollectionScope.objects.create(
            organization=self.org,
            source=source,
            domain="remote",
            effective_at=self.before,
            published_by=self.admin,
        )
        CollectionReport.objects.create(
            organization=self.org,
            scope=scope,
            external_id="clock-zero",
            sequence=1,
            covered_from=self.before,
            covered_until=self.end + timedelta(days=1),
            state="complete",
            clock_uncertainty_seconds=0,
        )
        event = self.observed(source=str(source.pk))
        self.assertEqual(self.evaluation(event).verdict, "expected")
        CollectionReport.objects.create(
            organization=self.org,
            scope=scope,
            external_id="clock-two",
            sequence=2,
            covered_from=self.before,
            covered_until=self.end + timedelta(days=1),
            state="complete",
            clock_uncertainty_seconds=2,
        )
        updated = reevaluate_event(event.pk, actor=self.admin, organization=self.org)
        self.assertEqual(updated.verdict, "unknown")
        self.assertEqual(event.evaluations.count(), 2)

    def test_negative_naive_and_future_end_are_rejected_without_new_fact(self):
        for end in (
            self.start - timedelta(seconds=1),
            self.end.replace(tzinfo=None),
            timezone.now() + timedelta(minutes=10),
        ):
            with self.subTest(end=end), self.assertRaises(ValidationError):
                self.observed(ended_at=end)
        self.assertFalse(AccessEvent.objects.exists())

    def test_instant_and_zero_duration_keep_point_semantics(self):
        self.intent(starts_at=self.start - timedelta(hours=1), ends_at=self.start)
        for end in (None, self.start):
            event = self.observed(ended_at=end)
            self.assertEqual(self.evaluation(event).verdict, "unknown")
            self.assertFalse(
                any(item["code"] == "observed_interval" for item in self.evaluation(event).findings)
            )

    def test_export_preserves_duration_and_reevaluation_never_modifies_source(self):
        self.intent()
        event = self.observed()
        before = AccessEvent.objects.values().get(pk=event.pk)
        old = self.evaluation(event)
        reevaluate_event(event.pk, actor=self.admin, organization=self.org)
        self.assertEqual(AccessEvent.objects.values().get(pk=event.pk), before)
        old.refresh_from_db()
        self.assertEqual(old.rule_version, "access-context/7")
        self.client.force_login(self.admin)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session.save()
        response = self.client.get(reverse("event-export", args=[event.pk]))
        payload = response.json()
        self.assertEqual(payload["ended_at"], self.end.isoformat())
        self.assertEqual(payload["duration_seconds"], 1800)

    def test_api_accepts_aware_end_and_rejects_naive_end(self):
        _, token = create_source("API intervals", actor=self.admin, organization=self.org)
        values = dict(
            external_id="api-interval",
            identity=str(self.person.pk),
            account=str(self.account.pk),
            resource=str(self.resource.pk),
            method="TeamViewer",
            action="completed",
            result="success",
            occurred_at=self.start.isoformat(),
            ended_at=self.end.isoformat(),
        )
        response = self.client.post(
            reverse("api-events"),
            json.dumps(values),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + token,
        )
        self.assertEqual(response.status_code, 201, response.content)
        values.update(
            external_id="naive-interval", ended_at=self.end.replace(tzinfo=None).isoformat()
        )
        response = self.client.post(
            reverse("api-events"),
            json.dumps(values),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + token,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(AccessEvent.objects.count(), 1)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL interval constraints")
    def test_database_rejects_negative_duration_and_updates_of_source_fact(self):
        event = self.observed()
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "UPDATE access_accessevent SET ended_at = occurred_at WHERE id = %s", [event.pk]
            )
        with self.assertRaises(DatabaseError) as raised:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO access_accessevent "
                    "(id, organization_id, source, external_id, occurred_at, ended_at, "
                    "received_at, resource_id, method, action, location, privilege, "
                    "result, country_code, evidence, "
                    "domain, network_port, network_vlan, credential_observation) "
                    "SELECT gen_random_uuid(), organization_id, source, 'negative', occurred_at, "
                    "occurred_at - interval '1 second', received_at, resource_id, method, action, "
                    "location, privilege, result, country_code, evidence, domain, network_port, "
                    "network_vlan, credential_observation FROM access_accessevent WHERE id = %s",
                    [event.pk],
                )
        self.assertEqual(raised.exception.__cause__.sqlstate, "23514")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL observation interval upgrade")
class ObservationIntervalUpgradeTests(TransactionTestCase):
    def test_old_facts_evaluations_and_audit_survive_and_new_evaluation_appends(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        previous = historical_targets(
            executor, "0009_person_mandate_evaluation", app_label="access"
        )
        try:
            executor.migrate(previous)
            old = MigrationExecutor(connection).loader.project_state(previous).apps
            org = old.get_model("platform_core", "Organization").objects.create(
                key="interval-upgrade", name="Existing organization"
            )
            resource = old.get_model("identity", "Resource").objects.create(
                organization=org, name="Existing target", kind="server"
            )
            event_model = old.get_model("access", "AccessEvent")
            self.assertNotIn("ended_at", {field.name for field in event_model._meta.fields})
            event = event_model.objects.create(
                organization=org,
                resource=resource,
                source="old-source",
                external_id="existing-event",
                occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
                method="SSH",
                action="login",
            )
            old_evaluation = old.get_model("access", "AccessEvaluation").objects.create(
                organization=org,
                event=event,
                verdict="unknown",
                rule_version="access-context/5",
                findings=[
                    dict(
                        code="preserved",
                        state="unknown",
                        detail="Original explanation",
                        evidence="original-proof",
                    )
                ],
            )
            proof = record(
                organization=Organization.objects.get(pk=org.pk),
                action="upgrade.interval.fixture.v1",
                summary="Before interval schema",
            )
            before_event = event_model.objects.filter(pk=event.pk).values().get()
            before_evaluation = (
                old_evaluation.__class__.objects.filter(pk=old_evaluation.pk).values().get()
            )
            before_audit = proof.__class__.objects.filter(pk=proof.pk).values().get()
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(
                AccessEvent.unscoped.filter(pk=event.pk).values(*before_event).get(), before_event
            )
            self.assertIsNone(AccessEvent.unscoped.get(pk=event.pk).ended_at)
            self.assertEqual(
                AccessEvaluation.unscoped.filter(pk=old_evaluation.pk)
                .values(*before_evaluation)
                .get(),
                before_evaluation,
            )
            self.assertEqual(
                proof.__class__.objects.filter(pk=proof.pk).values().get(), before_audit
            )
            organization = Organization.objects.get(pk=org.pk)
            for key in ("identity", "access"):
                ModuleActivation.objects.create(
                    organization=organization, module_key=key, version="test", enabled=True
                )
            actor = get_user_model().objects.create_superuser("interval-upgrade-admin")
            new = reevaluate_event(event.pk, actor=actor, organization=organization)
            self.assertEqual(new.rule_version, "access-context/7")
            self.assertEqual(AccessEvaluation.unscoped.filter(event_id=event.pk).count(), 2)
            self.assertEqual(
                AccessEvaluation.unscoped.get(pk=old_evaluation.pk).rule_version, "access-context/5"
            )
            self.assertTrue(verify_chain(organization))
        finally:
            MigrationExecutor(connection).migrate(latest)
