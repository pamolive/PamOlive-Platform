import json
import os
import time
from datetime import time as wall_time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity
from platform_core.services import install_module
from platform_modules.access.models import AccessEvent
from platform_modules.access.services import create_record, reevaluate_event
from platform_modules.approvals.services import decide
from platform_modules.connectors.services import create_source
from platform_modules.identity.models import Credential, Grant, Identity, Resource
from platform_modules.intelligence import services
from platform_modules.intelligence.coverage import collection_coverage, event_timeline
from platform_modules.intelligence.models import (
    CollectionReport,
    ContextLink,
    GraphNode,
)
from platform_modules.intelligence.projection import graph_for_identity, investigate

from . import test_platform as baseline


class IntelligenceTests(TestCase):
    event = baseline.PlatformTests.event
    intent = baseline.PlatformTests.intent

    def setUp(self):
        baseline.PlatformTests.setUp(self)
        install_module("intelligence", actor=self.admin, organization=self.org)
        AccountSecurity.objects.create(account=self.admin, encrypted_secret="fixture-assurance")
        ctx = recent_authentication(self.admin, self.org, time.time())
        ctx.__enter__()
        self.addCleanup(ctx.__exit__, None, None, None)
        self.zone = Resource.objects.create(
            organization=self.org, name="Salle serveur", kind="zone"
        )
        self.door = Resource.objects.create(organization=self.org, name="Porte DC", kind="door")
        self.switch = Resource.objects.create(
            organization=self.org, name="ARUBA-RADIO-03", kind="network"
        )
        self.core = Resource.objects.create(
            organization=self.org, name="ARUBA-CORE-01", kind="network"
        )
        self.base = timezone.now() - timedelta(hours=2)
        self.source, self.token = create_source(
            "Wallix collector", actor=self.admin, organization=self.org
        )

    def link(self, source, relation, target, confidence="verified"):
        kinds = {"Identity": "identity", "Resource": "resource", "Credential": "credential"}
        return services.publish_link(
            {
                "source": f"{kinds[type(source).__name__]}:{source.pk}",
                "target": f"{kinds[type(target).__name__]}:{target.pk}",
                "relation": relation,
                "evidence": "CMDB / CHG-0837",
                "confidence": confidence,
            },
            actor=self.admin,
            organization=self.org,
        )

    def scope(self, domain="pam", resource=None):
        with patch("platform_modules.intelligence.services.timezone.now", return_value=self.base):
            return services.publish_scope(
                {
                    "source": self.source,
                    "domain": domain,
                    "resource": resource,
                    "whole_organization": resource is None,
                },
                actor=self.admin,
                organization=self.org,
            )

    def report(self, scope, state="complete", external_id="r1", **overrides):
        return services.ingest_report(
            {
                "scope": scope.pk,
                "external_id": external_id,
                "covered_from": self.base + timedelta(minutes=1),
                "covered_until": self.base + timedelta(hours=1),
                "state": state,
                "clock_uncertainty_seconds": 3,
                **overrides,
            },
            source=self.source,
            organization=self.org,
        )

    def domain(self, name, resource=None):
        return next(
            item
            for item in collection_coverage(
                self.base + timedelta(minutes=1), self.base + timedelta(hours=1), resource=resource
            )
            if item["domain"] == name
        )

    def test_graph_separates_context_capability_intention_and_observation(self):
        self.link(self.identity, "owns", self.resource)
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            entitlement="admin",
            justification="Fonction",
        )
        intent = self.intent()
        decide(
            intent.pk, actor=self.reviewer, organization=self.org, approved=True, comment="Validé"
        )
        self.event()
        graph = graph_for_identity(self.identity)
        self.assertEqual(
            {edge["layer"] for edge in graph["edges"]},
            {"context", "capability", "intention", "observation"},
        )
        self.assertTrue(all(edge["evidence"] for edge in graph["edges"]))
        self.assertTrue(all("path" in edge for edge in graph["edges"]))
        self.assertTrue(all(isinstance(node["y"], int) for node in graph["nodes"]))
        self.assertEqual(GraphNode.objects.count(), 2)  # Projection reads do not materialize nodes.
        self.assertTrue(verify_chain(self.org))

    def test_ownership_and_topology_never_grant_privileged_access(self):
        self.link(self.identity, "owns", self.door)
        self.link(self.door, "located-in", self.zone)
        self.link(self.resource, "located-in", self.zone)
        graph = graph_for_identity(self.identity)
        self.assertFalse(any(e["layer"] == "capability" for e in graph["edges"]))
        rows, _, _ = investigate(
            "physical-admin", at=timezone.now(), start=self.base, end=timezone.now(), zone=self.zone
        )
        self.assertEqual(rows, [])

    def test_physical_and_privileged_paths_require_dated_grants_and_verified_placement(self):
        self.link(self.door, "located-in", self.zone)
        placement = self.link(self.resource, "located-in", self.zone, confidence="declared")
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.door,
            entitlement="open",
            justification="Fonction",
        )
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            entitlement="admin",
            justification="Fonction",
        )

        def query():
            return investigate(
                "physical-admin",
                at=timezone.now(),
                start=self.base,
                end=timezone.now(),
                zone=self.zone,
            )[0]

        self.assertEqual(query(), [])
        services.retire("link", placement.pk, actor=self.admin, organization=self.org)
        self.link(self.resource, "located-in", self.zone)
        rows = query()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identity"], self.identity)
        self.assertEqual(len(rows[0]["evidence"]), 4)

    def test_resource_door_management_is_not_the_machine_or_person_identity(self):
        application = Resource.objects.create(
            organization=self.org, name="Application contrôle des portes", kind="application"
        )
        link = self.link(self.door, "managed-by", application)
        self.assertEqual(link.source.subject, self.door)
        self.assertEqual(link.target.subject, application)
        with self.assertRaises(ValidationError):
            self.link(self.identity, "managed-by", application)

    def test_node_types_tenants_and_publication_mfa_are_enforced(self):
        foreign = Resource.unscoped.create(
            organization=self.other, name="Secret foreign", kind="server"
        )
        with self.assertRaises(ValidationError):
            self.link(self.identity, "owns", foreign)
        foreign_identity = Identity.unscoped.create(
            organization=self.other, name="Hidden", kind="human"
        )
        with self.assertRaises(PermissionDenied):
            graph_for_identity(foreign_identity)
        with self.assertRaises(ValidationError):
            GraphNode(
                organization=self.org,
                kind="resource",
                resource=self.resource,
                identity=self.identity,
            ).full_clean()
        with (
            self.assertRaises(PermissionDenied),
            recent_authentication(self.admin, self.org, time.time() - 10000),
        ):
            self.link(self.identity, "owns", self.resource)

    def test_network_comparison_has_explicit_expected_and_observed_evidence(self):
        machine = Identity.objects.create(
            organization=self.org, name="PC-RADIO-034", kind="machine"
        )
        placement = services.publish_placement(
            {
                "identity": machine,
                "switch": self.switch,
                "port": "1/1/24",
                "vlan": "RADIOLOGY",
                "evidence": "CMDB-v1",
            },
            actor=self.admin,
            organization=self.org,
        )
        event = self.event(
            identity=machine,
            account=None,
            method="802.1X",
            domain="network",
            network_switch=self.core,
            network_port="1/1/7",
            network_vlan="IT",
            occurred_at=timezone.now() + timedelta(seconds=1),
        )
        evaluation = event.evaluations.get()
        self.assertEqual(evaluation.verdict, "deviation")
        finding = next(f for f in evaluation.findings if f["code"] == "network_placement")
        self.assertIn("RADIOLOGY", finding["detail"])
        self.assertIn("VLAN IT", finding["detail"])
        self.assertEqual(finding["evidence"], str(placement.pk))

    def test_precise_approved_network_change_explains_move_not_arbitrary_other_port(self):
        machine = Identity.objects.create(
            organization=self.org, name="PC-RADIO-034", kind="machine"
        )
        services.publish_placement(
            {
                "identity": machine,
                "switch": self.switch,
                "port": "24",
                "vlan": "RADIOLOGY",
                "evidence": "CMDB",
            },
            actor=self.admin,
            organization=self.org,
        )
        now = timezone.now()
        intent = create_record(
            "intent",
            {
                "identity": machine,
                "resource": self.resource,
                "method": "802.1X",
                "reason": "Déplacement approuvé",
                "reference": "CHG-1",
                "starts_at": now,
                "ends_at": now + timedelta(minutes=30),
                "network_switch": self.core,
                "network_port": "7",
                "network_vlan": "IT",
            },
            actor=self.operator,
            organization=self.org,
        )
        decide(
            intent.pk,
            actor=self.reviewer,
            organization=self.org,
            approved=True,
            comment="Plan validé",
        )
        event = self.event(
            identity=machine,
            account=None,
            domain="network",
            method="802.1X",
            network_switch=self.core,
            network_port="7",
            network_vlan="IT",
            occurred_at=now + timedelta(seconds=1),
        )
        self.assertEqual(event.evaluations.get().verdict, "expected")
        wrong = self.event(
            identity=machine,
            account=None,
            domain="network",
            method="802.1X",
            network_switch=self.core,
            network_port="8",
            network_vlan="IT",
            external_id="different-port",
            occurred_at=now + timedelta(seconds=1),
        )
        self.assertEqual(wrong.evaluations.get().verdict, "deviation")

    def test_certificate_host_signal_does_not_claim_private_key_duplication(self):
        certificate = Credential.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.resource,
            name="CN=SRV-ORACLE01",
            kind="certificate",
            fingerprint="public-fingerprint",
        )
        other = Resource.objects.create(organization=self.org, name="UNKNOWN-VM-342", kind="server")
        observed = timezone.now() + timedelta(seconds=1)
        event = self.event(
            resource=other, credential=certificate, domain="certificate", occurred_at=observed
        )
        self.assertEqual(event.evaluations.get().verdict, "deviation")
        self.assertTrue(
            any("ne prouve jamais" in f["detail"] for f in event.evaluations.get().findings)
        )
        with patch(
            "platform_modules.intelligence.services.timezone.now",
            return_value=observed + timedelta(seconds=1),
        ):
            self.link(certificate, "expected-on", other)
        reevaluate_event(event.pk, actor=self.admin, organization=self.org)
        self.assertEqual(event.evaluations.count(), 2)
        self.assertTrue(all(e.verdict == "deviation" for e in event.evaluations.all()))
        future = self.event(
            resource=other,
            credential=certificate,
            domain="certificate",
            external_id="failover",
            occurred_at=observed + timedelta(seconds=2),
        )
        self.assertFalse(
            any(
                f["code"] == "credential_host" and f["state"] == "deviation"
                for f in future.evaluations.get().findings
            )
        )

    def test_absence_of_events_never_implies_a_working_source(self):
        self.scope()
        coverage = self.domain("pam")
        self.assertNotEqual(coverage["state"], "complete")
        self.assertIn("aucune conclusion", coverage["explanation"])

    def test_collection_gap_and_boundary_are_not_filled_by_assumption(self):
        scope = self.scope()
        middle = self.base + timedelta(minutes=30)
        self.report(scope, covered_until=middle)
        self.assertEqual(self.domain("pam")["state"], "partial")
        self.report(scope, external_id="second-half", covered_from=middle)
        self.assertEqual(self.domain("pam")["state"], "complete")
        # An unavailable correction overrides only its own subinterval.
        self.report(
            scope,
            state="unavailable",
            external_id="gap",
            covered_from=middle,
            covered_until=middle + timedelta(seconds=1),
        )
        self.assertEqual(self.domain("pam")["state"], "partial")

    def test_supplier_production_query_uses_contract_not_company_name_guess(self):
        from platform_modules.governance import services as governance

        install_module("governance", actor=self.admin, organization=self.org)
        supplier = governance.create_supplier(
            {"name": "Gleamer"}, actor=self.admin, organization=self.org
        )
        now = timezone.now()
        contract = governance.publish_contract(
            {
                "supplier": supplier,
                "name": "Maintenance",
                "reference": "CTR-graph",
                "sponsor": self.reviewer,
                "starts_at": now - timedelta(days=1),
                "ends_at": now + timedelta(days=1),
                "timezone_name": "Europe/Brussels",
                "weekdays": list(range(7)),
                "daily_start": wall_time(0),
                "daily_end": wall_time(0),
                "allowed_methods": ["SSH"],
                "allowed_countries": [],
                "physical_allowed": False,
                "require_reference": True,
            },
            [{"resource": self.resource, "privilege": "admin", "locations": []}],
            actor=self.admin,
            organization=self.org,
        )
        participant = governance.add_participant(
            {"contract": contract, "identity": self.identity},
            actor=self.admin,
            organization=self.org,
        )
        self.resource.environment = "production"
        self.resource.save()
        create_record(
            "grant",
            {
                "identity": self.identity,
                "resource": self.resource,
                "account": self.account,
                "entitlement": "admin",
                "justification": "Intervention",
                "contract": contract,
                "reference": "CHG-graph",
                "method": "SSH",
                "expires_at": now + timedelta(minutes=15),
            },
            actor=self.admin,
            organization=self.org,
        )
        rows, _, _ = investigate(
            "supplier-production", at=timezone.now(), start=self.base, end=timezone.now()
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("Gleamer", rows[0]["detail"])
        governance.withdraw("participant", participant.pk, actor=self.admin, organization=self.org)
        self.assertEqual(
            investigate(
                "supplier-production", at=timezone.now(), start=self.base, end=timezone.now()
            )[0],
            [],
        )

    def test_report_coverage_requires_whole_window_and_newer_correction_wins(self):
        scope = self.scope()
        first, _ = self.report(scope)
        self.assertEqual(self.domain("pam")["state"], "complete")
        self.report(scope, "unavailable", "r2")
        state = self.domain("pam")
        self.assertEqual(state["state"], "partial")
        self.assertEqual(state["sources"][0]["segments"][0]["state"], "unavailable")
        self.assertEqual(CollectionReport.objects.get(pk=first.pk).state, "complete")

    def test_scoped_resource_coverage_is_not_organization_wide(self):
        scope = self.scope(resource=self.resource)
        self.report(scope)
        self.assertEqual(self.domain("pam")["state"], "unknown")
        self.assertEqual(self.domain("pam", resource=self.resource)["state"], "complete")

    def test_report_replay_is_deduplicated_and_future_or_preconfiguration_coverage_is_denied(self):
        scope = self.scope()
        report, created = self.report(scope)
        same, replay = self.report(scope, "unavailable")
        self.assertTrue(created)
        self.assertFalse(replay)
        self.assertEqual(report.pk, same.pk)
        self.assertEqual(same.state, "complete")
        with self.assertRaises(ValidationError):
            self.report(
                scope, external_id="future", covered_until=timezone.now() + timedelta(hours=1)
            )
        with self.assertRaises(ValidationError):
            self.report(scope, external_id="past", covered_from=self.base - timedelta(seconds=1))

    def test_report_api_uses_source_token_and_rejects_scope_forgery(self):
        scope = self.scope()
        payload = {
            "scope": str(scope.pk),
            "external_id": "api-report",
            "state": "complete",
            "covered_from": (self.base + timedelta(minutes=1)).isoformat(),
            "covered_until": (self.base + timedelta(hours=1)).isoformat(),
            "clock_uncertainty_seconds": 0,
        }
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        url = reverse("collection-report-api")
        self.assertEqual(
            self.client.post(
                url, json.dumps(payload), content_type="application/json", **headers
            ).status_code,
            201,
        )
        self.assertEqual(
            self.client.post(
                url, json.dumps(payload), content_type="application/json", **headers
            ).status_code,
            200,
        )
        payload["scope"] = str(self.org.pk)  # valid UUID, not an authorized collection scope
        self.assertEqual(
            self.client.post(
                url, json.dumps(payload), content_type="application/json", **headers
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(url, "{}", content_type="application/json").status_code, 401
        )

    def test_timeline_shows_late_arrivals_clock_overlap_and_physical_digital_domains(self):
        scope = self.scope()
        self.report(scope, clock_uncertainty_seconds=30)
        at = self.base + timedelta(minutes=15)
        first = self.event(source=str(self.source.pk), domain="pam", occurred_at=at)
        second = self.event(
            source="badge-source",
            domain="physical",
            resource=self.door,
            occurred_at=at + timedelta(seconds=10),
            external_id="badge-1",
            method="badge",
        )
        rows, truncated = event_timeline(
            AccessEvent.objects.all(), self.base, self.base + timedelta(hours=1)
        )
        self.assertFalse(truncated)
        self.assertEqual([row["event"].pk for row in rows], [first.pk, second.pk])
        self.assertEqual(rows[0]["clock_uncertainty"], 30)
        self.assertTrue(rows[1]["order_uncertain"])
        self.assertTrue(all(row["arrived_late"] for row in rows))

    def test_reported_clock_uncertainty_at_authorization_boundary_is_not_confirmed(self):
        scope = self.scope()
        self.report(scope, clock_uncertainty_seconds=30)
        at = self.base + timedelta(minutes=15)
        event = AccessEvent(
            organization=self.org,
            source=str(self.source.pk),
            domain="pam",
            resource=self.resource,
            occurred_at=at,
            external_id="boundary",
            method="SSH",
            action="login",
        )
        intent = SimpleNamespace(
            starts_at=at - timedelta(seconds=10), ends_at=at + timedelta(minutes=15)
        )
        findings = services.context_findings(event, organization=self.org, matched_intent=intent)
        self.assertTrue(
            any(f["code"] == "time_boundary" and f["state"] == "unknown" for f in findings)
        )

    def test_native_graph_timeline_forms_exports_and_cross_tenant_read_isolation(self):
        owned_link = self.link(self.identity, "owns", self.resource)
        self.link(self.resource, "located-in", self.zone)
        self.link(self.identity, "owns", self.door)
        self.link(self.door, "located-in", self.zone)
        app = Resource.objects.create(
            organization=self.org, name="Gestion des portes", kind="application"
        )
        self.link(self.door, "managed-by", app)
        Credential.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.resource,
            name="Certificat administrateur",
            kind="certificate",
            fingerprint="sha256:public-demo",
        )
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            entitlement="admin",
            justification="Fonction infrastructure",
        )
        intent = self.intent()
        decide(
            intent.pk,
            actor=self.reviewer,
            organization=self.org,
            approved=True,
            comment="Maintenance validée",
        )
        self.event()
        self.client.force_login(self.admin)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session["organization_id"] = str(self.org.pk)
        session.save()
        url = reverse("intelligence-home")
        response = self.client.get(url, {"identity": self.identity.pk})
        self.assertContains(response, "<svg")
        self.assertContains(response, "Chronologie physique et numérique")
        if os.environ.get("PAMOLIVE_RENDER_GRAPH_QA"):
            Path(os.environ["PAMOLIVE_RENDER_GRAPH_QA"]).write_bytes(response.content)
        for kind in ["link", "placement", "scope"]:
            self.assertEqual(
                self.client.get(reverse("intelligence-configure", args=[kind])).status_code, 200
            )
        self.assertEqual(self.client.get(reverse("intelligence-configuration")).status_code, 200)
        exported = self.client.get(reverse("intelligence-graph-export", args=[self.identity.pk]))
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.json()["identity"], str(self.identity.pk))
        proof = self.client.get(reverse("intelligence-evidence", args=["link", owned_link.pk]))
        self.assertEqual(proof.status_code, 200)
        self.assertEqual(proof.json()["fields"]["evidence"], "CMDB / CHG-0837")
        foreign = Identity.unscoped.create(
            organization=self.other, name="Foreign identity", kind="human"
        )
        self.assertEqual(
            self.client.get(reverse("intelligence-graph-export", args=[foreign.pk])).status_code,
            404,
        )
        self.assertNotContains(self.client.get(url, {"identity": foreign.pk}), "Foreign identity")
        foreign_node = GraphNode.unscoped.create(
            organization=self.other, kind="identity", identity=foreign
        )
        self.assertEqual(
            self.client.get(
                reverse("intelligence-evidence", args=["node", foreign_node.pk])
            ).status_code,
            404,
        )

    def test_query_without_window_is_a_review_not_an_unauthorized_access_claim(self):
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            entitlement="admin",
            justification="Fonction permanente",
        )
        rows, _, notice = investigate(
            "privileged-without-window", at=timezone.now(), start=self.base, end=timezone.now()
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("pas automatiquement illégitime", notice)
        self.assertIn("Fonction permanente", rows[0]["detail"])

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL policy boundary")
    def test_postgresql_blocks_tenant_crossing_and_rewriting_graph_or_collection_history(self):
        link = self.link(self.identity, "owns", self.resource)
        foreign = Resource.unscoped.create(organization=self.other, name="Foreign", kind="server")
        with self.assertRaises(DatabaseError), transaction.atomic():
            GraphNode.objects.filter(pk=link.target_id).update(resource=foreign)
        with self.assertRaises(DatabaseError), transaction.atomic():
            ContextLink.objects.filter(pk=link.pk).update(evidence="rewritten")
        scope = self.scope()
        report, _ = self.report(scope)
        with self.assertRaises(DatabaseError), transaction.atomic():
            CollectionReport.objects.filter(pk=report.pk).update(state="unavailable")
        services.retire("link", link.pk, actor=self.admin, organization=self.org)
        with self.assertRaises(DatabaseError), transaction.atomic():
            ContextLink.objects.filter(pk=link.pk).update(retired_at=None)
