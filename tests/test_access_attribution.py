"""Source attribution is not inventory ownership or permission to execute."""

import json
import time
from datetime import timedelta
from unittest import skipUnless

from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity
from platform_core.security import cipher
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvaluation, AccessEvent
from platform_modules.access.services import (
    create_record,
    ingest_event,
    reevaluate_event,
    revoke_identity,
)
from platform_modules.approvals.services import decide
from platform_modules.connectors.services import create_source
from platform_modules.identity.models import Credential, ExternalAccount, Grant, Identity
from platform_modules.intelligence.projection import graph_for_identity
from platform_modules.pam.services import open_lease

from . import test_platform as baseline


class AccessAttributionTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.service = Identity.objects.create(
            organization=self.org, name="Service radiologie", kind="service"
        )
        self.shared = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.service,
            username="svc-radiology",
            system="AD",
            kind="privileged",
        )
        self.certificate = Credential.objects.create(
            organization=self.org,
            identity=self.service,
            resource=self.resource,
            kind="certificate",
            name="Certificat du service",
            fingerprint="fixture-public-fingerprint",
        )
        self.second = Identity.objects.create(
            organization=self.org, name="Deuxième intervenante", kind="human"
        )

    def planned(self, identity=None, account=None, **changes):
        return create_record(
            "intent",
            {
                "identity": identity or self.identity,
                "account": account or self.shared,
                "resource": self.resource,
                "method": "SSH",
                "reason": "Maintenance avec compte de service partagé",
                "reference": "CHG-shared-account",
                "starts_at": timezone.now() - timedelta(minutes=1),
                "ends_at": timezone.now() + timedelta(minutes=10),
                **changes,
            },
            actor=self.operator,
            organization=self.org,
        )

    def approved(self, **kwargs):
        intent = self.planned(**kwargs)
        decide(
            intent.pk,
            actor=self.reviewer,
            organization=self.org,
            approved=True,
            comment="Acteur et compte précisément examinés",
        )
        intent.refresh_from_db()
        return intent

    def observed(self, **changes):
        return ingest_event(
            {
                "source": "support-collector",
                "external_id": "shared-1",
                "identity": self.identity,
                "account": self.shared,
                "credential": self.certificate,
                "resource": self.resource,
                "method": "SSH",
                "action": "session.start",
                "occurred_at": timezone.now(),
                **changes,
            },
            actor=self.operator,
            organization=self.org,
        )[0]

    def test_human_actor_and_service_account_owner_are_separate(self):
        intent = self.approved()
        event = self.observed()
        evaluation = event.evaluations.get()
        self.assertEqual(event.identity_id, self.identity.pk)
        self.assertEqual(event.account.identity_id, self.service.pk)
        self.assertEqual(event.credential.identity_id, self.service.pk)
        self.assertEqual((evaluation.verdict, evaluation.intent_id), ("expected", intent.pk))
        self.assertEqual(evaluation.rule_version, "access-context/5")
        context = next(f for f in evaluation.findings if f["code"] == "account_owner_context")
        self.assertEqual(context["state"], "observed")
        self.assertIn(str(self.service.pk), context["detail"])
        self.assertIn("ne prouve ni l’acteur", context["detail"])
        self.assertTrue(verify_chain(self.org))

    def test_unknown_actor_is_not_replaced_by_account_or_certificate_owner(self):
        self.approved()
        event = self.observed(identity=None)
        evaluation = event.evaluations.get()
        self.assertIsNone(event.identity_id)
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertIsNone(evaluation.intent_id)
        self.assertTrue(any(f["code"] == "identity" for f in evaluation.findings))

    def test_credential_can_be_observed_without_account_or_actor(self):
        event = self.observed(identity=None, account=None)
        self.assertIsNone(event.identity_id)
        self.assertEqual(event.evaluations.get().verdict, "unknown")
        self.assertEqual(event.credential.identity_id, self.service.pk)

    def test_another_reported_actor_does_not_inherit_the_intention(self):
        self.approved()
        evaluation = self.observed(identity=self.second).evaluations.get()
        self.assertEqual(evaluation.verdict, "unknown")
        self.assertIsNone(evaluation.intent_id)

    def test_another_account_does_not_inherit_the_intention(self):
        self.approved()
        evaluation = self.observed(account=self.account).evaluations.get()
        self.assertEqual(evaluation.verdict, "deviation")
        self.assertIsNone(evaluation.intent_id)

    def test_owner_is_not_automatically_the_actor_even_for_a_personal_account(self):
        event = self.observed(account=self.account, identity=self.second, credential=None)
        self.assertEqual(event.identity_id, self.second.pk)
        self.assertEqual(event.account.identity_id, self.identity.pk)
        self.assertEqual(event.evaluations.get().verdict, "unknown")

    def test_observation_does_not_enable_shared_account_provisioning_or_pam(self):
        AccountSecurity.objects.create(
            account=self.operator, encrypted_secret=cipher().encrypt(b"fixture-assurance").decode()
        )
        for fulfillment in ("pam", "iam_group"):
            with (
                self.subTest(fulfillment=fulfillment),
                recent_authentication(self.operator, self.org, time.time()),
                self.assertRaises(ValidationError),
            ):
                self.planned(fulfillment=fulfillment, privilege="Administrator")
        intent = self.approved()
        with self.assertRaises(ValidationError):
            open_lease(intent.pk, actor=self.operator, organization=self.org)
        with self.assertRaises(ValidationError):
            create_record(
                "grant",
                {
                    "identity": self.identity,
                    "account": self.shared,
                    "resource": self.resource,
                    "entitlement": "Administrator",
                    "justification": "Ce n’est pas une délégation approuvée",
                },
                actor=self.operator,
                organization=self.org,
            )

    def test_actor_departure_preserves_shared_service_and_other_interventions(self):
        mine = self.approved()
        other = self.approved(identity=self.second)
        event = self.observed()
        grant = Grant.objects.create(
            organization=self.org,
            identity=self.service,
            account=self.shared,
            resource=self.resource,
            entitlement="Service runtime",
            justification="Droit propre au service",
        )
        revoke_identity(
            self.identity.pk,
            actor=self.operator,
            organization=self.org,
            reason="Départ de l’intervenant, pas du service",
        )
        for obj in (mine, other, self.service, self.shared, grant):
            obj.refresh_from_db()
        self.assertEqual(mine.status, "revoked")
        self.assertEqual(other.status, "approved")
        self.assertEqual(self.service.status, "active")
        self.assertTrue(self.shared.active)
        self.assertEqual(grant.status, "active")
        historical = reevaluate_event(event.pk, actor=self.operator, organization=self.org)
        self.assertEqual(historical.verdict, "expected")
        self.assertEqual(historical.intent_id, mine.pk)

    def test_owner_departure_revokes_plans_using_its_accounts_not_the_other_people(self):
        first = self.approved()
        second = self.approved(identity=self.second)
        event = self.observed()
        revoke_identity(
            self.service.pk,
            actor=self.operator,
            organization=self.org,
            reason="Retrait définitif du service",
        )
        for obj in (first, second, self.shared, self.identity, self.second, self.account):
            obj.refresh_from_db()
        self.assertEqual((first.status, second.status), ("revoked", "revoked"))
        self.assertFalse(self.shared.active)
        self.assertEqual((self.identity.status, self.second.status), ("active", "active"))
        self.assertTrue(self.account.active)
        self.assertEqual(
            reevaluate_event(event.pk, actor=self.operator, organization=self.org).verdict,
            "expected",
        )
        self.assertEqual(
            self.observed(external_id="after-departure").evaluations.get().verdict, "unknown"
        )

    def test_ownership_context_is_dated_and_does_not_rewrite_source_or_old_evaluation(self):
        event = self.observed(identity=None)
        original = event.evaluations.get()
        original_findings = original.findings
        ExternalAccount.objects.filter(pk=self.shared.pk).update(identity=self.second)
        latest = reevaluate_event(event.pk, actor=self.operator, organization=self.org)
        original.refresh_from_db()
        event.refresh_from_db()
        self.assertIsNone(event.identity_id)
        self.assertEqual(original.findings, original_findings)
        self.assertEqual(latest.verdict, "unknown")
        context = next(f for f in latest.findings if f["code"] == "account_owner_context")
        self.assertIn(str(self.second.pk), context["detail"])
        old_context = next(f for f in original.findings if f["code"] == "account_owner_context")
        self.assertIn(str(self.service.pk), old_context["detail"])

    def test_export_and_detail_label_current_ownership_separately_from_source_facts(self):
        event = self.observed(identity=None)
        self.client.force_login(self.operator)
        response = self.client.get(reverse("event-export", args=[event.pk]))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIsNone(payload["who"])
        self.assertIsNone(payload["facts"]["identity_id"])
        self.assertEqual(payload["facts"]["identity_attribution"], "unresolved")
        self.assertNotIn("account_owner_identity_id", payload["facts"])
        self.assertEqual(
            payload["inventory_context"]["account_owner_identity_id"], str(self.service.pk)
        )
        self.assertFalse(payload["inventory_context"]["actor_inferred_from_ownership"])
        self.assertContains(
            self.client.get(reverse("record-detail", args=["event", event.pk])),
            "contexte, pas acteur déduit",
        )

    def test_graph_of_owner_shows_the_real_actor_and_not_inferred_owner_activity(self):
        install_module("intelligence", actor=self.admin, organization=self.org)
        event = self.observed()
        graph = graph_for_identity(self.service)
        observed = [e for e in graph["edges"] if e["layer"] == "observation"]
        self.assertTrue(observed)
        self.assertTrue(all(e["source"] == f"identity:{self.identity.pk}" for e in observed))
        self.assertTrue(any(e["relation"] == "observed-with-account" for e in observed))
        self.assertTrue(all(e["evidence"] == str(event.pk) for e in observed))
        unknown = self.observed(identity=None, external_id="unknown-graph")
        graph = graph_for_identity(self.service)
        origins = {e["source"] for e in graph["edges"] if e["evidence"] == str(unknown.pk)}
        self.assertEqual(origins, {f"event:{unknown.pk}"})
        node = next(n for n in graph["nodes"] if n["id"] == f"event:{unknown.pk}")
        self.assertIn("Acteur non résolu", node["short_label"])

    def test_api_accepts_independent_actor_and_preserves_unknown_actor_on_replay(self):
        _, token = create_source("Remote support", actor=self.admin, organization=self.org)
        payload = {
            "external_id": "api-shared-1",
            "occurred_at": timezone.now().isoformat(),
            "account": str(self.shared.pk),
            "credential": str(self.certificate.pk),
            "resource": str(self.resource.pk),
            "method": "SSH",
            "action": "session.start",
            "result": "success",
        }
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

        def post(data):
            return self.client.post(
                reverse("api-events"), json.dumps(data), content_type="application/json", **headers
            )

        response = post(payload)
        self.assertEqual(response.status_code, 201, response.content)
        event_id = response.json()["event_id"]
        response = post({**payload, "identity": str(self.identity.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["event_id"], event_id)
        self.assertIsNone(AccessEvent.objects.get(pk=event_id).identity_id)
        response = post({**payload, "identity": str(self.identity.pk), "external_id": "api-human"})
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(
            AccessEvent.objects.get(pk=response.json()["event_id"]).identity_id, self.identity.pk
        )

    def test_distinct_actor_still_cannot_reference_other_tenant_accounts_or_credentials(self):
        with organization_context(self.other):
            foreign = Identity.objects.create(
                organization=self.other, name="Foreign", kind="service"
            )
            account = ExternalAccount.objects.create(
                organization=self.other, identity=foreign, username="secret", system="secret"
            )
            credential = Credential.objects.create(
                organization=self.other,
                identity=foreign,
                name="Foreign cert",
                kind="certificate",
                fingerprint="public-foreign-fingerprint",
            )
        for changes in ({"account": account}, {"credential": credential}, {"identity": foreign}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.observed(**changes)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL tenant relation gate")
    def test_database_still_rejects_cross_tenant_account_without_resolved_actor(self):
        foreign = Identity.unscoped.create(organization=self.other, name="Foreign", kind="service")
        account = ExternalAccount.unscoped.create(
            organization=self.other, identity=foreign, username="secret", system="secret"
        )
        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessEvent.unscoped.bulk_create(
                [
                    AccessEvent(
                        organization=self.org,
                        source="raw-fixture",
                        external_id="cross-org",
                        account=account,
                        resource=self.resource,
                        method="SSH",
                        action="start",
                        occurred_at=timezone.now(),
                    )
                ]
            )

    def test_new_rule_version_does_not_relabel_previous_evaluations(self):
        event = self.observed()
        old = AccessEvaluation.objects.create(
            organization=self.org,
            event=event,
            verdict="unknown",
            rule_version="access-context/3",
            findings=[
                {"code": "historical-fixture", "state": "unknown", "detail": "Ancienne règle"}
            ],
        )
        current = reevaluate_event(event.pk, actor=self.operator, organization=self.org)
        old.refresh_from_db()
        self.assertEqual(old.rule_version, "access-context/3")
        self.assertEqual(current.rule_version, "access-context/5")
        self.assertEqual(event.evaluations.count(), 3)
