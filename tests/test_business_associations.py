import copy
import json
import time
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import record, verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity
from platform_core.services import disable_module, install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvaluation, AccessIntent
from platform_modules.access.services import create_record
from platform_modules.approvals.services import decide
from platform_modules.connectors.business import (
    FORMAT,
    create_business_source,
    ingest_business_record,
    verify_business_evidence,
)
from platform_modules.connectors.business_associations import (
    intent_business_context,
    publish_business_association,
    verify_business_association,
)
from platform_modules.connectors.business_models import BusinessAssociation
from platform_modules.identity.models import Grant, Identity, Resource
from platform_modules.pam.models import SessionLease

from . import test_platform as baseline


class BusinessAssociationTests(TestCase):
    intent = baseline.PlatformTests.intent
    event = baseline.PlatformTests.event

    def setUp(self):
        baseline.PlatformTests.setUp(self)
        for actor in (self.admin, self.operator):
            AccountSecurity.objects.create(account=actor, encrypted_secret="fixture-assurance")
        with recent_authentication(self.admin, self.org, time.time()):
            self.source, self.token = create_business_source(
                {"key": "glpi", "name": "GLPI IT"}, actor=self.admin, organization=self.org
            )
        self.payload = dict(
            schema=FORMAT,
            external_id="483",
            sequence=1,
            kind="change",
            reference="CHG-483",
            state="approved",
            title="PRIVATE-EXTERNAL-TITLE",
            source_updated_at=(timezone.now() - timedelta(hours=1)).isoformat(),
            observed_at=(timezone.now() - timedelta(seconds=1)).isoformat(),
        )
        self.receipt, _ = ingest_business_record(
            self.payload, token=self.token, organization=self.org
        )
        self.item = self.intent(reference="CHG-483")

    def associate(self, receipt=None, intent=None, actor=None, **kwargs):
        actor = actor or self.operator
        with recent_authentication(actor, self.org, time.time()):
            return publish_business_association(
                (intent or self.item).pk,
                (receipt or self.receipt).pk,
                "Intervention déclarée pour cette intention",
                actor=actor,
                organization=self.org,
                **kwargs,
            )

    def portal(self, fresh=True):
        self.client.force_login(self.operator)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time() if fresh else 0
        session.save()

    def test_association_is_explicit_and_does_not_approve_or_provision(self):
        self.assertEqual(intent_business_context(self.item.pk)["rows"], [])
        before = (Grant.unscoped.count(), SessionLease.unscoped.count())
        obj = self.associate()
        self.assertTrue(verify_business_association(obj))
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, "pending")
        self.assertEqual((Grant.unscoped.count(), SessionLease.unscoped.count()), before)
        context = intent_business_context(self.item.pk)
        self.assertEqual(context["rows"][0]["latest_read"]["payload"]["state"], "approved")
        self.assertFalse(context["rows"][0]["latest_read"]["local_access_approval"])
        self.assertTrue(verify_chain(self.org))

    def test_only_requester_or_administrator_can_publish_with_personal_recent_mfa(self):
        with self.assertRaises(PermissionDenied):
            publish_business_association(
                self.item.pk, self.receipt.pk, "No MFA", actor=self.operator, organization=self.org
            )
        other = create_record(
            "intent",
            dict(
                identity=self.identity,
                resource=self.resource,
                method="SSH",
                reason="Other request",
                starts_at=self.now,
                ends_at=self.now + timedelta(minutes=10),
            ),
            actor=self.admin,
            organization=self.org,
        )
        with self.assertRaises(PermissionDenied):
            self.associate(intent=other)
        with self.assertRaises(PermissionDenied):
            self.associate(actor=self.reviewer)
        self.assertTrue(verify_business_association(self.associate(intent=other, actor=self.admin)))

    def test_history_and_withdrawal_preserve_proofs_and_reject_stale_commands(self):
        first = self.associate()
        second = self.associate()
        with self.assertRaises(ValidationError):
            self.associate(withdraw_association_id=first.pk)
        withdrawn = self.associate(withdraw_association_id=second.pk)
        self.assertTrue(withdrawn.withdrawn)
        self.assertEqual(withdrawn.sequence, 3)
        self.assertEqual(BusinessAssociation.objects.count(), 3)
        self.assertTrue(
            all(verify_business_association(obj) for obj in BusinessAssociation.objects.all())
        )
        row = intent_business_context(self.item.pk)["rows"][0]
        self.assertEqual(row["state"], "withdrawn")
        self.assertFalse(row["usable_current_context"])
        with self.assertRaises(ValidationError):
            first.save()

    def test_current_source_state_does_not_replace_the_chosen_historical_read(self):
        obj = self.associate()
        later, _ = ingest_business_record(
            {**self.payload, "sequence": 2, "state": "closed"},
            token=self.token,
            organization=self.org,
        )
        row = intent_business_context(self.item.pk)["rows"][0]
        self.assertEqual(row["pinned_read"]["payload"]["state"], "approved")
        self.assertEqual(row["latest_read"]["payload"]["state"], "closed")
        self.assertEqual(row["latest_read"]["receipt_id"], str(later.pk))
        self.assertFalse(row["latest_read"]["local_access_approval"])
        changed, _ = ingest_business_record(
            {**self.payload, "sequence": 3, "reference": "CHG-NEW"},
            token=self.token,
            organization=self.org,
        )
        row = intent_business_context(self.item.pk)["rows"][0]
        self.assertEqual(row["state"], "source_reference_changed")
        self.assertFalse(row["usable_current_context"])
        self.associate(receipt=changed)
        self.assertTrue(
            intent_business_context(self.item.pk)["rows"][0]["source_reference_unchanged"]
        )
        obj.refresh_from_db()
        self.assertEqual(obj.receipt_id, self.receipt.pk)

    def test_scope_change_does_not_rewrite_an_old_association(self):
        obj = self.associate()
        signature = obj.signature
        AccessIntent.objects.filter(pk=self.item.pk).update(reason="Changed scope")
        row = intent_business_context(self.item.pk)["rows"][0]
        self.assertEqual(row["state"], "intent_scope_changed")
        self.assertFalse(row["usable_current_context"])
        obj.refresh_from_db()
        self.assertEqual(obj.signature, signature)
        self.assertTrue(verify_business_association(obj))
        bad = copy.copy(obj)
        bad.published_at += timedelta(microseconds=1)
        self.assertFalse(verify_business_association(bad))

    def test_export_uses_separate_context_and_cannot_retroactively_bless_the_access(self):
        decide(
            self.item.pk,
            approved=True,
            comment="Local approval",
            actor=self.reviewer,
            organization=self.org,
        )
        event = self.event()
        evaluation = AccessEvaluation.objects.get(event=event)
        signature = evaluation.signature
        self.associate()
        self.portal(fresh=False)
        detail = self.client.get(reverse("record-detail", args=["event", event.pk]))
        self.assertEqual(detail.status_code, 200)
        self.assertNotContains(detail, "PRIVATE-EXTERNAL-TITLE")
        response = self.client.get(reverse("event-export", args=[event.pk]))
        self.assertRedirects(response, reverse("account-security"), fetch_redirect_response=False)
        self.portal()
        response = self.client.get(reverse("event-export", args=[event.pk]))
        self.assertEqual(response.status_code, 200)
        data = response.json()["business_context"]
        self.assertFalse(data["included_in_historical_evaluation"])
        row = data["intents"][0]["rows"][0]
        self.assertFalse(row["association_known_before_access"])
        self.assertFalse(row["association_known_before_evaluation"])
        self.assertEqual(row["pinned_read"]["payload"]["title"], "PRIVATE-EXTERNAL-TITLE")
        evaluation.refresh_from_db()
        self.assertEqual(evaluation.signature, signature)
        self.assertEqual(AccessEvaluation.objects.filter(event=event).count(), 1)

    def test_native_preview_publication_withdrawal_and_historical_proof(self):
        self.portal()
        url = reverse("intent-business-associate", args=[self.item.pk])
        values = dict(source=str(self.source.pk), external_id="483", rationale="Ticket lié")
        self.assertEqual(self.client.get(url).status_code, 200)
        preview = self.client.post(url, {**values, "command": "preview"})
        self.assertContains(preview, "Confirmer cette association")
        self.assertFalse(BusinessAssociation.objects.exists())
        response = self.client.post(
            url, {**values, "receipt_id": str(self.receipt.pk), "command": "associate"}
        )
        self.assertEqual(response.status_code, 302)
        obj = BusinessAssociation.objects.get()
        self.assertEqual(
            self.client.get(reverse("intent-business-context", args=[self.item.pk])).status_code,
            200,
        )
        proof = self.client.get(reverse("business-association-proof", args=[obj.pk]))
        self.assertTrue(proof.json()["proof_verified"])
        self.assertEqual(proof.json()["body"]["intent_scope"]["reference"], "CHG-483")
        response = self.client.post(
            reverse("business-association-withdraw", args=[obj.pk]),
            {"rationale": "Investigation terminée"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(BusinessAssociation.objects.count(), 2)

    def test_interval_export_keeps_each_signed_intent_match_not_only_one_global_intent(self):
        start = timezone.now()
        boundary = start + timedelta(minutes=1)
        AccessIntent.objects.filter(pk=self.item.pk).update(
            starts_at=start - timedelta(minutes=1), ends_at=boundary
        )
        self.item.refresh_from_db()
        second = self.intent(
            reference="CHG-483", starts_at=boundary, ends_at=boundary + timedelta(minutes=1)
        )
        for intent in (self.item, second):
            decide(
                intent.pk,
                approved=True,
                comment="Local interval approval",
                actor=self.reviewer,
                organization=self.org,
            )
            self.associate(intent=intent)
        event = self.event(
            occurred_at=start + timedelta(seconds=20), ended_at=boundary + timedelta(seconds=20)
        )
        evaluation = AccessEvaluation.objects.get(event=event)
        self.assertIsNone(evaluation.intent_id)
        self.portal()
        response = self.client.get(reverse("event-export", args=[event.pk]))
        self.assertEqual(response.status_code, 200)
        contexts = response.json()["business_context"]["intents"]
        self.assertEqual(
            {item["intent_id"] for item in contexts}, {str(self.item.pk), str(second.pk)}
        )
        self.assertTrue(all(item["rows"] for item in contexts))
        self.assertTrue(all(not item["observed_interval_evaluated"] for item in contexts))

    def test_source_credentials_cannot_associate_a_reference_or_approve_an_intent(self):
        api = Client(enforce_csrf_checks=True)
        response = api.post(
            reverse("business-records-api"),
            json.dumps(
                {
                    **self.payload,
                    "intent_id": str(self.item.pk),
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + self.token,
        )
        self.assertEqual(response.status_code, 400)
        response = api.post(
            reverse("intent-business-associate", args=[self.item.pk]),
            {},
            HTTP_AUTHORIZATION="Bearer " + self.token,
        )
        self.assertIn(response.status_code, {302, 403})
        self.assertFalse(BusinessAssociation.objects.exists())

    def test_disabled_module_and_invalid_proof_do_not_claim_available_corroboration(self):
        obj = self.associate()
        with patch(
            "platform_modules.connectors.business_associations.verify_business_association",
            return_value=False,
        ):
            row = intent_business_context(self.item.pk)["rows"][0]
        self.assertEqual(row["state"], "invalid_association_proof")
        self.assertNotIn("latest_read", row)
        disable_module("connectors", actor=self.admin, organization=self.org)
        context = intent_business_context(self.item.pk)
        self.assertFalse(context["available"])
        self.assertEqual(context["rows"], [])
        self.assertTrue(verify_business_association(obj))
        with organization_context(None):
            self.assertEqual(verify_business_evidence(), 3)

    def test_cross_organization_evidence_is_refused_without_using_reference_strings(self):
        with organization_context(self.other):
            for key in ("identity", "access", "connectors"):
                install_module(key, actor=self.admin, organization=self.other)
            with recent_authentication(self.admin, self.other, time.time()):
                _, token = create_business_source(
                    {"key": "glpi", "name": "Other GLPI"}, actor=self.admin, organization=self.other
                )
            foreign, _ = ingest_business_record(self.payload, token=token, organization=self.other)
        with self.assertRaises(ValidationError):
            self.associate(receipt=foreign)
        self.assertEqual(intent_business_context(self.item.pk)["rows"], [])

    def test_two_systems_with_the_same_reference_remain_distinct_explicit_associations(self):
        with recent_authentication(self.admin, self.org, time.time()):
            _, token = create_business_source(
                {"key": "jira", "name": "Jira projets"}, actor=self.admin, organization=self.org
            )
        second, _ = ingest_business_record(self.payload, token=token, organization=self.org)
        self.assertEqual(intent_business_context(self.item.pk)["rows"], [])
        self.associate()
        self.associate(receipt=second)
        context = intent_business_context(self.item.pk)
        self.assertEqual(len(context["rows"]), 2)
        self.assertEqual(
            {row["pinned_read"]["source_key"] for row in context["rows"]}, {"glpi", "jira"}
        )
        self.assertEqual(context["local_intent_status"], "pending")

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL association scopes")
    def test_sql_rejects_mutation_and_a_receipt_from_another_record_or_intent_org(self):
        obj = self.associate()
        with self.assertRaises(DatabaseError) as error:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE connectors_businessassociation SET rationale=rationale WHERE id=%s",
                    [obj.pk],
                )
        self.assertEqual(error.exception.__cause__.sqlstate, "P0001")
        second, _ = ingest_business_record(
            {**self.payload, "external_id": "second"}, token=self.token, organization=self.org
        )
        identity = Identity.unscoped.create(organization=self.other, name="Foreign", kind="human")
        resource = Resource.unscoped.create(organization=self.other, name="Foreign", kind="server")
        foreign = AccessIntent.unscoped.create(
            organization=self.other,
            identity=identity,
            resource=resource,
            method="SSH",
            reason="Foreign",
            requested_by=self.admin,
            starts_at=self.now,
            ends_at=self.now + timedelta(minutes=5),
        )
        audit = record(action="fixture.probe", summary="SQL FK probe", organization=self.org)
        for intent_id, record_id in ((self.item.pk, second.record_id), (foreign.pk, obj.record_id)):
            with self.assertRaises(DatabaseError) as error:
                with transaction.atomic(), connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO connectors_businessassociation "
                        "(id,organization_id,intent_id,record_id,receipt_id,sequence,withdrawn,"
                        "rationale,intent_scope,published_at,published_by_id,mfa_verified_at,"
                        "mfa_window_minutes,audit_id,signature) "
                        "VALUES (%s,%s,%s,%s,%s,99,false,'fixture','{}'::jsonb,%s,%s,%s,5,%s,%s)",
                        [
                            uuid4(),
                            self.org.pk,
                            intent_id,
                            record_id,
                            self.receipt.pk,
                            timezone.now(),
                            self.admin.pk,
                            timezone.now(),
                            audit.pk,
                            "0" * 64,
                        ],
                    )
            self.assertEqual(error.exception.__cause__.sqlstate, "23503")
