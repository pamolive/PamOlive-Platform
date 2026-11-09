import time
from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from platform_core.authorization import recent_authentication
from platform_core.services import disable_module, install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.connectors.business import configure_business_source, create_business_source
from platform_modules.connectors.business_models import BusinessReceipt
from platform_modules.identity.models import Grant
from platform_modules.identity.mover import propose_move, verify_mover
from platform_modules.identity.mover_models import MoveDecision, MoveProposal
from tests import test_platform as baseline
from tests.test_mover import MoverFixture


class MoverBusinessTests(MoverFixture, TestCase):
    event = baseline.PlatformTests.event
    intent = baseline.PlatformTests.intent

    def setUp(self):
        super().setUp()
        self.hr, self.hr_token = self.source("hr")
        self.ticket, self.ticket_token = self.source("tickets")
        self.modified = timezone.now() - timedelta(minutes=3)

    def source(self, key, *, organization=None):
        organization = organization or self.org
        with (
            organization_context(organization),
            recent_authentication(self.admin, organization, time.time()),
        ):
            return create_business_source(
                dict(key=key, name=key.upper(), freshness_seconds=900),
                actor=self.admin,
                organization=organization,
            )

    def reading(self, token=None, *, sequence=1, state="approved", organization=None):
        organization = organization or self.org
        # Use the real source API, including source-token authentication.
        result = Client().post(
            reverse("business-records-api"),
            dict(
                schema="pamolive.business-record/1",
                external_id="42",
                sequence=sequence,
                kind="change",
                reference="REQ-42",
                state=state,
                title="Synthetic source dossier",
                observed_at=timezone.now().isoformat(),
                source_updated_at=self.modified.isoformat(),
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token or self.hr_token}",
        )
        self.assertEqual(result.status_code, 201, result.content)
        return BusinessReceipt.unscoped.get(
            pk=result.json()["receipt_id"], organization=organization
        )

    def anchored_move(self, readings, assignments=None, *, department="Operations"):
        with self.mfa(self.operator):
            return propose_move(
                identity_id=self.identity.pk,
                department=department,
                assignments=assignments or {},
                reason="Vérifier le contexte du transfert",
                reference="RH-42",
                business_receipts=[item.pk for item in readings],
                actor=self.operator,
                organization=self.org,
            )

    def login(self, actor, *, recent=True, organization=None):
        self.client.force_login(actor)
        session = self.client.session
        session["organization_id"] = str((organization or self.org).pk)
        session["mfa_verified_at"] = time.time() if recent else 0
        session.save()

    def move_with_access(self):
        receipt = self.reading()
        role = self.role()
        proposal = self.anchored_move([receipt], {role.pk: [self.account.pk]})
        reviewed = self.reading(sequence=2)
        decision = self.apply(proposal)
        intent = AccessIntent.objects.get()
        self.approve_access(intent)
        intent.refresh_from_db()
        return intent, proposal, decision, receipt, reviewed

    def mobility_export(self, event):
        response = self.client.get(reverse("event-export", args=[event.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        return response.json()

    def test_explained_access_keeps_frozen_mobility_proof_separate_from_live_dossier(self):
        intent, proposal, decision, selected, reviewed = self.move_with_access()
        event = self.event(method="SSO", privilege="read")
        evaluation = event.evaluations.get()
        self.assertEqual(evaluation.intent_id, intent.pk)
        latest = self.reading(sequence=3, state="cancelled")
        self.login(self.reviewer)
        page = self.client.get(reverse("event-mobility-context", args=[event.pk]))
        self.assertContains(page, "Synthetic source dossier")
        self.assertContains(page, "Lecture examinée à la décision")
        self.assertContains(page, "cancelled")
        self.assertEqual(page["Cache-Control"], "no-store")
        exported = self.mobility_export(event)
        self.assertEqual(exported["evaluation"]["signature"], evaluation.signature)
        mobility = exported["business_context"]["mobility"]
        self.assertFalse(mobility["included_in_historical_evaluation"])
        self.assertFalse(mobility["local_authorizations_modified"])
        row = mobility["rows"][0]
        self.assertEqual(row["state"], "verified_origin")
        self.assertEqual(row["basis"], "intent")
        self.assertEqual(row["matched_id"], str(intent.pk))
        self.assertEqual(row["proposal"]["signature"], proposal.signature)
        self.assertEqual(row["decision"]["signature"], decision.signature)
        self.assertTrue(row["matches"][0]["reviewed_provenance_known_at_start"])
        reading = row["references"][0]
        self.assertEqual(reading["selected"]["receipt_id"], str(selected.pk))
        self.assertEqual(reading["reviewed"]["receipt_id"], str(reviewed.pk))
        self.assertEqual(reading["latest"]["receipt_id"], str(latest.pk))
        self.assertFalse(reading["same_context"])
        self.assertEqual(event.evaluations.get().signature, evaluation.signature)
        self.assertEqual(Grant.objects.get().status, "active")

    def test_segment_context_does_not_cover_access_before_local_approval(self):
        intent, *_ = self.move_with_access()
        start, end = intent.approved_at - timedelta(seconds=1), timezone.now()
        event = self.event(method="SSO", privilege="read", occurred_at=start, ended_at=end)
        evaluation = event.evaluations.get()
        self.assertIsNone(evaluation.intent_id)
        self.assertNotEqual(evaluation.verdict, "expected")
        self.login(self.reviewer)
        data = self.mobility_export(event)
        row = data["business_context"]["mobility"]["rows"][0]
        self.assertEqual(row["matched_id"], str(intent.pk))
        self.assertEqual(row["matches"][0]["start"], intent.approved_at.isoformat())
        self.assertNotEqual(row["matches"][0]["start"], start.isoformat())
        self.assertEqual(row["matches"][-1]["end"], end.isoformat())

    def test_grant_basis_and_zero_duration_match_use_the_exact_attested_grant(self):
        intent, *_ = self.move_with_access()
        # A right can be evaluated independently of the originating request.
        AccessIntent.objects.filter(pk=intent.pk).update(
            status="revoked", revoked_at=timezone.now()
        )
        instant = timezone.now()
        event = self.event(method="SSO", privilege="read", occurred_at=instant, ended_at=instant)
        self.assertIsNone(event.evaluations.get().intent_id)
        self.login(self.reviewer)
        row = self.mobility_export(event)["business_context"]["mobility"]["rows"][0]
        self.assertEqual(row["basis"], "grant")
        self.assertEqual(row["matched_id"], str(intent.provisioned_grant_id))
        self.assertIsNotNone(row["grant_origin"])
        self.assertIsNone(row["matches"][0]["end"])

    def test_matched_mobility_proofs_require_session_recent_mfa_and_enabled_module(self):
        self.move_with_access()
        event = self.event(method="SSO", privilege="read")
        page = reverse("event-mobility-context", args=[event.pk])
        export = reverse("event-export", args=[event.pk])
        self.assertEqual(
            Client().get(page, HTTP_AUTHORIZATION=f"Bearer {self.hr_token}").status_code, 302
        )
        self.login(self.reviewer, recent=False)
        detail = self.client.get(reverse("record-detail", args=["event", event.pk]))
        self.assertContains(detail, page)
        self.assertNotContains(detail, "Synthetic source dossier")
        for url in (page, export):
            self.assertRedirects(
                self.client.get(url), reverse("account-security"), fetch_redirect_response=False
            )
        for module in ("identity", "access", "connectors"):
            install_module(module, actor=self.admin, organization=self.other)
        self.login(self.admin, organization=self.other)
        self.assertEqual(self.client.get(page).status_code, 404)
        self.assertEqual(self.client.get(export).status_code, 404)
        disable_module("connectors", actor=self.admin, organization=self.org)
        self.login(self.reviewer)
        self.assertNotContains(self.client.get(page), "Synthetic source dossier")
        self.assertEqual(self.mobility_export(event)["business_context"]["mobility"]["rows"], [])

    def test_reference_text_and_invalid_proofs_never_imply_mobility_origin(self):
        intent, *_ = self.move_with_access()
        event = self.event(method="SSO", privilege="read")
        self.login(self.reviewer)
        with patch("platform_modules.access.ui.verify_evaluation", return_value=False):
            self.assertEqual(
                self.mobility_export(event)["business_context"]["mobility"]["rows"], []
            )
        with patch(
            "platform_modules.access.mobility_context.observed_business_origin",
            side_effect=ValidationError("invalid origin"),
        ):
            row = self.mobility_export(event)["business_context"]["mobility"]["rows"][0]
            self.assertEqual(row["state"], "invalid_origin")
            self.assertNotIn("references", row)
        separate = self.intent(reference=intent.reference)
        self.approve_access(separate)
        unrelated = self.event(external_id="unrelated")
        self.assertEqual(unrelated.evaluations.get().intent_id, separate.pk)
        self.assertEqual(
            self.mobility_export(unrelated)["business_context"]["mobility"]["rows"], []
        )

    def test_invalid_current_dossier_does_not_replace_authenticated_historical_reads(self):
        _, _, _, _, reviewed = self.move_with_access()
        event = self.event(method="SSO", privilege="read")
        self.reading(sequence=3, state="closed")
        self.login(self.reviewer)
        from platform_modules.connectors import business

        verify = business.verify_business_receipt
        with patch.object(
            business,
            "verify_business_receipt",
            side_effect=lambda obj: obj.sequence != 3 and verify(obj),
        ):
            row = self.mobility_export(event)["business_context"]["mobility"]["rows"][0]
        evidence = row["references"][0]
        self.assertEqual(row["state"], "verified_origin")
        self.assertEqual(evidence["reviewed"]["receipt_id"], str(reviewed.pk))
        self.assertIsNone(evidence["latest"])
        self.assertIsNone(evidence["same_context"])

    def test_multiple_sources_same_external_id_and_unchanged_new_observation(self):
        hr, ticket = self.reading(), self.reading(self.ticket_token)
        self.assertFalse(MoveProposal.objects.exists())
        self.assertFalse(Grant.objects.exists())
        role = self.role()
        proposal = self.anchored_move([hr, ticket], {role.pk: [self.account.pk]})
        submitted = proposal.body["business"]
        self.assertEqual(len(submitted["selected"]), 2)
        self.assertNotEqual(hr.record_id, ticket.record_id)
        refreshed = self.reading(sequence=2)
        applied = self.apply(proposal)
        self.assertEqual(applied.body["business_checked"][0]["receipt_id"], str(refreshed.pk))
        self.assertEqual(submitted["selected"][0]["receipt_id"], str(hr.pk))
        request = AccessIntent.objects.get()
        self.assertEqual(request.status, "pending")
        self.assertFalse(Grant.objects.exists())
        self.reading(sequence=3, state="cancelled")
        self.approve_access(request)
        self.assertEqual(Grant.objects.count(), 1)
        self.login(self.reviewer)
        response = self.client.get(reverse("mover-business-export", args=[proposal.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        exported = response.json()
        self.assertFalse(exported["local_access_approval"])
        self.assertEqual(exported["references"][0]["reviewed"]["receipt_id"], str(refreshed.pk))
        self.assertFalse(exported["references"][0]["same_context"])
        self.assertNotContains(response, self.hr_token)
        self.assertContains(
            self.client.get(reverse("record-detail", args=["intent", request.pk])),
            reverse("mover-business-proof", args=[proposal.pk]),
        )
        with organization_context(None):
            self.assertEqual(verify_mover(), 5)

    def test_changed_source_contents_block_apply_but_not_denial(self):
        reading = self.reading()
        change = self.anchored_move([reading])
        self.reading(sequence=2, state="closed")
        with self.assertRaisesMessage(ValidationError, "référence métier a changé"):
            self.apply(change)
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.department, "")
        self.assertFalse(MoveDecision.objects.exists())
        self.assertFalse(AccessIntent.objects.exists())
        self.apply(change, approved=False)
        with organization_context(None):
            self.assertEqual(verify_mover(), 2)

    def test_rotation_is_not_an_unchanged_reobservation(self):
        change = self.anchored_move([self.reading()])
        with self.mfa(self.admin):
            _, replacement = configure_business_source(
                self.hr.pk,
                actor=self.admin,
                organization=self.org,
                rotate=True,
            )
        self.reading(replacement, sequence=2)
        with self.assertRaises(ValidationError):
            self.apply(change)

    def test_expired_context_blocks_both_new_attachment_and_approval(self):
        reading = self.reading()
        change = self.anchored_move([reading])
        with patch(
            "platform_modules.connectors.business_references.timezone.now",
            return_value=timezone.now() + timedelta(minutes=30),
        ):
            with self.assertRaises(ValidationError):
                self.anchored_move([reading], department="Other")
            with self.assertRaises(ValidationError):
                self.apply(change)
        self.assertFalse(MoveDecision.objects.exists())

    def test_foreign_and_duplicate_dossier_pins_rejected(self):
        for module in ("identity", "access", "connectors"):
            install_module(module, actor=self.admin, organization=self.other)
        _, foreign_token = self.source("foreign", organization=self.other)
        foreign = self.reading(foreign_token, organization=self.other)
        with self.assertRaises(ValidationError):
            self.anchored_move([foreign])
        a, b = self.reading(), self.reading(sequence=2)
        with self.assertRaises(ValidationError):
            self.anchored_move([a, b])
        self.assertFalse(MoveProposal.objects.exists())

    def test_http_requires_review_of_bound_preview_and_independent_review_page(self):
        first = self.reading()
        self.login(self.operator)
        prepare = reverse("mover-prepare", args=[self.identity.pk])
        data = {
            "department": "Operations",
            "reference": "HR-42",
            "reason": "Exact source selection",
            "business-TOTAL_FORMS": "1",
            "business-INITIAL_FORMS": "0",
            "business-0-source": str(self.hr.pk),
            "business-0-external_id": "42",
        }
        submit = self.client.post(prepare, {**data, "command": "submit"})
        self.assertContains(submit, "Examinez les lectures")
        self.assertFalse(MoveProposal.objects.exists())
        preview = self.client.post(prepare, {**data, "command": "preview"})
        self.assertContains(preview, "Synthetic source dossier")
        self.assertFalse(MoveProposal.objects.exists())
        token = preview.context["preview_token"]
        changed = self.client.post(
            prepare,
            {**data, "department": "Changed", "command": "submit", "business_preview": token},
        )
        self.assertContains(changed, "La demande a changé")
        second = self.reading(sequence=2)
        result = self.client.post(prepare, {**data, "command": "submit", "business_preview": token})
        self.assertEqual(result.status_code, 302)
        proposal = MoveProposal.objects.get()
        self.assertEqual(proposal.body["business"]["selected"][0]["receipt_id"], str(first.pk))
        self.assertEqual(proposal.body["business"]["submitted"][0]["receipt_id"], str(second.pk))
        proof = reverse("mover-business-proof", args=[proposal.pk])
        decision = reverse("mover-decision", args=[proposal.pk])
        self.login(self.reviewer, recent=False)
        self.assertEqual(self.client.get(proof).status_code, 302)
        self.login(self.reviewer)
        self.client.post(decision, {"decision": "approve", "comment": "No examination"})
        self.assertFalse(MoveDecision.objects.exists())
        page = self.client.get(proof)
        self.assertContains(page, "Approuver le transfert après examen")
        self.client.post(
            decision,
            {
                "decision": "approve",
                "comment": "Reviewed",
                "business_review": page.context["review_token"],
            },
        )
        self.assertTrue(MoveDecision.objects.get().applied)

    def test_source_token_cannot_see_or_approve_proposal_and_foreign_portal_is_404(self):
        proposal = self.anchored_move([self.reading()])
        export = reverse("mover-business-export", args=[proposal.pk])
        decision = reverse("mover-decision", args=[proposal.pk])
        headers = dict(HTTP_AUTHORIZATION=f"Bearer {self.hr_token}")
        self.assertEqual(Client().get(export, **headers).status_code, 302)
        self.assertEqual(
            Client().post(decision, {"decision": "approve"}, **headers).status_code, 302
        )
        self.assertFalse(MoveDecision.objects.exists())
        for module in ("identity", "access", "connectors"):
            install_module(module, actor=self.admin, organization=self.other)
        self.login(self.admin, organization=self.other)
        self.assertEqual(self.client.get(export).status_code, 404)
