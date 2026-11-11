"""Synthetic P1-D IGA catalogue, withdrawal tracking and non-authorizing exceptions."""

import json
import time
from datetime import timedelta
from unittest import skipUnless
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from platform_core.audit import record
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, ModuleActivation, OrganizationMembership
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.connectors.models import (
    AccountBinding,
    ExecutionEvidence,
    ExternalChange,
    ProvisioningConnector,
)
from platform_modules.governance.exception_models import ExceptionCase, ExceptionDecision
from platform_modules.governance.exceptions import (
    case_state,
    decide_exception,
    request_exception,
    verified,
)
from platform_modules.governance.policy import separation_findings
from platform_modules.governance.services import publish_policy, publish_separation
from platform_modules.governance.workspace import SCHEMA, build_governance_workspace
from platform_modules.identity.models import Grant, Identity, Resource
from platform_modules.identity.mover import publish_role
from platform_modules.recertification.schedules import publish_schedule, set_schedule_enabled
from platform_modules.recertification.services import start_campaign

from . import test_platform as baseline


class GovernanceFixture:
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        install_module("governance", actor=self.admin, organization=self.org)
        for actor in (self.admin, self.operator, self.reviewer):
            AccountSecurity.objects.get_or_create(
                account=actor,
                defaults={"encrypted_secret": "synthetic-factor-reference"},
            )

    def read(self, **kwargs):
        return build_governance_workspace(
            actor=kwargs.pop("actor", self.operator),
            organization=kwargs.pop("organization", self.org),
            **kwargs,
        )

    def exception(self, actor=None, **changes):
        actor = actor or self.operator
        data = dict(
            identity_id=self.identity.pk,
            resource_id=self.resource.pk,
            entitlement="Administrator",
            reason="Synthetic tracked business risk",
            reference="SYNTHETIC-RISK-483",
            compensating_controls="Synthetic supervised review",
            expires_at=timezone.now() + timedelta(days=7),
        )
        data.update(changes)
        with recent_authentication(actor, self.org, time.time()):
            return request_exception(actor=actor, organization=self.org, **data)

    def decision(self, case, decision="accepted", actor=None):
        actor = actor or self.reviewer
        with recent_authentication(actor, self.org, time.time()):
            return decide_exception(
                case.pk,
                actor=actor,
                organization=self.org,
                decision=decision,
                comment="Synthetic reviewed justification",
            )

    def schedule_data(self):
        return dict(
            name="Synthetic periodic IGA review",
            first_at=timezone.now(),
            interval_days=7,
            review_window_days=3,
            scope={},
            owner=self.reviewer,
        )

    def schedule_draft(self):
        with recent_authentication(self.admin, self.org, time.time()):
            return publish_schedule(
                self.schedule_data(),
                key="synthetic-review",
                actor=self.admin,
                organization=self.org,
            )


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class GovernanceWorkspaceTests(GovernanceFixture, TestCase):
    def test_stale_active_administrator_cannot_publish_recertification_schedule(self):
        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=False)
        with (
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            publish_schedule(
                self.schedule_data(),
                key="synthetic-review",
                actor=self.admin,
                organization=self.org,
            )

    def test_stale_active_administrator_cannot_enable_recertification_schedule(self):
        publication = self.schedule_draft()
        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=False)
        with (
            recent_authentication(self.admin, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            set_schedule_enabled(
                publication.schedule_id,
                True,
                expected_revision=1,
                actor=self.admin,
                organization=self.org,
            )

    def test_stale_active_reviewer_cannot_open_manual_recertification_campaign(self):
        get_user_model().objects.filter(pk=self.reviewer.pk).update(is_active=False)
        with (
            recent_authentication(self.reviewer, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            start_campaign(
                actor=self.reviewer,
                organization=self.org,
                name="Synthetic revoked reviewer",
                due_at=timezone.now() + timedelta(days=1),
            )

    def test_stale_active_administrator_cannot_publish_after_account_deactivation(self):
        OrganizationMembership.objects.filter(account=self.operator, organization=self.org).update(
            role="admin",
        )
        get_user_model().objects.filter(pk=self.operator.pk).update(is_active=False)
        self.assertTrue(self.operator.is_active)  # Deliberately stale request object.
        with (
            recent_authentication(self.operator, self.org, time.time()),
            self.assertRaises(PermissionDenied),
        ):
            publish_policy(
                dict(
                    min_reviewers=1,
                    critical_reviewers=1,
                    require_external_contract=False,
                    supplier_sponsor_required=False,
                ),
                actor=self.operator,
                organization=self.org,
            )

    def test_catalogue_contains_only_verified_enabled_role_entries(self):
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.resource,
            entitlement="Unpublished permission",
            justification="Synthetic preexisting grant",
        )
        with recent_authentication(self.admin, self.org, time.time()):
            role = publish_role(
                key="synthetic-operations",
                name="Synthetic operations",
                enabled=True,
                expected_revision=0,
                actor=self.admin,
                organization=self.org,
                entries=[
                    dict(resource=self.resource.pk, method="SSH", privilege="Administrator", days=7)
                ],
            )
        result = self.read()
        self.assertEqual(result["schema"], SCHEMA)
        self.assertTrue(result["read_only"])
        self.assertEqual(len(result["entitlement_catalog"]["items"]), 1)
        entry = result["entitlement_catalog"]["items"][0]
        self.assertEqual(entry["role_id"], str(role.pk))
        self.assertEqual(entry["eligibility"], "requires_request_policy_evaluation")
        self.assertEqual(entry["risk"], "not_classified")
        self.assertNotIn("Unpublished permission", json.dumps(result))
        with recent_authentication(self.admin, self.org, time.time()):
            publish_role(
                key=role.key,
                name="Retired synthetic role",
                enabled=False,
                expected_revision=1,
                actor=self.admin,
                organization=self.org,
                entries=role.body["entries"],
            )
        self.assertEqual(self.read()["entitlement_catalog"]["items"], [])

    def test_succeeded_flag_does_not_confirm_a_withdrawal_and_history_keeps_origin(self):
        grant = Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=self.resource,
            account=self.account,
            entitlement="Administrator",
            justification="Synthetic revoke",
            status="revoked",
            revoked_at=timezone.now(),
        )
        connector = ProvisioningConnector.objects.create(
            organization=self.org,
            name="Synthetic original directory",
            base_url="https://original.invalid/scim",
            encrypted_token="synthetic-unused",
        )
        binding = AccountBinding.objects.create(
            organization=self.org,
            connector=connector,
            account=self.account,
            remote_id="same-id",
        )
        change = ExternalChange.objects.create(
            organization=self.org,
            account=self.account,
            grant=grant,
            binding=binding,
            kind="remove_membership",
            idempotency_key="synthetic-withdrawal",
            status="succeeded",
            connector_revision=1,
        )
        row = self.read()["withdrawal_operations"]["items"][0]
        self.assertEqual(row["confirmation_state"], "unconfirmed")
        proof = ExecutionEvidence.objects.create(
            organization=self.org,
            change=change,
            attempt=1,
            confirmed=True,
            code="removal_confirmed",
            observed={"secret": "SYNTHETIC-DO-NOT-EXPORT"},
        )
        # P0-2 requires an explicit new destination, not rewriting the old URL.
        ProvisioningConnector.objects.create(
            organization=self.org,
            name="Synthetic replacement directory",
            base_url="https://replacement.invalid/scim",
            encrypted_token="synthetic-new-secret",
        )
        ProvisioningConnector.objects.filter(pk=connector.pk).update(revision=2)
        result = self.read()
        row = result["withdrawal_operations"]["items"][0]
        self.assertEqual(row["recorded_confirmation_id"], str(proof.pk))
        self.assertEqual(row["confirmation_state"], "historically_confirmed")
        self.assertEqual(row["current_provider_state"], "not_asserted")
        self.assertEqual(row["origin"]["recorded_connector_revision"], 1)
        for forbidden in ("SYNTHETIC-DO-NOT-EXPORT", "original.invalid", "replacement.invalid"):
            self.assertNotIn(forbidden, json.dumps(result))

    def test_disabled_domains_are_not_queried_or_exposed(self):
        ModuleActivation.objects.filter(
            organization=self.org, module_key__in=("connectors", "approvals", "recertification")
        ).update(enabled=False)
        with CaptureQueriesContext(connection) as queries:
            result = self.read()
        for key in ("withdrawal_operations", "approval_decisions", "campaigns", "access_reviews"):
            self.assertEqual(result[key]["availability"], "module_disabled")
            self.assertEqual(result[key]["items"], [])
        self.assertFalse(
            any(
                any(
                    f'"{prefix}_' in row["sql"]
                    for prefix in ("connectors", "approvals", "recertification")
                )
                for row in queries
            )
        )

    def test_tenant_scope_and_revoked_role_are_checked_in_service(self):
        with organization_context(self.other), self.assertRaises(PermissionDenied):
            self.read()
        outsider = get_user_model().objects.create_user("synthetic-governance-outsider")
        with self.assertRaises(PermissionDenied):
            self.read(actor=outsider)
        OrganizationMembership.objects.filter(account=self.operator).update(active=False)
        with self.assertRaises(PermissionDenied):
            self.read()

    def test_limits_are_explicit_and_bounded(self):
        baseline.PlatformTests.intent(self)
        baseline.PlatformTests.intent(self, reference="synthetic-second")
        result = self.read(limit=1)
        self.assertEqual(len(result["access_requests"]["items"]), 1)
        self.assertTrue(result["access_requests"]["truncated"])
        for invalid in (0, 101, True, "5"):
            with self.assertRaises(ValidationError):
                self.read(limit=invalid)


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class GovernanceExceptionTests(GovernanceFixture, TestCase):
    def test_acceptance_is_signed_bounded_and_does_not_grant_or_approve(self):
        intent = baseline.PlatformTests.intent(self, privilege="Administrator")
        case = self.exception()
        decision = self.decision(case)
        self.assertTrue(verified(case))
        self.assertTrue(verified(decision))
        self.assertEqual(case_state(case, [decision], at=timezone.now()), "accepted")
        self.assertEqual(case_state(case, [decision], at=case.expires_at), "expired")
        intent.refresh_from_db()
        self.assertEqual(intent.status, "pending")
        self.assertFalse(Grant.objects.exists())
        self.assertFalse(ExternalChange.objects.exists())
        projection = self.read()["exceptions"]["items"][0]
        self.assertFalse(projection["grants_authority"])
        self.assertEqual(projection["state"], "accepted")

    def test_self_review_operator_review_and_repeated_review_are_refused(self):
        case = self.exception(actor=self.admin)
        with self.assertRaises(PermissionDenied):
            self.decision(case, actor=self.admin)
        with self.assertRaises(PermissionDenied):
            self.decision(case, actor=self.operator)
        self.decision(case, decision="rejected")
        with self.assertRaises(ValidationError):
            self.decision(case)
        self.assertEqual(case.decisions.count(), 1)

    def test_requester_can_close_early_and_case_cannot_reopen(self):
        case = self.exception()
        self.decision(case)
        closed = self.decision(case, decision="closed", actor=self.operator)
        self.assertEqual(case_state(case, list(case.decisions.all()), at=timezone.now()), "closed")
        self.assertTrue(verified(closed))
        with self.assertRaises(ValidationError):
            self.decision(case)

    def test_required_assurance_duration_and_module_are_enforced(self):
        with self.assertRaises(PermissionDenied):
            request_exception(
                actor=self.operator,
                organization=self.org,
                identity_id=self.identity.pk,
                resource_id=self.resource.pk,
                entitlement="read",
                reference="synthetic",
                reason="synthetic",
                compensating_controls="synthetic",
                expires_at=timezone.now() + timedelta(days=1),
            )
        for invalid in (
            timezone.now() - timedelta(seconds=1),
            timezone.now() + timedelta(days=31),
            "2026-11-20",
            None,
        ):
            with self.assertRaises(ValidationError):
                self.exception(expires_at=invalid)
        ModuleActivation.objects.filter(organization=self.org, module_key="governance").update(
            enabled=False,
        )
        with self.assertRaises(PermissionDenied):
            self.exception()

    def test_foreign_subject_and_foreign_case_cannot_be_used(self):
        with organization_context(self.other):
            identity = Identity.objects.create(organization=self.other, name="Foreign synthetic")
        with self.assertRaises(Identity.DoesNotExist):
            self.exception(identity_id=identity.pk)
        case = self.exception()
        for key in ("identity", "access", "governance"):
            install_module(key, actor=self.admin, organization=self.other)
        with (
            organization_context(self.other),
            recent_authentication(self.admin, self.other, time.time()),
            self.assertRaises(ExceptionCase.DoesNotExist),
        ):
            decide_exception(
                case.pk,
                actor=self.admin,
                organization=self.other,
                decision="accepted",
                comment="Synthetic cross-tenant attempt",
            )

    def test_proofs_are_immutable_and_tampering_is_not_accepted(self):
        case = self.exception()
        with self.assertRaises(ValidationError):
            ExceptionCase.objects.filter(pk=case.pk).update(reason="tampered")
        with self.assertRaises(ValidationError):
            case.delete()
        case.reason = "Tampered synthetic justification"
        self.assertFalse(verified(case))
        self.assertEqual(case_state(case, [], at=timezone.now()), "invalid_evidence")

    def test_accepted_exception_never_suppresses_separation_of_duties(self):
        other_resource = Resource.objects.create(
            organization=self.org,
            name="Synthetic payment approval",
            kind="application",
        )
        with recent_authentication(self.admin, self.org, time.time()):
            publish_separation(
                dict(
                    name="Synthetic separation",
                    left_resource=self.resource,
                    left_entitlement="Administrator",
                    right_resource=other_resource,
                    right_entitlement="Approve payments",
                ),
                actor=self.admin,
                organization=self.org,
            )
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=other_resource,
            entitlement="Approve payments",
            justification="Synthetic existing conflicting right",
            valid_from=timezone.now() - timedelta(days=1),
        )
        case = self.exception()
        self.decision(case)
        now = timezone.now()
        assessment = separation_findings(
            identity=self.identity,
            resource=self.resource,
            entitlement="Administrator",
            start=now,
            end=now + timedelta(hours=1),
            as_of=now,
        )
        self.assertEqual(assessment.status, "deny")

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL exception database guards")
    def test_postgresql_prevents_raw_tamper_foreign_links_and_self_review(self):
        case = self.exception()
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "UPDATE governance_exceptioncase SET reason = %s WHERE id = %s",
                ["synthetic-tamper", case.pk],
            )
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("DELETE FROM governance_exceptioncase WHERE id = %s", [case.pk])
        foreign_audit = record(
            action="synthetic.exception.foreign",
            summary="Synthetic foreign relation attempt",
            actor=self.admin,
            organization=self.other,
        )
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO governance_exceptioncase SELECT "
                "gen_random_uuid(), entitlement, reason, reference, compensating_controls, "
                "created_at, expires_at, mfa_verified_at, mfa_window_minutes, signature, "
                "%s, identity_id, %s, requested_by_id, resource_id "
                "FROM governance_exceptioncase WHERE id = %s",
                [foreign_audit.pk, self.other.pk, case.pk],
            )
        self_review_audit = record(
            action="synthetic.exception.self",
            summary="Synthetic self-review attempt",
            actor=self.operator,
            organization=self.org,
        )
        with self.assertRaises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO governance_exceptiondecision "
                "(id, case_id, organization_id, decision, comment, decided_by_id, decided_at, "
                "mfa_verified_at, mfa_window_minutes, audit_id, signature) "
                "VALUES (%s, %s, %s, 'accepted', 'synthetic', %s, %s, %s, 5, %s, %s)",
                [
                    uuid4(),
                    case.pk,
                    self.org.pk,
                    self.operator.pk,
                    timezone.now(),
                    timezone.now() - timedelta(seconds=1),
                    self_review_audit.pk,
                    "0" * 64,
                ],
            )


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class GovernanceWorkspaceViewsTests(GovernanceFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.operator)

    def test_ui_api_and_export_are_read_only_no_store(self):
        for name in (
            "governance-workspace",
            "api-governance-workspace",
            "governance-workspace-export",
        ):
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertEqual(self.client.post(reverse(name)).status_code, 405)
        self.assertEqual(response.json()["schema"], SCHEMA)
        self.assertIn("attachment", response["Content-Disposition"])

    def test_disabled_governance_and_missing_session_are_refused(self):
        ModuleActivation.objects.filter(organization=self.org, module_key="governance").update(
            enabled=False,
        )
        self.assertEqual(self.client.get(reverse("api-governance-workspace")).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(reverse("api-governance-workspace")).status_code, 302)

    def test_foreign_exception_does_not_appear_and_auditor_cannot_create(self):
        case = self.exception()
        auditor = get_user_model().objects.create_user("synthetic-governance-auditor")
        OrganizationMembership.objects.create(
            organization=self.other, account=auditor, role="auditor"
        )
        for key in ("identity", "access", "governance"):
            install_module(key, actor=self.admin, organization=self.other)
        self.client.force_login(auditor)
        response = self.client.get(reverse("api-governance-workspace"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(str(case.pk), response.content.decode())
        self.assertEqual(self.client.get(reverse("governance-exception-create")).status_code, 403)

    def test_exception_forms_require_mfa_and_display_non_override_semantics(self):
        response = self.client.get(reverse("governance-exception-create"))
        self.assertContains(response, "ne crée aucun droit")
        response = self.client.post(
            reverse("governance-exception-create"),
            dict(
                identity=self.identity.pk,
                resource=self.resource.pk,
                entitlement="Administrator",
                reference="SYNTHETIC-FORM",
                reason="Synthetic reason",
                compensating_controls="Synthetic follow-up",
                days=7,
            ),
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ExceptionCase.objects.exists())

    def test_native_form_request_and_independent_review_keep_access_unchanged(self):
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.post(
            reverse("governance-exception-create"),
            dict(
                identity=self.identity.pk,
                resource=self.resource.pk,
                entitlement="Administrator",
                reference="SYNTHETIC-FORM-REVIEW",
                reason="Synthetic reviewed reason",
                compensating_controls="Synthetic follow-up",
                days=7,
            ),
        )
        self.assertRedirects(response, reverse("governance-workspace"))
        case = ExceptionCase.objects.get()
        response = self.client.post(
            reverse("governance-exception-decide", args=[case.pk]),
            {"decision": "accepted", "comment": "Synthetic self-review"},
        )
        self.assertEqual(response.status_code, 403)
        self.client.force_login(self.reviewer)
        session = self.client.session
        session["mfa_verified_at"] = time.time()
        session.save()
        response = self.client.post(
            reverse("governance-exception-decide", args=[case.pk]),
            {"decision": "accepted", "comment": "Synthetic independent review"},
        )
        self.assertRedirects(response, reverse("governance-workspace"))
        self.assertEqual(ExceptionDecision.objects.get().decision, "accepted")
        self.assertFalse(Grant.objects.exists())
        self.assertFalse(AccessIntent.objects.exists())

    def test_exception_creation_requires_csrf_protection(self):
        from django.test import Client

        protected = Client(enforce_csrf_checks=True)
        protected.force_login(self.operator)
        self.assertEqual(
            protected.post(reverse("governance-exception-create"), {}).status_code, 403
        )
        self.assertFalse(ExceptionCase.objects.exists())
