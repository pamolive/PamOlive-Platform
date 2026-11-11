"""Synthetic acceptance tests for the P1 read-only access contract."""

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from platform_core.access_contract import SCHEMA, build_access_contract
from platform_core.models import AuditEvent, ModuleActivation
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent
from platform_modules.approvals.models import ApprovalDecision
from platform_modules.connectors.models import (
    AccountBinding,
    ExecutionEvidence,
    ExternalChange,
    ProvisioningConnector,
)
from platform_modules.identity.models import ExternalAccount, Grant, Identity, Resource

from . import test_platform as baseline


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class AccessContractTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.intent = baseline.PlatformTests.intent(self, privilege="Administrator")

    def read(self, **changes):
        return build_access_contract(
            self.intent.pk, actor=changes.pop("actor", self.operator),
            organization=changes.pop("organization", self.org), **changes,
        )

    def grant(self):
        grant = Grant.objects.create(
            organization=self.org, identity=self.identity, account=self.account,
            resource=self.resource, entitlement="Administrator", justification="Synthetic request",
            method=self.intent.method,
        )
        AccessIntent.objects.filter(pk=self.intent.pk).update(provisioned_grant=grant)
        return grant

    def change(self, grant, **changes):
        return ExternalChange.objects.create(
            organization=self.org, grant=grant, account=self.account,
            kind="add_membership", idempotency_key="synthetic-contract-change", **changes,
        )

    def test_pending_intention_is_not_an_approval_or_provider_effect(self):
        before = AuditEvent.objects.count()
        result = self.read()
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["intention"]["status"], "pending")
        self.assertEqual(result["requested_right"]["state"], "requested")
        for key in ("approval_decisions", "local_grant", "provisioned_right",
                    "confirmed_executions", "observations"):
            self.assertEqual(result[key]["items"], [])
        self.assertEqual(AuditEvent.objects.count(), before)
        self.assertTrue(result["read_only"])
        json.dumps(result)

    def test_local_grant_and_succeeded_flag_do_not_invent_provider_confirmation(self):
        grant = self.grant()
        change = self.change(grant, status="succeeded")
        result = self.read()
        self.assertEqual(result["local_grant"]["items"][0]["assurance"], "local_record")
        self.assertEqual(result["provisioned_right"]["items"], [])
        self.assertEqual(result["confirmed_executions"]["items"], [])
        ExecutionEvidence.objects.create(
            organization=self.org, change=change, attempt=1, confirmed=True,
            code="membership_confirmed", observed={"token": "must-not-be-projected"},
        )
        result = self.read()
        self.assertEqual(len(result["provisioned_right"]["items"]), 1)
        self.assertEqual(result["confirmed_executions"]["items"][0]["code"],
                         "membership_confirmed")
        self.assertNotIn("must-not-be-projected", json.dumps(result))
        self.assertEqual(result["provisioned_right"]["items"][0]["current_provider_state"],
                         "not_asserted")
        self.assertEqual(result["provisioned_right"]["items"][0]["origin"]["state"], "unknown")

    def test_mismatched_linked_grant_is_not_presented_as_requested_right(self):
        grant = self.grant()
        for field, incorrect in (("entitlement", "Other permission"), ("method", "RDP")):
            with self.subTest(field=field):
                Grant.objects.filter(pk=grant.pk).update(**{field: incorrect})
                with self.assertRaises(ValidationError):
                    self.read()
                Grant.objects.filter(pk=grant.pk).update(
                    entitlement=self.intent.privilege, method=self.intent.method
                )

    def test_identical_remote_ids_on_two_connectors_keep_distinct_recorded_origins(self):
        first_grant = self.grant()
        origins = []
        for index in range(2):
            connector = ProvisioningConnector.objects.create(
                organization=self.org, name=f"Synthetic directory {index}",
                base_url=f"https://directory-{index}.invalid/scim",
                encrypted_token="synthetic-only",
            )
            account = self.account if index == 0 else ExternalAccount.objects.create(
                organization=self.org, identity=self.identity,
                username="synthetic-second", system="synthetic-second",
            )
            binding = AccountBinding.objects.create(
                organization=self.org, connector=connector, account=account, remote_id="same-id",
            )
            grant = first_grant if index == 0 else Grant.objects.create(
                organization=self.org, identity=self.identity, account=account,
                resource=self.resource, entitlement=self.intent.privilege,
                method=self.intent.method, justification="Synthetic second directory",
            )
            intent = self.intent if index == 0 else baseline.PlatformTests.intent(
                self, account=account, privilege=self.intent.privilege,
            )
            AccessIntent.objects.filter(pk=intent.pk).update(provisioned_grant=grant)
            change = ExternalChange.objects.create(
                organization=self.org, grant=grant, account=account, binding=binding,
                kind="add_membership", idempotency_key=f"synthetic-origin-{index}",
                status="succeeded", connector_revision=index + 3,
            )
            ExecutionEvidence.objects.create(
                organization=self.org, change=change, attempt=1, confirmed=True,
                code="membership_confirmed", observed={"token": "never-expose-this"},
            )
            result = build_access_contract(intent.pk, actor=self.operator, organization=self.org)
            origin = result["confirmed_executions"]["items"][0]["origin"]
            self.assertEqual(origin, {
                "state": "recorded_reference", "binding_id": str(binding.pk),
                "connector_id": str(connector.pk), "recorded_connector_revision": index + 3,
            })
            for section in ("execution_attempts", "provisioned_right"):
                self.assertEqual(result[section]["items"][0]["origin"], origin)
            self.assertNotIn("never-expose-this", json.dumps(result))
            self.assertNotIn(connector.base_url, json.dumps(result))
            origins.append(origin)
        self.assertNotEqual(origins[0]["connector_id"], origins[1]["connector_id"])

    def test_disabled_connectors_are_unavailable_without_querying_the_domain(self):
        self.change(self.grant(), status="queued")
        ModuleActivation.objects.filter(module_key="connectors").update(enabled=False)
        with CaptureQueriesContext(connection) as queries:
            result = self.read()
        for key in ("execution_attempts", "confirmed_executions", "provisioned_right"):
            self.assertEqual(result[key]["availability"], "module_disabled")
            self.assertEqual(result[key]["items"], [])
        self.assertFalse(any('"connectors_' in row["sql"] for row in queries))

    def test_disabled_approvals_do_not_leak_decision_comments(self):
        ApprovalDecision.objects.create(
            organization=self.org, intent=self.intent, reviewer=self.reviewer,
            approved=True, comment="synthetic-private-decision",
        )
        ModuleActivation.objects.filter(module_key="approvals").update(enabled=False)
        result = self.read()
        self.assertEqual(result["approval_decisions"]["availability"], "module_disabled")
        self.assertNotIn("synthetic-private-decision", json.dumps(result))

    def test_context_membership_and_required_dependencies_are_enforced(self):
        outsider = get_user_model().objects.create_user("synthetic-contract-outsider")
        with self.assertRaises(PermissionDenied):
            self.read(actor=outsider)
        with organization_context(self.other), self.assertRaises(PermissionDenied):
            self.read()
        ModuleActivation.objects.filter(module_key="identity").update(enabled=False)
        with self.assertRaises(PermissionDenied):
            self.read()

    def test_foreign_intent_is_not_resolved_from_an_authorized_tenant(self):
        with organization_context(self.other):
            identity = Identity.objects.create(organization=self.other, name="Foreign synthetic")
            resource = Resource.objects.create(organization=self.other, name="Foreign target")
            foreign = AccessIntent.objects.create(
                organization=self.other, identity=identity, resource=resource,
                method="SSH", reason="foreign", starts_at=self.now,
                ends_at=self.now + timedelta(minutes=5), requested_by=self.admin,
            )
        with self.assertRaises(AccessIntent.DoesNotExist):
            build_access_contract(foreign.pk, actor=self.operator, organization=self.org)

    def test_collection_limits_are_explicit_and_no_mutation_occurs(self):
        ApprovalDecision.objects.create(
            organization=self.org, intent=self.intent, reviewer=self.reviewer,
            approved=True, comment="first",
        )
        ApprovalDecision.objects.create(
            organization=self.org, intent=self.intent, reviewer=self.admin,
            approved=False, comment="second",
        )
        before = ApprovalDecision.objects.count()
        result = self.read(limit=1)
        self.assertEqual(len(result["approval_decisions"]["items"]), 1)
        self.assertTrue(result["approval_decisions"]["truncated"])
        self.assertEqual(ApprovalDecision.objects.count(), before)

    def test_observation_requires_a_verified_explicit_evaluation_reference(self):
        event = baseline.PlatformTests.event(self, privilege=self.intent.privilege)
        self.assertEqual(self.read()["observations"]["items"], [])
        AccessIntent.objects.filter(pk=self.intent.pk).update(
            status="approved", approved_at=self.now - timedelta(seconds=1)
        )
        from platform_modules.access.services import reevaluate_event

        reevaluate_event(event.pk, actor=self.admin, organization=self.org)
        result = self.read()
        self.assertEqual(result["observations"]["items"][0]["id"], str(event.pk))
        self.assertEqual(result["observations"]["items"][0]["provenance"], "manual")
        self.assertTrue(result["observations"]["items"][0]["provenance_verified"])
        self.assertEqual(
            result["observations"]["items"][0]["provenance_principal_id"],
            str(self.operator.pk),
        )
        self.assertEqual(
            result["observations"]["items"][0]["provenance_receipt_id"],
            str(event.provenance_receipt.pk),
        )
