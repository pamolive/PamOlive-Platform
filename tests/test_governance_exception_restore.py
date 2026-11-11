"""Offline verification preserves risk-tracking evidence without granting access."""

from copy import deepcopy
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import Mock, patch

from django.db import connection
from django.test import TestCase, override_settings

from deploy.restore_application_check import model_fingerprints, verify_application
from platform_core.attestations import anchor_signature, signature
from platform_core.audit import digest
from platform_core.models import AccountSecurity
from platform_core.security import cipher
from platform_core.tenancy import organization_context
from platform_modules.governance.exception_models import ExceptionCase, ExceptionDecision
from platform_modules.governance.exceptions import (
    NAMESPACE,
    _body,
    case_state,
    verified,
    verify_exceptions,
)
from platform_modules.identity.models import Identity

from .test_governance_workspace import GovernanceFixture


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class GovernanceExceptionRestoreTests(GovernanceFixture, TestCase):
    def test_expired_and_closed_history_still_verifies_without_becoming_active(self):
        case = self.exception()
        accepted = self.decision(case)
        expired_at = case.expires_at + timedelta(days=1)
        self.assertEqual(case_state(case, [accepted], at=expired_at), "expired")
        self.assertEqual(verify_exceptions(), 2)
        self.decision(case, decision="closed", actor=self.operator)
        self.assertEqual(verify_exceptions(), 3)
        self.assertEqual(case_state(case, list(case.decisions.all()), at=expired_at), "closed")

    def test_a_changed_restored_fact_fails_its_real_hmac_verification(self):
        case = self.exception()
        self.decision(case)
        damaged = ExceptionCase.objects.select_related("audit", "identity", "resource").get(
            pk=case.pk,
        )
        damaged.compensating_controls = "Different restored controls without a new signature"
        restored_rows = Mock()
        restored_rows.iterator.return_value = iter([damaged])
        with patch.object(ExceptionCase.unscoped, "select_related", return_value=restored_rows):
            with self.assertRaisesRegex(RuntimeError, "exception request is invalid"):
                verify_exceptions()

    def test_missing_restored_decision_is_detected_by_its_retained_audit_anchor(self):
        case = self.exception()
        self.decision(case)
        empty = Mock()
        empty.select_related.return_value = []
        # The copy under verification appears to have lost a row. Its audit
        # anchor remains present, which must prevent treating it as pending.
        with (
            patch.object(ExceptionDecision.unscoped, "filter", return_value=empty),
            patch.object(ExceptionDecision.unscoped, "count", return_value=0),
        ):
            with self.assertRaisesRegex(RuntimeError, "unlinked evidence"):
                verify_exceptions()

    def test_cross_tenant_restored_subject_is_rejected_even_with_matching_test_signatures(self):
        case = self.exception()
        with organization_context(self.other):
            foreign = Identity.objects.create(organization=self.other, name="Synthetic foreign")
        damaged = ExceptionCase.objects.select_related("audit", "identity", "resource").get(
            pk=case.pk,
        )
        damaged.identity = foreign
        # Construct only an in-memory restored row and synthetic audit copy.
        # No service, model validation or PostgreSQL constraint is disabled.
        damaged.audit = deepcopy(damaged.audit)
        damaged.audit.metadata = {"body_hash": signature(NAMESPACE, "request-body", _body(damaged))}
        damaged.audit.event_hash = digest(damaged.audit)
        damaged.signature = anchor_signature(damaged, NAMESPACE, "request", _body(damaged))
        self.assertTrue(verified(damaged))
        restored_rows = Mock()
        restored_rows.iterator.return_value = iter([damaged])
        with patch.object(ExceptionCase.unscoped, "select_related", return_value=restored_rows):
            with self.assertRaisesRegex(RuntimeError, "exception request is invalid"):
                verify_exceptions()

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL full restoration verifier")
    def test_full_restore_verifier_checks_exception_proofs_and_preserves_rows(self):
        case = self.exception()
        self.decision(case)
        self.decision(case, decision="closed", actor=self.operator)
        # The fixture's assurance marker is sufficient for service tests; the
        # full restore verifier also decrypts all factors, so use ciphertext.
        AccountSecurity.objects.filter(
            account__in=(self.admin, self.operator, self.reviewer)
        ).update(
            encrypted_secret=cipher().encrypt(b"synthetic-offline-factor").decode(),
        )
        before = model_fingerprints(transaction_started=True)
        with patch("deploy.restore_application_check.database_guard"):
            result = verify_application()
        self.assertEqual(result["governance_exception_proofs_checked"], 3)
        self.assertGreaterEqual(result["signed_proofs_checked"], 3)
        self.assertTrue(result["postgresql_audit_guard"])
        self.assertEqual(model_fingerprints(transaction_started=True), before)
