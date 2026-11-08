from datetime import UTC, datetime, timedelta
from fractions import Fraction
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from django.core.exceptions import PermissionDenied

from platform_core.authorization import assurance_datetime, recent_authentication
from platform_modules.identity.bindings import binding_signature, binding_valid
from platform_modules.identity.models import LoginIdentityBinding


class AssuranceTimeTests(TestCase):
    def test_conversion_is_exact_floor_not_nearest_microsecond(self):
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        for stamp in (0, 59, 1_000_000_000.0000006, 1_794_119_999.9999998, -0.0000006):
            with self.subTest(stamp=stamp):
                value = assurance_datetime(stamp)
                delta = value - epoch
                micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
                exact_micros = Fraction(stamp) * 1_000_000
                self.assertLessEqual(micros, exact_micros)
                self.assertLess(exact_micros - micros, 1)
        with self.assertRaises(ValueError):
            assurance_datetime(float("nan"))
        for invalid in (True, "123", None):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                assurance_datetime(invalid)

    def test_strict_future_and_expiry_checks_are_not_relaxed(self):
        now = 1_794_119_999.5
        actor, org = SimpleNamespace(pk=1), SimpleNamespace(pk="test-org")
        profile = SimpleNamespace(encrypted_secret="test-presence", freshness_minutes=5)
        with (
            patch("platform_core.authorization.AccountSecurity.objects.filter") as query,
            patch("platform_core.authorization.time.time", return_value=now),
        ):
            query.return_value.first.return_value = profile
            for stamp in (now + 0.000001, now - 300, float("nan"), float("inf")):
                with self.subTest(stamp=stamp), self.assertRaises(PermissionDenied):
                    with recent_authentication(actor, org, stamp):
                        self.fail("Future or expired evidence must not authorize a mutation.")
            with recent_authentication(actor, org, now - 0.000001):
                pass

    def test_signed_future_and_exactly_expired_proofs_are_still_refused(self):
        created = datetime(2026, 1, 1, tzinfo=UTC)
        for mfa_at in (created + timedelta(microseconds=1), created - timedelta(minutes=5)):
            binding = LoginIdentityBinding(
                organization_id="00000000-0000-0000-0000-000000000001",
                login_account_id=1,
                identity_id="00000000-0000-0000-0000-000000000002",
                created_by_id=2,
                verification_reference="Explicit precision regression fixture",
                created_at=created,
                mfa_verified_at=mfa_at,
                mfa_window_minutes=5,
            )
            binding.signature = binding_signature(binding)
            self.assertFalse(binding_valid(binding))
