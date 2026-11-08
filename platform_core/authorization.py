"""Recent interactive assurance for services that can affect external systems."""

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime

from django.core.exceptions import PermissionDenied

from .models import AccountSecurity


@dataclass(frozen=True)
class MutationAssurance:
    account_id: int
    organization_id: object
    verified_at: float
    freshness_minutes: int = 0


_assurance = ContextVar("pamolive_mutation_assurance", default=None)


@contextmanager
def without_interactive_authentication():
    """A background notification never inherits a publishing user's MFA."""
    token = _assurance.set(None)
    try:
        yield
    finally:
        _assurance.reset(token)


def assurance_datetime(verified_at):
    """Conservatively quantize float evidence to PostgreSQL/Django microseconds.

    datetime.fromtimestamp(float) rounds to nearest microsecond whereas a
    datetime clock sample may truncate the same tick. Never manufacture a
    future proof by rounding up. This conversion does not authorize anything;
    the original float's strict future/expiry checks remain authoritative.
    """
    if isinstance(verified_at, bool) or not isinstance(verified_at, (int, float)):
        raise ValueError("Invalid assurance timestamp.")
    numerator, denominator = verified_at.as_integer_ratio()
    # Exact integer arithmetic also avoids a second float multiplication rounding.
    seconds, microseconds = divmod(numerator * 1_000_000 // denominator, 1_000_000)
    return datetime.fromtimestamp(seconds, UTC).replace(microsecond=microseconds)


@contextmanager
def recent_authentication(actor, organization, verified_at):
    evidence = MutationAssurance(actor.pk, organization.pk, verified_at)
    token = _assurance.set(evidence)
    try:
        yield require_recent_authentication(actor, organization)
    finally:
        _assurance.reset(token)


def require_recent_authentication(actor, organization):
    evidence = _assurance.get()
    profile = AccountSecurity.objects.filter(account=actor).first()
    if (
        not evidence
        or evidence.account_id != actor.pk
        or evidence.organization_id != organization.pk
        or not profile
        or not profile.encrypted_secret
        or not 0 <= time.time() - evidence.verified_at < profile.freshness_minutes * 60
    ):
        raise PermissionDenied("Une MFA récente est nécessaire pour cette action externe.")
    return MutationAssurance(
        evidence.account_id,
        evidence.organization_id,
        evidence.verified_at,
        profile.freshness_minutes,
    )
