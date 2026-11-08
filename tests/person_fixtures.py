"""Explicit person attestations for fixtures; production never guesses these links."""

import pyotp
from django.utils import timezone

from platform_core.models import AccountSecurity, OrganizationMembership
from platform_core.security import cipher
from platform_modules.identity.bindings import binding_signature
from platform_modules.identity.models import Identity, LoginIdentityBinding


def bind_person(account, *, organization, administrator, identity=None, role="operator"):
    OrganizationMembership.objects.get_or_create(
        organization=organization, account=account, defaults={"role": role, "active": True}
    )
    AccountSecurity.objects.get_or_create(
        account=account,
        defaults={"encrypted_secret": cipher().encrypt(pyotp.random_base32().encode()).decode()},
    )
    existing = LoginIdentityBinding.objects.filter(
        login_account=account, revoked_at__isnull=True
    ).first()
    if existing:
        assert identity is None or existing.identity_id == identity.pk
        return existing
    identity = identity or Identity.objects.create(
        organization=organization, name=f"Person fixture {account.username}", kind="human"
    )
    binding = LoginIdentityBinding(
        organization=organization,
        login_account=account,
        identity=identity,
        verification_reference="Explicit fixture person attestation",
        created_by=administrator,
        mfa_verified_at=timezone.now(),
        mfa_window_minutes=5,
    )
    binding.signature = binding_signature(binding)
    binding.save()
    return binding
