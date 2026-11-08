"""Explicit, tenant-local linkage of authenticated accounts to governed people."""

import json
from datetime import UTC

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac

from platform_core.audit import record
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.models import Organization, OrganizationMembership
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context

from .models import LoginIdentityBinding


def binding_signature(binding):
    content = {
        "id": str(binding.pk),
        "organization": str(binding.organization_id),
        "login_account": str(binding.login_account_id),
        "identity": str(binding.identity_id),
        "verified_by": str(binding.created_by_id),
        "reference": binding.verification_reference,
        "created_at": binding.created_at.astimezone(UTC).isoformat(timespec="microseconds"),
        "mfa_at": binding.mfa_verified_at.astimezone(UTC).isoformat(timespec="microseconds")
        if binding.mfa_verified_at
        else None,
        "mfa_window": binding.mfa_window_minutes,
    }
    return salted_hmac(
        "pamolive.identity.person-binding.v1",
        json.dumps(content, sort_keys=True, separators=(",", ":")),
        secret=settings.PAMOLIVE_ENCRYPTION_KEY,
        algorithm="sha256",
    ).hexdigest()


def binding_valid(binding):
    return bool(
        binding.mfa_verified_at
        and binding.mfa_window_minutes in (2, 5, 10, 15)
        and 0
        <= (binding.created_at - binding.mfa_verified_at).total_seconds()
        < binding.mfa_window_minutes * 60
        and constant_time_compare(binding.signature, binding_signature(binding))
    )


def current_binding(account, *, organization, identity_id=None, binding_id=None):
    require_module(organization, "identity")
    with organization_context(organization):
        binding = (
            LoginIdentityBinding.objects.select_related("identity", "login_account")
            .filter(login_account=account, revoked_at__isnull=True, created_at__lte=timezone.now())
            .first()
        )
        if (
            not binding
            or not binding_valid(binding)
            or not account.is_active
            or binding.identity.status != "active"
            or binding.identity.kind not in ("human", "external")
            or (identity_id and binding.identity_id != identity_id)
            or (binding_id and binding.pk != binding_id)
            or not OrganizationMembership.objects.filter(
                organization=organization, account=account, active=True
            ).exists()
        ):
            raise ValidationError(
                "Un lien actif entre ce compte PAM-olive et la personne intervenante "
                "doit être établi par un administrateur dans cette organisation."
            )
        return binding


@transaction.atomic
def create_binding(*, login_account, identity, verification_reference, actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "identity")
    assurance = require_recent_authentication(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        if LoginIdentityBinding.objects.filter(
            login_account=login_account, revoked_at__isnull=True
        ).exists():
            raise ValidationError("Révoquez d’abord le lien actuel de ce compte.")
        binding = LoginIdentityBinding(
            organization=organization,
            login_account=login_account,
            identity=identity,
            verification_reference=verification_reference.strip(),
            created_by=actor,
            mfa_verified_at=assurance_datetime(assurance.verified_at),
            mfa_window_minutes=assurance.freshness_minutes,
        )
        binding.signature = binding_signature(binding)
        binding.full_clean()
        binding.save()
        record(
            action="identity.login_binding.created.v1",
            summary="Lien compte connecté / personne établi par un administrateur",
            actor=actor,
            organization=organization,
            target=binding,
            metadata={
                "identity_id": str(identity.pk),
                "login_account_id": str(login_account.pk),
                "verification_reference": binding.verification_reference,
                "mfa_verified_at": assurance.verified_at,
                "mfa_window_minutes": assurance.freshness_minutes,
            },
        )
        return binding


@transaction.atomic
def revoke_binding(binding_id, *, reason, actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "identity")
    require_recent_authentication(actor, organization)
    if not reason.strip():
        raise ValidationError("Motivez la révocation du lien.")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        binding = LoginIdentityBinding.objects.select_for_update().get(pk=binding_id)
        if binding.revoked_at:
            return binding
        binding.revoked_at, binding.revoked_by = timezone.now(), actor
        binding.revocation_reason = reason.strip()
        binding.save(update_fields=["revoked_at", "revoked_by", "revocation_reason"])
        from platform_modules.access.models import AccessIntent
        from platform_modules.pam.models import SessionLease

        AccessIntent.objects.filter(
            requester_binding=binding, status__in=("pending", "approved")
        ).update(status="revoked", revoked_at=binding.revoked_at)
        SessionLease.objects.filter(intent__requester_binding=binding, status="active").update(
            status="revoked", ended_at=binding.revoked_at
        )
        record(
            action="identity.login_binding.revoked.v1",
            summary="Lien de personne révoqué",
            actor=actor,
            organization=organization,
            target=binding,
            metadata={"reason": reason.strip(), "global_login_account_disabled": False},
        )
        return binding
