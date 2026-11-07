from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent

from .models import SessionLease


@transaction.atomic
def open_lease(intent_id, *, actor, organization):
    authorize(actor, organization)
    require_module(organization, "pam")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        intent = AccessIntent.objects.get(pk=intent_id)
        now = timezone.now()
        if (
            intent.status != "approved"
            or not intent.starts_at <= now < intent.ends_at
            or intent.identity.status != "active"
            or not intent.account_id
            or not intent.account.active
            or intent.account.kind != "privileged"
            or intent.method.casefold() not in ("ssh", "rdp")
        ):
            raise ValidationError(
                "L’accès privilégié doit être approuvé, actif et dans sa fenêtre."
            )
        if actor.pk != intent.requested_by_id:
            raise ValidationError("Seul le demandeur peut ouvrir son accès.")
        existing = SessionLease.objects.filter(intent=intent, status="active").first()
        if existing:
            return existing
        lease = SessionLease.objects.create(
            organization=organization, intent=intent, opened_by=actor, expires_at=intent.ends_at
        )
        record(
            action="pam.lease.opened.v1",
            summary=f"Accès temporaire : {intent}",
            actor=actor,
            organization=organization,
            target=lease,
        )
        return lease


@transaction.atomic
def expire_leases(organization):
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        for lease in SessionLease.objects.select_for_update().filter(
            status="active", expires_at__lte=timezone.now()
        ):
            lease.status, lease.ended_at = "expired", timezone.now()
            lease.save(update_fields=["status", "ended_at"])
            record(
                action="pam.lease.expired.v1",
                summary="Accès temporaire expiré",
                organization=organization,
                target=lease,
            )
