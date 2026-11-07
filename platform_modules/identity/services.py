from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.services import authorize
from platform_core.tenancy import organization_context
from platform_modules.connectors.outbound import queue_grant_state

from .models import Grant


@transaction.atomic
def revoke_grant(grant, *, actor, organization, origin):
    if grant.organization_id != organization.pk:
        raise ValidationError("Droit d’une autre organisation.")
    if actor:
        authorize(actor, organization, roles=("admin", "operator", "reviewer"))
    elif origin != "grant.expired" or not grant.expires_at or grant.expires_at > timezone.now():
        raise ValidationError("L’expiration automatique doit correspondre à une échéance passée.")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        grant = Grant.objects.select_for_update().get(pk=grant.pk)
        if grant.status != "revoked":
            grant.status = "revoked"
            grant.state_revision += 1
            grant.save(update_fields=["status", "state_revision"])
            queue_grant_state(grant, actor=actor, organization=organization, origin=origin)
            record(
                action="identity.grant.revoked.v1",
                summary=str(grant),
                actor=actor,
                organization=organization,
                target=grant,
                metadata={"origin": origin},
            )
        return grant


def expire_grants(organization):
    with organization_context(organization):
        for grant in Grant.objects.filter(status="active", expires_at__lte=timezone.now())[:100]:
            revoke_grant(grant, actor=None, organization=organization, origin="grant.expired")


@transaction.atomic
def grant_from_approval(intent, *, actor, organization):
    from platform_modules.approvals.models import ApprovalDecision

    authorize(actor, organization, roles=("admin", "reviewer"))
    if (
        intent.organization_id != organization.pk
        or intent.status != "approved"
        or intent.fulfillment != "iam_group"
        or intent.identity.status != "active"
        or not intent.account_id
        or not intent.account.active
        or not intent.privilege
        or intent.ends_at <= timezone.now()
    ):
        raise ValidationError("L’intention ne permet pas cette attribution IAM.")
    if not ApprovalDecision.objects.filter(intent=intent, reviewer=actor, approved=True).exists():
        raise ValidationError("La preuve d’approbation correspondante est requise.")
    Organization.objects.select_for_update().get(pk=organization.pk)
    if intent.provisioned_grant_id:
        return intent.provisioned_grant
    grant = Grant(
        organization=organization,
        identity=intent.identity,
        account=intent.account,
        resource=intent.resource,
        entitlement=intent.privilege,
        justification=f"{intent.reason} · {intent.reference}".strip(" ·"),
        expires_at=intent.ends_at,
    )
    grant.full_clean()
    grant.save()
    queue_grant_state(grant, actor=actor, organization=organization, origin="approvals.approved")
    record(
        action="identity.grant.approved.v1",
        summary=str(grant),
        actor=actor,
        organization=organization,
        target=grant,
        metadata={"intent_id": str(intent.pk)},
    )
    return grant
