from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.services import authorize, lock_authorized_actor, require_module
from platform_core.tenancy import organization_context
from platform_modules.connectors.outbound import queue_grant_state

from .models import Grant


@transaction.atomic
def revoke_grant(grant, *, actor, organization, origin):
    if grant.organization_id != organization.pk:
        raise ValidationError("Droit d’une autre organisation.")
    if actor:
        authorize(actor, organization, roles=("admin", "operator", "reviewer"))
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        grant = Grant.objects.select_for_update().get(pk=grant.pk)
        if actor is None:
            from platform_modules.governance.policy import contract_withdrawal_required

            expired = (
                origin == "grant.expired"
                and grant.expires_at
                and grant.expires_at <= timezone.now()
            )
            withdrawn = (
                origin == "contract.withdrawn"
                and grant.contract_id
                and contract_withdrawal_required(grant, organization=organization)
            )
            if not expired and not withdrawn:
                raise ValidationError(
                    "La révocation automatique doit correspondre à une politique persistée "
                    "ou une expiration."
                )
        if grant.status != "revoked":
            grant.status = "revoked"
            grant.revoked_at = timezone.now()
            grant.state_revision += 1
            grant.save(update_fields=["status", "state_revision", "revoked_at"])
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

    actor, organization = lock_authorized_actor(
        actor, organization, roles=("admin", "reviewer")
    )
    # A direct domain caller must meet the same activation contract as the
    # approval endpoint. Mandatory revocation/expiry above remains available.
    require_module(organization, "identity")
    require_module(organization, "access")
    require_module(organization, "approvals")
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
    from .mover import attest_grant, authorize_move_intent

    link, _ = authorize_move_intent(intent, actor=actor, organization=organization)
    if link:
        from platform_modules.governance.policy import approval_requirements

        if link.intent.status != "approved" or not approval_requirements(link.intent)["complete"]:
            raise ValidationError(
                "Les approbations requises pour cet accès métier sont incomplètes."
            )
        intent = link.intent
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
        valid_from=max(intent.starts_at, timezone.now()),
        contract=intent.contract,
        method=intent.method,
        location=intent.location,
        country_code=intent.country_code,
        reference=intent.reference,
    )
    grant.full_clean()
    from platform_modules.governance.policy import enforce_authorization

    enforce_authorization(grant, organization=organization)
    grant.save()
    if link:
        attest_grant(link, grant, actor=actor, organization=organization)
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
