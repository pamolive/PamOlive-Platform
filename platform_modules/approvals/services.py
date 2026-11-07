from django.core.exceptions import ValidationError
from django.db import transaction

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessIntent

from .models import ApprovalDecision


@transaction.atomic
def decide(intent_id, *, actor, organization, approved, comment):
    authorize(actor, organization, roles=("admin", "reviewer"))
    require_module(organization, "approvals")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        intent = AccessIntent.objects.select_for_update().get(pk=intent_id)
        if intent.requested_by_id == actor.pk:
            raise ValidationError("Le demandeur ne peut pas approuver sa propre demande.")
        if intent.status != "pending":
            raise ValidationError("Cette demande a déjà reçu une décision.")
        if not comment.strip():
            raise ValidationError("Motivez la décision.")
        decision = ApprovalDecision.objects.create(
            organization=organization,
            intent=intent,
            reviewer=actor,
            approved=approved,
            comment=comment,
        )
        intent.status = "approved" if approved else "denied"
        intent.save(update_fields=["status"])
        if approved and intent.fulfillment == "iam_group":
            from platform_modules.identity.services import grant_from_approval

            intent.provisioned_grant = grant_from_approval(
                intent, actor=actor, organization=organization
            )
            intent.save(update_fields=["provisioned_grant"])
        record(
            action="approvals.intent.decided.v1",
            summary=f"Demande {intent.status}",
            actor=actor,
            organization=organization,
            target=decision,
            metadata={"intent_id": str(intent.pk), "comment": comment},
        )
        return decision
