from datetime import UTC, datetime

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.audit import record
from platform_core.authorization import require_recent_authentication
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
        if intent.ends_at <= timezone.now():
            raise ValidationError("Cette demande est expirée.")
        if ApprovalDecision.objects.filter(intent=intent, reviewer=actor).exists():
            raise ValidationError("Vous avez déjà voté sur cette demande.")
        from platform_modules.governance.policy import approval_requirements, enforce_authorization

        binding = None
        assurance = None
        if intent.fulfillment == "pam":
            from platform_modules.identity.bindings import current_binding
            from platform_modules.pam.mandates import validate_request

            assurance = require_recent_authentication(actor, organization)
            # A refusal may close an obsolete request; an approval may not revive it.
            if approved:
                validate_request(intent, organization=organization)
            binding = current_binding(actor, organization=organization)
            if binding.identity_id == intent.identity_id:
                raise ValidationError("L’intervenant ne peut pas approuver avec un autre compte.")
            if ApprovalDecision.objects.filter(
                intent=intent, reviewer_identity_id=binding.identity_id
            ).exists():
                raise ValidationError("Cette personne a déjà voté, même avec un autre compte.")
        if approved:
            enforce_authorization(intent, organization=organization, remaining=True)
        if not comment.strip():
            raise ValidationError("Motivez la décision.")
        decision = ApprovalDecision(
            organization=organization,
            intent=intent,
            reviewer=actor,
            approved=approved,
            comment=comment,
            reviewer_binding=binding,
            reviewer_identity=binding.identity if binding else None,
            mfa_verified_at=datetime.fromtimestamp(assurance.verified_at, UTC)
            if assurance
            else None,
            mfa_window_minutes=assurance.freshness_minutes if assurance else 0,
        )
        if intent.fulfillment == "pam":
            from platform_modules.pam.mandates import decision_signature, scope_hash

            decision.scope_hash = scope_hash(intent)
            decision.signature = decision_signature(decision)
        decision.full_clean()
        decision.save()
        requirements = approval_requirements(intent)
        intent.status = (
            "approved"
            if approved and requirements["complete"]
            else "pending"
            if approved
            else "denied"
        )
        if intent.status == "approved":
            intent.approved_at = timezone.now()
        intent.save(update_fields=["status", "approved_at"])
        if intent.status == "approved" and intent.fulfillment == "iam_group":
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
            metadata={
                "intent_id": str(intent.pk),
                "comment": comment,
                "requirements": requirements,
            },
        )
        return decision
