from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context
from platform_modules.identity.models import Grant

from .models import Campaign, Review


@transaction.atomic
def start_campaign(*, actor, organization, name, due_at):
    authorize(actor, organization, roles=("admin", "reviewer"))
    require_module(organization, "recertification")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        campaign = Campaign(organization=organization, name=name, due_at=due_at)
        campaign.full_clean()
        campaign.save()
        for grant in Grant.objects.filter(status="active"):
            Review.objects.create(organization=organization, campaign=campaign, grant=grant)
        record(
            action="recertification.campaign.created.v1",
            summary=name,
            actor=actor,
            organization=organization,
            target=campaign,
        )
        return campaign


@transaction.atomic
def review_grant(review_id, *, actor, organization, keep, comment):
    authorize(actor, organization, roles=("admin", "reviewer"))
    require_module(organization, "recertification")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        review = Review.objects.select_for_update().get(pk=review_id)
        if review.decision != "pending" or not comment.strip():
            raise ValidationError("Une revue doit être en attente et comporter un motif.")
        review.decision = "keep" if keep else "revoke"
        review.reviewer, review.comment, review.reviewed_at = actor, comment, timezone.now()
        review.save()
        if not keep:
            grant = review.grant
            grant.status = "revoked"
            grant.save(update_fields=["status"])
        record(
            action="recertification.grant.reviewed.v1",
            summary=review.decision,
            actor=actor,
            organization=organization,
            target=review,
            metadata={"comment": comment, "external_execution": "not_confirmed"},
        )
        return review
