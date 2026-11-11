from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from platform_core.attestations import seal
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.events import publish_domain_event
from platform_core.models import OrganizationMembership
from platform_core.services import lock_authorized_actor, require_module
from platform_core.tenancy import current_organization
from platform_modules.identity.review_contract import apply_review

from .campaigns import start_campaign  # noqa: F401 -- public compatibility facade
from .evidence import DECISION_ACTION, NAMESPACE, decision_body, verify_scope
from .evidence_models import ReviewDecision, ReviewScope
from .models import Review


@transaction.atomic
def review_grant(review_id, *, actor, organization, keep, comment):
    if current_organization().pk != organization.pk or type(keep) is not bool:
        raise PermissionDenied
    actor, organization = lock_authorized_actor(
        actor, organization, roles=("admin", "reviewer")
    )
    require_module(organization, "recertification")
    assurance = require_recent_authentication(actor, organization)
    if (
        not isinstance(comment, str)
        or not comment.strip()
        or len(comment) > 2000
        or any(ord(c) < 32 and c not in "\n\t\r" for c in comment)
    ):
        raise ValidationError("Un motif de 2000 caractères maximum est requis.")
    review = Review.objects.select_for_update().get(pk=review_id)
    scope = ReviewScope.objects.select_related("run__audit", "review").filter(review=review).first()
    if not scope:
        raise ValidationError(
            "Cette revue historique n’a pas de périmètre figé : ouvrez une nouvelle campagne."
        )
    if not verify_scope(scope):
        raise ValidationError("Le périmètre ou son manifeste est invalide.")
    is_admin = (
        actor.is_superuser
        or OrganizationMembership.objects.filter(
            organization=organization, account=actor, active=True, role="admin"
        ).exists()
    )
    if scope.run.owner_id != actor.pk and not is_admin:
        raise PermissionDenied("Cette campagne possède un autre responsable.")
    if review.decision != "pending" or ReviewDecision.objects.filter(scope=scope).exists():
        raise ValidationError("Cette revue a déjà été traitée.")
    result = apply_review(organization, scope.grant_id, scope.snapshot, actor=actor, keep=keep)
    decision = ReviewDecision(
        organization=organization,
        scope=scope,
        decided_by=actor,
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
        keep=keep,
        comment=comment.strip(),
        local_outcome=result["outcome"],
        grant_state=result["state"],
    )
    seal(
        decision,
        NAMESPACE,
        "decision",
        decision_body(decision, scope),
        DECISION_ACTION,
        actor=actor,
        summary="Décision de revue sur un périmètre figé",
    )
    review.decision = "keep" if keep else "revoke"
    review.reviewer, review.comment, review.reviewed_at = (
        actor,
        decision.comment,
        decision.decided_at,
    )
    review.save(update_fields=("decision", "reviewer", "comment", "reviewed_at"))
    publish_domain_event(
        organization=organization,
        emitter="recertification",
        topic="recertification.review.decided.v1",
        actor=actor,
        target=decision,
        payload=dict(
            decision_id=str(decision.pk),
            run_id=str(scope.run_id),
            grant_id=str(scope.grant_id),
            local_outcome=result["outcome"],
        ),
    )
    return review
