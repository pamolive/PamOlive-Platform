"""Frozen cohorts, prepared before the short organization commit lock."""

from datetime import timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from platform_core.attestations import seal, signature
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.events import publish_domain_event
from platform_core.models import Organization, OrganizationMembership
from platform_core.services import authorize, lock_authorized_actor, require_module
from platform_core.tenancy import current_organization
from platform_modules.identity.review_contract import capture_for_review, normalize_scope

from .evidence import (
    NAMESPACE,
    RUN_ACTION,
    manifest_hash,
    run_body,
    scope_body,
    verify_manifest,
    verify_publication,
)
from .evidence_models import CampaignRun, ReviewScope, SchedulePublication
from .models import Campaign, Review


def owner_eligible(owner, organization):
    return bool(
        owner.is_active
        and OrganizationMembership.objects.filter(
            organization=organization,
            account=owner,
            account__is_active=True,
            active=True,
            role__in=("admin", "reviewer"),
        ).exists()
    )


def _prepare(
    capture,
    organization,
    *,
    name,
    due_at,
    owner,
    scope,
    actor=None,
    assurance=None,
    publication=None,
    scheduled_for=None,
    next_due_at=None,
    missed_periods=0,
):
    campaign = Campaign(organization=organization, name=name, due_at=due_at)
    run = CampaignRun(
        organization=organization,
        campaign=campaign,
        name=name,
        due_at=due_at,
        owner=owner,
        opened_by=actor,
        capture_started_at=capture.started_at,
        snapshot_at=capture.finished_at,
        selection_scope=scope,
        review_count=len(capture.items),
        publication=publication,
        schedule_id=publication.schedule_id if publication else None,
        scheduled_for=scheduled_for,
        next_due_at=next_due_at,
        missed_periods=missed_periods,
        mfa_verified_at=assurance_datetime(assurance.verified_at) if assurance else None,
        mfa_window_minutes=assurance.freshness_minutes if assurance else None,
    )
    reviews, scopes = [], []
    for grant_id, body in capture.items:
        review = Review(organization=organization, campaign=campaign, grant_id=grant_id)
        item = ReviewScope(
            organization=organization,
            run=run,
            campaign=campaign,
            review=review,
            grant_id=grant_id,
            snapshot=body,
        )
        item.signature = signature(NAMESPACE, "scope", scope_body(item))
        reviews.append(review)
        scopes.append(item)
    run.manifest_hash = manifest_hash(scopes)
    return run, reviews, scopes


@transaction.atomic
def _commit(prepared, organization, *, actor=None):
    run, reviews, scopes = prepared
    locked = Organization.objects.select_for_update().get(pk=organization.pk)
    if not locked.active:
        raise PermissionDenied
    for module in ("identity", "recertification"):
        require_module(locked, module)
    if run.publication_id:
        current = (
            SchedulePublication.objects.filter(schedule_id=run.schedule_id)
            .order_by("-revision")
            .first()
        )
        if not current or current.pk != run.publication_id or not current.active:
            return None
        if not verify_publication(current) or not owner_eligible(current.owner, locked):
            raise ValidationError(
                "Le responsable de la règle n’est plus disponible.", code="review_owner_unavailable"
            )
        if current.published_at > run.capture_started_at:
            return None
        existing = CampaignRun.objects.filter(
            publication=current, scheduled_for=run.scheduled_for
        ).first()
        if existing:
            if not verify_manifest(existing):
                raise ValidationError(
                    "La campagne existante est invalide.", code="review_manifest_invalid"
                )
            return None
    else:
        actor, locked = lock_authorized_actor(actor, locked, roles=("admin", "reviewer"))
        require_recent_authentication(actor, locked)
        if actor.pk != run.owner_id and not owner_eligible(run.owner, locked):
            raise ValidationError("Choisissez un responsable actif de cette organisation.")
    run.campaign.full_clean()
    run.campaign.save()
    seal(
        run,
        NAMESPACE,
        "run",
        run_body(run),
        RUN_ACTION,
        actor=actor,
        summary="Ouverture d’une campagne avec périmètre figé",
    )
    Review.objects.bulk_create(reviews, batch_size=500)
    ReviewScope.objects.bulk_create(scopes, batch_size=500)
    publish_domain_event(
        organization=locked,
        emitter="recertification",
        topic="recertification.campaign.opened.v1",
        actor=actor,
        target=run,
        payload=dict(
            run_id=str(run.pk),
            campaign_id=str(run.campaign_id),
            review_count=run.review_count,
            scheduled=bool(run.publication_id),
        ),
    )
    return run


def start_campaign(*, actor, organization, name, due_at, owner=None):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin", "reviewer"))
    require_module(organization, "recertification")
    assurance = require_recent_authentication(actor, organization)
    if not isinstance(name, str) or not name.strip() or len(name) > 180:
        raise ValidationError("Un nom de campagne de 180 caractères maximum est requis.")
    if not due_at or timezone.is_naive(due_at):
        raise ValidationError("Une échéance avec fuseau est requise.")
    owner = owner or actor
    if owner.pk != actor.pk and not owner_eligible(owner, organization):
        raise ValidationError("Le responsable doit appartenir à cette organisation.")
    scope = normalize_scope({})
    capture = capture_for_review(
        organization,
        scope,
        max_items=settings.RECERTIFICATION_MAX_GRANTS,
        max_bytes=settings.RECERTIFICATION_MAX_BYTES,
    )
    if due_at <= capture.finished_at:
        raise ValidationError("L’échéance doit être postérieure à la capture.")
    run = _commit(
        _prepare(
            capture,
            organization,
            name=name.strip(),
            due_at=due_at,
            owner=owner,
            scope=scope,
            actor=actor,
            assurance=assurance,
        ),
        organization,
        actor=actor,
    )
    return run.campaign


def open_scheduled_campaign(publication, organization):
    capture = capture_for_review(
        organization,
        publication.scope,
        max_items=settings.RECERTIFICATION_MAX_GRANTS,
        max_bytes=settings.RECERTIFICATION_MAX_BYTES,
    )
    elapsed = capture.finished_at - publication.first_at
    if elapsed < timedelta(0):
        return None
    period = timedelta(days=publication.interval_days)
    slot = elapsed // period
    scheduled_for = publication.first_at + slot * period
    previous = (
        CampaignRun.objects.filter(publication=publication).order_by("-scheduled_for").first()
    )
    if previous and previous.scheduled_for >= scheduled_for:
        return None
    previous_slot = (previous.scheduled_for - publication.first_at) // period if previous else -1
    name = f"{publication.name} · {scheduled_for:%Y-%m-%d} · r{publication.revision}"
    prepared = _prepare(
        capture,
        organization,
        name=name,
        due_at=capture.finished_at + timedelta(days=publication.review_window_days),
        owner=publication.owner,
        scope=publication.scope,
        publication=publication,
        scheduled_for=scheduled_for,
        next_due_at=scheduled_for + period,
        missed_periods=max(0, slot - previous_slot - 1),
    )
    return _commit(prepared, organization)
