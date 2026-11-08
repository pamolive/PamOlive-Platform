"""Latest signed policy only; one current occurrence, no historical backfill fiction."""

from datetime import UTC, datetime, timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import F, OuterRef, Q, Subquery

from platform_core.attestations import seal
from platform_core.audit import record
from platform_core.authorization import (
    assurance_datetime,
    require_recent_authentication,
    without_interactive_authentication,
)
from platform_core.events import publish_domain_event
from platform_core.models import ModuleActivation, Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import current_organization, organization_context
from platform_modules.identity.review_contract import database_now, normalize_scope

from .campaigns import open_scheduled_campaign, owner_eligible
from .evidence import NAMESPACE, PUBLICATION_ACTION, publication_body, verify_publication
from .evidence_models import CampaignRun, Schedule, SchedulePublication


def latest_publications():
    latest = (
        SchedulePublication.unscoped.filter(schedule_id=OuterRef("schedule_id"))
        .order_by("-revision")
        .values("pk")[:1]
    )
    return SchedulePublication.objects.alias(_current=Subquery(latest)).filter(pk=F("_current"))


def current_publication(schedule):
    return SchedulePublication.objects.filter(schedule=schedule).order_by("-revision").first()


def _operator(actor, organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "recertification")
    return require_recent_authentication(actor, organization)


def _validated(data, organization):
    if type(data) is not dict or set(data) != {
        "name",
        "first_at",
        "interval_days",
        "review_window_days",
        "scope",
        "owner",
    }:
        raise ValidationError("Configuration de planification inconnue.")
    value = dict(data)
    if (
        not isinstance(value["name"], str)
        or not value["name"].strip()
        or not value["name"].isprintable()
        or len(value["name"]) > 140
    ):
        raise ValidationError("Un nom lisible de 140 caractères maximum est requis.")
    value["name"] = value["name"].strip()
    for key, upper in (("interval_days", 3660), ("review_window_days", 365)):
        if type(value[key]) is not int or not 1 <= value[key] <= upper:
            raise ValidationError(f"{key} doit être compris entre 1 et {upper}.")
    first, now = value["first_at"], database_now()
    if (
        not isinstance(first, datetime)
        or first.tzinfo is None
        or first.utcoffset() is None
        or not datetime(1970, 1, 1, tzinfo=UTC) <= first <= now + timedelta(days=3660)
    ):
        raise ValidationError(
            "Le départ doit avoir un fuseau, depuis 1970 et au plus dix ans à l’avance."
        )
    if not owner_eligible(value["owner"], organization):
        raise ValidationError(
            "Choisissez un responsable actif, administrateur ou approbateur de l’organisation."
        )
    value["scope"] = normalize_scope(value["scope"])
    return value


def _publish(schedule, data, *, active, actor, organization, assurance, revision):
    publication = SchedulePublication(
        organization=organization,
        schedule=schedule,
        revision=revision,
        active=active,
        published_by=actor,
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
        **data,
    )
    seal(
        publication,
        NAMESPACE,
        "publication",
        publication_body(publication),
        PUBLICATION_ACTION,
        actor=actor,
        summary="Publication d’une règle de recertification",
    )
    schedule.retry_after, schedule.last_error, schedule.last_checked_at = None, "", None
    schedule.save(update_fields=("retry_after", "last_error", "last_checked_at"))
    publish_domain_event(
        organization=organization,
        emitter="recertification",
        topic="recertification.schedule.published.v1",
        actor=actor,
        target=publication,
        payload=dict(
            schedule_id=str(schedule.pk),
            publication_id=str(publication.pk),
            revision=revision,
            active=active,
        ),
    )
    return publication


@transaction.atomic
def publish_schedule(
    data, *, key=None, schedule_id=None, expected_revision=None, actor, organization
):
    assurance = _operator(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    value = _validated(data, organization)
    if schedule_id:
        schedule = Schedule.objects.get(pk=schedule_id)
        current = current_publication(schedule)
        if not current or not verify_publication(current) or current.revision != expected_revision:
            raise ValidationError(
                "La règle a changé ou sa preuve est invalide : rechargez la page."
            )
        revision = current.revision + 1
    else:
        schedule = Schedule(organization=organization, key=key)
        schedule.full_clean()
        schedule.save()
        revision = 1
    return _publish(
        schedule,
        value,
        active=False,
        actor=actor,
        organization=organization,
        assurance=assurance,
        revision=revision,
    )


@transaction.atomic
def set_schedule_enabled(schedule_id, enabled, *, expected_revision, actor, organization):
    assurance = _operator(actor, organization)
    if type(enabled) is not bool:
        raise ValidationError("Commande d’activation invalide.")
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    schedule = Schedule.objects.get(pk=schedule_id)
    current = current_publication(schedule)
    if not current or current.revision != expected_revision or not verify_publication(current):
        raise ValidationError("La règle a changé ou sa preuve est invalide : rechargez la page.")
    if current.active == enabled:
        return current
    fields = {
        key: getattr(current, key)
        for key in ("name", "first_at", "interval_days", "review_window_days", "scope", "owner")
    }
    if enabled:
        fields = _validated(fields, organization)
    return _publish(
        schedule,
        fields,
        active=enabled,
        actor=actor,
        organization=organization,
        assurance=assurance,
        revision=current.revision + 1,
    )


@transaction.atomic
def _issue(publication, organization, code):
    locked = Organization.objects.select_for_update().get(pk=organization.pk)
    if not locked.active:
        return
    schedule = Schedule.objects.get(pk=publication.schedule_id)
    current = current_publication(schedule)
    if not current or current.pk != publication.pk:
        return
    now = database_now()
    if schedule.last_error != code:
        record(
            action="recertification.schedule.blocked.v1",
            summary=code,
            organization=organization,
            target=schedule,
            metadata={"publication_id": str(publication.pk), "revision": publication.revision},
        )
    schedule.last_error, schedule.retry_after, schedule.last_checked_at = (
        code,
        now + timedelta(minutes=15),
        now,
    )
    schedule.save(update_fields=("last_error", "retry_after", "last_checked_at"))


def due_publications(now):
    last_due = (
        CampaignRun.unscoped.filter(publication_id=OuterRef("pk"))
        .order_by("-scheduled_for")
        .values("next_due_at")[:1]
    )
    return (
        latest_publications()
        .annotate(_next_due=Subquery(last_due))
        .filter(active=True, first_at__lte=now, published_at__lte=now)
        .filter(Q(_next_due__isnull=True) | Q(_next_due__lte=now))
        .filter(Q(schedule__retry_after__isnull=True) | Q(schedule__retry_after__lte=now))
        .select_related("audit", "schedule", "owner")
        .order_by("first_at", "id")
    )


def process_schedules(organization, *, limit=1):
    processed = 0
    with organization_context(organization), without_interactive_authentication():
        if not Organization.objects.filter(pk=organization.pk, active=True).exists() or not (
            ModuleActivation.objects.filter(
                organization=organization, module_key="recertification", enabled=True
            ).exists()
        ):
            return 0
        for publication in list(due_publications(database_now())[:limit]):
            if not verify_publication(publication):
                _issue(publication, organization, "schedule_proof_invalid")
                continue
            if not owner_eligible(publication.owner, organization):
                _issue(publication, organization, "review_owner_unavailable")
                continue
            try:
                run = open_scheduled_campaign(publication, organization)
            except PermissionDenied:
                _issue(publication, organization, "review_module_or_organization_unavailable")
                continue
            except ValidationError as error:
                code = getattr(error, "code", None)
                if code not in {
                    "review_scope_limit",
                    "review_clock_regressed",
                    "review_owner_unavailable",
                    "review_manifest_invalid",
                }:
                    code = "review_configuration_unavailable"
                _issue(publication, organization, code)
                continue
            if run:
                Schedule.objects.filter(pk=publication.schedule_id).update(
                    last_checked_at=database_now(), last_error="", retry_after=None
                )
                processed += 1
    return processed
