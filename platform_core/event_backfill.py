"""Reviewed, tenant-local delivery of existing signed facts to an active extension."""

import hmac
from datetime import UTC, datetime, timedelta

from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.utils import timezone

from .audit import record
from .authorization import require_recent_authentication
from .events import (
    _subscriptions,
    contract_hash,
    delivery_signature,
    event_is_valid,
    signature,
)
from .models import EventDelivery, ModuleEvent, Organization
from .services import authorize
from .tenancy import current_organization

LIMIT = 100
TOKEN_SALT = "pamolive.module-event-backfill.v1"
TOKEN_AGE_SECONDS = 300


def choices(organization):
    return [
        (f"{release.manifest.key}:{handler.name}", f"{release.manifest.name} · {handler.topic}")
        for release, handler in _subscriptions(organization)
    ]


def _guard(actor, organization):
    current = current_organization()
    if current is None or current.pk != organization.pk:
        raise PermissionDenied
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL statement_timeout='3s'")
            cursor.execute("SET LOCAL lock_timeout='1s'")
    org = Organization.objects.select_for_update().filter(pk=organization.pk, active=True).first()
    if org is None:
        raise PermissionDenied
    authorize(actor, org, roles=("admin",))
    require_recent_authentication(actor, org)
    return org


def _scope(org, selected, start, end):
    if (
        not isinstance(start, datetime)
        or not isinstance(end, datetime)
        or timezone.is_naive(start)
        or timezone.is_naive(end)
        or end > timezone.now()
        or not timedelta(0) < end - start <= timedelta(days=31)
    ):
        raise ValidationError("Choisissez une période passée de 31 jours maximum.")
    for release, handler in _subscriptions(org):
        if selected == f"{release.manifest.key}:{handler.name}":
            return {
                "organization": str(org.pk),
                "consumer": release.manifest.key,
                "release": release.release_hash,
                "handler": handler.name,
                "contract": contract_hash(handler),
                "topic": handler.topic,
                "start": start.astimezone(UTC).isoformat(),
                "end": end.astimezone(UTC).isoformat(),
            }
    raise ValidationError("Cet abonnement n’est pas actif dans cette organisation.")


def _plan(org, selected, start, end):
    scope = _scope(org, selected, start, end)
    events = list(
        ModuleEvent.objects.filter(
            topic=scope["topic"], occurred_at__gte=start, occurred_at__lt=end
        )
        .select_related("audit")
        .order_by("occurred_at", "pk")[: LIMIT + 1]
    )
    truncated = len(events) > LIMIT
    events = events[:LIMIT]
    existing = {
        delivery.event_id: delivery
        for delivery in EventDelivery.objects.filter(
            event_id__in=[event.pk for event in events],
            consumer=scope["consumer"],
            handler_name=scope["handler"],
        )
    }
    rows = []
    for event in events:
        delivery = existing.get(event.pk)
        if not event_is_valid(event) or (
            delivery is not None
            and (
                not delivery.signature.isascii()
                or not hmac.compare_digest(delivery.signature, delivery_signature(delivery))
            )
        ):
            state = "invalid"
        elif delivery is None:
            state = "ready"
        elif delivery.contract_hash != scope["contract"]:
            state = "old_contract"
        else:
            state = "existing"
        rows.append(
            {
                "event": str(event.pk),
                "occurred_at": event.occurred_at.isoformat(),
                "state": state,
                "event_signature": event.signature,
                "delivery": str(delivery.pk) if delivery else None,
                "contract": delivery.contract_hash if delivery else None,
            }
        )
    return {
        "scope": scope,
        "rows": rows,
        "truncated": truncated,
        "ready": sum(row["state"] == "ready" for row in rows),
        "blocked": any(row["state"] == "invalid" for row in rows),
    }


def _confirmation(actor, plan):
    return {
        "actor": actor.pk,
        "organization": plan["scope"]["organization"],
        "digest": signature(b"pamolive.module-backfill-plan.v1", plan),
    }


@transaction.atomic
def preview(*, actor, organization, selected, start, end):
    org = _guard(actor, organization)
    plan = _plan(org, selected, start, end)
    return plan, signing.dumps(_confirmation(actor, plan), salt=TOKEN_SALT)


@transaction.atomic
def submit(*, actor, organization, selected, start, end, token):
    org = _guard(actor, organization)
    try:
        expected = signing.loads(token, salt=TOKEN_SALT, max_age=TOKEN_AGE_SECONDS)
    except signing.BadSignature:
        raise ValidationError("L’aperçu n’est plus valide. Prévisualisez à nouveau.") from None
    plan = _plan(org, selected, start, end)
    if expected != _confirmation(actor, plan):
        raise ValidationError("Le périmètre a changé. Prévisualisez à nouveau.")
    if plan["truncated"] or plan["blocked"] or not plan["ready"]:
        raise ValidationError("Cet aperçu ne peut pas être mis en file.")
    scope = plan["scope"]
    deliveries = []
    now = timezone.now()
    for row in plan["rows"]:
        if row["state"] != "ready":
            continue
        delivery = EventDelivery(
            organization=org,
            event_id=row["event"],
            consumer=scope["consumer"],
            handler_name=scope["handler"],
            contract_hash=scope["contract"],
            available_at=now,
        )
        delivery.signature = delivery_signature(delivery)
        deliveries.append(delivery)
    EventDelivery.objects.bulk_create(deliveries)
    record(
        action="core.module_event.backfill_requested.v1",
        summary="Rattrapage d’événements mis en file",
        actor=actor,
        organization=org,
        metadata={
            **scope,
            "preview_digest": expected["digest"],
            "recipients": [
                {"event": str(row.event_id), "delivery": str(row.pk)} for row in deliveries
            ],
        },
    )
    return len(deliveries)
