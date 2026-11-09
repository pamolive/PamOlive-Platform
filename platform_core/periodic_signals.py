"""Publish one bounded UTC signal per active signed contract, on the existing outbox."""

import uuid
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .events import _subscriptions, _write_delivery, _write_event
from .extensions.manifest import PERIODIC_TOPIC, PeriodicSignal
from .models import ModuleActivation, ModuleEvent, Organization
from .tenancy import organization_context

NAMESPACE = uuid.UUID("a9c87a1d-d38f-49c3-bd11-ed7035ea813a")
GRACE = timedelta(minutes=10)
MAX_PER_PASS = 4


def database_clock():
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT clock_timestamp()")
            return cursor.fetchone()[0].astimezone(UTC)
    return timezone.now().astimezone(UTC)


def _slot(now, signal):
    seconds = signal.interval_minutes * 60
    epoch = int(now.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, tz=UTC)


def _identifier(org_id, module, signal, slot):
    # The release does not participate: a release replaced within one slot
    # cannot schedule a second execution of the same named operation.
    return uuid.uuid5(NAMESPACE, f"{org_id}:{module}:{signal.name}:{slot.isoformat()}")


def _activation(org, release):
    return (
        ModuleActivation.objects.filter(
            organization=org,
            module_key=release.manifest.key,
            version=release.manifest.version,
            release_hash=release.release_hash,
            enabled=True,
        )
        .values_list("updated_at", flat=True)
        .first()
    )


def _payload(release, signal, slot, activation):
    return {
        "module": release.manifest.key,
        "release": release.release_hash,
        "name": signal.name,
        "period_minutes": signal.interval_minutes,
        "slot_utc": slot.isoformat(),
        "activation_utc": activation.astimezone(UTC).isoformat(),
    }


def enqueue_periodic_signals(organization):
    if not any(release.manifest.periodic_signals for release in settings.PAMOLIVE_EXTENSIONS):
        return 0
    with transaction.atomic(), organization_context(organization):
        active = Organization.objects.select_for_update().filter(pk=organization.pk, active=True)
        if not active.exists():
            return 0
        now = database_clock()
        count = 0
        for release, signal in _subscriptions(organization, include_periodic=True):
            if not isinstance(signal, PeriodicSignal):
                continue
            slot = _slot(now, signal)
            if now >= slot + GRACE:
                continue
            activation = _activation(organization, release)
            if activation is None or activation >= slot:
                continue
            event_id = _identifier(organization.pk, release.manifest.key, signal, slot)
            if ModuleEvent.objects.filter(pk=event_id).exists():
                continue
            event = ModuleEvent(
                id=event_id,
                organization=organization,
                emitter="core",
                topic=PERIODIC_TOPIC,
                occurred_at=now,
                correlation_id=event_id,
                payload=_payload(release, signal, slot, activation),
            )
            _write_event(event)
            _write_delivery(event, release, signal)
            count += 1
            if count >= MAX_PER_PASS:
                break
        return count


def periodic_delivery_state(event, release, signal):
    # Called after event/recipient integrity, under the same organization lock.
    try:
        slot = parse_datetime(event.payload["slot_utc"])
        issued = parse_datetime(event.payload["activation_utc"])
        release_hash = event.payload["release"]
        if (
            slot is None
            or issued is None
            or timezone.is_naive(slot)
            or timezone.is_naive(issued)
            or slot != _slot(slot, signal)
            or event.emitter != "core"
            or event.actor_account_id is not None
            or event.depth != 0
            or event.causation_id is not None
            or event.correlation_id != event.pk
            or event.aggregate_type
            or event.aggregate_id
            or issued >= slot
            or not slot <= event.occurred_at < slot + GRACE
            or event.pk != _identifier(event.organization_id, release.manifest.key, signal, slot)
        ):
            return "invalid", "PeriodicScope"
    except (KeyError, TypeError, ValueError, OverflowError):
        return "invalid", "PeriodicScope"
    activation = _activation(event.organization, release)
    now = database_clock()
    if (
        activation is None
        or activation != issued
        or release_hash != release.release_hash
        or not event.occurred_at <= now < slot + GRACE
    ):
        return "expired", "PeriodicWindowClosed"
    if event.payload != _payload(release, signal, slot, activation):
        return "invalid", "PeriodicScope"
    return "ready", ""
