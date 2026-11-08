"""Transactional module notifications. No task names, code paths or authority in messages."""

import hashlib
import hmac
import json
import math
import re
import uuid
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import timedelta
from types import MappingProxyType

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.module_loading import import_string

from .audit import record
from .authorization import without_interactive_authentication
from .models import EventAttempt, EventDelivery, ModuleEvent, Organization
from .tenancy import current_organization, organization_context

_parent = ContextVar("pamolive_parent_module_event", default=None)
MAX_ATTEMPTS = 5


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def payload_bytes(payload):
    def check(value, depth=0):
        if depth > 6:
            raise ValidationError("Charge utile trop imbriquée.")
        if value is None or type(value) is bool:
            return
        if type(value) is int and -(2**63) <= value < 2**63:
            return
        if type(value) is float and math.isfinite(value) and abs(value) <= 2**53 - 1:
            return
        if type(value) is str and len(value) <= 8192:
            return
        if type(value) is dict and len(value) <= 100:
            for key, child in value.items():
                if type(key) is not str or not key or len(key) > 100:
                    raise ValidationError("Clé JSON invalide.")
                check(child, depth + 1)
            return
        if type(value) is list and len(value) <= 100:
            for child in value:
                check(child, depth + 1)
            return
        raise ValidationError("Valeur JSON hors du contrat d’événement.")

    if type(payload) is not dict:
        raise ValidationError("Un événement transporte un objet JSON, pas une commande.")
    check(payload)

    def normalize(value):
        # JSONB normalizes negative zero and exponent-form integral floats.
        # Sign one stable representation before persistence.
        if type(value) is float and value.is_integer():
            return int(value)
        if type(value) is dict:
            return {key: normalize(item) for key, item in value.items()}
        if type(value) is list:
            return [normalize(item) for item in value]
        return value

    result = canonical(normalize(payload))
    if len(result) > 32768:
        raise ValidationError("Charge utile de plus de 32 Kio.")
    return result


def signature(domain, value):
    return hmac.new(
        settings.SECRET_KEY.encode(), domain + b"\0" + canonical(value), "sha256"
    ).hexdigest()


def event_data(event):
    return {
        "event_id": str(event.pk),
        "organization_id": str(event.organization_id),
        "topic": event.topic,
        "emitter": event.emitter,
        "emitter_release": event.emitter_release,
        "occurred_at": event.occurred_at.isoformat(),
        "actor_account_id": event.actor_account_id,
        "aggregate_type": event.aggregate_type,
        "aggregate_id": event.aggregate_id,
        "correlation_id": str(event.correlation_id),
        "causation_id": str(event.causation_id) if event.causation_id else None,
        "depth": event.depth,
        "payload": event.payload,
    }


def event_signature(event):
    return signature(b"pamolive.module-event.v1", event_data(event))


def delivery_signature(delivery):
    return signature(
        b"pamolive.module-recipient.v1",
        {
            "id": str(delivery.pk),
            "organization_id": str(delivery.organization_id),
            "event_id": str(delivery.event_id),
            "consumer": delivery.consumer,
            "handler_name": delivery.handler_name,
            "contract_hash": delivery.contract_hash,
        },
    )


def contract_hash(subscription):
    return hashlib.sha256(canonical(asdict(subscription))).hexdigest()


def _subscriptions(organization):
    from .extensions.api import require_delivery

    for release in settings.PAMOLIVE_EXTENSIONS:
        if not release.manifest.consumed_events:
            continue
        try:
            require_delivery(organization, release.manifest.key)
        except PermissionDenied:
            continue
        for subscription in release.manifest.consumed_events:
            yield release, subscription


@transaction.atomic
def publish_domain_event(
    *,
    organization,
    emitter,
    topic,
    payload,
    actor=None,
    target=None,
    emitter_release="",
    correlation_id=None,
):
    """Internal domain service; extensions must use the authorized SDK facade instead."""
    if current_organization().pk != organization.pk:
        raise PermissionDenied("Contexte organisationnel incorrect.")
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    if (
        not re.fullmatch(
            re.escape(emitter) + r"\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.v[1-9][0-9]{0,3}", topic
        )
        or len(topic) > 120
    ):
        raise ValidationError("Événement versionné hors de son espace de nom.")
    data = json.loads(payload_bytes(payload))
    if target is not None and getattr(target, "organization_id", None) != organization.pk:
        raise PermissionDenied("Agrégat d’une autre organisation.")
    parent = _parent.get()
    if parent and (parent.organization_id != str(organization.pk) or parent.depth >= 16):
        raise ValidationError("Chaîne causale d’événements refusée.")
    event = ModuleEvent(
        organization=organization,
        emitter=emitter,
        emitter_release=emitter_release,
        topic=topic,
        payload=data,
        occurred_at=timezone.now(),
        actor_account_id=actor.pk if actor else None,
        aggregate_type=target._meta.label_lower if target else "",
        aggregate_id=str(target.pk) if target else "",
        correlation_id=parent.correlation_id
        if parent
        else uuid.UUID(str(correlation_id))
        if correlation_id
        else uuid.uuid4(),
        causation_id=parent.event_id if parent else None,
        depth=parent.depth + 1 if parent else 0,
    )
    event.signature = event_signature(event)
    event.audit = record(
        action="core.module_event.published.v1",
        summary="Notification de module publiée",
        actor=actor,
        organization=organization,
        target=event,
        metadata={"topic": topic, "event_signature": event.signature},
    )
    event.save()
    for release, subscription in _subscriptions(organization):
        if subscription.topic != topic:
            continue
        delivery = EventDelivery(
            organization=organization,
            event=event,
            consumer=release.manifest.key,
            handler_name=subscription.name,
            contract_hash=contract_hash(subscription),
            available_at=timezone.now(),
        )
        delivery.signature = delivery_signature(delivery)
        delivery.save()
    return event


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    organization_id: str
    topic: str
    emitter: str
    emitter_release: str
    occurred_at: str
    actor_account_id: int | None
    aggregate_type: str
    aggregate_id: str
    correlation_id: str
    causation_id: str | None
    depth: int
    payload: object

    @classmethod
    def from_event(cls, event):
        values = event_data(event)
        values["payload"] = _freeze(values["payload"])
        return cls(**values)


def _process_one(organization):
    with transaction.atomic(), organization_context(organization):
        if (
            not Organization.objects.select_for_update()
            .filter(pk=organization.pk, active=True)
            .exists()
        ):
            return False
        subscriptions = list(_subscriptions(organization))
        if not subscriptions:
            return False
        allowed = Q(pk__in=[])
        by_contract = {}
        for release, subscription in subscriptions:
            key = (release.manifest.key, subscription.name, contract_hash(subscription))
            allowed |= Q(consumer=key[0], handler_name=key[1], contract_hash=key[2])
            by_contract[key] = (release, subscription)
        query = EventDelivery.objects.filter(
            allowed, status="pending", available_at__lte=timezone.now()
        ).order_by("available_at", "pk")
        delivery = query.select_for_update(skip_locked=connection.vendor == "postgresql").first()
        if delivery is None:
            return False
        release, subscription = by_contract[
            (delivery.consumer, delivery.handler_name, delivery.contract_hash)
        ]
        event = ModuleEvent.objects.get(pk=delivery.event_id)
        delivery.attempts += 1
        try:
            payload_bytes(event.payload)
            bounded = True
        except ValidationError:
            bounded = False
        valid = bounded and (
            event.topic == subscription.topic
            and event.organization_id == delivery.organization_id
            and hmac.compare_digest(event.signature, event_signature(event))
            and hmac.compare_digest(delivery.signature, delivery_signature(delivery))
            and event.audit.organization_id == event.organization_id
            and event.audit.metadata.get("event_signature") == event.signature
        )
        outcome, code = "invalid", "EnvelopeIntegrity"
        if valid:
            try:
                # Only installed signed-manifest paths reach import_string. The
                # queue never contains an import path or a caller's MFA evidence.
                with transaction.atomic(), without_interactive_authentication():
                    if connection.vendor == "postgresql":
                        with connection.cursor() as cursor:
                            cursor.execute("SET LOCAL statement_timeout='3s'")
                            cursor.execute("SET LOCAL lock_timeout='1s'")
                    envelope = EventEnvelope.from_event(event)
                    token = _parent.set(envelope)
                    try:
                        import_string(subscription.handler)(envelope)
                    finally:
                        _parent.reset(token)
                outcome, code = "delivered", ""
            except Exception as error:
                outcome = "dead" if delivery.attempts >= MAX_ATTEMPTS else "retry"
                name = type(error).__name__
                code = name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", name) else "HandlerError"
        EventAttempt.objects.create(
            organization=organization,
            delivery=delivery,
            number=delivery.attempts,
            outcome=outcome,
            error_code=code,
            consumer_release=release.release_hash,
        )
        delivery.status = "pending" if outcome == "retry" else outcome
        delivery.available_at = timezone.now() + timedelta(
            seconds=min(300, 5 * 2**delivery.attempts)
        )
        delivery.completed_at = None if outcome == "retry" else timezone.now()
        delivery.save(update_fields=["status", "attempts", "available_at", "completed_at"])
        record(
            action="core.module_event.processed.v1",
            summary="Notification de module traitée",
            organization=organization,
            target=delivery,
            metadata={
                "outcome": outcome,
                "error_code": code,
                "attempt": delivery.attempts,
                "consumer_release": release.release_hash,
            },
        )
        return True


def process_events(organization, *, limit=10):
    if not any(release.manifest.consumed_events for release in settings.PAMOLIVE_EXTENSIONS):
        return 0
    if not Organization.objects.filter(pk=organization.pk, active=True).exists():
        return 0
    processed = 0
    for _ in range(max(0, min(limit, 100))):
        if not _process_one(organization):
            break
        processed += 1
    return processed
