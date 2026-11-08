"""Deployment-owned observation adapters; source facts never become mutable inventory."""

import hashlib
import hmac
import json
import re
from copy import copy
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from platform_core.models import Organization
from platform_core.services import require_module
from platform_core.tenancy import current_organization

MANAGED_PREFIX = "managed:"
EVENT_FACT_FIELDS = (
    "id",
    "organization_id",
    "source",
    "external_id",
    "occurred_at",
    "ended_at",
    "received_at",
    "identity_id",
    "account_id",
    "resource_id",
    "credential_id",
    "method",
    "action",
    "location",
    "privilege",
    "result",
    "contract_id",
    "country_code",
    "evidence",
    "domain",
    "network_switch_id",
    "network_port",
    "network_vlan",
    "credential_observation",
)


def source_snapshot(event):
    """Versioned source schema; future nullable fields must not break old seals."""
    values = {}
    for key in EVENT_FACT_FIELDS:
        value = getattr(event, key)
        if isinstance(value, datetime):
            if value.utcoffset() is None:
                raise ValidationError("Source timestamp requires a timezone")
            value = value.astimezone(UTC).isoformat(timespec="microseconds")
        elif isinstance(value, UUID):
            value = str(value)
        values[key] = value
    return values


def sign(value, domain):
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hmac.new(
        settings.SECRET_KEY.encode(),
        ("pamolive.access." + domain + ".v1\0").encode() + payload,
        hashlib.sha256,
    ).hexdigest()


def context_hash(snapshot):
    # A new reading of identical source data need not create another evaluation.
    # The evaluation signature separately authenticates the complete witness list.
    return sign(snapshot.get("semantic", snapshot), "context")


@dataclass(frozen=True)
class ObservationContext:
    event: object
    snapshot: dict
    findings: tuple = ()
    blocked: bool = False

    @property
    def fingerprint(self):
        return context_hash(self.snapshot)


@dataclass(frozen=True)
class ObservationProvider:
    key: str
    module: str
    resolve: object
    related: object


_providers = {}


def register_provider(*, key, module, resolve, related):
    """AppConfig/deployment code only, never a form, DB path or uploaded script."""
    if (
        not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", key)
        or not callable(resolve)
        or not callable(related)
    ):
        raise ValueError("Invalid observation provider")
    provider = ObservationProvider(key, module, resolve, related)
    if key in _providers and _providers[key] != provider:
        raise RuntimeError("Observation provider already registered")
    _providers[key] = provider
    return provider


def is_managed_source(value):
    return isinstance(value, str) and value.strip().casefold().startswith(MANAGED_PREFIX)


def blocked_context(event, *, code, detail):
    observed = copy(event)
    observed.identity = observed.account = observed.resource = None
    return ObservationContext(
        observed,
        dict(semantic=dict(provider=event.source, state=code)),
        (dict(code=code, state="unknown", detail=detail, evidence=str(event.pk)),),
        True,
    )


@transaction.atomic
def observation_context(event, *, organization):
    if current_organization().pk != organization.pk or event.organization_id != organization.pk:
        raise PermissionDenied
    if not is_managed_source(event.source):
        return ObservationContext(copy(event), dict(attribution="source_reported"))
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    key = event.source.removeprefix(MANAGED_PREFIX)
    provider = _providers.get(key)
    if provider is not None:
        try:
            require_module(organization, provider.module)
            result = provider.resolve(event, organization=organization)
            if not isinstance(result, ObservationContext) or result.event.pk != event.pk:
                raise ValidationError("Invalid observation context")
            for field in event._meta.concrete_fields:
                if field.name not in {"identity", "account", "resource"} and (
                    getattr(event, field.attname) != getattr(result.event, field.attname)
                ):
                    raise ValidationError("An observation adapter cannot rewrite source facts")
            for key in ("identity", "account", "resource"):
                target = getattr(result.event, key)
                if target is not None and (
                    target.organization_id != organization.pk or result.blocked
                ):
                    raise ValidationError("Invalid interpretation scope")
            return result
        except (PermissionDenied, ValidationError):
            pass
    return blocked_context(
        event,
        code="observation_provider_unavailable",
        detail="La preuve ou le module de cette observation n’est pas disponible. "
        "Aucune attribution ni conformité n’est supposée.",
    )


def related_event_candidates(identity, *, limit=500, start=None, end=None):
    organization = current_organization()
    if identity.organization_id != organization.pk:
        raise PermissionDenied
    ids, truncated = set(), False
    for provider in _providers.values():
        try:
            require_module(organization, provider.module)
            found, limited = provider.related(identity, limit=limit, start=start, end=end)
        except PermissionDenied:
            continue
        ids.update(found)
        truncated |= limited
    return ids, truncated
