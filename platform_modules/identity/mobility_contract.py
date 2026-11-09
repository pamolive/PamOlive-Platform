"""identity.mobility-observation/1: read-only exact mobility provenance."""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from typing import Literal
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from platform_core.services import require_module
from platform_core.tenancy import current_organization

from .mover import observed_business_origin, proof_anchor
from .mover_models import MoveAccess, MoveGrant

CONTRACT = "identity.mobility-observation/1"
MAX_ORIGINS = 32


@dataclass(frozen=True)
class MobilityOriginKey:
    kind: Literal["intent", "grant"]
    object_id: UUID


@dataclass(frozen=True)
class MobilityOrigin:
    intent_id: UUID
    proposal_id: UUID
    decision_id: UUID
    role_key: str
    role_revision: int
    role_name: str
    decided_at: datetime
    last_proof_at: datetime
    submitted_references: dict
    reviewed_references: list
    proposal_proof: dict
    decision_proof: dict
    role_proof: dict
    intent_proof: dict
    grant_proof: dict | None


def _query(keys, organization):
    if current_organization().pk != organization.pk:
        raise PermissionDenied
    require_module(organization, "identity")
    keys = tuple(islice(keys, MAX_ORIGINS + 1))
    if len(keys) > MAX_ORIGINS or any(
        type(key) is not MobilityOriginKey
        or key.kind not in ("intent", "grant")
        or not isinstance(key.object_id, UUID)
        for key in keys
    ):
        raise ValidationError("Clés de provenance de mobilité invalides.")
    return (
        MoveAccess.objects.filter(
            intent_id__in=[key.object_id for key in keys if key.kind == "intent"],
            decision__proposal__body__has_key="business",
        ),
        MoveGrant.objects.filter(
            grant_id__in=[key.object_id for key in keys if key.kind == "grant"],
            access__decision__proposal__body__has_key="business",
        ),
    )


def discover_origins(keys, *, organization):
    """Return only opaque IDs. Safe to run before the interactive proof challenge."""
    intents, grants = _query(keys, organization)
    return frozenset(
        [MobilityOriginKey("intent", pk) for pk in intents.values_list("intent_id", flat=True)]
        + [MobilityOriginKey("grant", pk) for pk in grants.values_list("grant_id", flat=True)]
    )


def _snapshot(link, grant=None):
    proposal, decision = observed_business_origin(link, grant)
    chronology = [
        parse_datetime(item.body["at"])
        for item in (proposal, decision, link, *((grant,) if grant else ()))
    ]
    if any(item is None or timezone.is_naive(item) for item in chronology) or chronology != sorted(
        chronology
    ):
        raise ValidationError("Chronologie de provenance invalide.")
    return MobilityOrigin(
        intent_id=link.intent_id,
        proposal_id=proposal.pk,
        decision_id=decision.pk,
        role_key=link.role.key,
        role_revision=link.role.revision,
        role_name=link.role.body["name"],
        decided_at=chronology[1],
        last_proof_at=chronology[-1],
        submitted_references=deepcopy(proposal.body["business"]),
        reviewed_references=deepcopy(decision.body["business_checked"]),
        proposal_proof=proof_anchor(proposal),
        decision_proof=proof_anchor(decision),
        role_proof=proof_anchor(link.role),
        intent_proof=proof_anchor(link),
        grant_proof=proof_anchor(grant) if grant else None,
    )


def read_origins(keys, *, organization):
    """Materialize only signed snapshots; portal callers must already have checked MFA."""
    intents, grants = _query(keys, organization)
    intents = intents.select_related(
        "intent", "audit", "role__audit", "decision__audit", "decision__proposal__audit"
    )
    grants = grants.select_related(
        "audit",
        "grant__identity",
        "grant__account",
        "grant__resource",
        "access__intent",
        "access__audit",
        "access__role__audit",
        "access__decision__audit",
        "access__decision__proposal__audit",
    )
    result = {}
    for key, link, grant in [
        (MobilityOriginKey("intent", row.intent_id), row, None) for row in intents
    ] + [(MobilityOriginKey("grant", row.grant_id), row.access, row) for row in grants]:
        try:
            result[key] = _snapshot(link, grant)
        except (ValidationError, ValueError, TypeError, KeyError):
            # No attestation, business reference or ORM object crosses on failure.
            continue
    return result
