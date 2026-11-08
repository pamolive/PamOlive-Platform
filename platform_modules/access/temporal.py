"""Evaluate a completed observation on each interval of stable policy context.

Boundary selection uses only tenant-local facts consumed by the point evaluator.
Calendar schedules are checked over each whole interval by assess_contract, not
sampled at the two endpoints. Excessive histories remain explicitly unknown.
"""

import uuid
from datetime import timedelta

from django.db.models import Q

MAX_SEGMENTS = 32
MAX_DURATION = timedelta(days=31)


def overlapping_events(queryset, start, end):
    """Half-open overlap; legacy instants and zero-duration facts stay instants."""
    return queryset.filter(occurred_at__lt=end).filter(
        Q(occurred_at__gte=start) | Q(ended_at__gt=start)
    )


def observation_segments(event):
    start, end = event.occurred_at, event.ended_at
    if end is None or end == start:
        return [(start, None)], None
    if end < start:
        return [], "invalid_interval"
    if end - start > MAX_DURATION:
        return [], "interval_duration_limit"
    boundaries = {start, end}

    from platform_modules.governance.models import (
        ApprovalPolicyRevision,
        ContractParticipant,
        ContractRevision,
        SeparationRule,
        SupplierContract,
    )
    from platform_modules.identity.models import Grant, IdentityStateChange, LoginIdentityBinding
    from platform_modules.intelligence.models import (
        CollectionReport,
        CollectionScope,
        ContextLink,
        NetworkPlacement,
    )

    from .models import AccessIntent

    def collect(queryset, fields):
        for field in fields:
            values = (
                queryset.filter(**{field + "__gt": start, field + "__lt": end})
                .order_by(field)
                .values_list(field, flat=True)
                .distinct()[: MAX_SEGMENTS + 1]
            )
            boundaries.update(values)
            if len(boundaries) > MAX_SEGMENTS + 1:
                return False
        return True

    def add(value):
        if value is not None and start < value < end:
            boundaries.add(value)

    queries = []
    if event.identity_id:
        intents = AccessIntent.objects.filter(identity_id=event.identity_id)
        grants = Grant.objects.filter(identity_id=event.identity_id)
        contracts = (
            Q(pk__in=intents.exclude(contract=None).values("contract_id"))
            | Q(pk__in=grants.exclude(contract=None).values("contract_id"))
            | Q(pk=event.contract_id)
        )
        if event.account_id:
            contracts |= Q(pk=event.account.managed_contract_id)
        contract_ids = SupplierContract.objects.filter(contracts).values("pk")
        add(event.identity.created_at)
        queries.extend(
            [
                (intents, ("created_at", "approved_at", "starts_at", "ends_at", "revoked_at")),
                (grants, ("created_at", "valid_from", "expires_at", "revoked_at")),
                (
                    IdentityStateChange.objects.filter(identity_id=event.identity_id),
                    ("effective_at",),
                ),
                (
                    LoginIdentityBinding.objects.filter(identity_id=event.identity_id),
                    ("created_at", "revoked_at"),
                ),
                (ApprovalPolicyRevision.objects.all(), ("effective_at",)),
                (
                    ContractRevision.objects.filter(contract_id__in=contract_ids),
                    ("effective_at", "starts_at", "ends_at"),
                ),
                (SupplierContract.objects.filter(pk__in=contract_ids), ("retired_at",)),
                (
                    ContractParticipant.objects.filter(identity_id=event.identity_id),
                    ("valid_from", "valid_until", "revoked_at"),
                ),
                (SeparationRule.objects.all(), ("effective_at", "retired_at")),
            ]
        )
        if event.domain == "network":
            queries.append(
                (
                    NetworkPlacement.objects.filter(identity_id=event.identity_id),
                    ("valid_from", "valid_until", "recorded_at", "retired_at"),
                )
            )
    if event.credential_id:
        add(event.credential.expires_at)
        add(event.credential.registered_at)
        queries.append(
            (
                ContextLink.objects.filter(source__credential_id=event.credential_id),
                ("valid_from", "valid_until", "recorded_at", "retired_at"),
            )
        )
    if event.domain:
        try:
            source_id = uuid.UUID(event.source)
        except (ValueError, TypeError, AttributeError):
            source_id = None
        if source_id:
            scopes = CollectionScope.objects.filter(
                source_id=source_id, domain=event.domain
            ).filter(Q(resource__isnull=True) | Q(resource_id=event.resource_id))
            queries.extend(
                [
                    (scopes, ("effective_at", "retired_at")),
                    (
                        CollectionReport.objects.filter(scope__in=scopes),
                        ("covered_from", "covered_until"),
                    ),
                ]
            )
    for queryset, fields in queries:
        if not collect(queryset, fields):
            return [], "interval_boundary_limit"
    if len(boundaries) > MAX_SEGMENTS + 1:
        return [], "interval_boundary_limit"
    ordered = sorted(boundaries)
    return list(zip(ordered, ordered[1:])), None
