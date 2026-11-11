"""Explicit temporal mappings are evidence, never ownership-based attribution."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Max, Q
from django.utils import timezone

from platform_core.audit import digest, record
from platform_core.authorization import assurance_datetime
from platform_core.models import Organization
from platform_core.tenancy import current_organization
from platform_modules.identity.models import ExternalAccount, Identity, Resource

from .scim import IntegrationFailure
from .teamviewer import _time
from .teamviewer_collection import _admin, tag, verify_configuration, verify_signature, verify_tag
from .teamviewer_mapping_models import TeamViewerMapping, TeamViewerSighting
from .teamviewer_models import TeamViewerCollector
from .teamviewer_sightings import verify_sighting

KINDS = {"account": ExternalAccount, "actor": Identity, "device": Resource}
MAX_STATEMENTS = 64


def _date(value):
    if isinstance(value, str):
        try:
            value = _time(value)
        except IntegrationFailure:
            raise ValidationError("Date de correspondance invalide ou sans fuseau.") from None
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValidationError("Les dates de correspondance exigent un fuseau explicite.")
    return value.astimezone(UTC)


def _text(value, maximum):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(char) < 32 for char in value)
    ):
        raise ValidationError("Identifiant ou référence de vérification invalide.")
    return value


def target_snapshot(kind, target):
    if not isinstance(target, KINDS[kind]):
        raise ValidationError("Le type de cible ne correspond pas à cette association.")
    if kind == "account":
        if target.system.strip().casefold() != "teamviewer":
            raise ValidationError(
                "Liez le compte opérateur du système TeamViewer, pas le compte Windows de la cible."
            )
        return dict(system="teamviewer")
    if kind == "device" and target.kind not in {"server", "device"}:
        raise ValidationError("La cible TeamViewer doit être un serveur ou un appareil.")
    if kind == "actor" and target.kind not in {
        key for key, _ in Identity._meta.get_field("kind").choices
    }:
        raise ValidationError("Type d’identité non pris en charge.")
    return dict(kind=target.kind)


def mapping_body(mapping):
    return dict(
        id=str(mapping.pk),
        organization=str(mapping.organization_id),
        collector=str(mapping.collector_id),
        source_revision=mapping.source_revision,
        source_config_hash=mapping.source_config_hash,
        kind=mapping.kind,
        remote_ref=mapping.remote_ref,
        sequence=mapping.sequence,
        account=str(mapping.account_id) if mapping.account_id else None,
        identity=str(mapping.identity_id) if mapping.identity_id else None,
        resource=str(mapping.resource_id) if mapping.resource_id else None,
        withdrawn=mapping.withdrawn,
        target_snapshot=mapping.target_snapshot,
        valid_from=mapping.valid_from.isoformat(),
        valid_until=mapping.valid_until.isoformat() if mapping.valid_until else None,
        verification_reference=mapping.verification_reference,
        published_at=mapping.published_at.isoformat(),
        published_by=mapping.published_by_id,
        mfa_verified_at=mapping.mfa_verified_at.isoformat(),
        mfa_window_minutes=mapping.mfa_window_minutes,
    )


def mapping_signature(mapping, *, key=None):
    return tag(
        dict(
            body=mapping_body(mapping),
            audit_id=mapping.audit_id,
            audit_hash=mapping.audit.event_hash,
        ),
        "mapping",
        key=key,
    )


def verify_mapping(mapping, *, check_target=True):
    try:
        columns = dict(
            account=mapping.account_id, actor=mapping.identity_id, device=mapping.resource_id
        )
        typed = mapping.kind in KINDS and all(
            (value is not None) == (key == mapping.kind and not mapping.withdrawn)
            for key, value in columns.items()
        )
        valid = bool(
            typed
            and mapping.source_revision >= 1
            and mapping.sequence >= 1
            and mapping.organization_id == mapping.collector.organization_id
            and mapping.mfa_window_minutes in {2, 5, 10, 15}
            and 0
            <= (mapping.published_at - mapping.mfa_verified_at).total_seconds()
            < mapping.mfa_window_minutes * 60
            and mapping.published_at <= timezone.now()
            and (mapping.valid_until is None or mapping.valid_until > mapping.valid_from)
            and mapping.audit.organization_id == mapping.organization_id
            and mapping.audit.actor_id == mapping.published_by_id
            and mapping.audit.action == "connectors.teamviewer.mapping.published.v1"
            and mapping.audit.object_id == str(mapping.pk)
            and mapping.audit.object_type == mapping._meta.label_lower
            and mapping.audit.event_hash == digest(mapping.audit)
            and verify_tag(
                mapping_body(mapping), "mapping-body", mapping.audit.metadata.get("mapping_hash")
            )
            and verify_signature(mapping.signature, mapping_signature, mapping)
        )
        if not valid or not check_target:
            return valid
        if mapping.withdrawn:
            return mapping.target_snapshot == {}
        target = (
            KINDS[mapping.kind]
            .unscoped.filter(pk=mapping.target.pk, organization_id=mapping.organization_id)
            .first()
        )
        return target is not None and mapping.target_snapshot == target_snapshot(
            mapping.kind, target
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


@transaction.atomic
def publish_mapping(
    *,
    actor,
    organization,
    collector_id,
    kind,
    remote_ref,
    valid_from,
    verification_reference,
    target=None,
    valid_until=None,
    withdrawn=False,
    sighting_id=None,
):
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    actor, assurance = _admin(actor, organization)
    if (
        kind not in KINDS
        or type(withdrawn) is not bool
        or (withdrawn and target is not None)
        or (not withdrawn and target is None)
    ):
        raise ValidationError("Choisissez une cible du bon type ou un retrait explicite.")
    collector = TeamViewerCollector.objects.get(pk=collector_id)
    if sighting_id:
        sighting = TeamViewerSighting.objects.select_related("run__audit", "report").get(
            pk=sighting_id, collector=collector
        )
        if not verify_sighting(sighting):
            raise ValidationError("Observation source invalide.")
        revision, config_hash = sighting.run.revision, sighting.run.config_hash
    else:
        if not verify_configuration(collector):
            raise ValidationError("La configuration du collecteur n’est pas vérifiable.")
        revision, config_hash = collector.revision, collector.config_hash
    remote_ref = _text(remote_ref, 180)
    verification_reference = _text(verification_reference, 255)
    start, end = _date(valid_from), _date(valid_until) if valid_until is not None else None
    if end is not None and end <= start:
        raise ValidationError("La fin doit suivre le début de l’affectation.")
    snapshot = {}
    if not withdrawn:
        target_snapshot(kind, target)
        try:
            target = KINDS[kind].objects.get(pk=target.pk)
        except KINDS[kind].DoesNotExist:
            raise ValidationError("Cible absente de cette organisation.") from None
        snapshot = target_snapshot(kind, target)
    previous = TeamViewerMapping.objects.filter(
        collector=collector, source_revision=revision, kind=kind, remote_ref=remote_ref
    )
    actor, assurance = _admin(actor, organization)
    mapping = TeamViewerMapping(
        organization=organization,
        collector=collector,
        source_revision=revision,
        source_config_hash=config_hash,
        kind=kind,
        remote_ref=remote_ref,
        sequence=(previous.aggregate(last=Max("sequence"))["last"] or 0) + 1,
        withdrawn=withdrawn,
        target_snapshot=snapshot,
        valid_from=start,
        valid_until=end,
        verification_reference=verification_reference,
        published_by=actor,
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
        **(
            {{"account": "account", "actor": "identity", "device": "resource"}[kind]: target}
            if target is not None
            else {}
        ),
    )
    mapping.audit = record(
        organization=organization,
        actor=actor,
        target=mapping,
        action="connectors.teamviewer.mapping.published.v1",
        summary="Correspondance TeamViewer publiée",
        metadata=dict(
            mapping_hash=tag(mapping_body(mapping), "mapping-body"),
            kind=kind,
            source_revision=revision,
            withdrawn=withdrawn,
        ),
    )
    mapping.signature = mapping_signature(mapping)
    if not verify_mapping(mapping, check_target=False):
        raise PermissionDenied("Une MFA récente est nécessaire pour publier cette correspondance.")
    mapping.full_clean()
    mapping.save()
    return mapping


@dataclass(frozen=True)
class MappingResolution:
    state: str
    target: object | None
    statements: tuple
    segments: tuple


def _resolve(sighting, kind, remote_ref):
    report = sighting.report
    if not remote_ref:
        return MappingResolution("unmapped", None, (), ())
    start, end = report.started_at, report.ended_at
    end = end if end > start else start + timedelta(microseconds=1)
    candidates = list(
        TeamViewerMapping.objects.filter(
            collector_id=sighting.collector_id,
            source_revision=sighting.run.revision,
            source_config_hash=sighting.run.config_hash,
            kind=kind,
            remote_ref=remote_ref,
            valid_from__lt=end,
        )
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gt=start))
        .select_related("audit", "collector", "account", "identity", "resource")
        .order_by("-sequence")[: MAX_STATEMENTS + 1]
    )
    if (
        candidates
        and candidates[0].valid_from <= start
        and (candidates[0].valid_until is None or candidates[0].valid_until >= end)
    ):
        winner = candidates[0]
        if not verify_mapping(winner):
            return MappingResolution("invalid", None, (str(winner.pk),), ())
        segment = dict(
            start=start.isoformat(),
            end=end.isoformat(),
            statement=str(winner.pk),
            target=str(winner.target.pk) if not winner.withdrawn else None,
            withdrawn=winner.withdrawn,
        )
        return MappingResolution(
            "withdrawn" if winner.withdrawn else "mapped",
            None if winner.withdrawn else winner.target,
            (str(winner.pk),),
            (segment,),
        )
    if len(candidates) > MAX_STATEMENTS:
        return MappingResolution("limit", None, (), ())
    if any(not verify_mapping(item, check_target=False) for item in candidates):
        return MappingResolution("invalid", None, (), ())
    boundaries = {start, end}
    for item in candidates:
        boundaries.add(max(start, item.valid_from))
        if item.valid_until:
            boundaries.add(min(end, item.valid_until))
    ordered = sorted(boundaries)
    winners, segments = [], []
    for left, right in zip(ordered, ordered[1:]):
        winner = next(
            (
                item
                for item in candidates
                if item.valid_from <= left
                and (item.valid_until is None or item.valid_until >= right)
            ),
            None,
        )
        winners.append(winner)
        segments.append(
            dict(
                start=left.isoformat(),
                end=right.isoformat(),
                statement=str(winner.pk) if winner else None,
                target=str(winner.target.pk) if winner and not winner.withdrawn else None,
                withdrawn=winner.withdrawn if winner else False,
            )
        )
    selected = {item.pk: item for item in winners if item}
    if any(not verify_mapping(item) for item in selected.values()):
        return MappingResolution(
            "invalid", None, tuple(str(key) for key in selected), tuple(segments)
        )
    targets = {item.target.pk if not item.withdrawn else None for item in winners if item}
    complete = all(item is not None for item in winners)
    state = (
        "mapped"
        if complete and len(targets) == 1 and None not in targets
        else "withdrawn"
        if complete and targets == {None}
        else "ambiguous"
        if len(targets) > 1
        else "partial"
        if selected
        else "unmapped"
    )
    return MappingResolution(
        state,
        next(iter(selected.values())).target if state == "mapped" else None,
        tuple(str(key) for key in selected),
        tuple(segments),
    )


@transaction.atomic
def resolve_sighting(sighting, *, organization):
    if current_organization().pk != organization.pk or sighting.organization_id != organization.pk:
        raise PermissionDenied
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    if not verify_sighting(sighting):
        raise ValidationError("Preuve d’observation invalide ; aucune identité n’est attribuée.")
    return dict(
        account=_resolve(sighting, "account", sighting.report.account_ref),
        actor=_resolve(sighting, "actor", sighting.report.account_ref),
        device=_resolve(sighting, "device", sighting.report.device_ref),
        actor_provenance="explicit_mapping_attestation_not_authentication_proof",
        actor_inferred_from_owner=False,
        remote_os_privilege=None,
        observed_location=None,
        normalized_access_events=0,
    )
