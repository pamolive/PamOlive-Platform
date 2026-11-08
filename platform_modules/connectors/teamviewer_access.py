"""Canonical source events and separately verified, dated interpretation."""

import json
import logging
from copy import copy

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.crypto import constant_time_compare

from platform_core.audit import record
from platform_core.models import AuditEvent, Organization
from platform_core.services import require_module
from platform_core.tenancy import organization_context
from platform_modules.access.evidence import verify_evaluation
from platform_modules.access.models import AccessEvent
from platform_modules.access.observations import (
    ObservationContext,
    blocked_context,
    source_snapshot,
)
from platform_modules.access.services import evaluate_event

from .teamviewer_access_models import TeamViewerAccessCursor, TeamViewerAccessObservation
from .teamviewer_collection import tag
from .teamviewer_mapping_models import TeamViewerMapping
from .teamviewer_session_models import TeamViewerSession
from .teamviewer_sessions import _anchored, _seal, resolve_session, verify_session

SOURCE = "managed:teamviewer"


def event_snapshot(event):
    return source_snapshot(event)


def observation_body(link):
    return dict(
        id=str(link.pk),
        organization=str(link.organization_id),
        session=str(link.session_id),
        session_signature=link.session.signature,
        event=event_snapshot(link.event),
        registered_at=link.registered_at.isoformat(),
    )


def verify_observation(link):
    try:
        report, event = link.session.origin.report, link.event
        return bool(
            link.organization_id == link.session.organization_id == event.organization_id
            and verify_session(link.session)
            and event.source == SOURCE
            and event.external_id == str(link.session.remote_id)
            and event.occurred_at == report.started_at
            and event.ended_at == report.ended_at
            and event.received_at == report.observed_at
            and event.identity_id is None
            and event.account_id is None
            and event.resource_id is None
            and event.credential_id is None
            and event.contract_id is None
            and not event.location
            and not event.privilege
            and not event.country_code
            and not event.network_switch_id
            and not event.network_port
            and not event.network_vlan
            and event.method == "TeamViewer"
            and event.action == "remote_session"
            and event.domain == "remote"
            and event.result == "reported_completed"
            and _anchored(
                link,
                observation_body(link),
                "access-observation",
                "connectors.teamviewer.access.normalized.v1",
            )
        )
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError):
        return False


def _link_query():
    return TeamViewerAccessObservation.objects.select_related(
        "audit", "event", "session__audit", "session__origin__report", "session__origin__run__audit"
    )


def resolve_observation(event, *, organization):
    link = _link_query().filter(event_id=event.pk).first()
    if (
        link is None
        or not verify_observation(link)
        or event_snapshot(event) != event_snapshot(link.event)
    ):
        return blocked_context(
            event,
            code="teamviewer_normalization_invalid",
            detail="Aucun lien signé vérifiable entre cet événement et sa session source.",
        )
    resolution = resolve_session(link.session, organization=organization)
    observed = copy(event)
    observed._identity_attribution = "administrative_attestation"
    semantic = dict(
        provider="teamviewer",
        normalization=str(link.pk),
        normalization_signature=link.signature,
        session=str(link.session_id),
        source_state=resolution.state,
        facts=resolution.facts,
        variants=sorted(
            [
                {key: variant[key] for key in ("report", "collector", "revision", "config_hash")}
                for variant in resolution.variants
            ],
            key=lambda value: json.dumps(value, sort_keys=True),
        ),
        attribution={},
        actor_provenance="administrative_attestation_not_authentication_proof",
        actor_inferred_from_owner=False,
        observed_privilege=None,
        observed_location=None,
    )
    for kind, field in (("actor", "identity"), ("account", "account"), ("device", "resource")):
        result = resolution.dimensions[kind]
        setattr(observed, field, result.target if result.state == "mapped" else None)
        semantic["attribution"][kind] = dict(
            state=result.state,
            target=str(result.target.pk) if result.target else None,
            statements=sorted(result.statements),
            # Witness IDs change on identical re-reads; dated assignment segments do not.
            segments=sorted(
                [
                    {key: value for key, value in segment.items() if key != "sighting"}
                    for segment in result.segments
                ],
                key=lambda value: json.dumps(value, sort_keys=True),
            ),
        )
    blocked = resolution.state in {"pending", "conflict", "invalid", "limit"}
    findings = (
        dict(
            code="teamviewer_interpretation",
            state="unknown" if blocked else "observed",
            detail=resolution.detail,
            evidence=str(link.session_id),
        ),
        dict(
            code="teamviewer_telemetry",
            state="observed",
            detail="Le compte source est l’opérateur TeamViewer, pas le compte Windows distant. "
            "Le privilège OS et l’origine réseau ne sont pas rapportés ; "
            "les notes ne vérifient aucun ticket.",
            evidence=str(link.pk),
        ),
        dict(
            code="teamviewer_attribution",
            state="observed" if resolution.state == "resolved" else "unknown",
            detail="Résolution des correspondances : "
            + ", ".join(f"{kind}={result.state}" for kind, result in resolution.dimensions.items())
            + ". Les propriétaires ne complètent pas les acteurs inconnus.",
            evidence=str(link.session_id),
        ),
    )
    return ObservationContext(
        observed, dict(semantic=semantic, witnesses=list(resolution.variants)), findings, blocked
    )


def related_events(identity, *, limit, start=None, end=None):
    # Candidate selection is not attribution. Each retained event is resolved and
    # checked again before displaying it as this identity's observed activity.
    mappings = TeamViewerMapping.objects.filter(
        Q(identity=identity) | Q(account__identity=identity), withdrawn=False
    )
    if end is not None:
        mappings = mappings.filter(valid_from__lt=end)
    if start is not None:
        mappings = mappings.filter(Q(valid_until__isnull=True) | Q(valid_until__gt=start))
    refs = list(mappings.values_list("remote_ref", flat=True).distinct()[: limit + 1])
    limited = len(refs) > limit
    query = _link_query().filter(
        session__observations__sighting__report__account_ref__in=refs[:limit]
    )
    if end is not None:
        query = query.filter(event__occurred_at__lt=end)
    if start is not None:
        query = query.filter(Q(event__occurred_at__gte=start) | Q(event__ended_at__gt=start))
    ids = list(query.values_list("event_id", flat=True).distinct()[: limit + 1])
    return ids[:limit], limited or len(ids) > limit


def _ensure_observation(session, organization):
    link = _link_query().filter(session=session).first()
    if link:
        if not verify_observation(link):
            raise ValidationError("teamviewer_normalization_invalid")
        return link
    if not verify_session(session):
        raise ValidationError("teamviewer_session_invalid")
    if AccessEvent.objects.filter(source=SOURCE, external_id=str(session.remote_id)).exists():
        raise ValidationError("managed_source_collision")
    report = session.origin.report
    event = AccessEvent(
        organization=organization,
        source=SOURCE,
        external_id=str(session.remote_id),
        occurred_at=report.started_at,
        ended_at=report.ended_at,
        received_at=report.observed_at,
        method="TeamViewer",
        action="remote_session",
        domain="remote",
        result="reported_completed",
        evidence=f"teamviewer-session:{session.pk}",
    )
    event.full_clean()
    event.save()
    record(
        organization=organization,
        target=event,
        action="access.event.received.v1",
        summary="Observation source TeamViewer conservée sans attribution implicite",
    )
    link = TeamViewerAccessObservation(organization=organization, session=session, event=event)
    _seal(
        link,
        observation_body(link),
        "access-observation",
        "connectors.teamviewer.access.normalized.v1",
        "Événement lié aux preuves de session TeamViewer",
    )
    return link


def _cursor_signature(cursor):
    return tag(
        dict(
            id=str(cursor.pk),
            organization=str(cursor.organization_id),
            last=str(cursor.last_session_id) if cursor.last_session_id else None,
            checked_at=cursor.checked_at.isoformat(),
        ),
        "access-cursor",
    )


def _note_issue(session, organization, code):
    action = "connectors.teamviewer.access.refused.v1"
    previous = (
        AuditEvent.objects.filter(
            organization=organization,
            action=action,
            object_type=session._meta.label_lower,
            object_id=str(session.pk),
        )
        .order_by("-sequence")
        .first()
    )
    if previous is None or previous.metadata.get("code") != code:
        record(
            organization=organization,
            target=session,
            action=action,
            summary="Normalisation TeamViewer refusée sans adoption d’un fait non vérifié",
            metadata=dict(code=code),
        )


@transaction.atomic
def normalize_sessions(organization, *, limit=5):
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("Invalid normalization batch size")
    organization = Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    with organization_context(organization):
        require_module(organization, "access")
        require_module(organization, "connectors")
        if not TeamViewerSession.objects.exists():
            return 0
        cursor, _ = TeamViewerAccessCursor.objects.get_or_create(organization=organization)
        if not constant_time_compare(cursor.signature, _cursor_signature(cursor)):
            cursor.last_session_id = None
        query = TeamViewerSession.objects.select_related(
            "audit", "origin__report", "origin__run__audit"
        )
        sessions = (
            list(query.filter(pk__gt=cursor.last_session_id).order_by("pk")[:limit])
            if cursor.last_session_id
            else []
        )
        if not sessions:
            sessions = list(query.order_by("pk")[:limit])
        from platform_modules.access.observations import observation_context

        for session in sessions:
            try:
                with transaction.atomic():
                    link = _ensure_observation(session, organization)
                    context = observation_context(link.event, organization=organization)
                    latest = (
                        link.event.evaluations.select_related("audit", "event", "intent")
                        .order_by("-evaluated_at")
                        .first()
                    )
                    if (
                        not latest
                        or latest.context_hash != context.fingerprint
                        or not verify_evaluation(latest)
                    ):
                        evaluate_event(link.event, organization=organization)
            except ValidationError as error:
                code = (
                    error.messages[0]
                    if error.messages[0]
                    in {
                        "managed_source_collision",
                        "teamviewer_normalization_invalid",
                        "teamviewer_session_invalid",
                    }
                    else "teamviewer_normalization_refused"
                )
                _note_issue(session, organization, code)
            cursor.last_session_id = session.pk
        cursor.checked_at = timezone.now()
        cursor.signature = _cursor_signature(cursor)
        cursor.save()
        return len(sessions)


def process_access_observations(organization):
    try:
        return normalize_sessions(organization)
    except (PermissionDenied, Organization.DoesNotExist):
        return 0
    except ValidationError:
        logging.getLogger(__name__).warning(
            "TeamViewer access normalization refused invalid evidence"
        )
        return 0
