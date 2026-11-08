from datetime import timedelta

from django.apps import apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Max, Q
from django.utils import timezone

from platform_core.audit import record
from platform_core.authorization import require_recent_authentication
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context

from .models import (
    NODE_FIELDS,
    CollectionReport,
    CollectionScope,
    ContextLink,
    GraphNode,
    NetworkPlacement,
)


def visible_at(queryset, at):
    return (
        queryset.filter(valid_from__lte=at, recorded_at__lte=at)
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gt=at))
        .filter(Q(retired_at__isnull=True) | Q(retired_at__gt=at))
    )


def subject(kind, object_id):
    if kind not in NODE_FIELDS:
        raise ValidationError("Type de nœud inconnu.")
    try:
        return apps.get_model(NODE_FIELDS[kind]).objects.get(pk=object_id)
    except (ValueError, ValidationError, apps.get_model(NODE_FIELDS[kind]).DoesNotExist):
        raise ValidationError("Objet absent de cette organisation.") from None


def _publisher(actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "intelligence")
    require_recent_authentication(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)


@transaction.atomic
def publish_link(data, *, actor, organization):
    _publisher(actor, organization)
    with organization_context(organization):
        nodes = []
        for side in ("source", "target"):
            kind, object_id = data[side].split(":", 1)
            obj = subject(kind, object_id)
            node, _ = GraphNode.objects.get_or_create(
                organization=organization, kind=kind, **{kind: obj}
            )
            node.full_clean()
            nodes.append(node)
        link = ContextLink(
            organization=organization,
            source=nodes[0],
            target=nodes[1],
            published_by=actor,
            valid_from=timezone.now(),
            **{
                k: data[k]
                for k in ("relation", "evidence", "confidence", "valid_until")
                if k in data
            },
        )
        link.full_clean()
        link.save()
        record(
            action="intelligence.link.published.v1",
            summary=f"{link.source} → {link.get_relation_display()} → {link.target}",
            actor=actor,
            organization=organization,
            target=link,
        )
        return link


@transaction.atomic
def publish_placement(data, *, actor, organization):
    _publisher(actor, organization)
    with organization_context(organization):
        now = timezone.now()
        identity = data["identity"]
        if identity.organization_id != organization.pk:
            raise ValidationError("Identité d’une autre organisation.")
        existing = visible_at(NetworkPlacement.objects.filter(identity=identity), now)
        if existing.exists():
            raise ValidationError("Retirez le placement précédent avant d’en publier un nouveau.")
        obj = NetworkPlacement(
            organization=organization,
            published_by=actor,
            valid_from=now,
            **{
                k: data[k]
                for k in ("identity", "switch", "port", "vlan", "evidence", "valid_until")
                if k in data
            },
        )
        obj.full_clean()
        obj.save()
        record(
            action="intelligence.network.published.v1",
            summary=f"Placement : {identity}",
            actor=actor,
            organization=organization,
            target=obj,
        )
        return obj


@transaction.atomic
def publish_scope(data, *, actor, organization):
    _publisher(actor, organization)
    require_module(organization, "connectors")
    with organization_context(organization):
        if not data.get("resource") and not data.get("whole_organization"):
            raise ValidationError(
                "La couverture de l’organisation entière doit être confirmée explicitement."
            )
        obj = CollectionScope(
            organization=organization,
            published_by=actor,
            effective_at=timezone.now(),
            **{k: data[k] for k in ("source", "domain", "resource") if k in data},
        )
        obj.full_clean()
        if CollectionScope.objects.filter(
            source=obj.source, domain=obj.domain, resource=obj.resource, retired_at__isnull=True
        ).exists():
            raise ValidationError("Ce périmètre est déjà configuré.")
        obj.save()
        record(
            action="intelligence.collection.configured.v1",
            summary=str(obj),
            actor=actor,
            organization=organization,
            target=obj,
        )
        return obj


@transaction.atomic
def retire(kind, object_id, *, actor, organization):
    _publisher(actor, organization)
    model = {"link": ContextLink, "placement": NetworkPlacement, "scope": CollectionScope}[kind]
    with organization_context(organization):
        obj = model.objects.get(pk=object_id)
        if not obj.retired_at:
            obj.retired_at = timezone.now()
            obj.save(update_fields=["retired_at"])
            record(
                action=f"intelligence.{kind}.retired.v1",
                summary=str(obj.pk),
                actor=actor,
                organization=organization,
                target=obj,
            )
        return obj


@transaction.atomic
def ingest_report(data, *, source, organization):
    require_module(organization, "intelligence")
    require_module(organization, "connectors")
    if not source or not source.active or source.organization_id != organization.pk:
        raise PermissionDenied
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        try:
            scope = CollectionScope.objects.get(
                pk=data["scope"], source=source, retired_at__isnull=True
            )
        except (CollectionScope.DoesNotExist, ValueError, ValidationError):
            raise ValidationError("Périmètre de collecte non autorisé.") from None
        existing = CollectionReport.objects.filter(
            scope=scope, external_id=data["external_id"]
        ).first()
        if existing:
            return existing, False
        report = CollectionReport(
            organization=organization,
            scope=scope,
            sequence=(
                CollectionReport.objects.filter(scope=scope).aggregate(value=Max("sequence"))[
                    "value"
                ]
                or 0
            )
            + 1,
            **{
                k: data[k]
                for k in (
                    "external_id",
                    "covered_from",
                    "covered_until",
                    "state",
                    "clock_uncertainty_seconds",
                    "detail",
                )
                if k in data
            },
        )
        report.full_clean()
        if report.covered_from < scope.effective_at or report.covered_until > timezone.now():
            raise ValidationError(
                "La collecte doit être postérieure au périmètre publié "
                "et ne peut pas couvrir le futur."
            )
        report.save()
        record(
            action="intelligence.collection.received.v1",
            summary=f"{scope}: {report.state}",
            organization=organization,
            target=report,
        )
        return report, True


def context_findings(event, *, organization, matched_intent=None, matched_grant=None):
    """Evidence enriches an explanation; topological familiarity never grants a right."""
    findings = []
    with organization_context(organization):

        def add(code, state, detail, proof=""):
            findings.append(
                {"code": code, "state": state, "detail": detail, "evidence": str(proof)}
            )

        if event.domain:
            from .coverage import event_clock

            uncertainty, report_id = event_clock(event)
            add(
                "source_clock",
                "observed",
                f"Précision d’horloge déclarée : ±{uncertainty} secondes."
                if uncertainty is not None
                else "Horloge de précision inconnue : comparaison selon la date source déclarée.",
                report_id or event.pk,
            )
            authorization = matched_intent or matched_grant
            if authorization and uncertainty is not None:
                opening = (
                    max(matched_intent.starts_at, matched_intent.approved_at)
                    if matched_intent
                    else max(matched_grant.valid_from, matched_grant.created_at)
                )
                closing = matched_intent.ends_at if matched_intent else matched_grant.expires_at
                revoked = authorization.revoked_at
                if revoked and (closing is None or revoked < closing):
                    closing = revoked
                interval = event.ended_at and event.ended_at > event.occurred_at
                right = (event.ended_at if interval else event.occurred_at) + timedelta(
                    seconds=uncertainty
                )
                ambiguous = event.occurred_at - timedelta(seconds=uncertainty) < opening or bool(
                    closing and (right > closing if interval else right >= closing)
                )
            else:
                ambiguous = False
            if ambiguous:
                add(
                    "time_boundary",
                    "unknown",
                    "L’incertitude d’horloge recouvre une borne de l’autorisation.",
                    report_id,
                )

        if event.identity_id and event.domain == "network":
            placement = (
                visible_at(
                    NetworkPlacement.objects.filter(identity=event.identity), event.occurred_at
                )
                .select_related("switch")
                .first()
            )
            if not placement:
                add("network_expected", "unknown", "Aucun placement réseau déclaré à cette date.")
            elif not event.network_switch_id or not event.network_port or not event.network_vlan:
                add(
                    "network_observed",
                    "unknown",
                    "Observation réseau incomplète : switch, port et VLAN requis.",
                    placement.pk,
                )
            else:
                actual = (event.network_switch_id, event.network_port, event.network_vlan)
                expected = (placement.switch_id, placement.port, placement.vlan)
                authorized_move = (
                    matched_intent
                    and matched_intent.network_switch_id
                    and actual
                    == (
                        matched_intent.network_switch_id,
                        matched_intent.network_port,
                        matched_intent.network_vlan,
                    )
                )
                add(
                    "network_placement",
                    "confirmed" if actual == expected or authorized_move else "deviation",
                    f"Attendu {placement.switch} / {placement.port} / VLAN {placement.vlan} ; "
                    f"observé {event.network_switch} / {event.network_port} / "
                    f"VLAN {event.network_vlan}. "
                    + (
                        "Déplacement explicitement prévu par l’intention approuvée."
                        if authorized_move
                        else "Un écart de placement est à examiner, pas une preuve d’intrusion."
                    ),
                    matched_intent.pk if authorized_move else placement.pk,
                )
        if event.credential_id and event.credential.kind == "certificate":
            add(
                "credential_evidence",
                "observed",
                event.get_credential_observation_display()
                + ". Le CN ou l’identifiant public seul ne prouve jamais une copie de clé.",
                event.pk,
            )
    return findings


def expected_certificate_hosts(credential, at):
    links = visible_at(
        ContextLink.objects.filter(
            relation="expected-on", confidence="verified", source__credential=credential
        ),
        at,
    )
    result = set(links.values_list("target__resource_id", flat=True))
    if credential.resource_id and credential.registered_at <= at:
        result.add(credential.resource_id)
    return result


def validate_window(start, end):
    if end <= start or end - start > timedelta(days=31):
        raise ValidationError("Choisissez une période positive d’au plus 31 jours.")
