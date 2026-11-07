"""Read-only relational graph. Context, authorization, intention and observation stay distinct."""

from datetime import timedelta

from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from platform_core.tenancy import current_organization
from platform_modules.access.models import AccessEvent, AccessIntent
from platform_modules.access.services import identity_status_at
from platform_modules.governance.models import ContractParticipant
from platform_modules.governance.policy import assess_contract
from platform_modules.identity.models import Credential, ExternalAccount, Grant, Resource

from .models import NODE_FIELDS, ContextLink, NetworkPlacement
from .services import visible_at


def applicable_grants(at):
    return (
        Grant.objects.filter(created_at__lte=at, valid_from__lte=at)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=at))
        .filter(Q(status="active") | Q(status="revoked", revoked_at__gt=at))
        .select_related("identity", "account", "resource", "contract")
    )


def applicable_intents(at):
    return AccessIntent.objects.filter(
        approved_at__lte=at, starts_at__lte=at, ends_at__gt=at
    ).filter(Q(status="approved") | Q(status="revoked", revoked_at__gt=at))


def grant_contract_applies(grant, at):
    if identity_status_at(grant.identity, at) != "active":
        return False
    if not grant.contract_id:
        return True
    assessment = assess_contract(
        contract=grant.contract,
        identity=grant.identity,
        resource=grant.resource,
        method=grant.method,
        privilege=grant.entitlement,
        location=grant.location,
        country_code=grant.country_code,
        reference=grant.reference,
        start=at,
        as_of=at,
    )
    grant.contract_findings = assessment.findings
    return assessment.status == "allow"


def graph_for_identity(identity, *, at=None):
    if identity.organization_id != current_organization().pk:
        raise PermissionDenied
    at = at or timezone.now()
    nodes, edges = {}, []
    truncated = False

    def bounded(queryset, limit=100):
        nonlocal truncated
        values = list(queryset[: limit + 1])
        truncated |= len(values) > limit
        return values[:limit]

    def add_node(kind, obj):
        key = f"{kind}:{obj.pk}"
        if key not in nodes:
            url = (
                reverse("record-detail", args=[kind, obj.pk])
                if kind
                in ("identity", "account", "resource", "credential", "intent", "event", "grant")
                else reverse("governance-home")
            )
            nodes[key] = {
                "id": key,
                "kind": kind,
                "type_label": {
                    "identity": "Identité",
                    "account": "Compte",
                    "resource": "Ressource",
                    "credential": "Credential",
                    "supplier": "Fournisseur",
                    "intent": "Intention",
                    "event": "Observation",
                    "grant": "Droit",
                }[kind],
                "subtype": getattr(obj, "kind", ""),
                "subtype_label": obj.get_kind_display() if hasattr(obj, "get_kind_display") else "",
                "label": str(obj),
                "short_label": str(obj)[:26] + ("…" if len(str(obj)) > 26 else ""),
                "url": url,
            }
        return key

    def edge(left, right, relation, layer, evidence, detail="", confidence="recorded"):
        edges.append(
            {
                "source": left,
                "target": right,
                "relation": relation,
                "layer": layer,
                "evidence": str(evidence),
                "detail": detail,
                "confidence": confidence,
            }
        )

    focus = add_node("identity", identity)
    for account in bounded(ExternalAccount.objects.filter(identity=identity)):
        edge(
            focus,
            add_node("account", account),
            "has-account",
            "context",
            account.pk,
            f"Compte {account.kind}, état actuel actif={account.active}. "
            "Ce n’est pas une preuve de connexion.",
        )
    for credential in bounded(Credential.objects.filter(identity=identity, registered_at__lte=at)):
        key = add_node("credential", credential)
        edge(
            focus,
            key,
            "has-credential",
            "context",
            credential.pk,
            f"Empreinte publique : {credential.fingerprint}. Aucune clé privée collectée.",
        )
        if credential.resource_id:
            edge(
                key,
                add_node("resource", credential.resource),
                "expected-on",
                "context",
                credential.pk,
            )
    grants = list(applicable_grants(at).filter(identity=identity)[:201])
    truncated |= len(grants) > 200
    for grant in grants[:200]:
        if grant_contract_applies(grant, at):
            origin = add_node("account", grant.account) if grant.account_id else focus
            edge(
                origin,
                add_node("resource", grant.resource),
                "authorized-for",
                "capability",
                grant.pk,
                f"{grant.entitlement} · {grant.justification}. "
                "Autorisation locale ; effet externe à vérifier.",
            )
    for intent in bounded(applicable_intents(at).filter(identity=identity)):
        key = add_node("intent", intent)
        edge(focus, key, "declared-intent", "intention", intent.pk, intent.reason)
        edge(
            key,
            add_node("resource", intent.resource),
            "approved-for",
            "intention",
            intent.pk,
            f"{intent.starts_at.isoformat()} → {intent.ends_at.isoformat()} · "
            f"{intent.method} · {intent.reference}",
        )
    participants = (
        ContractParticipant.objects.filter(identity=identity, valid_from__lte=at)
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gt=at))
        .filter(Q(revoked_at__isnull=True) | Q(revoked_at__gt=at))
        .select_related("contract__supplier")
    )
    for participant in bounded(participants):
        edge(
            add_node("supplier", participant.contract.supplier),
            focus,
            "authorized-participant",
            "context",
            participant.pk,
            f"Inscription au contrat {participant.contract.reference} ; périmètre à vérifier.",
        )
    for placement in visible_at(NetworkPlacement.objects.filter(identity=identity), at):
        edge(
            focus,
            add_node("resource", placement.switch),
            "expected-network",
            "context",
            placement.pk,
            f"Port {placement.port} · VLAN {placement.vlan} · {placement.evidence}",
        )
    observed = list(
        AccessEvent.objects.filter(
            identity=identity, occurred_at__gte=at - timedelta(days=1), occurred_at__lte=at
        )
        .select_related("resource")
        .order_by("-occurred_at")[:101]
    )
    truncated |= len(observed) > 100
    for event in observed[:100]:
        edge(
            focus,
            add_node("resource", event.resource),
            "observed-on",
            "observation",
            event.pk,
            f"{event.occurred_at.isoformat()} · {event.method} · {event.action} · "
            f"résultat {event.result} · source {event.source}",
        )
    seen_links = set()
    for _ in range(2):
        selection = Q(pk__in=[])
        for kind in NODE_FIELDS:
            ids = [key.split(":", 1)[1] for key in nodes if key.startswith(kind + ":")]
            if ids:
                selection |= Q(**{f"source__{kind}_id__in": ids}) | Q(
                    **{f"target__{kind}_id__in": ids}
                )
        links = list(
            visible_at(ContextLink.objects.filter(selection), at).select_related(
                *[f"{side}__{kind}" for side in ("source", "target") for kind in NODE_FIELDS]
            )[:201]
        )
        truncated |= len(links) > 200
        for link in links[:200]:
            if link.pk not in seen_links:
                seen_links.add(link.pk)
                edge(
                    add_node(link.source.kind, link.source.subject),
                    add_node(link.target.kind, link.target.subject),
                    link.relation,
                    "context",
                    link.pk,
                    link.evidence,
                    link.confidence,
                )
    # Keep SVG and payload bounded; never silently present a partial projection as complete.
    retained = list(nodes.values())[:120]
    truncated |= len(nodes) > 120 or len(edges) > 400
    ids = {node["id"] for node in retained}
    edges = [e for e in edges if e["source"] in ids and e["target"] in ids][:400]
    left = [n for n in retained if n["id"] != focus and n["kind"] in ("credential", "supplier")]
    right = [n for n in retained if n["id"] != focus and n not in left]
    height = max(400, 100 + max(len(left), len(right)) * 85)
    coordinates = {focus: (430, height // 2)}
    for column, values in ((40, left), (770, right)):
        for index, node in enumerate(values):
            coordinates[node["id"]] = column, 55 + index * 85
    for node in retained:
        node["x"], node["y"] = coordinates[node["id"]]
    for item in edges:
        sx, sy = coordinates[item["source"]]
        tx, ty = coordinates[item["target"]]
        if sx == tx:
            outside = sx + 235 if sx >= 430 else sx - 30
            boundary = sx + 190 if sx >= 430 else sx
            item["path"] = (
                f"M {boundary} {sy + 25} C {outside} {sy + 25}, "
                f"{outside} {ty + 25}, {boundary} {ty + 25}"
            )
            continue
        sx += 190 if tx > sx else 0
        tx += 0 if tx > sx else 190
        item["path"] = (
            f"M {sx} {sy + 25} C {(sx + tx) / 2} {sy + 25}, "
            f"{(sx + tx) / 2} {ty + 25}, {tx} {ty + 25}"
        )
    return {
        "identity": str(identity.pk),
        "at": at.isoformat(),
        "nodes": retained,
        "edges": edges,
        "height": height,
        "truncated": truncated,
        "notice": (
            "Voisinage de contexte limité à deux sauts. "
            "Liens et droits datés ; noms, types et états de comptes actuellement renseignés. "
            "Un lien de contexte ou une observation n’accorde aucun droit. "
            "Aucune relation causale n’est déduite de la proximité horaire."
        ),
    }


def investigate(kind, *, at, start, end, zone=None):
    """Named questions with dated evidence, not a query-language/code execution endpoint."""
    results, truncated = [], False
    grants = list(applicable_grants(at)[:1001])
    truncated |= len(grants) > 1000
    grants = [g for g in grants[:1000] if grant_contract_applies(g, at)]
    if kind == "physical-admin":
        if not zone or zone.kind != "zone":
            return [], False, "Choisissez une zone physique."
        contained = set(
            visible_at(
                ContextLink.objects.filter(
                    relation="located-in", confidence="verified", target__resource=zone
                ),
                at,
            ).values_list("source__resource_id", flat=True)
        )
        placement_proofs = {}
        for link in visible_at(
            ContextLink.objects.filter(
                relation="located-in", confidence="verified", target__resource=zone
            ),
            at,
        ).select_related("source"):
            placement_proofs.setdefault(link.source.resource_id, []).append(str(link.pk))
        physical = {
            g.identity_id: g
            for g in grants
            if g.resource_id == zone.pk or g.resource_id in contained and g.resource.kind == "door"
        }
        for grant in grants:
            if (
                grant.identity_id in physical
                and grant.resource_id in contained
                and grant.account_id
                and grant.account.kind == "privileged"
                and grant.account.active
            ):
                results.append(
                    {
                        "identity": grant.identity,
                        "resource": grant.resource,
                        "detail": (
                            f"Accès physique : droit {physical[grant.identity_id].pk}. "
                            f"Compte privilégié : {grant.account}. Ressource déclarée dans {zone}."
                        ),
                        "evidence": [str(physical[grant.identity_id].pk), str(grant.pk)]
                        + placement_proofs.get(physical[grant.identity_id].resource_id, [])
                        + placement_proofs.get(grant.resource_id, []),
                    }
                )
        notice = (
            "Intersection de droits locaux datés et de placements vérifiés par le déclarant, "
            "avec le type de compte actuel, pas une preuve d’accès effectivement exercé."
        )
    elif kind == "supplier-production":
        for grant in grants:
            if grant.contract_id and grant.resource.environment == "production":
                results.append(
                    {
                        "identity": grant.identity,
                        "resource": grant.resource,
                        "detail": (
                            f"{grant.contract.supplier} · contrat {grant.contract.reference} · "
                            f"{grant.entitlement}"
                        ),
                        "evidence": list(
                            dict.fromkeys(
                                [str(grant.pk), str(grant.contract_id)]
                                + [
                                    f["evidence"]
                                    for f in getattr(grant, "contract_findings", [])
                                    if f["evidence"]
                                ]
                            )
                        ),
                    }
                )
        unclassified = Resource.objects.filter(environment="unknown").count()
        notice = (
            f"Ressources actuellement classées production uniquement. {unclassified} "
            "ressource(s) non classée(s). Les chemins réseau déclarés ne prouvent pas "
            "une capacité d’accès."
        )
    elif kind == "privileged-without-window":
        for grant in grants:
            if not grant.account_id or grant.account.kind != "privileged":
                continue
            intents = (
                applicable_intents(at)
                .filter(identity=grant.identity, resource=grant.resource)
                .filter(Q(account__isnull=True) | Q(account=grant.account))
                .filter(Q(privilege="") | Q(privilege=grant.entitlement))
            )
            if grant.method:
                intents = intents.filter(method__iexact=grant.method)
            if not intents.exists():
                results.append(
                    {
                        "identity": grant.identity,
                        "resource": grant.resource,
                        "detail": (
                            f"Compte {grant.account} ; justification permanente : "
                            f"{grant.justification}. Aucune intention approuvée active rapprochée."
                        ),
                        "evidence": [str(grant.pk)],
                    }
                )
        notice = (
            "À revoir, pas automatiquement illégitime : un droit permanent motivé peut "
            "être autorisé sans intervention ponctuelle."
        )
    elif kind == "events-without-reference":
        from .coverage import event_timeline

        rows, limited = event_timeline(AccessEvent.objects.all(), start, end)
        truncated |= limited
        for row in rows:
            if not row["reference"]:
                event = row["event"]
                results.append(
                    {
                        "identity": event.identity,
                        "resource": event.resource,
                        "detail": (
                            f"{event.occurred_at.isoformat()} · {event.method} · {event.action}. "
                            "Pas de référence dans une intention rapprochée."
                        ),
                        "evidence": [str(event.pk)],
                        "event": event,
                    }
                )
        notice = (
            "Une référence déclarée n’est pas un ticket vérifié. Cette recherche ne prouve "
            "ni l’absence de ticket dans un outil externe ni l’absence d’autorisation."
        )
    else:
        raise ValueError("Unknown investigation")
    return results[:500], truncated or len(results) > 500, notice
