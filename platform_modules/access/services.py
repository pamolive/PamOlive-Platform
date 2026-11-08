from datetime import datetime

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from platform_core.audit import record
from platform_core.models import Organization
from platform_core.services import authorize, require_module
from platform_core.tenancy import organization_context
from platform_modules.identity.models import Credential, ExternalAccount, Grant, Identity, Resource

from .models import AccessEvaluation, AccessEvent, AccessIntent

RECORD_TYPES = {
    "identity": Identity,
    "resource": Resource,
    "account": ExternalAccount,
    "credential": Credential,
    "grant": Grant,
    "intent": AccessIntent,
}


@transaction.atomic
def create_record(kind, data, *, actor, organization):
    authorize(actor, organization)
    require_module(organization, "access" if kind == "intent" else "identity")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        model = RECORD_TYPES[kind]
        if kind == "intent":
            data = {**data, "requested_by": actor, "status": "pending"}
        obj = model(organization=organization, **data)
        if kind == "intent" and obj.fulfillment == "pam":
            from platform_modules.pam.mandates import prepare_request

            require_module(organization, "pam")
            prepare_request(obj, actor=actor, organization=organization)
        obj.full_clean()
        from platform_modules.governance.policy import account_contract_live, enforce_authorization

        if kind in ("grant", "intent"):
            from platform_modules.governance.policy import policy_at

            if kind == "grant" and policy_at(timezone.now()):
                raise ValidationError(
                    "Une politique d’approbation est publiée : utilisez une demande IAM "
                    "plutôt qu’une attribution directe."
                )
            if obj.identity.status != "active" or (obj.account_id and not obj.account.active):
                raise ValidationError("L’identité et son compte doivent être actifs.")
            enforce_authorization(obj, organization=organization)
        elif kind == "account" and obj.managed_contract_id and not account_contract_live(obj):
            raise ValidationError(
                "Le contrat dédié doit être en cours avec cette identité inscrite."
            )
        obj.save()
        if kind == "grant":
            from platform_modules.connectors.outbound import queue_grant_state

            queue_grant_state(obj, actor=actor, organization=organization, origin="grant.created")
        record(
            action=f"{model._meta.app_label}.{kind}.created.v1",
            summary=str(obj),
            actor=actor,
            organization=organization,
            target=obj,
        )
        if kind == "identity":
            from platform_core.events import publish_domain_event

            publish_domain_event(
                organization=organization,
                actor=actor,
                emitter="identity",
                topic="identity.identity.created.v1",
                target=obj,
                payload={"identity_id": str(obj.pk), "kind": obj.kind, "status": obj.status},
            )
        return obj


@transaction.atomic
def ingest_event(data, *, organization, actor=None, source=None):
    if actor:
        authorize(actor, organization)
    elif not source or not source.active or source.organization_id != organization.pk:
        raise ValidationError("Source inactive ou organisation incorrecte.")
    require_module(organization, "access")
    if source:
        require_module(organization, "connectors")
        data = {**data, "source": str(source.pk)}
    from .observations import is_managed_source

    if is_managed_source(data.get("source")):
        raise ValidationError(
            "Cet espace de sources est réservé aux collecteurs internes vérifiés."
        )
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        existing = AccessEvent.objects.filter(
            source=data["source"], external_id=data["external_id"]
        ).first()
        if existing:
            return existing, False
        data = dict(data)
        for field in ("occurred_at", "ended_at"):
            value = data.get(field)
            if value is None:
                continue
            if isinstance(value, str):
                try:
                    value = parse_datetime(value)
                except ValueError:
                    value = None
            if not isinstance(value, datetime) or not timezone.is_aware(value):
                raise ValidationError("Les dates source doivent comporter un fuseau horaire.")
            data[field] = value
        event = AccessEvent(organization=organization, **data)
        event.full_clean()
        from datetime import timedelta

        if max(event.occurred_at, event.ended_at or event.occurred_at) > timezone.now() + timedelta(
            minutes=5
        ):
            raise ValidationError(
                "Un événement observé ne peut pas être daté de plus de cinq minutes dans le futur."
            )
        event.save()
        record(
            action="access.event.received.v1",
            summary=str(event),
            actor=actor,
            organization=organization,
            target=event,
        )
        evaluate_event(event, organization=organization)
        return event, True


def _scope_match(event, candidate, *, grant=False):
    """Missing telemetry is not evidence that an observed value differs."""
    expected = dict(
        resource_id=candidate.resource_id,
        method=candidate.method,
        account_id=candidate.account_id,
        location=candidate.location,
        privilege=candidate.entitlement if grant else candidate.privilege,
    )
    if not grant and candidate.network_switch_id:
        expected.update(
            network_switch_id=candidate.network_switch_id,
            network_port=candidate.network_port,
            network_vlan=candidate.network_vlan,
        )
    missing = []
    for key, value in expected.items():
        if value in (None, ""):
            continue
        actual = getattr(event, key)
        if actual in (None, ""):
            missing.append(key)
        elif (actual.casefold() if key == "method" else actual) != (
            value.casefold() if key == "method" else value
        ):
            return False, ()
    return not missing, tuple(missing)


def _point_findings(event, *, organization, interval_end=None):
    if event.organization_id != organization.pk:
        raise ValidationError("Événement d’une autre organisation.")
    require_module(organization, "access")
    with organization_context(organization):
        findings, match, verdict, grants = [], None, "unknown", []
        uncertain_scope = set()

        def add(code, state, detail, evidence=""):
            findings.append(
                {"code": code, "state": state, "detail": detail, "evidence": str(evidence)}
            )

        if not event.resource_id:
            add(
                "resource", "unknown", "Ressource locale non résolue ; aucune cible n’est inventée."
            )

        # Ownership is inventory context, never attribution of an observed action.
        # Capture the context in this immutable evaluation, not in the source fact.
        for relation in ("account", "credential"):
            subject = getattr(event, relation)
            if subject is not None:
                owner = subject.identity
                add(
                    f"{relation}_owner_context",
                    "observed",
                    f"Rattachement d’inventaire lors de cette évaluation : {subject} → "
                    f"{owner} ({owner.pk}). Ce rattachement actuel ne prouve ni l’acteur "
                    "de l’accès ni la propriété à la date source.",
                    subject.pk,
                )

        status = (
            identity_status_at(event.identity, event.occurred_at) if event.identity_id else None
        )
        if not event.identity_id:
            add(
                "identity",
                "unknown",
                "Acteur non rapporté par la source ; aucune attribution au propriétaire "
                "du compte ou du credential n’est supposée.",
            )
        elif status == "unknown":
            add(
                "lifecycle",
                "unknown",
                "Aucun état de cycle de vie connu à cette date ; "
                "la date d’enregistrement dans la plateforme ne prouve pas un départ antérieur.",
                event.identity_id,
            )
        elif status != "active":
            verdict = "deviation"
            add("lifecycle", "deviation", "Identité suspendue ou partie.", event.identity_id)
        else:
            add(
                "identity",
                "confirmed",
                (
                    "Acteur attribué par une attestation administrative : "
                    if getattr(event, "_identity_attribution", "") == "administrative_attestation"
                    else "Acteur rapporté par la source : "
                )
                + f"{event.identity.name}. "
                "Le rapprochement ne constitue pas une preuve indépendante d’authentification.",
                event.identity_id,
            )
            candidates = (
                AccessIntent.objects.filter(
                    identity=event.identity,
                    approved_at__lte=event.occurred_at,
                    starts_at__lte=event.occurred_at,
                    ends_at__gt=event.occurred_at,
                )
                .filter(
                    Q(status="approved") | Q(status="revoked", revoked_at__gt=event.occurred_at)
                )
                .order_by("created_at")
            )
            for candidate in candidates:
                if candidate.fulfillment == "pam":
                    from platform_modules.pam.mandates import authorized_at

                    if not authorized_at(candidate, event.occurred_at):
                        continue
                matches_scope, missing = _scope_match(event, candidate)
                uncertain_scope.update(missing)
                if matches_scope:
                    match = candidate
                    break
            if match:
                verdict = "expected"
                add(
                    "intent",
                    "confirmed",
                    "Identité, ressource, méthode et période concordent.",
                    match.pk,
                )
                add("why", "confirmed", match.reason, match.reference or match.pk)
                findings[-1]["business_reference"] = match.reference
            else:
                grants = Grant.objects.filter(
                    identity=event.identity,
                    created_at__lte=event.occurred_at,
                    valid_from__lte=event.occurred_at,
                ).filter(Q(status="active") | Q(status="revoked", revoked_at__gt=event.occurred_at))
                grants = (
                    grants.filter(resource_id=event.resource_id)
                    if event.resource_id
                    else grants.none()
                )
                applicable = []
                for grant in grants:
                    if grant.expires_at and grant.expires_at <= event.occurred_at:
                        continue
                    matches_scope, missing = _scope_match(event, grant, grant=True)
                    uncertain_scope.update(missing)
                    if matches_scope:
                        applicable.append(grant)
                grants = applicable
                if grants:
                    verdict = "expected"
                    add(
                        "grant",
                        "confirmed",
                        "Droit permanent ou temporaire applicable.",
                        grants[0].pk,
                    )
                    add("why", "confirmed", grants[0].justification, grants[0].pk)
                    findings[-1]["business_reference"] = grants[0].reference
                elif uncertain_scope:
                    add(
                        "scope_telemetry",
                        "unknown",
                        "Des champs nécessaires à la comparaison ne sont pas observés : "
                        + ", ".join(sorted(uncertain_scope))
                        + ". Aucun écart n’est déduit du vide.",
                    )
                elif candidates.exists():
                    verdict = "deviation"
                    add(
                        "scope", "deviation", "L’accès sort du périmètre des intentions approuvées."
                    )
                else:
                    add(
                        "why",
                        "unknown",
                        "Aucune autorisation applicable dans les données collectées.",
                    )

        if event.identity_id:
            from platform_modules.governance.policy import (
                assess_contract,
                policy_at,
                separation_findings,
            )

            contract = event.contract or (match.contract if match else None)
            if not contract and not match and verdict == "expected" and grants:
                contract = grants[0].contract
            if event.account_id and event.account.managed_contract_id:
                if contract and contract.pk != event.account.managed_contract_id:
                    add(
                        "dedicated_account_contract",
                        "deviation",
                        "Le contrat observé ne correspond pas au compte dédié.",
                    )
                contract = event.account.managed_contract
            policy = policy_at(event.occurred_at)
            if (
                policy
                and policy.require_external_contract
                and event.identity.kind == "external"
                and not contract
            ):
                add(
                    "contract_required",
                    "unknown" if uncertain_scope else "deviation",
                    "Contrat applicable non établi faute de contexte observé."
                    if uncertain_scope
                    else "Accès prestataire sans contrat applicable.",
                    policy.pk,
                )
            if contract and not event.resource_id:
                add("contract_scope", "unknown", "Ressource manquante pour vérifier le contrat.")
            if contract and event.resource_id:
                reference = (
                    match.reference
                    if match
                    else (grants[0].reference if verdict == "expected" and grants else "")
                )
                findings.extend(
                    assess_contract(
                        contract=contract,
                        identity=event.identity,
                        resource=event.resource,
                        method=event.method,
                        privilege=event.privilege,
                        location=event.location,
                        country_code=event.country_code,
                        reference=reference,
                        start=event.occurred_at,
                        end=interval_end,
                    ).findings
                )
            from datetime import timedelta

            findings.extend(
                separation_findings(
                    identity=event.identity,
                    resource=event.resource,
                    entitlement=event.privilege,
                    start=event.occurred_at,
                    end=interval_end or event.occurred_at + timedelta(microseconds=1),
                    as_of=event.occurred_at,
                ).findings
                if event.resource_id
                else []
            )

        if event.credential_id:
            credential = event.credential
            if credential.expires_at and credential.expires_at <= event.occurred_at:
                verdict = "deviation"
                add("credential_expired", "deviation", "Credential expiré.", credential.pk)
            from platform_modules.intelligence.services import expected_certificate_hosts

            expected_hosts = (
                expected_certificate_hosts(credential, event.occurred_at)
                if credential.kind == "certificate"
                else {credential.resource_id}
                if credential.resource_id
                else set()
            )
            if expected_hosts and event.resource_id not in expected_hosts:
                verdict = "deviation"
                add(
                    "credential_host",
                    "deviation",
                    "Usage sur une ressource inattendue ; à examiner.",
                    credential.pk,
                )
            elif credential.kind == "certificate" and not expected_hosts:
                add(
                    "credential_host",
                    "unknown",
                    "Aucun hôte attendu documenté à la date de l’événement.",
                    credential.pk,
                )
        from platform_modules.intelligence.services import context_findings

        findings.extend(
            context_findings(
                event,
                organization=organization,
                matched_intent=match,
                matched_grant=grants[0] if grants and not match and verdict == "expected" else None,
            )
        )
        if event.result != "success":
            add(
                "result",
                "observed",
                f"Résultat source : {event.result}. L’effet n’est pas présumé.",
            )
        add(
            "provenance",
            "observed",
            "Source et identifiant de l’événement conservés.",
            f"{event.source}/{event.external_id}",
        )
        if any(f["state"] == "deviation" for f in findings):
            verdict = "deviation"
        elif any(f["state"] == "unknown" for f in findings):
            verdict = "unknown"
        return verdict, match, findings


@transaction.atomic
def evaluate_event(event, *, organization):
    from copy import copy

    from .evidence import evaluation_body, evaluation_signature
    from .observations import observation_context, sign
    from .temporal import observation_segments

    if event.organization_id != organization.pk:
        raise ValidationError("Événement d’une autre organisation.")
    require_module(organization, "access")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        event = AccessEvent.objects.select_related(
            "identity", "account__identity", "resource", "credential__identity"
        ).get(pk=event.pk)
        context = observation_context(event, organization=organization)
        segments, limit = ([], None) if context.blocked else observation_segments(context.event)
        findings, matches = list(context.findings), []
        verdicts = [
            item["state"] for item in context.findings if item["state"] in {"unknown", "deviation"}
        ]
        if context.blocked:
            verdicts.append("unknown")
        if limit:
            verdicts.append("unknown")
            findings.append(
                dict(
                    code=limit,
                    state="unknown",
                    detail="La période dépasse les limites de l’évaluation temporelle "
                    "(31 jours ou 32 segments). Aucune conformité globale n’est déclarée.",
                    evidence=str(event.pk),
                )
            )
        for start, end in segments:
            observed = copy(context.event)
            observed.occurred_at, observed.ended_at = start, end
            verdict, match, result = _point_findings(
                observed, organization=organization, interval_end=end
            )
            verdicts.append(verdict)
            matches.append(match)
            if end is not None:
                findings.append(
                    dict(
                        code="observed_interval",
                        state="observed",
                        detail=f"Période examinée : [{start.isoformat()}, {end.isoformat()}).",
                        evidence=str(event.pk),
                    )
                )
                result = [
                    dict(item, interval_start=start.isoformat(), interval_end=end.isoformat())
                    for item in result
                ]
            findings.extend(result)
        verdict = (
            "deviation"
            if "deviation" in verdicts
            else "unknown"
            if "unknown" in verdicts
            else "expected"
        )
        match = (
            matches[0]
            if matches and all(item and item.pk == matches[0].pk for item in matches)
            else None
        )
        evaluation = AccessEvaluation(
            organization=organization,
            event=event,
            intent=match,
            verdict=verdict,
            findings=findings,
            context=context.snapshot,
            context_hash=context.fingerprint,
        )
        evaluation.audit = record(
            action="access.event.evaluated.v1",
            summary=f"Évaluation : {verdict}",
            organization=organization,
            target=evaluation,
            metadata={
                "event_id": str(event.pk),
                "rule_version": evaluation.rule_version,
                "segments": len(segments),
                "temporal_limit": limit,
                "body_hash": sign(evaluation_body(evaluation), "evaluation-body"),
            },
        )
        evaluation.signature = evaluation_signature(evaluation)
        evaluation.full_clean()
        evaluation.save()
        return evaluation


@transaction.atomic
def revoke_identity(identity_id, *, actor, organization, reason):
    authorize(actor, organization)
    require_module(organization, "identity")
    if not reason.strip():
        raise ValidationError("Une raison de départ est requise.")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        identity = Identity.objects.select_for_update().get(pk=identity_id)
        newly_departed = identity.status != "departed"
        from platform_modules.identity.models import IdentityStateChange

        now = timezone.now()
        if identity.status != "departed":
            IdentityStateChange.objects.create(
                organization=organization,
                identity=identity,
                previous_status=identity.status,
                next_status="departed",
                effective_at=now,
            )
        identity.status = "departed"
        identity.save(update_fields=["status"])
        from platform_modules.identity.models import LoginIdentityBinding

        linked = LoginIdentityBinding.objects.filter(identity=identity, revoked_at__isnull=True)
        binding_ids = list(linked.values_list("id", flat=True))
        linked.update(revoked_at=now, revoked_by=actor, revocation_reason=f"Départ : {reason}")
        accounts = ExternalAccount.objects.filter(identity=identity, active=True)
        account_ids = list(accounts.values_list("id", flat=True))
        owned_account_ids = list(
            ExternalAccount.objects.filter(identity=identity).values_list("id", flat=True)
        )
        from platform_modules.connectors.outbound import queue_account_disable
        from platform_modules.identity.services import revoke_grant

        for account in accounts:
            account.active = False
            account.state_revision += 1
            account.save(update_fields=["active", "state_revision"])
            queue_account_disable(
                account, actor=actor, organization=organization, origin="identity.departed"
            )
        for grant in Grant.objects.filter(identity=identity, status="active"):
            revoke_grant(grant, actor=actor, organization=organization, origin="identity.departed")
        AccessIntent.objects.filter(
            Q(identity=identity) | Q(account_id__in=owned_account_ids),
            status__in=["pending", "approved"],
        ).update(status="revoked", revoked_at=now)
        from platform_modules.pam.models import SessionLease

        SessionLease.objects.filter(
            Q(intent__identity=identity) | Q(intent__account_id__in=owned_account_ids),
            status="active",
        ).update(status="revoked", ended_at=now)
        record(
            action="identity.departed.v1",
            summary=f"Départ : {identity.name}",
            actor=actor,
            organization=organization,
            target=identity,
            metadata={
                "reason": reason,
                "accounts": [str(i) for i in account_ids],
                "login_bindings_revoked": [str(i) for i in binding_ids],
                "external_execution": "requires_connector_confirmation",
            },
        )
        if newly_departed:
            from platform_core.events import publish_domain_event

            publish_domain_event(
                organization=organization,
                actor=actor,
                emitter="identity",
                topic="identity.identity.departed.v1",
                target=identity,
                payload={"identity_id": str(identity.pk), "status": "departed"},
            )
        return identity


def identity_status_at(identity, at):
    if identity.created_at > at:
        return "unknown"
    last = identity.state_changes.filter(effective_at__lte=at).order_by("-effective_at").first()
    if last:
        return last.next_status
    first = identity.state_changes.order_by("effective_at").first()
    return first.previous_status if first else identity.status


@transaction.atomic
def reevaluate_event(event_id, *, actor, organization):
    authorize(actor, organization, roles=("admin", "operator"))
    require_module(organization, "access")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        event = AccessEvent.objects.get(pk=event_id)
        return evaluate_event(event, organization=organization)
