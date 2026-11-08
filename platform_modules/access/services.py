from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

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
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        existing = AccessEvent.objects.filter(
            source=data["source"], external_id=data["external_id"]
        ).first()
        if existing:
            return existing, False
        event = AccessEvent(organization=organization, **data)
        event.full_clean()
        from datetime import timedelta

        if event.occurred_at > timezone.now() + timedelta(minutes=5):
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


def evaluate_event(event, *, organization):
    if event.organization_id != organization.pk:
        raise ValidationError("Événement d’une autre organisation.")
    require_module(organization, "access")
    with organization_context(organization):
        findings, match, verdict, grants = [], None, "unknown", []

        def add(code, state, detail, evidence=""):
            findings.append(
                {"code": code, "state": state, "detail": detail, "evidence": str(evidence)}
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

        if not event.identity_id:
            add(
                "identity",
                "unknown",
                "Acteur non rapporté par la source ; aucune attribution au propriétaire "
                "du compte ou du credential n’est supposée.",
            )
        elif identity_status_at(event.identity, event.occurred_at) != "active":
            verdict = "deviation"
            add("lifecycle", "deviation", "Identité suspendue ou partie.", event.identity_id)
        else:
            add(
                "identity",
                "confirmed",
                f"Acteur rapporté par la source : {event.identity.name}. "
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
                if (
                    candidate.resource_id == event.resource_id
                    and candidate.method.casefold() == event.method.casefold()
                    and (not candidate.account_id or candidate.account_id == event.account_id)
                    and (not candidate.location or candidate.location == event.location)
                    and (not candidate.privilege or candidate.privilege == event.privilege)
                    and (
                        not candidate.network_switch_id
                        or (
                            candidate.network_switch_id,
                            candidate.network_port,
                            candidate.network_vlan,
                        )
                        == (event.network_switch_id, event.network_port, event.network_vlan)
                    )
                ):
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
            else:
                grants = Grant.objects.filter(
                    identity=event.identity,
                    resource=event.resource,
                    created_at__lte=event.occurred_at,
                    valid_from__lte=event.occurred_at,
                ).filter(Q(status="active") | Q(status="revoked", revoked_at__gt=event.occurred_at))
                grants = [
                    g
                    for g in grants
                    if (not g.expires_at or g.expires_at > event.occurred_at)
                    and (not g.account_id or g.account_id == event.account_id)
                    and g.entitlement == event.privilege
                    and (not g.method or g.method.casefold() == event.method.casefold())
                    and (not g.location or g.location == event.location)
                ]
                if grants:
                    verdict = "expected"
                    add(
                        "grant",
                        "confirmed",
                        "Droit permanent ou temporaire applicable.",
                        grants[0].pk,
                    )
                    add("why", "confirmed", grants[0].justification, grants[0].pk)
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
                    "deviation",
                    "Accès prestataire sans contrat applicable.",
                    policy.pk,
                )
            if contract:
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
                    ).findings
                )
            from datetime import timedelta

            findings.extend(
                separation_findings(
                    identity=event.identity,
                    resource=event.resource,
                    entitlement=event.privilege,
                    start=event.occurred_at,
                    end=event.occurred_at + timedelta(microseconds=1),
                    as_of=event.occurred_at,
                ).findings
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

        findings.extend(context_findings(event, organization=organization, matched_intent=match))
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
        evaluation = AccessEvaluation.objects.create(
            organization=organization, event=event, intent=match, verdict=verdict, findings=findings
        )
        record(
            action="access.event.evaluated.v1",
            summary=f"Évaluation : {verdict}",
            organization=organization,
            target=evaluation,
            metadata={"event_id": str(event.pk), "rule_version": evaluation.rule_version},
        )
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
