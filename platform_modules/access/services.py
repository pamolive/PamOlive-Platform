from django.core.exceptions import ValidationError
from django.db import transaction
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
        obj.full_clean()
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
        findings, match, verdict = [], None, "unknown"

        def add(code, state, detail, evidence=""):
            findings.append(
                {"code": code, "state": state, "detail": detail, "evidence": str(evidence)}
            )

        if not event.identity_id:
            add("identity", "unknown", "Identité non résolue ; aucune attribution supposée.")
        elif event.identity.status != "active":
            verdict = "deviation"
            add("lifecycle", "deviation", "Identité suspendue ou partie.", event.identity_id)
        else:
            add("identity", "confirmed", f"Identité : {event.identity.name}", event.identity_id)
            candidates = AccessIntent.objects.filter(
                identity=event.identity,
                status="approved",
                starts_at__lte=event.occurred_at,
                ends_at__gte=event.occurred_at,
            ).order_by("created_at")
            for candidate in candidates:
                if (
                    candidate.resource_id == event.resource_id
                    and candidate.method.casefold() == event.method.casefold()
                    and (not candidate.account_id or candidate.account_id == event.account_id)
                    and (not candidate.location or candidate.location == event.location)
                    and (not candidate.privilege or candidate.privilege == event.privilege)
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
                    identity=event.identity, resource=event.resource, status="active"
                )
                grants = [
                    g
                    for g in grants
                    if (not g.expires_at or g.expires_at >= event.occurred_at)
                    and (not g.account_id or g.account_id == event.account_id)
                    and g.entitlement == event.privilege
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

        if event.credential_id:
            credential = event.credential
            if credential.expires_at and credential.expires_at < event.occurred_at:
                verdict = "deviation"
                add("credential_expired", "deviation", "Credential expiré.", credential.pk)
            if credential.resource_id and credential.resource_id != event.resource_id:
                verdict = "deviation"
                add(
                    "credential_host",
                    "deviation",
                    "Usage sur une ressource inattendue ; à examiner.",
                    credential.pk,
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
        identity.status = "departed"
        identity.save(update_fields=["status"])
        accounts = ExternalAccount.objects.filter(identity=identity, active=True)
        account_ids = list(accounts.values_list("id", flat=True))
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
        AccessIntent.objects.filter(identity=identity, status__in=["pending", "approved"]).update(
            status="revoked"
        )
        from platform_modules.pam.models import SessionLease

        SessionLease.objects.filter(intent__identity=identity, status="active").update(
            status="revoked", ended_at=timezone.now()
        )
        record(
            action="identity.departed.v1",
            summary=f"Départ : {identity.name}",
            actor=actor,
            organization=organization,
            target=identity,
            metadata={
                "reason": reason,
                "accounts": [str(i) for i in account_ids],
                "external_execution": "requires_connector_confirmation",
            },
        )
        return identity
