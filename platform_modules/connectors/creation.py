"""Initial SCIM accounts: signed authority, one POST reservation, read-only recovery."""

import hashlib
import uuid
from datetime import timedelta

from cryptography.fernet import InvalidToken
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.crypto import constant_time_compare

from platform_core.audit import record
from platform_core.authorization import assurance_datetime, require_recent_authentication
from platform_core.models import ModuleActivation, Organization
from platform_core.security import cipher
from platform_core.services import authorize, require_module
from platform_core.tenancy import current_organization, organization_context
from platform_modules.access.models import AccessIntent

from .business import anchor_valid, anchored_signature, canonical, sign
from .business_associations import intent_scope
from .creation_models import (
    ScimCreationDispatch,
    ScimCreationJob,
    ScimCreationProof,
    ScimCreationRequest,
)
from .models import AccountBinding, ExternalChange, GroupBinding, ProvisioningConnector
from .scim import IntegrationFailure, ScimAdapter

REQUEST_ACTION = "connectors.account_creation.requested.v1"
DISPATCH_ACTION = "connectors.account_creation.reserved.v1"
PROOF_ACTION = "connectors.account_creation.confirmed.v1"


def _stamp(value):
    return value.isoformat(timespec="microseconds") if value else None


def connector_scope(connector):
    return dict(
        id=str(connector.pk),
        revision=connector.revision,
        base_url=connector.base_url,
        token_hash=hashlib.sha256(connector.encrypted_token.encode()).hexdigest(),
    )


def creation_scope(intent, connector, group):
    account, grant = intent.account, intent.provisioned_grant
    result = dict(
        intent=intent_scope(intent),
        approved_at=_stamp(intent.approved_at),
        connector=connector_scope(connector),
        account=dict(
            id=str(account.pk),
            identity_id=str(account.identity_id),
            username=account.username,
            system=account.system,
            kind=account.kind,
            revision=account.state_revision,
        ),
        grant=dict(
            id=str(grant.pk),
            account_id=str(grant.account_id),
            identity_id=str(grant.identity_id),
            resource_id=str(grant.resource_id),
            entitlement=grant.entitlement,
            revision=grant.state_revision,
            valid_from=_stamp(grant.valid_from),
            expires_at=_stamp(grant.expires_at),
        ),
        group=dict(id=str(group.pk), remote_id=group.remote_id),
    )
    if len(canonical(result).encode()) > 65536:
        raise ValidationError("Le périmètre de création dépasse 64 Kio.")
    return result


def request_body(obj):
    return {
        key: getattr(obj, key)
        for key in (
            "id",
            "organization_id",
            "account_id",
            "intent_id",
            "connector_id",
            "scope",
            "username",
            "external_id",
            "activate_after_grant",
            "requested_by_id",
            "published_at",
            "mfa_verified_at",
            "mfa_window_minutes",
        )
    }


def dispatch_body(obj):
    return dict(
        id=obj.pk,
        organization_id=obj.organization_id,
        job_id=obj.job_id,
        request_id=obj.request_id,
        request_signature=obj.request.signature,
        reserved_at=obj.reserved_at,
    )


def proof_body(obj):
    return dict(
        id=obj.pk,
        organization_id=obj.organization_id,
        dispatch_id=obj.dispatch_id,
        dispatch_signature=obj.dispatch.signature,
        binding_id=obj.binding_id,
        remote_id=obj.remote_id,
        confirmed_at=obj.confirmed_at,
        active=False,
    )


def _seal(obj, body, purpose, action, *, actor=None):
    obj.audit = record(
        action=action,
        summary="Création initiale SCIM",
        actor=actor,
        organization=obj.organization,
        target=obj,
        metadata={"body_hash": sign(body, purpose + "-body")},
    )
    obj.signature = anchored_signature(body, obj.audit, purpose)
    obj.full_clean()
    obj.save()
    return obj


def verify_request(obj):
    try:
        age = (obj.published_at - obj.mfa_verified_at).total_seconds()
        return bool(
            obj.mfa_window_minutes in (2, 5, 10, 15)
            and 0 <= age < obj.mfa_window_minutes * 60
            and obj.account.organization_id == obj.organization_id
            and obj.connector.organization_id == obj.organization_id
            and obj.intent.organization_id == obj.organization_id
            and obj.scope["account"]["id"] == str(obj.account_id)
            and obj.scope["intent"]["account_id"] == str(obj.account_id)
            and obj.scope["account"]["username"] == obj.username
            and obj.scope["connector"]["id"] == str(obj.connector_id)
            and obj.external_id == f"pamolive:{obj.organization_id}:{obj.account_id}:{obj.pk}"
            and anchor_valid(
                obj, request_body(obj), "scim-creation-request", REQUEST_ACTION, obj.requested_by_id
            )
        )
    except (ValueError, TypeError, KeyError, AttributeError, ValidationError):
        return False


def verify_dispatch(obj):
    try:
        return bool(
            obj.request.organization_id == obj.organization_id
            and obj.job.organization_id == obj.organization_id
            and obj.job.account_id == obj.request.account_id
            and obj.reserved_at >= obj.request.published_at
            and verify_request(obj.request)
            and anchor_valid(
                obj, dispatch_body(obj), "scim-creation-dispatch", DISPATCH_ACTION, None
            )
        )
    except (ValueError, TypeError, KeyError, AttributeError, ValidationError):
        return False


def verify_proof(obj):
    try:
        return bool(
            obj.dispatch.organization_id == obj.organization_id
            and obj.binding.organization_id == obj.organization_id
            and obj.confirmed_at >= obj.dispatch.reserved_at
            and verify_dispatch(obj.dispatch)
            and anchor_valid(obj, proof_body(obj), "scim-creation-proof", PROOF_ACTION, None)
        )
    except (ValueError, TypeError, KeyError, AttributeError, ValidationError):
        return False


def _initial_intent(intent, organization):
    """Creating a target account does not manufacture a grant or approval."""
    grant, account, now = intent.provisioned_grant, intent.account, timezone.now()
    if (
        not account
        or not grant
        or intent.organization_id != organization.pk
        or intent.status != "approved"
        or not intent.approved_at
        or intent.approved_at > now
        or intent.revoked_at
        or intent.fulfillment != "iam_group"
        or not intent.starts_at <= now < intent.ends_at
        or not account.active
        or account.identity.status != "active"
        or account.identity_id != intent.identity_id
        or grant.status != "active"
        or grant.account_id != account.pk
        or grant.identity_id != intent.identity_id
        or grant.resource_id != intent.resource_id
        or grant.entitlement != intent.privilege
        or grant.valid_from > now
        or (grant.expires_at and grant.expires_at <= now)
    ):
        raise ValidationError("Une intention IAM approuvée et actuellement valable est requise.")
    from platform_modules.governance.policy import assess_authorization

    if assess_authorization(grant, organization=organization, remaining=True).status != "allow":
        raise ValidationError("Le droit approuvé n’est plus autorisé par la politique.")


def live_request(obj):
    if not verify_request(obj):
        return False
    try:
        authorize(obj.requested_by, obj.organization, roles=("admin",))
        for key in ("identity", "access", "connectors"):
            require_module(obj.organization, key)
        intent = AccessIntent.objects.select_related(
            "account__identity", "provisioned_grant", "identity", "resource"
        ).get(pk=obj.intent_id)
        connector = ProvisioningConnector.objects.get(pk=obj.connector_id)
        _initial_intent(intent, obj.organization)
        group = GroupBinding.objects.get(
            pk=obj.scope["group"]["id"],
            connector=connector,
            resource=intent.resource,
            entitlement=intent.privilege,
        )
        return bool(
            connector.enabled
            and connector.verified_revision == connector.revision
            and creation_scope(intent, connector, group) == obj.scope
        )
    except (
        PermissionDenied,
        ValidationError,
        KeyError,
        ValueError,
        TypeError,
        AccessIntent.DoesNotExist,
        ProvisioningConnector.DoesNotExist,
        GroupBinding.DoesNotExist,
    ):
        return False


@transaction.atomic
def request_creation(
    intent_id, connector_id, *, activate_after_grant, actor, organization, preview_signature=None
):
    if organization.pk != current_organization().pk or type(activate_after_grant) is not bool:
        raise PermissionDenied
    authorize(actor, organization, roles=("admin",))
    assurance = require_recent_authentication(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    for key in ("identity", "access", "connectors"):
        require_module(organization, key)
    intent = AccessIntent.objects.select_related(
        "account__identity", "provisioned_grant", "identity", "resource"
    ).get(pk=intent_id)
    connector = ProvisioningConnector.objects.get(pk=connector_id)
    _initial_intent(intent, organization)
    if not connector.enabled or connector.verified_revision != connector.revision:
        raise ValidationError("Le connecteur doit être testé puis activé.")
    if AccountBinding.objects.filter(account=intent.account).exists():
        raise ValidationError("Ce compte possède déjà une correspondance distante.")
    username = intent.account.username
    if (
        not username
        or len(username) > 180
        or not username.isprintable()
        or any(c.isspace() for c in username)
    ):
        raise ValidationError("L’identifiant SCIM ne doit contenir ni espace ni contrôle.")
    try:
        group = GroupBinding.objects.get(
            connector=connector, resource=intent.resource, entitlement=intent.privilege
        )
    except GroupBinding.DoesNotExist:
        raise ValidationError("Reliez d’abord le droit approuvé à son groupe SCIM.") from None
    job = ScimCreationJob.objects.filter(account=intent.account).first()
    if job and (ScimCreationDispatch.objects.filter(job=job).exists() or job.status == "running"):
        raise ValidationError("Une création a déjà été réservée ou est en cours : réconciliez-la.")
    obj = ScimCreationRequest(
        organization=organization,
        account=intent.account,
        intent=intent,
        connector=connector,
        scope=creation_scope(intent, connector, group),
        username=username,
        activate_after_grant=activate_after_grant,
        requested_by=actor,
        mfa_verified_at=assurance_datetime(assurance.verified_at),
        mfa_window_minutes=assurance.freshness_minutes,
    )
    obj.external_id = f"pamolive:{organization.pk}:{obj.account_id}:{obj.pk}"
    if preview_signature is not None and not constant_time_compare(
        preview_signature,
        sign(
            dict(scope=obj.scope, actor_id=actor.pk, activate_after_grant=activate_after_grant),
            "scim-creation-preview",
        ),
    ):
        raise ValidationError("Le périmètre a changé : vérifiez à nouveau la destination.")
    _seal(obj, request_body(obj), "scim-creation-request", REQUEST_ACTION, actor=actor)
    if job:
        job.request, job.status, job.result_code = obj, "queued", ""
        job.attempts, job.next_attempt_at = 0, timezone.now()
        job.claim_token = job.claim_expires_at = None
        job.save()
    else:
        job = ScimCreationJob.objects.create(
            organization=organization, account=intent.account, request=obj
        )
    return job


@transaction.atomic
def retry_creation(job_id, *, actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "connectors")
    require_recent_authentication(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk, active=True)
    job = ScimCreationJob.objects.get(pk=job_id)
    if job.status in ("running", "created"):
        raise ValidationError("Cette opération est en cours ou déjà confirmée.")
    if not ScimCreationDispatch.objects.filter(job=job).exists() and not live_request(job.request):
        raise ValidationError("Publiez une nouvelle demande valable avant tout envoi.")
    job.status, job.attempts, job.next_attempt_at = "queued", 0, timezone.now()
    job.claim_token = job.claim_expires_at = None
    job.save()
    record(
        action="connectors.account_creation.reconcile_requested.v1",
        summary="Réexaminer la création sans réserver un second POST",
        actor=actor,
        organization=organization,
        target=job,
    )
    return job


@transaction.atomic
def _claim_creation(organization):
    locked = Organization.objects.select_for_update().get(pk=organization.pk)
    if not locked.active:
        return None
    if not ModuleActivation.objects.filter(
        organization=organization, module_key="connectors", enabled=True
    ).exists():
        return None
    now = timezone.now()
    for job in (
        ScimCreationJob.objects.filter(next_attempt_at__lte=now)
        .filter(Q(status__in=("queued", "retry")) | Q(status="running", claim_expires_at__lte=now))
        .select_related("request__connector", "request__requested_by", "account")
        .order_by("next_attempt_at", "id")[:50]
    ):
        req, connector = job.request, job.request.connector
        dispatched = ScimCreationDispatch.objects.filter(job=job).exists()
        if not verify_request(req) or connector_scope(connector) != req.scope.get("connector"):
            job.status, job.result_code = (
                "unconfirmed" if dispatched else "failed",
                "creation_configuration_changed",
            )
        elif not connector.enabled or connector.verified_revision != connector.revision:
            continue
        elif not dispatched and not live_request(req):
            job.status, job.result_code = "cancelled", "creation_authorization_ended"
        elif job.attempts >= 5:
            job.status, job.result_code = (
                "unconfirmed" if dispatched else "failed",
                "creation_read_limit_reached",
            )
        else:
            job.status, job.claim_token = "running", uuid.uuid4()
            job.claim_expires_at = now + timedelta(seconds=90)
            job.attempts += 1
            job.save()
            return job
        job.claim_token = job.claim_expires_at = None
        job.save()
        record(
            action="connectors.account_creation.stopped.v1",
            summary=job.result_code,
            organization=organization,
            target=job,
        )
    return None


@transaction.atomic
def _reserve_creation(claim, organization):
    locked = Organization.objects.select_for_update().get(pk=organization.pk)
    if not locked.active:
        raise IntegrationFailure("creation_organization_inactive")
    job = ScimCreationJob.objects.select_related("request__requested_by").get(pk=claim.pk)
    if (
        job.status != "running"
        or job.claim_token != claim.claim_token
        or job.request_id != claim.request_id
        or job.claim_expires_at <= timezone.now() + timedelta(seconds=30)
        or not live_request(job.request)
        or AccountBinding.objects.filter(account=job.account).exists()
        or ScimCreationDispatch.objects.filter(job=job).exists()
    ):
        raise IntegrationFailure("creation_dispatch_not_authorized")
    dispatch = ScimCreationDispatch(organization=organization, job=job, request=job.request)
    _seal(dispatch, dispatch_body(dispatch), "scim-creation-dispatch", DISPATCH_ACTION)


def _resume_initial_grant(proof, organization):
    """Only the already-approved exact grant can be routed; no new local grant."""
    from .outbound import _enqueue, _route

    req = proof.dispatch.request
    if not req.activate_after_grant or not live_request(req):
        return
    grant = req.intent.provisioned_grant
    add = _enqueue(
        account=grant.account,
        grant=grant,
        kind="add_membership",
        key=f"grant:{grant.pk}:{grant.status}:{grant.state_revision}",
        actor=None,
        organization=organization,
        origin="scim.initial_creation",
    )
    if add.status in ("unmapped", "blocked"):
        add.authorized_by, add.authorization_at = req.requested_by, req.mfa_verified_at
        _route(add, actor=None, organization=organization)
        add.next_attempt_at = max(timezone.now(), grant.valid_from)
        add.save()
    elif not add.authorization_at:
        add.authorized_by, add.authorization_at = req.requested_by, req.mfa_verified_at
        add.save()
    activation = ExternalChange(
        organization=organization,
        account=req.account,
        grant=grant,
        binding=proof.binding,
        group=add.group,
        connector_revision=req.connector.revision,
        creation_proof=proof,
        kind="activate_account",
        status="queued",
        idempotency_key=f"creation:{proof.pk}:activate",
        authorized_by=req.requested_by,
        authorization_at=req.mfa_verified_at,
    )
    activation.full_clean()
    activation.save()
    record(
        action="connectors.account_creation.activation_queued.v1",
        summary="Activation après confirmation du seul droit déjà approuvé",
        organization=organization,
        target=activation,
        metadata={"creation_proof": str(proof.pk), "grant_id": str(grant.pk)},
    )


def _resume_creation_revocations(proof, organization):
    """An offboarding queued before the mapping must still be confirmed remotely."""
    from .outbound import _obsolete, _route

    req = proof.dispatch.request
    for change in ExternalChange.objects.filter(
        account=req.account,
        kind__in=("disable_account", "remove_membership"),
        status__in=("unmapped", "blocked"),
    ):
        _route(change, actor=None, organization=organization)
        if (
            change.status == "queued"
            and (change.kind == "disable_account" or change.grant_id)
            and not _obsolete(change)
        ):
            change.next_attempt_at = timezone.now()
            change.save()
            record(
                action="connectors.account_creation.withdrawal_routed.v1",
                summary="Retrait déjà demandé relié au compte nouvellement confirmé",
                organization=organization,
                target=change,
                metadata={"creation_proof": str(proof.pk)},
            )


@transaction.atomic
def _finish_creation(claim, organization, *, observed=None, code="", retryable=False):
    Organization.objects.select_for_update().get(pk=organization.pk)
    job = ScimCreationJob.objects.select_related("request__account", "request__connector").get(
        pk=claim.pk
    )
    if (
        job.claim_token != claim.claim_token
        or job.status != "running"
        or job.request_id != claim.request_id
    ):
        record(
            action="connectors.account_creation.late_result.v1",
            summary="Résultat tardif écarté",
            organization=organization,
            target=job,
        )
        return
    req = job.request
    dispatch = ScimCreationDispatch.objects.filter(job=job).first()
    if observed:
        if (
            not dispatch
            or not verify_dispatch(dispatch)
            or dispatch.request_id != req.pk
            or observed.get("username") != req.username
            or observed.get("external_id") != req.external_id
            or observed.get("active") is not False
        ):
            raise ValidationError("Confirmation de création invalide.")
        binding = AccountBinding.objects.filter(account=job.account).first()
        if binding and (
            binding.connector_id != req.connector_id or binding.remote_id != observed["remote_id"]
        ):
            job.status, code = "unconfirmed", "creation_binding_conflict"
        elif connector_scope(req.connector) != req.scope["connector"]:
            job.status, code = "unconfirmed", "creation_configuration_changed"
        elif any(
            str(getattr(job.account, name)) != str(req.scope["account"][key])
            for name, key in (
                ("pk", "id"),
                ("identity_id", "identity_id"),
                ("username", "username"),
                ("system", "system"),
                ("kind", "kind"),
            )
        ):
            job.status, code = "unconfirmed", "creation_local_account_scope_changed"
        else:
            if not binding:
                binding = AccountBinding(
                    organization=organization,
                    account=job.account,
                    connector=req.connector,
                    remote_id=observed["remote_id"],
                )
                binding.full_clean()
                binding.save()
            proof = ScimCreationProof(
                organization=organization,
                dispatch=dispatch,
                binding=binding,
                remote_id=observed["remote_id"],
            )
            _seal(proof, proof_body(proof), "scim-creation-proof", PROOF_ACTION)
            job.binding, job.status, code = (
                binding,
                "created",
                "inactive_account_readback_confirmed",
            )
            _resume_initial_grant(proof, organization)
            _resume_creation_revocations(proof, organization)
    elif retryable and job.attempts < 5:
        job.status = "retry"
        job.next_attempt_at = timezone.now() + timedelta(seconds=min(300, 5 * 2**job.attempts))
    else:
        job.status = "unconfirmed" if dispatch else "failed"
    job.result_code, job.claim_token, job.claim_expires_at = code, None, None
    job.save()
    record(
        action="connectors.account_creation.result.v1",
        summary=f"{job.status}: {code}",
        organization=organization,
        target=job,
        metadata={
            "attempt": job.attempts,
            "post_reserved": bool(dispatch),
            "inactive_confirmed": bool(job.binding_id),
        },
    )


def process_creations(organization, *, limit=1):
    processed = 0
    with organization_context(organization):
        for _ in range(limit):
            claim = _claim_creation(organization)
            if not claim:
                break
            observed, code, retryable = None, "inactive_account_readback_confirmed", False
            try:
                req = claim.request
                adapter = ScimAdapter(
                    req.connector.base_url,
                    cipher().decrypt(req.connector.encrypted_token.encode()).decode(),
                    before_write=lambda: _reserve_creation(claim, organization),
                )
                dispatch = ScimCreationDispatch.objects.filter(job=claim).first()
                if dispatch:
                    if dispatch.request_id != req.pk or not verify_dispatch(dispatch):
                        raise IntegrationFailure("creation_dispatch_invalid")
                    observed = adapter.read_created_user(req.username, req.external_id)
                    if observed is None:
                        raise IntegrationFailure(
                            "creation_unconfirmed_no_second_post", retryable=True
                        )
                else:
                    observed = adapter.create_inactive_user(req.username, req.external_id)
            except IntegrationFailure as error:
                code, retryable = error.code, error.retryable
                # Any outcome after the durable reservation can only trigger reads.
                retryable |= ScimCreationDispatch.objects.filter(job=claim).exists()
            except (InvalidToken, ValueError, OSError):
                code = "creation_connector_configuration_invalid"
            _finish_creation(claim, organization, observed=observed, code=code, retryable=retryable)
            processed += 1
    return processed


def activation_authorized(change):
    proof = change.creation_proof
    if not proof or not verify_proof(proof):
        return False
    req, binding = proof.dispatch.request, change.binding
    return bool(
        req.activate_after_grant
        and live_request(req)
        and change.grant_id == req.intent.provisioned_grant_id
        and str(change.group_id) == req.scope["group"]["id"]
        and change.account_id == req.account_id
        and binding.pk == proof.binding_id
        and binding.account_id == req.account_id
        and binding.connector_id == req.connector_id
        and binding.remote_id == proof.remote_id
    )


def activation_ready(change):
    grant = change.grant
    return ExternalChange.objects.filter(
        grant=grant,
        kind="add_membership",
        status="succeeded",
        binding=change.binding,
        group=change.group,
        connector_revision=change.connector_revision,
        idempotency_key=f"grant:{grant.pk}:active:{grant.state_revision}",
    ).exists()


def verify_creations():
    """Historical proof verification never requires a request, active grant or module."""
    total = 0
    for model, verify in (
        (ScimCreationRequest, verify_request),
        (ScimCreationDispatch, verify_dispatch),
        (ScimCreationProof, verify_proof),
    ):
        for obj in model.unscoped.all().iterator():
            if not verify(obj):
                raise RuntimeError("Invalid restored SCIM creation evidence")
            total += 1
    return total
