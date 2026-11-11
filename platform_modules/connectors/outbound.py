"""Transactional change queue, bounded retries and read-after-write evidence."""

import uuid
from datetime import datetime, timedelta

from cryptography.fernet import InvalidToken
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from platform_core.audit import record
from platform_core.authorization import require_recent_authentication
from platform_core.models import Organization
from platform_core.security import cipher
from platform_core.services import authorize, module_available, require_module
from platform_core.tenancy import organization_context
from platform_modules.identity.models import Grant

from .models import (
    AccountBinding,
    ExecutionEvidence,
    ExternalChange,
    GroupBinding,
    ProvisioningConnector,
)
from .scim import IntegrationFailure, ScimAdapter, destination, remote_id
from .scim_credentials import connector_token, destination_seal, destination_verified


def _operator(actor, organization):
    authorize(actor, organization, roles=("admin",))
    require_module(organization, "connectors")
    return require_recent_authentication(actor, organization)


@transaction.atomic
def configure_connector(*, actor, organization, name, base_url, token="", connector_id=None):
    _operator(actor, organization)
    requested_destination = destination(base_url)
    if token and (len(token) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise ValidationError("Jeton invalide.")
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        connector = (
            ProvisioningConnector.objects.get(pk=connector_id)
            if connector_id
            else ProvisioningConnector(organization=organization)
        )
        if not connector_id and not token:
            raise ValidationError("Un jeton initial est requis.")
        if connector_id:
            if not destination_verified(connector):
                raise ValidationError(
                    "Destination historique non vérifiable. Configurez un nouveau connecteur."
                )
            if requested_destination != destination(connector.base_url):
                raise ValidationError("Destination immuable. Configurez un nouveau connecteur.")
            if token:
                from .creation_models import ScimCreationRequest

                if (
                    AccountBinding.objects.filter(connector=connector).exists()
                    or GroupBinding.objects.filter(connector=connector).exists()
                    or ScimCreationRequest.objects.filter(connector=connector).exists()
                ):
                    raise ValidationError(
                        "Ce jeton porte un historique de destination. "
                        "Configurez un nouveau connecteur et de nouvelles correspondances."
                    )
        else:
            connector.base_url = base_url
        connector.name = name
        if token:
            connector.encrypted_token = cipher().encrypt(token.encode()).decode()
            connector.destination_seal = destination_seal(connector)
        if connector_id:
            connector.revision += 1
        connector.enabled, connector.verified_revision = False, None
        connector.tested_at, connector.test_code = None, ""
        connector.full_clean()
        connector.save()
        record(
            action="connectors.configuration.changed.v1",
            summary=f"Configuration : {name}",
            actor=actor,
            organization=organization,
            target=connector,
            metadata={"revision": connector.revision},
        )
        return connector


def test_connector(connector_id, *, actor, organization):
    _operator(actor, organization)
    with organization_context(organization):
        connector = ProvisioningConnector.objects.get(pk=connector_id)
        revision = connector.revision
        try:
            ScimAdapter(connector.base_url, connector_token(connector)).test()
            code, verified = "scim_read_and_patch_capability_confirmed", True
        except IntegrationFailure as error:
            code, verified = error.code, False
        except (InvalidToken, ValueError, OSError):
            code, verified = "connector_configuration_invalid", False
        with transaction.atomic():
            Organization.objects.select_for_update().get(pk=organization.pk)
            connector = ProvisioningConnector.objects.select_for_update().get(pk=connector_id)
            if connector.revision != revision:
                raise ValidationError("La configuration a changé pendant le test. Relancez-le.")
            connector.tested_at, connector.test_code = timezone.now(), code
            if verified:
                connector.verified_revision = revision
            elif not connector.enabled:
                connector.verified_revision = None
            connector.save()
            record(
                action="connectors.connection.tested.v1",
                summary=f"Test SCIM : {code}",
                actor=actor,
                organization=organization,
                target=connector,
            )
        return verified, code


@transaction.atomic
def set_connector_enabled(connector_id, *, actor, organization, enabled):
    _operator(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        connector = ProvisioningConnector.objects.get(pk=connector_id)
        if enabled and connector.verified_revision != connector.revision:
            raise ValidationError("Testez cette configuration avant de l’activer.")
        if enabled:
            destination(connector.base_url)
            if not destination_verified(connector):
                raise ValidationError("Destination du connecteur SCIM non vérifiée.")
        connector.enabled = enabled
        connector.save(update_fields=["enabled"])
        record(
            action="connectors.activation.changed.v1",
            summary=f"Connecteur actif : {enabled}",
            actor=actor,
            organization=organization,
            target=connector,
        )
        return connector


@transaction.atomic
def bind_account(*, actor, organization, connector, account, remote_identifier):
    _operator(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)
    remote_id(remote_identifier)
    binding = AccountBinding(
        organization=organization, connector=connector, account=account, remote_id=remote_identifier
    )
    with organization_context(organization):
        binding.full_clean()
        binding.save()
    record(
        action="connectors.account.bound.v1",
        summary=f"Compte relié : {account}",
        actor=actor,
        organization=organization,
        target=binding,
    )
    return binding


@transaction.atomic
def bind_group(*, actor, organization, connector, resource, entitlement, remote_identifier):
    _operator(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)
    remote_id(remote_identifier)
    binding = GroupBinding(
        organization=organization,
        connector=connector,
        resource=resource,
        entitlement=entitlement,
        remote_id=remote_identifier,
    )
    with organization_context(organization):
        binding.full_clean()
        binding.save()
    record(
        action="connectors.group.bound.v1",
        summary=f"Droit relié : {entitlement}",
        actor=actor,
        organization=organization,
        target=binding,
    )
    return binding


def _route(change, *, actor, organization):
    if change.grant_id:
        change.account = change.grant.account
    binding = (
        change.binding
        if change.binding_id
        else (
            AccountBinding.objects.filter(account_id=change.account_id)
            .select_related("connector")
            .first()
            if change.account_id
            else None
        )
    )
    group = change.group if change.group_id else None
    if not group and binding and change.grant_id:
        group = GroupBinding.objects.filter(
            connector=binding.connector,
            resource_id=change.grant.resource_id,
            entitlement=change.grant.entitlement,
        ).first()
    change.binding, change.group = binding, group
    if not binding or (change.grant_id and not group):
        change.status, change.result_code = "unmapped", "mapping_required"
        return
    if binding.account_id != change.account_id or (
        group and group.connector_id != binding.connector_id
    ):
        raise ValidationError("Les correspondances SCIM ne désignent pas la même destination.")
    if actor:
        assurance = require_recent_authentication(actor, organization)
        change.authorized_by = actor
        change.authorization_at = datetime.fromtimestamp(
            assurance.verified_at, tz=timezone.get_default_timezone()
        )
    elif not change.authorization_at:
        # System expirations derive from a previously persisted, dated grant.
        change.authorization_at = timezone.now()
    connector = binding.connector
    change.connector_revision = connector.revision
    if not destination_verified(connector):
        change.status, change.result_code = "blocked", "connector_destination_unverified"
        return
    ready = connector.enabled and connector.verified_revision == connector.revision
    change.status, change.result_code = (
        ("queued", "") if ready else ("blocked", "connector_inactive")
    )


def queue_account_disable(account, *, actor, organization, origin):
    if account.organization_id != organization.pk or account.active:
        raise ValidationError("Le compte doit être localement désactivé dans cette organisation.")
    if actor is None:
        from platform_modules.governance.policy import account_contract_live

        if (
            origin != "contract.withdrawn"
            or not account.managed_contract_id
            or account_contract_live(account)
        ):
            raise PermissionDenied
    else:
        authorize(actor, organization, roles=("admin", "operator", "reviewer"))
    key = f"account:{account.pk}:disable:{account.state_revision}"
    return _enqueue(
        account=account,
        grant=None,
        kind="disable_account",
        key=key,
        actor=actor,
        organization=organization,
        origin=origin,
    )


def queue_grant_state(grant, *, actor, organization, origin):
    if grant.organization_id != organization.pk:
        raise ValidationError("Droit d’une autre organisation.")
    if actor:
        authorize(actor, organization, roles=("admin", "operator", "reviewer"))
    if actor is None:
        from platform_modules.governance.policy import contract_withdrawal_required

        system_withdrawal = (
            origin == "contract.withdrawn"
            and grant.contract_id
            and contract_withdrawal_required(grant, organization=organization)
        )
        expired = (
            origin == "grant.expired" and grant.expires_at and grant.expires_at <= timezone.now()
        )
        if grant.status != "revoked" or not (expired or system_withdrawal):
            raise PermissionDenied
    present = grant.status == "active"
    key = f"grant:{grant.pk}:{grant.status}:{grant.state_revision}"
    return _enqueue(
        account=grant.account,
        grant=grant,
        kind="add_membership" if present else "remove_membership",
        key=key,
        actor=actor,
        organization=organization,
        origin=origin,
    )


@transaction.atomic
def _enqueue(*, account, grant, kind, key, actor, organization, origin):
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        existing = ExternalChange.objects.filter(idempotency_key=key).first()
        if existing:
            return existing
        change = ExternalChange(
            organization=organization,
            account=account,
            grant=grant,
            kind=kind,
            idempotency_key=key,
            authorized_by=actor,
        )
        _route(change, actor=actor, organization=organization)
        if kind == "add_membership":
            change.next_attempt_at = max(timezone.now(), grant.valid_from)
        change.full_clean()
        change.save()
        record(
            action="connectors.external_change.queued.v1",
            summary=str(change),
            actor=actor,
            organization=organization,
            target=change,
            metadata={"origin": origin},
        )
        return change


@transaction.atomic
def retry_change(change_id, *, actor, organization):
    from .mover_handover import can_reconcile, is_role_effect

    _operator(actor, organization)
    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        change = ExternalChange.objects.get(pk=change_id)
        if change.status in ("succeeded", "cancelled") and (
            change.kind == "remove_membership" and is_role_effect(change)
        ):
            if ExternalChange.objects.filter(
                grant=change.grant,
                kind="remove_membership",
                status__in=("queued", "retry", "running"),
            ).exists():
                raise ValidationError("Un retrait de ce droit est déjà en cours.")
            candidate = ExternalChange(
                organization=organization,
                account=change.account,
                grant=change.grant,
                binding=change.binding,
                group=change.group,
                kind=change.kind,
                authorized_by=actor,
                idempotency_key=f"mover-reconcile:{change.grant_id}:{uuid.uuid4()}",
            )
            _route(candidate, actor=actor, organization=organization)
            if candidate.status != "queued" or not can_reconcile(candidate):
                raise ValidationError("Aucun retrait non confirmé sur cette destination exacte.")
            candidate.full_clean()
            candidate.save()
            record(
                action="connectors.external_change.queued.v1",
                summary=str(candidate),
                actor=actor,
                organization=organization,
                target=candidate,
                metadata={"origin": "mover_reconciliation", "previous_change_id": str(change.pk)},
            )
            return candidate
        if change.status in ("running", "succeeded", "cancelled"):
            raise ValidationError("Cette opération ne peut pas être relancée dans cet état.")
        _route(change, actor=actor, organization=organization)
        change.attempt_limit = change.attempts + 5
        change.next_attempt_at = (
            max(timezone.now(), change.grant.valid_from)
            if change.kind == "add_membership"
            else timezone.now()
        )
        change.save()
        record(
            action="connectors.external_change.reauthorized.v1",
            summary=str(change),
            actor=actor,
            organization=organization,
            target=change,
        )
        return change


def _obsolete(change):
    account = change.account
    if change.kind == "activate_account":
        from .creation import activation_authorized

        return not activation_authorized(change)
    if change.kind == "disable_account":
        return account.active and account.identity.status == "active"
    aliases = GroupBinding.objects.filter(
        connector_id=change.binding.connector_id, remote_id=change.group.remote_id
    ).values_list("resource_id", "entitlement")
    scope = Q(pk__in=[])
    for resource_id, entitlement in aliases:
        scope |= Q(resource_id=resource_id, entitlement=entitlement)
    active = (
        Grant.objects.filter(
            account=account,
            status="active",
            identity__status="active",
            account__active=True,
            valid_from__lte=timezone.now(),
        )
        .filter(scope)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
    )
    from platform_modules.governance.policy import assess_authorization

    allowed = any(
        assess_authorization(grant, organization=grant.organization, remaining=True).status
        == "allow"
        for grant in active
    )
    if change.kind == "add_membership":
        own_allowed = (
            change.grant.status == "active"
            and change.grant.valid_from <= timezone.now()
            and assess_authorization(
                change.grant, organization=change.organization, remaining=True
            ).status
            == "allow"
        )
        return not allowed or not own_allowed
    return allowed


def _check_dispatch(claim, organization):
    from .mover_handover import (
        TARGET_CHANGED,
        WAITING,
        is_role_effect,
        membership_scope,
        needs_handover,
        removal_problem,
    )

    with organization_context(organization):
        change = ExternalChange.objects.select_related(
            "binding__connector", "account__identity", "grant", "group"
        ).get(pk=claim.pk)
        if (
            change.claim_token != claim.claim_token
            or change.status != "running"
            or change.binding.claim_token != claim.claim_token
            or change.claim_expires_at < timezone.now() + timedelta(seconds=30)
        ):
            raise IntegrationFailure("execution_lease_expired", retryable=True)
        connector = change.binding.connector
        if (
            not connector.enabled
            or connector.revision != change.connector_revision
            or not destination_verified(connector)
            or claim.binding_id != change.binding_id
            or claim.group_id != change.group_id
            or not module_available(organization, "connectors")
            or _obsolete(change)
            or (change.kind == "activate_account" and not _activation_ready(change))
        ):
            raise IntegrationFailure("operation_superseded")
        if needs_handover(change):
            raise IntegrationFailure(WAITING, retryable=True)
        if is_role_effect(change) and membership_scope(claim) != membership_scope(change):
            raise IntegrationFailure(TARGET_CHANGED)
        problem = removal_problem(change)
        if problem:
            raise IntegrationFailure(problem)


@transaction.atomic
def _claim(organization):
    from .mover_handover import (
        NEVER_ATTEMPTED,
        WAITING,
        effect_metadata,
        needs_handover,
        removal_problem,
    )

    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        now = timezone.now()
        candidates = (
            ExternalChange.objects.filter(next_attempt_at__lte=now)
            .filter(
                Q(status__in=["queued", "retry"]) | Q(status="running", claim_expires_at__lte=now)
            )
            .select_related("binding__connector", "account__identity", "grant", "group")
            .order_by("created_at")
        )
        candidates = list(candidates[:50])
        if not candidates:
            return None
        available = module_available(organization, "connectors")
        for change in candidates:
            binding = change.binding
            if (
                not binding
                or binding.account_id != change.account_id
                or (change.grant_id and not change.group_id)
                or (change.group_id and change.group.connector_id != binding.connector_id)
                or not change.authorization_at
            ):
                change.status, change.result_code = "blocked", "authorization_or_mapping_required"
            elif binding.claim_expires_at and binding.claim_expires_at > now:
                continue
            elif not destination_verified(binding.connector):
                change.status, change.result_code = "blocked", "connector_destination_unverified"
            elif (
                not binding.connector.enabled
                or binding.connector.verified_revision != change.connector_revision
                or binding.connector.revision != change.connector_revision
                or not available
            ):
                change.status, change.result_code = "blocked", "connector_configuration_changed"
            elif _obsolete(change):
                change.status, change.result_code = "cancelled", "desired_state_superseded"
            elif problem := removal_problem(change):
                change.status = "cancelled" if problem == NEVER_ATTEMPTED else "blocked"
                change.result_code = problem
            elif needs_handover(change):
                change.status, change.result_code = "retry", WAITING
                change.next_attempt_at = now + timedelta(seconds=15)
                change.save(update_fields=["status", "result_code", "next_attempt_at"])
                continue
            elif change.kind == "activate_account" and not _activation_ready(change):
                if change.result_code != "waiting_for_confirmed_initial_grant":
                    change.result_code = "waiting_for_confirmed_initial_grant"
                    change.save(update_fields=["result_code"])
                continue
            elif change.attempts >= change.attempt_limit:
                change.status, change.result_code = "failed", "attempt_limit_reached"
            else:
                token = uuid.uuid4()
                change.claim_token = binding.claim_token = token
                change.claim_expires_at = binding.claim_expires_at = now + timedelta(seconds=90)
                change.status, change.attempts = "running", change.attempts + 1
                binding.save(update_fields=["claim_token", "claim_expires_at"])
                change.save()
                record(
                    action="connectors.external_change.started.v1",
                    summary=str(change),
                    organization=organization,
                    target=change,
                    metadata={"attempt": change.attempts, **effect_metadata(change)},
                )
                return change
            change.save()
            record(
                action="connectors.external_change.stopped.v1",
                summary=change.result_code,
                organization=organization,
                target=change,
            )
        return None


def _compensate_late_positive(claim, current, observed, organization):
    """A stale acknowledgement cannot revive access after a completed withdrawal."""
    binding = current.binding
    if (
        claim.kind not in ("activate_account", "add_membership")
        or binding.pk != claim.binding_id
        or binding.connector_id != claim.binding.connector_id
        or binding.remote_id != claim.binding.remote_id
        or binding.connector.revision != claim.connector_revision
    ):
        return
    kind, grant = None, None
    if (
        claim.kind == "activate_account"
        and observed.get("active") is True
        and observed.get("remote_id") == binding.remote_id
        and (not current.account.active or current.account.identity.status != "active")
    ):
        kind = "disable_account"
    elif (
        claim.kind == "add_membership"
        and observed.get("member") is True
        and observed.get("remote_account_id") == binding.remote_id
        and observed.get("remote_group_id") == claim.group.remote_id
        and current.group_id == claim.group_id
        and current.group.remote_id == claim.group.remote_id
        and _obsolete(current)
    ):
        kind, grant = "remove_membership", current.grant
    if kind:
        negative = _enqueue(
            account=current.account,
            grant=grant,
            kind=kind,
            key=f"late:{current.pk}:{claim.claim_token}:{kind}",
            actor=None,
            organization=organization,
            origin="late_positive_after_withdrawal",
        )
        record(
            action="connectors.external_change.compensation_queued.v1",
            summary="Relecture et retrait après un effet positif tardif",
            organization=organization,
            target=negative,
            metadata={"late_change_id": str(current.pk), "attempt": claim.attempts},
        )


@transaction.atomic
def _finish(claim, *, code, observed, confirmed, retryable, organization):
    from .mover_handover import WAITING, effect_metadata, needs_handover

    Organization.objects.select_for_update().get(pk=organization.pk)
    with organization_context(organization):
        change = ExternalChange.objects.select_related("binding", "account__identity", "grant").get(
            pk=claim.pk
        )
        binding = change.binding
        if change.claim_token != claim.claim_token or binding.claim_token != claim.claim_token:
            proof = ExecutionEvidence.objects.create(
                organization=organization,
                change=change,
                attempt=claim.attempts,
                code="late_result_discarded",
                observed=observed,
            )
            record(
                action="connectors.external_change.late_result.v1",
                summary="Résultat tardif écarté",
                organization=organization,
                target=proof,
                metadata={"change_id": str(change.pk), **effect_metadata(claim)},
            )
            if confirmed:
                _compensate_late_positive(claim, change, observed, organization)
            return
        if binding.connector.revision != change.connector_revision or not binding.connector.enabled:
            change.status, code, confirmed = (
                "blocked",
                "configuration_changed_after_dispatch",
                False,
            )
        elif _obsolete(change):
            change.status, code, confirmed = "cancelled", "desired_state_superseded", False
        elif confirmed and needs_handover(change):
            change.status, code, confirmed = "retry", WAITING, False
            change.next_attempt_at = timezone.now() + timedelta(seconds=15)
        elif confirmed:
            change.status = "succeeded"
        elif retryable and change.attempts < change.attempt_limit:
            change.status = "retry"
            change.next_attempt_at = timezone.now() + timedelta(
                seconds=min(300, 5 * 2**change.attempts)
            )
        else:
            change.status = "failed"
        change.result_code, change.claim_token, change.claim_expires_at = code, None, None
        binding.claim_token, binding.claim_expires_at = None, None
        binding.save(update_fields=["claim_token", "claim_expires_at"])
        change.save()
        proof = ExecutionEvidence.objects.create(
            organization=organization,
            change=change,
            attempt=change.attempts,
            code=code,
            confirmed=confirmed,
            observed=observed,
        )
        record(
            action="connectors.external_change.executed.v1",
            summary=f"{change.status} · {code}",
            organization=organization,
            target=proof,
            metadata={
                "change_id": str(change.pk),
                "confirmed": confirmed,
                "attempt": change.attempts,
                **effect_metadata(claim),
            },
        )


def process_changes(organization, *, limit=10):
    processed = 0
    for _ in range(limit):
        claim = _claim(organization)
        if not claim:
            break
        code, observed, confirmed, retryable = "read_after_write_confirmed", {}, True, False
        try:
            connector = claim.binding.connector
            adapter = ScimAdapter(
                connector.base_url,
                connector_token(connector),
                before_write=lambda: _check_dispatch(claim, organization),
            )
            if claim.kind == "disable_account":
                observed = adapter.disable_account(claim.binding.remote_id)
            elif claim.kind == "activate_account":
                req = claim.creation_proof.dispatch.request
                observed = adapter.activate_created_user(
                    claim.binding.remote_id, req.username, req.external_id, claim.group.remote_id
                )
            else:
                observed = adapter.membership(
                    claim.binding.remote_id,
                    claim.group.remote_id,
                    present=claim.kind == "add_membership",
                )
        except IntegrationFailure as error:
            code, confirmed, retryable = error.code, False, error.retryable
        except (InvalidToken, ValueError, OSError):
            code, confirmed = "connector_configuration_invalid", False
        _finish(
            claim,
            code=code,
            observed=observed,
            confirmed=confirmed,
            retryable=retryable,
            organization=organization,
        )
        processed += 1
    return processed


def _activation_ready(change):
    from .creation import activation_ready

    return activation_ready(change)
