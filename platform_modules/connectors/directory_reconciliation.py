"""Read a page of directory facts beside distinct, explicitly linked execution histories."""

from urllib.parse import urlsplit
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import F, Q, Window
from django.db.models.functions import RowNumber
from django.utils import timezone

from platform_core.services import lock_authorized_actor, require_module

SCHEMA = "pamolive.directory-account-review/1"
READ_ROLES = ("admin", "operator", "reviewer", "auditor")
MAX_TV_SESSIONS = 10


def _time(value):
    return value.isoformat() if value else None


def _section(items=(), *, truncated=False, availability="available"):
    return dict(availability=availability, items=list(items), truncated=truncated)


def _safe_origin_url(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValidationError("Référence d’origine SCIM non exportable.")
    return value


def _origin(change, organization):
    """Use the immutable binding recorded on the operation, never a current lookup."""
    from .scim_credentials import destination_verified

    binding = change.binding
    if binding is None:
        return dict(
            state="not_recorded",
            binding_id=None,
            connector_id=None,
            recorded_connector_revision=change.connector_revision,
        )
    if (
        binding.organization_id != organization.pk
        or binding.connector.organization_id != organization.pk
        or binding.account_id != change.account_id
        or (
            change.group_id
            and (
                change.group.organization_id != organization.pk
                or change.group.connector_id != binding.connector_id
            )
        )
    ):
        raise ValidationError("Origine d’opération incohérente ou hors organisation.")
    # Migration0011 intentionally leaves previously edited legacy connectors
    # unsealed. A current URL on such a row cannot reconstruct an old route.
    # P0-2 refuses reconfiguration of these unsealed legacy rows; a new
    # connector is required. A normal rename of a sealed connector does not
    # rewrite its immutable destination or this operation's recorded revision.
    if not destination_verified(binding.connector):
        return dict(
            state="unverified_historical_destination",
            binding_id=str(binding.pk),
            connector_id=str(binding.connector_id),
            base_url=None,
            remote_account_id=None,
            remote_group_id=None,
            recorded_connector_revision=change.connector_revision,
            same_destination_relation="not_established",
        )
    return dict(
        state="recorded_operation_origin",
        binding_id=str(binding.pk),
        connector_id=str(binding.connector_id),
        base_url=_safe_origin_url(binding.connector.base_url),
        remote_account_id=binding.remote_id,
        remote_group_id=change.group.remote_id if change.group_id else None,
        recorded_connector_revision=change.connector_revision,
        same_destination_relation="not_established",
    )


def _scim_history(account_ids, *, organization, limit):
    from .creation import verify_proof
    from .creation_models import ScimCreationProof
    from .models import ExecutionEvidence, ExternalChange

    empty = dict(
        operations=_section(),
        results=_section(),
        creations=_section(),
        current_provider_state="not_asserted",
        same_destination_relation="not_established",
    )
    if not account_ids:
        for key in ("operations", "results", "creations"):
            empty[key]["availability"] = "no_explicit_account_link"
        return empty
    changes = list(
        ExternalChange.objects.filter(account_id__in=account_ids)
        .select_related("binding__connector", "group")
        .order_by("-created_at", "-pk")[: limit + 1]
    )
    change_truncated, changes = len(changes) > limit, changes[:limit]
    operations = [
        dict(
            id=str(row.pk),
            account_id=str(row.account_id),
            kind=row.kind,
            status=row.status,
            attempts=row.attempts,
            created_at=_time(row.created_at),
            updated_at=_time(row.updated_at),
            origin=_origin(row, organization),
            assurance="recorded_operation_not_provider_state",
        )
        for row in changes
    ]
    by_id = {row.pk: row for row in changes}
    proofs = (
        list(
            ExecutionEvidence.objects.filter(change_id__in=by_id).order_by("-recorded_at", "-pk")[
                : limit + 1
            ]
        )
        if by_id
        else []
    )
    proof_truncated, proofs = len(proofs) > limit, proofs[:limit]
    results = []
    for proof in proofs:
        if proof.organization_id != organization.pk:
            raise PermissionDenied
        change = by_id[proof.change_id]
        late = proof.code.startswith("late_result")
        results.append(
            dict(
                id=str(proof.pk),
                change_id=str(change.pk),
                account_id=str(change.account_id),
                kind=change.kind,
                attempt=proof.attempt,
                recorded_at=_time(proof.recorded_at),
                outcome="late_result_discarded"
                if late
                else "historical_confirmation_recorded"
                if proof.confirmed
                else "unconfirmed_result_recorded",
                confirmation_recorded=bool(proof.confirmed and not late),
                assurance="provider_result_recorded_not_independent_source_signature",
                current_provider_state="not_asserted",
                origin=_origin(change, organization),
            )
        )
    creations = list(
        ScimCreationProof.objects.filter(binding__account_id__in=account_ids)
        .select_related(
            "audit",
            "binding__connector",
            "dispatch__audit",
            "dispatch__job",
            "dispatch__request__audit",
            "dispatch__request__account__identity",
            "dispatch__request__connector",
            "dispatch__request__intent",
        )
        .order_by("-confirmed_at", "-pk")[: limit + 1]
    )
    creation_truncated, creations = len(creations) > limit, creations[:limit]
    creation_rows = []
    for proof in creations:
        request, binding = proof.dispatch.request, proof.binding
        valid = bool(
            verify_proof(proof)
            and proof.organization_id == organization.pk
            and binding.organization_id == organization.pk
            and binding.connector.organization_id == organization.pk
            and request.organization_id == organization.pk
            and request.account_id == binding.account_id
            and request.connector_id == binding.connector_id
            and proof.remote_id == binding.remote_id
            and request.scope.get("connector", {}).get("id") == str(binding.connector_id)
        )
        creation_rows.append(
            dict(
                id=str(proof.pk),
                account_id=str(binding.account_id),
                confirmed_at=_time(proof.confirmed_at),
                audit_id=str(proof.audit_id),
                state="created_inactive_recorded" if valid else "invalid_creation_proof",
                assurance="signed_creation_proof_verified" if valid else "proof_not_verified",
                active_right_asserted=False,
                current_provider_state="not_asserted",
                origin=dict(
                    binding_id=str(binding.pk),
                    connector_id=str(binding.connector_id),
                    base_url=_safe_origin_url(request.scope["connector"]["base_url"]),
                    remote_account_id=proof.remote_id,
                    recorded_connector_revision=request.scope.get("connector", {}).get("revision"),
                    same_destination_relation="not_established",
                )
                if valid
                else None,
            )
        )
    return dict(
        operations=_section(operations, truncated=change_truncated),
        results=_section(results, truncated=change_truncated or proof_truncated),
        creations=_section(creation_rows, truncated=creation_truncated),
        current_provider_state="not_asserted",
        same_destination_relation="not_established",
    )


def _teamviewer_history(accounts, *, organization, limit):
    # TeamViewer's own publisher requires this typed operator-account system.
    # An ordinary LDAP/OS account does not establish such a relationship.
    account_ids = {
        account.pk
        for account in accounts.values()
        if account.system.strip().casefold() == "teamviewer"
    }
    if not account_ids:
        return _section(availability="no_explicit_teamviewer_operator_account_link")
    from platform_modules.access.provenance_status import verified_origin_status

    from .teamviewer_access import verify_observation
    from .teamviewer_access_models import TeamViewerAccessObservation
    from .teamviewer_mapping import verify_mapping
    from .teamviewer_mapping_models import TeamViewerMapping
    from .teamviewer_session_models import TeamViewerSession
    from .teamviewer_sessions import resolve_session

    mappings = list(
        TeamViewerMapping.objects.filter(
            kind="account", account_id__in=account_ids, withdrawn=False
        )
        .select_related("audit", "collector")
        .order_by("-published_at", "-pk")[: limit + 1]
    )
    truncated, mappings = len(mappings) > limit, mappings[:limit]
    candidate = Q(pk__in=[])
    invalid = []
    for mapping in mappings:
        if not verify_mapping(mapping, check_target=False):
            invalid.append(
                dict(
                    mapping_id=str(mapping.pk),
                    account_id=str(mapping.account_id),
                    state="invalid_mapping_proof",
                    os_account="not_asserted",
                )
            )
            continue
        candidate |= Q(
            observations__sighting__collector_id=mapping.collector_id,
            observations__sighting__run__revision=mapping.source_revision,
            observations__sighting__run__config_hash=mapping.source_config_hash,
            observations__sighting__report__account_ref=mapping.remote_ref,
        )
    maximum = min(limit, MAX_TV_SESSIONS)
    sessions = list(
        TeamViewerSession.objects.filter(candidate)
        .distinct()
        .select_related("audit", "origin__report", "origin__run__audit")
        .order_by("-registered_at", "-pk")[: maximum + 1]
    )
    truncated = truncated or len(sessions) > maximum
    sessions = sessions[:maximum]
    links = {
        row.session_id: row
        for row in TeamViewerAccessObservation.objects.filter(
            session_id__in=[session.pk for session in sessions]
        ).select_related(
            "audit",
            "event",
            "session__audit",
            "session__origin__report",
            "session__origin__run__audit",
            "event__provenance_receipt__audit",
            "event__collector_source",
        )
    }
    rows = []
    for session in sessions:
        resolution = resolve_session(session, organization=organization)
        account = resolution.dimensions.get("account")
        matched = bool(
            account
            and account.state == "mapped"
            and account.target
            and account.target.pk in account_ids
        )
        link = links.get(session.pk)
        valid_link = bool(link and verify_observation(link))
        event_provenance = (
            verified_origin_status(link.event) if valid_link else ("unavailable_or_invalid")
        )
        receipt_verified = event_provenance in {"manual", "collector", "internal"}
        rows.append(
            dict(
                session_id=str(session.pk),
                state=resolution.state,
                association="operator_account_reference" if matched else "not_attributed",
                account_id=str(account.target.pk) if matched else None,
                os_account="not_asserted",
                historical_person_authentication="not_asserted",
                source_event_id=str(link.event_id) if valid_link else None,
                provenance_link="verified" if valid_link else "unavailable_or_invalid",
                event_provenance=event_provenance,
                provenance_receipt_verified=receipt_verified,
                provenance_receipt_id=str(link.event.provenance_receipt.pk)
                if receipt_verified
                else None,
                started_at=resolution.facts.get("started_at") if resolution.facts else None,
                ended_at=resolution.facts.get("ended_at") if resolution.facts else None,
                assurance="verified_dated_operator_account_mapping_not_os_authentication"
                if matched
                else "unresolved_or_unverified_session_reference",
                same_destination_relation="not_established",
            )
        )
    return _section((invalid + rows)[:limit], truncated=truncated or len(invalid + rows) > limit)


@transaction.atomic
def directory_account_review(
    source_id, *, actor, organization, limit=100, cursor=None, history_limit=20
):
    """A bounded review projection, not a new authority, signature or state-changing service."""
    if type(history_limit) is not int or not 1 <= history_limit <= 100:
        raise ValidationError("La limite d’histoire doit être comprise entre1 et100.")
    actor, organization = lock_authorized_actor(actor, organization, roles=READ_ROLES)
    require_module(organization, "identity")
    require_module(organization, "connectors")
    from platform_modules.identity.models import ExternalAccount

    from .directory_inventory import (
        directory_inventory,
        verify_directory_mapping,
        verify_directory_run,
    )
    from .directory_models import DirectoryMapping, DirectoryRun

    page = directory_inventory(
        source_id=source_id, actor=actor, organization=organization, limit=limit, cursor=cursor
    )
    source_id = page["source"]["id"]
    run = (
        DirectoryRun.objects.select_related("source__audit", "audit").get(
            pk=page["run_id"], source_id=source_id
        )
        if page["run_id"]
        else None
    )
    if run and not verify_directory_run(run):
        raise ValidationError("L’observation d’inventaire n’est pas vérifiable.")
    observations = [("observed", row) for row in page["items"]] + [
        ("not_observed", row) for row in page["not_observed"]
    ]
    remotes = [UUID(row["remote_id"]) for _, row in observations]
    mappings = {
        str(row.remote_id): row
        for row in DirectoryMapping.objects.filter(source_id=source_id, remote_id__in=remotes)
        .annotate(
            latest=Window(
                expression=RowNumber(), partition_by=[F("remote_id")], order_by=F("sequence").desc()
            )
        )
        .filter(latest=1)
        .select_related("audit", "source__audit", "previous", "account__identity")
    }
    if any(not verify_directory_mapping(mapping) for mapping in mappings.values()):
        raise ValidationError("La correspondance d’inventaire n’est pas vérifiable.")
    account_ids = {
        mapping.account_id
        for mapping in mappings.values()
        if mapping.kind == "bind" and page["source"]["enabled"]
    }
    accounts = {
        row.pk: row
        for row in ExternalAccount.objects.filter(pk__in=account_ids).select_related("identity")
    }
    if len(accounts) != len(account_ids) or any(
        account.identity.organization_id != organization.pk for account in accounts.values()
    ):
        raise ValidationError("Compte ou identité hors organisation.")
    scim = _scim_history(account_ids, organization=organization, limit=history_limit)
    teamviewer = _teamviewer_history(accounts, organization=organization, limit=history_limit)
    items = []
    for observation_state, observation in observations:
        mapping = mappings.get(observation["remote_id"])
        account = accounts.get(mapping.account_id) if mapping and mapping.kind == "bind" else None
        reasons = list(observation.get("warnings", []))
        if account is None:
            reasons.append("explicit_mapping_inactive_or_missing")
        elif observation_state == "not_observed":
            reasons.append("missing_observation_is_not_deletion")
        else:
            observed_enabled = observation.get("enabled")
            if observed_enabled is None:
                reasons.append("source_enabled_state_unknown")
            elif account.active and not observed_enabled:
                reasons.append("local_active_source_reports_disabled")
            elif not account.active and observed_enabled:
                reasons.append("local_inactive_source_reports_enabled")
        related_ops = [
            row
            for row in scim["operations"]["items"]
            if account and row["account_id"] == str(account.pk)
        ]
        related_results = [
            row
            for row in scim["results"]["items"]
            if account and row["account_id"] == str(account.pk)
        ]
        related_creations = [
            row
            for row in scim["creations"]["items"]
            if account and row["account_id"] == str(account.pk)
        ]
        if any(row["status"] != "succeeded" for row in related_ops):
            reasons.append("scim_operation_not_confirmed")
        if any(row["outcome"] == "late_result_discarded" for row in related_results):
            reasons.append("late_scim_result_discarded")
        if any(row["state"] == "invalid_creation_proof" for row in related_creations):
            reasons.append("invalid_scim_creation_proof")
        if run and any(row["recorded_at"] < run.observed_at.isoformat() for row in related_results):
            reasons.append("scim_result_predates_inventory_acceptance")
        if not page["complete"]:
            reasons.append("directory_snapshot_incomplete")
        if any(scim[key]["truncated"] for key in ("operations", "results", "creations")):
            reasons.append("related_history_truncated")
        items.append(
            dict(
                observation_state=observation_state,
                observation=observation,
                mapping=dict(
                    id=str(mapping.pk),
                    kind=mapping.kind,
                    recorded_at=_time(mapping.decided_at),
                    audit_id=str(mapping.audit_id),
                    assurance="verified_administrative_account_binding_not_person_attestation",
                )
                if mapping
                else None,
                local_account=dict(
                    id=str(account.pk),
                    username=account.username,
                    system=account.system,
                    active=account.active,
                    current_identity_id=str(account.identity_id),
                    current_identity_status=account.identity.status,
                    identity_relation="current_owner_not_historical_person_authentication",
                )
                if account
                else None,
                scim_operation_ids=[row["id"] for row in related_ops],
                scim_result_ids=[row["id"] for row in related_results],
                scim_creation_proof_ids=[row["id"] for row in related_creations],
                review_reasons=sorted(set(reasons)),
                same_destination_relation="not_established",
                current_provider_state="not_asserted",
            )
        )
    return dict(
        schema=SCHEMA,
        organization_id=str(organization.pk),
        generated_at=_time(timezone.now()),
        source=page["source"],
        run=dict(
            id=str(run.pk),
            accepted_at=_time(run.observed_at),
            audit_id=str(run.audit_id),
            provenance=run.provenance,
            complete=run.complete,
            limitations=run.limitations,
            assurance="verified_server_acceptance_reference_not_public_signature",
        )
        if run
        else None,
        items=items,
        page_limits=dict(
            facts=limit,
            not_observed=limit,
            total_items_max=2 * limit,
            history_per_section=history_limit,
        ),
        scim_history=scim,
        teamviewer_history=teamviewer,
        next_cursor=page["next_cursor"],
        not_observed_truncated=page["not_observed_truncated"],
        read_only=True,
        can_apply=False,
        current_provider_state="not_asserted",
        same_destination_relation="not_established",
        limitations=[
            "No realm association or group-to-entitlement equivalence is established.",
            "Historical account ownership does not identify an authenticated person.",
            "Recorded provider outcomes do not assert current remote state.",
            "References to verified HMAC evidence are not a public offline proof bundle.",
        ],
    )
