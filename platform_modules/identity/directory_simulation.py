"""Read-only AD/LDAP/Entra fixture adapters. No transport and no write/apply path."""

import hashlib
import json
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from platform_core.services import require_module

from .identity360 import _guard
from .models import ExternalAccount, Grant

SCHEMA = "pamolive.directory-reconciliation-preview/1"
MAX_RECORDS = 1000
ADAPTERS = {
    "ad": ("objectGUID", "sAMAccountName", "enabled", "memberOf"),
    "ldap": ("entryUUID", "uid", "enabled", "memberOf"),
    "entra": ("id", "userPrincipalName", "accountEnabled", "groups"),
}


def _text(value, maximum=180):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValidationError("Identifiant ou texte de simulation invalide.")
    if any(ord(c) < 32 for c in value):
        raise ValidationError("Caractère de contrôle interdit.")
    return value.strip()


def normalize_fixture(provider, records):
    """Unknown properties are rejected so a secret/configuration cannot be echoed."""
    if not isinstance(provider, str) or provider not in ADAPTERS:
        raise ValidationError("Simulateur inconnu : ad, ldap ou entra attendu.")
    if type(records) is not list or len(records) > MAX_RECORDS:
        raise ValidationError("La simulation accepte au plus 1000 enregistrements.")
    id_key, username_key, enabled_key, groups_key = ADAPTERS[provider]
    keys = set(ADAPTERS[provider])
    seen, result = set(), []
    for row in records:
        if type(row) is not dict or set(row) != keys or type(row[enabled_key]) is not bool:
            raise ValidationError(
                "Un enregistrement doit respecter exactement le schéma du simulateur."
            )
        remote_id = _text(row[id_key])
        # UUID-backed providers use a canonical immutable object identifier. LDAP
        # entryUUID is similarly strict: never use a mutable DN/login as identity.
        try:
            remote_id = str(UUID(remote_id))
        except ValueError as exc:
            raise ValidationError("Un identifiant d’objet UUID stable est requis.") from exc
        if remote_id in seen:
            raise ValidationError("Identifiant distant dupliqué dans la même source.")
        seen.add(remote_id)
        groups = row[groups_key]
        if type(groups) is not list or len(groups) > 32:
            raise ValidationError("Une fixture accepte au plus 32 groupes par compte.")
        groups = sorted({_text(group) for group in groups})
        result.append(
            {
                "remote_id": remote_id,
                "username": _text(row[username_key]),
                "enabled": row[enabled_key],
                "groups": groups,
            }
        )
    return sorted(result, key=lambda row: row["remote_id"])


@transaction.atomic
def preview_reconciliation(
    *, provider, source_id, records, mapping, actor, organization, synthetic=False
):
    """Compare explicit synthetic mapping; names/e-mails never establish a link.

    A mapping is a preview input, not a saved binding or identity attestation. A
    missing row cannot authorize deprovisioning: the snapshot may be incomplete.
    """
    _, organization = _guard(actor, organization)
    require_module(organization, "connectors")
    if synthetic is not True:
        raise ValidationError("Seules des fixtures explicitement synthétiques sont acceptées.")
    source_id = _text(source_id)
    normalized = normalize_fixture(provider, records)
    if type(mapping) is not dict or len(mapping) > MAX_RECORDS:
        raise ValidationError("Correspondances explicites invalides.")
    normalized_mapping = {}
    try:
        for remote, local in mapping.items():
            remote_id, local_id = str(UUID(remote)), UUID(local)
            if remote_id in normalized_mapping:
                raise ValueError
            normalized_mapping[remote_id] = local_id
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValidationError("Les correspondances doivent utiliser des UUID explicites.") from exc
    if len(set(normalized_mapping.values())) != len(normalized_mapping):
        raise ValidationError(
            "Un compte local ne peut pas représenter plusieurs objets de la source."
        )
    accounts = {
        row.pk: row
        for row in ExternalAccount.objects.filter(
            pk__in=normalized_mapping.values()
        ).select_related("identity")
    }
    if len(accounts) != len(normalized_mapping):
        raise ValidationError("Compte absent ou hors organisation dans les correspondances.")
    for account in accounts.values():
        if account.identity.organization_id != organization.pk:
            raise ValidationError("Rattachement d’identité inter-organisation invalide.")
    rights, now = {}, timezone.now()
    rows = list(
        Grant.objects.filter(account_id__in=accounts, status="active", valid_from__lte=now)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .values_list("account_id", "entitlement")[:32001]
    )
    if len(rows) > 32000:
        raise ValidationError("Trop de droits locaux pour cette prévisualisation bornée.")
    for account_id, entitlement in rows:
        rights.setdefault(account_id, set()).add(entitlement)
    names = {}
    for row in normalized:
        names.setdefault(row["username"].casefold(), []).append(row["remote_id"])
    comparisons = []
    for row in normalized:
        account_id = normalized_mapping.get(row["remote_id"])
        warnings = []
        if len(names[row["username"].casefold()]) > 1:
            warnings.append("duplicate_login_requires_human_review")
        if account_id is None:
            state = "unlinked_requires_human_review"
        else:
            account = accounts[account_id]
            if account.username != row["username"]:
                warnings.append("username_differs")
            if account.active != row["enabled"]:
                warnings.append("enabled_state_differs")
            if account.identity.status != "active" and row["enabled"]:
                warnings.append("enabled_account_for_inactive_identity")
            if rights.get(account_id, set()) != set(row["groups"]):
                warnings.append("group_labels_differ_from_local_entitlements")
            state = "review_required" if warnings else "fixture_matches_local_record"
        comparisons.append(
            {
                "remote_id": row["remote_id"],
                "account_id": str(account_id) if account_id else None,
                "username": row["username"],
                "state": state,
                "warnings": warnings,
            }
        )
    present = {row["remote_id"] for row in normalized}
    absent = [
        {
            "remote_id": remote,
            "account_id": str(account),
            "state": "not_observed_in_snapshot_requires_review",
        }
        for remote, account in sorted(normalized_mapping.items())
        if remote not in present
    ]
    facts = {
        "schema": SCHEMA,
        "organization_id": str(organization.pk),
        "provider": provider,
        "source_id": source_id,
        "records": normalized,
        "mapping": {key: str(value) for key, value in sorted(normalized_mapping.items())},
    }
    fingerprint = hashlib.sha256(
        json.dumps(facts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "organization_id": str(organization.pk),
        "provider": provider,
        "source_id": source_id,
        "synthetic": True,
        "read_only": True,
        "can_apply": False,
        "provenance": "caller_supplied_synthetic_fixture_not_authenticated_collector",
        "snapshot_sha256": fingerprint,
        "comparisons": comparisons,
        "not_observed": absent,
        "local_revisions": {str(row.pk): row.state_revision for row in accounts.values()},
        "limitations": [
            "No remote connection, persisted binding, identity attestation or mutation.",
            "Source identifiers are caller declarations scoped to this preview only.",
            "A missing record does not prove deletion and never authorizes a withdrawal.",
            "Group labels are compared literally, not resolved into effective permissions.",
        ],
    }
