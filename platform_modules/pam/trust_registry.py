"""Verify externally signed PAM authority against an independent checkpoint.

The database contains public evidence only. Registry mutations are authorized by
the previous revision, never by the new custodians or the tenant administrator.
"""

import base64
import hashlib
import json
import re
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import connection, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from platform_core.attestations import canonical
from platform_core.models import Organization, OrganizationMembership
from platform_core.tenancy import organization_context

from .trust_models import PAMAuthenticatorState, PAMTrustRevision

REGISTRY_DOMAIN = b"pamolive.pam.trust-registry.v1\0"
CHECKPOINT_DOMAIN = b"pamolive.pam.trust-checkpoint.v1\0"
REGISTRY_FORMAT = "pamolive.pam.trust-registry/1"
CHECKPOINT_FORMAT = "pamolive.pam.trust-checkpoint/1"
REGISTRY_TTL = 86400
CHECKPOINT_TTL = 60
ROLES = {"requester", "reviewer", "sponsor"}
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


class TrustError(PermissionDenied):
    pass


def _deny():
    raise TrustError("L’autorité PAM indépendante est absente, périmée ou non vérifiable.")


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _integer(value, minimum=1):
    return type(value) is int and value >= minimum


def _timestamp(value):
    if not isinstance(value, str):
        _deny()
    try:
        result = parse_datetime(value)
    except ValueError:
        _deny()
    if result is None or timezone.is_naive(result):
        _deny()
    return result


def _decode(value, *, length=None, maximum=8192):
    if not isinstance(value, str) or len(value) > maximum * 2:
        _deny()
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        _deny()
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        _deny()
    if len(decoded) > maximum or (length is not None and len(decoded) != length):
        _deny()
    return decoded


def _installation():
    value = getattr(settings, "PAM_TRUST_INSTALLATION_ID", "")
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        _deny()
    return value


def _maximum_age(name, maximum):
    value = getattr(settings, name, maximum)
    if not _integer(value) or value > maximum:
        _deny()
    return value


def signature_message(body):
    return REGISTRY_DOMAIN + canonical(body).encode()


def checkpoint_message(body):
    return CHECKPOINT_DOMAIN + canonical(body).encode()


def registry_digest(envelope):
    document = {
        "body": envelope["body"],
        "signatures": envelope.get("signatures", {}),
        "commissioning_signatures": envelope.get("commissioning_signatures", {}),
    }
    return hashlib.sha256(REGISTRY_DOMAIN + canonical(document).encode()).hexdigest()


def _verify(public_key, signature, message):
    try:
        key = Ed25519PublicKey.from_public_bytes(_decode(public_key, length=32))
        key.verify(_decode(signature, length=64), message)
    except (InvalidSignature, ValueError, TypeError):
        _deny()


def _configured_keys(name, organization):
    mappings = getattr(settings, name, {})
    keys = mappings.get(str(organization.pk), {}) if isinstance(mappings, dict) else {}
    if not isinstance(keys, dict) or not keys:
        _deny()
    return keys


def _external_key(value, at, *, historical):
    if isinstance(value, str):
        return value
    if not isinstance(value, dict) or (not historical and value.get("active") is False):
        _deny()
    if value.get("not_before") and at < _timestamp(value["not_before"]):
        _deny()
    if value.get("not_after") and at >= _timestamp(value["not_after"]):
        _deny()
    if value.get("revoked_at") and at >= _timestamp(value["revoked_at"]):
        _deny()
    return value.get("public_key")


def _unique(values):
    if not isinstance(values, list):
        _deny()
    try:
        if len(values) != len(set(values)):
            _deny()
    except TypeError:
        _deny()
    return values


def _validate_body(body, organization, *, historical):
    from .trust_auth import public_key_fingerprint

    if not isinstance(body, dict) or len(canonical(body).encode()) > MAX_DOCUMENT_BYTES:
        _deny()
    if (
        body.get("format") != REGISTRY_FORMAT
        or body.get("installation") != _installation()
        or body.get("organization") != str(organization.pk)
        or not _uuid(body.get("generation"))
        or not _integer(body.get("revision"))
        or body.get("operation") not in {"bootstrap", "update", "recommission"}
    ):
        _deny()
    issued, expires = _timestamp(body.get("issued_at")), _timestamp(body.get("expires_at"))
    maximum_age = (
        REGISTRY_TTL if historical
        else _maximum_age("PAM_TRUST_REGISTRY_MAX_SECONDS", REGISTRY_TTL)
    )
    if not issued < expires <= issued + timedelta(seconds=maximum_age):
        _deny()
    people, custodians, targets, policy = (
        body.get("persons"), body.get("custodians"), body.get("targets"), body.get("policy")
    )
    if not all(isinstance(value, dict) for value in (people, custodians, targets, policy)):
        _deny()
    if not _integer(policy.get("standard_min")) or not _integer(
        policy.get("critical_min"), max(2, policy["standard_min"])
    ):
        _deny()
    identity_owners, account_owners, credential_owners, key_owners = {}, {}, {}, {}
    for person_id, person in people.items():
        if (
            not _uuid(person_id)
            or not isinstance(person, dict)
            or type(person.get("active")) is not bool
        ):
            _deny()
        identities = _unique(person.get("identity_ids", []))
        accounts = _unique(person.get("account_ids", []))
        endpoints = _unique(person.get("endpoint_ids", []))
        roles = _unique(person.get("roles", []))
        if any(not _uuid(value) for value in identities + endpoints) or not set(roles) <= ROLES:
            _deny()
        for account in accounts:
            if not isinstance(account, str) or not account or len(account) > 180:
                _deny()
        for values, owners in ((identities, identity_owners), (accounts, account_owners)):
            for value in values:
                if value in owners:
                    _deny()
                owners[value] = person_id
        authenticators = person.get("authenticators", [])
        if not isinstance(authenticators, list):
            _deny()
        for authenticator in authenticators:
            if not isinstance(authenticator, dict) or type(authenticator.get("active")) is not bool:
                _deny()
            credential_id = authenticator.get("id")
            credential_bytes = _decode(credential_id, maximum=1024)
            _decode(authenticator.get("public_key"))
            if (
                not _uuid(authenticator.get("enrollment_id"))
                or not isinstance(authenticator.get("rp_id"), str)
                or not authenticator["rp_id"]
                or not isinstance(authenticator.get("origin"), str)
                or not authenticator["origin"].startswith("https://")
                or credential_bytes in credential_owners
                or credential_id != base64.urlsafe_b64encode(credential_bytes).decode().rstrip("=")
            ):
                _deny()
            fingerprint = public_key_fingerprint(authenticator["public_key"])
            if fingerprint in key_owners:
                _deny()
            credential_owners[credential_bytes] = person_id
            key_owners[fingerprint] = person_id
    custody_keys, active = set(), set()
    for person_id, custodian in custodians.items():
        if (
            person_id not in people
            or not isinstance(custodian, dict)
            or type(custodian.get("active")) is not bool
        ):
            _deny()
        key = _decode(custodian.get("public_key"), length=32)
        if key in custody_keys:
            _deny()
        custody_keys.add(key)
        if custodian["active"]:
            if not people[person_id]["active"]:
                _deny()
            active.add(person_id)
    if len(active) != 3:
        _deny()
    scope_fields = {
        "organization", "endpoint", "epoch", "resource", "account", "username", "protocol",
        "hostname", "port", "domain", "auth_method", "fingerprint",
    }
    for endpoint_id, target in targets.items():
        if not _uuid(endpoint_id) or not isinstance(target, dict):
            _deny()
        scope = target.get("scope")
        if (
            not isinstance(scope, dict)
            or set(scope) != scope_fields
            or scope.get("organization") != str(organization.pk)
            or scope.get("endpoint") != endpoint_id
            or not _integer(scope.get("epoch"))
            or not _uuid(scope.get("resource"))
            or not _uuid(scope.get("account"))
            or not _integer(scope.get("port"))
            or scope["port"] > 65535
            or scope.get("protocol") not in {"ssh", "rdp"}
            or scope.get("auth_method") not in {"password", "private_key"}
            or type(target.get("critical")) is not bool
        ):
            _deny()
        for field in ("username", "hostname", "fingerprint"):
            if not isinstance(scope.get(field), str) or not scope[field]:
                _deny()
        if not isinstance(scope.get("domain"), str):
            _deny()
        if target.get("min_reviewers") is not None and not _integer(target["min_reviewers"]):
            _deny()
        contract = target.get("contract_id", "")
        sponsor = target.get("sponsor_person", "")
        if contract and not _uuid(contract):
            _deny()
        if contract:
            authority = target.get("contract_authority", {})
            if (
                not isinstance(authority, dict) or not _uuid(authority.get("revision"))
                or not isinstance(authority.get("hash"), str)
                or not re.fullmatch("[0-9a-f]{64}", authority["hash"])
            ):
                _deny()
        if sponsor and (
            sponsor not in people
            or not people[sponsor]["active"]
            or "sponsor" not in people[sponsor].get("roles", [])
            or endpoint_id not in people[sponsor].get("endpoint_ids", [])
        ):
            _deny()
        for flag, required in (("contract_required", contract), ("sponsor_required", sponsor)):
            if flag in target and type(target[flag]) is not bool:
                _deny()
            if target.get(flag) and not required:
                _deny()
    return issued, expires


def _affected_people(previous, following):
    affected = {
        person for section in ("persons", "custodians")
        for person in previous[section].keys() | following[section].keys()
        if previous[section].get(person) != following[section].get(person)
    }
    for endpoint in previous["targets"].keys() | following["targets"].keys():
        before = previous["targets"].get(endpoint, {})
        after = following["targets"].get(endpoint, {})
        if before != after:
            affected.update(
                person for person in (before.get("sponsor_person"), after.get("sponsor_person"))
                if person
            )
    return affected


def _preserve_people(previous, following):
    for person_id, person in previous["persons"].items():
        current = following["persons"].get(person_id)
        if not current:
            _deny()
        for aliases in ("identity_ids", "account_ids"):
            if not set(person.get(aliases, [])) <= set(current.get(aliases, [])):
                _deny()
        authenticators = {item["id"]: item for item in current.get("authenticators", [])}
        for old in person.get("authenticators", []):
            new = authenticators.get(old["id"])
            if not new or any(
                old.get(field) != new.get(field)
                for field in ("id", "public_key", "rp_id", "origin", "enrollment_id")
            ) or (not old["active"] and new["active"]):
                _deny()


def _verify_transition(organization, envelope, previous=None, *, historical=True):
    if not isinstance(envelope, dict) or set(envelope) - {
        "body", "signatures", "commissioning_signatures"
    }:
        _deny()
    body = envelope.get("body")
    issued, expires = _validate_body(body, organization, historical=historical)
    signatures = envelope.get("signatures", {})
    commissioning = envelope.get("commissioning_signatures", {})
    if not isinstance(signatures, dict) or not isinstance(commissioning, dict):
        _deny()
    operation = body["operation"]
    if previous is None:
        if operation != "bootstrap" or body["revision"] != 1 or body.get("previous_hash") != "":
            _deny()
    elif (
        body["revision"] != previous.revision + 1
        or body.get("previous_hash") != previous.revision_hash
        or issued < _timestamp(previous.body["issued_at"])
    ):
        _deny()
    if operation == "update":
        if previous is None or body["generation"] != str(previous.generation) or commissioning:
            _deny()
        _preserve_people(previous.body, body)
        eligible = {
            person for person, value in previous.body["custodians"].items()
            if value["active"] and previous.body["persons"][person]["active"]
        } - _affected_people(previous.body, body)
        custody = previous.body["custodians"]
    else:
        if previous and (
            operation != "recommission" or body["generation"] == str(previous.generation)
        ):
            _deny()
        if any(person.get("authenticators") for person in body["persons"].values()):
            _deny()
        keys = _configured_keys("PAM_TRUST_COMMISSIONING_KEYS", organization)
        if not commissioning:
            _deny()
        for key_id, signed in commissioning.items():
            if key_id not in keys:
                _deny()
            public = _external_key(keys[key_id], issued, historical=historical)
            _verify(public, signed, signature_message(body))
        custody = body["custodians"]
        eligible = {person for person, value in custody.items() if value["active"]}
    if len(signatures) < 2 or not set(signatures) <= eligible:
        _deny()
    for person, signed in signatures.items():
        _verify(custody[person]["public_key"], signed, signature_message(body))
    return issued, expires


def _envelope(row):
    return {
        "body": row.body,
        "signatures": row.signatures,
        "commissioning_signatures": row.commissioning_signatures,
    }


def _history(organization, stop_hash=None):
    previous = None
    identities, accounts, credentials, public_keys, custody_keys = {}, {}, {}, {}, {}
    rows = PAMTrustRevision._base_manager.filter(organization=organization).order_by("revision")
    for row in rows:
        envelope = _envelope(row)
        _verify_transition(organization, envelope, previous)
        if (
            row.revision != row.body["revision"]
            or str(row.generation) != row.body["generation"]
            or row.previous_hash != row.body["previous_hash"]
            or row.revision_hash != registry_digest(envelope)
        ):
            _deny()
        _remember_owners(row.body, identities, accounts, credentials, public_keys, custody_keys)
        previous = row
        if stop_hash and row.revision_hash == stop_hash:
            return row
    if previous is None or stop_hash:
        _deny()
    return previous


def _remember_owners(body, identities, accounts, credentials, public_keys, custody_keys):
    from .trust_auth import public_key_fingerprint

    def remember(owners, value, person_id):
        if value in owners and owners[value] != person_id:
            _deny()
        owners[value] = person_id

    for person_id, person in body["persons"].items():
        for identity_id in person.get("identity_ids", []):
            remember(identities, identity_id, person_id)
        for account_id in person.get("account_ids", []):
            remember(accounts, account_id, person_id)
        for authenticator in person.get("authenticators", []):
            remember(credentials, _decode(authenticator["id"]), person_id)
            remember(public_keys, public_key_fingerprint(authenticator["public_key"]), person_id)
    for person_id, custodian in body["custodians"].items():
        remember(custody_keys, _decode(custodian["public_key"], length=32), person_id)


def verify_history(organization):
    """Verify archived authority as it stood at publication, without live freshness."""
    return _history(organization)


def historical_registry(organization, revision_hash):
    if not isinstance(revision_hash, str) or not re.fullmatch("[0-9a-f]{64}", revision_hash):
        _deny()
    return _history(organization, revision_hash)


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _deny()
        result[key] = value
    return result


def _invalid_constant(value):
    _deny()


def read_document(path, *, maximum=MAX_DOCUMENT_BYTES):
    try:
        with Path(path).open("rb") as source:
            data = source.read(maximum + 1)
        if len(data) > maximum:
            _deny()
        return json.loads(data, object_pairs_hook=_json_pairs, parse_constant=_invalid_constant)
    except (OSError, ValueError, UnicodeError, RecursionError):
        _deny()


def checkpoint_path(organization):
    directory = getattr(settings, "PAM_TRUST_CHECKPOINT_DIRECTORY", "")
    if not directory or not _uuid(str(organization.pk)):
        _deny()
    return Path(directory) / (str(organization.pk) + ".json")


def _checkpoint(organization, row, *, fresh=True):
    path = checkpoint_path(organization)
    if path.is_symlink():
        _deny()
    document = read_document(path, maximum=65536)
    if not isinstance(document, dict) or set(document) != {"body", "key_id", "signature"}:
        _deny()
    body = document["body"]
    if not isinstance(body, dict) or (
        body.get("format") != CHECKPOINT_FORMAT
        or body.get("installation") != _installation()
        or body.get("organization") != str(organization.pk)
        or body.get("generation") != str(row.generation)
        or body.get("revision") != row.revision
        or body.get("registry_hash") != row.revision_hash
    ):
        _deny()
    issued, expires = _timestamp(body.get("issued_at")), _timestamp(body.get("expires_at"))
    maximum_age = (
        _maximum_age("PAM_TRUST_CHECKPOINT_MAX_SECONDS", CHECKPOINT_TTL)
        if fresh else CHECKPOINT_TTL
    )
    if not issued < expires <= issued + timedelta(seconds=maximum_age):
        _deny()
    keys = _configured_keys("PAM_TRUST_CHECKPOINT_KEYS", organization)
    key_id = document["key_id"]
    if not isinstance(key_id, str) or key_id not in keys:
        _deny()
    public = _external_key(keys[key_id], issued, historical=not fresh)
    _verify(public, document["signature"], checkpoint_message(body))
    if fresh and not issued <= timezone.now() < expires:
        _deny()
    return document


def recognized_registry(organization, *, lock=False):
    if organization is None or not organization.active:
        _deny()
    if lock:
        if not connection.in_atomic_block:
            _deny()
        Organization.objects.select_for_update().get(pk=organization.pk)
    row = _history(organization)
    now = timezone.now()
    if not _timestamp(row.body["issued_at"]) <= now < _timestamp(row.body["expires_at"]):
        _deny()
    _checkpoint(organization, row)
    return row


def trust_state(organization, *, lock=False):
    return recognized_registry(organization, lock=lock)


def registry_person(registry, actor, *, identity=None, role=None, endpoint=None):
    actor_id = str(getattr(actor, "pk", ""))
    organization_id = registry.organization_id
    if (
        not get_user_model().objects.filter(pk=getattr(actor, "pk", None), is_active=True).exists()
        or not OrganizationMembership.objects.filter(
            organization_id=organization_id, account_id=actor_id, active=True
        ).exists()
    ):
        _deny()
    people = [
        (person_id, person) for person_id, person in registry.body["persons"].items()
        if actor_id in person.get("account_ids", [])
    ]
    if len(people) != 1:
        _deny()
    person_id, person = people[0]
    if not person["active"] or (role and role not in person.get("roles", [])):
        _deny()
    if identity is not None and str(getattr(identity, "pk", identity)) not in person.get(
        "identity_ids", []
    ):
        _deny()
    if endpoint is not None and str(getattr(endpoint, "pk", endpoint)) not in person.get(
        "endpoint_ids", []
    ):
        _deny()
    return person_id, deepcopy(person)


def canonical_person(actor, organization, registry=None, capability=None, *, endpoint=None):
    registry = registry or recognized_registry(organization)
    if registry.organization_id != organization.pk:
        _deny()
    return registry_person(registry, actor, role=capability, endpoint=endpoint)[0]


def protected_target(registry, endpoint, *, intent=None):
    from .target_binding import target_scope

    if endpoint.organization_id != registry.organization_id:
        _deny()
    target = registry.body["targets"].get(str(endpoint.pk))
    if target is None or target["scope"] != target_scope(endpoint):
        _deny()
    contract_id = target.get("contract_id", "")
    if intent is not None and str(intent.contract_id or "") != contract_id:
        _deny()
    tier = "critical_min" if target["critical"] else "standard_min"
    result = deepcopy(target)
    result["minimum"] = max(registry.body["policy"][tier], target.get("min_reviewers", 1))
    result["contract_required"] = bool(contract_id)
    result["sponsor_required"] = bool(target.get("sponsor_person"))
    return result


@transaction.atomic
def publish_registry(envelope, *, bootstrap=False, recommission=False):
    """Accept public evidence supplied by the offline signing ceremony."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("body"), dict):
        _deny()
    organization_id = envelope["body"].get("organization")
    if not _uuid(organization_id):
        _deny()
    organization = (
        Organization.objects.select_for_update()
        .filter(pk=organization_id, active=True)
        .first()
    )
    if organization is None:
        _deny()
    previous = None
    if PAMTrustRevision._base_manager.filter(organization=organization).exists():
        previous = _history(organization)
    operation = envelope["body"].get("operation")
    if previous is None:
        if not bootstrap or recommission or operation != "bootstrap":
            _deny()
        if checkpoint_path(organization).exists():
            _deny()
    elif recommission:
        if bootstrap or operation != "recommission":
            _deny()
        _checkpoint(organization, previous, fresh=False)
    else:
        if bootstrap or operation != "update":
            _deny()
        recognized_registry(organization)
    issued, expires = _verify_transition(organization, envelope, previous, historical=False)
    if not issued <= timezone.now() < expires:
        _deny()
    body = envelope["body"]
    if operation == "update":
        from .trust_auth import consume_enrollment

        for person_id, person in body["persons"].items():
            old = previous.body["persons"].get(person_id, {})
            existing = {item["id"] for item in old.get("authenticators", [])}
            for authenticator in person.get("authenticators", []):
                if authenticator["id"] in existing:
                    continue
                receipt = consume_enrollment(organization, person_id, authenticator)
                state, created = PAMAuthenticatorState._base_manager.get_or_create(
                    organization=organization, credential_id=authenticator["id"],
                    defaults={"sign_count": receipt.sign_count},
                )
                if not created:
                    _deny()
    row = PAMTrustRevision(
        organization=organization, generation=body["generation"], revision=body["revision"],
        previous_hash=body["previous_hash"], body=deepcopy(body),
        signatures=deepcopy(envelope.get("signatures", {})),
        commissioning_signatures=deepcopy(envelope.get("commissioning_signatures", {})),
        revision_hash=registry_digest(envelope),
    )
    with organization_context(organization):
        row.full_clean()
        row.save()
    _history(organization)
    return row
