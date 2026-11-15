"""Public V1 rules ported from Git a573; configuration/SQL removed explicitly."""

import base64
import re
from datetime import timedelta

from ._codec import canonical
from ._codec import fail as _deny
from ._codec import integer as _integer
from ._context import timestamp as _timestamp
from ._context import uuid as _uuid
from ._crypto import decode as _decode
from ._crypto import public_key_fingerprint

REGISTRY_FORMAT = "pamolive.pam.trust-registry/1"
REGISTRY_TTL = 86400
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
ROLES = {"requester", "reviewer", "sponsor"}


def _unique(values):
    if not isinstance(values, list):
        _deny()
    try:
        if len(values) != len(set(values)):
            _deny()
    except TypeError:
        _deny()
    return values


def _validate_body(body, context):
    if not isinstance(body, dict) or len(canonical(body)) > MAX_DOCUMENT_BYTES:
        _deny()
    if (
        body.get("format") != REGISTRY_FORMAT
        or body.get("installation") != context.installation
        or body.get("organization") != context.organization
        or not _uuid(body.get("generation"))
        or not _integer(body.get("revision"))
        or body.get("operation") not in {"bootstrap", "update", "recommission"}
    ):
        _deny()
    issued, expires = _timestamp(body.get("issued_at")), _timestamp(body.get("expires_at"))
    maximum_age = REGISTRY_TTL
    if not issued < expires <= issued + timedelta(seconds=maximum_age):
        _deny()
    people, custodians, targets, policy = (
        body.get("persons"),
        body.get("custodians"),
        body.get("targets"),
        body.get("policy"),
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
        "organization",
        "endpoint",
        "epoch",
        "resource",
        "account",
        "username",
        "protocol",
        "hostname",
        "port",
        "domain",
        "auth_method",
        "fingerprint",
    }
    for endpoint_id, target in targets.items():
        if not _uuid(endpoint_id) or not isinstance(target, dict):
            _deny()
        scope = target.get("scope")
        if (
            not isinstance(scope, dict)
            or set(scope) != scope_fields
            or scope.get("organization") != context.organization
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
                not isinstance(authority, dict)
                or not _uuid(authority.get("revision"))
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
        person
        for section in ("persons", "custodians")
        for person in previous[section].keys() | following[section].keys()
        if previous[section].get(person) != following[section].get(person)
    }
    for endpoint in previous["targets"].keys() | following["targets"].keys():
        before = previous["targets"].get(endpoint, {})
        after = following["targets"].get(endpoint, {})
        if before != after:
            affected.update(
                person
                for person in (before.get("sponsor_person"), after.get("sponsor_person"))
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
            if (
                not new
                or any(
                    old.get(field) != new.get(field)
                    for field in ("id", "public_key", "rp_id", "origin", "enrollment_id")
                )
                or (not old["active"] and new["active"])
            ):
                _deny()


def _remember_owners(body, identities, accounts, credentials, public_keys, custody_keys):
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
