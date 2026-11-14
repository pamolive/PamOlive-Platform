"""Closed, immutable and explicitly UNAUTHORIZED P2-R1a operation data.

Parsing does not authenticate a caller, attest a server nonce, verify a proof,
select a live credential, authorize any action or constitute a release token.
"""

import base64
import hashlib
import re
from dataclasses import dataclass, field
from uuid import UUID

from .canonical import (
    BODY_DOMAIN,
    CONFIRMATION_DOMAIN,
    DRAFT_DOMAIN,
    canonical_v2,
    parse_object,
    require,
)

DRAFT_SCHEMA = "pamolive.vault-operation-draft/1"
TRANSCRIPT_SCHEMA = "pamolive.privileged-operation/2"
OPERATION = "technical-credential.release.prepare"
CRYPTO_PROFILE = "vault_envelope_v2"
DESTINATION_FORMAT = "pamolive.pam.target-scope/1"
MAX_DRAFT_BYTES = 16384
MAX_TRANSCRIPT_BYTES = 32768
MAX_NONCE_SECONDS = 30
MAX_VERSION = 2**63 - 1
SHA = re.compile(r"[0-9a-f]{64}\Z")


def _uuid(value):
    require(type(value) is str and len(value) == 36)
    try:
        require(str(UUID(value)) == value)
    except ValueError:
        require(False)


def _version(value):
    require(type(value) is int and 1 <= value <= MAX_VERSION)


def _sha(value):
    require(type(value) is str and SHA.fullmatch(value) is not None)


def _service(value):
    require(type(value) is str and 1 <= len(value) <= 64)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", value, flags=re.ASCII) is not None)


class UnverifiedContract:
    """A format value, never a verified identity, attestation or permission."""

    __slots__ = ()

    @property
    def authorized(self):
        return False


@dataclass(frozen=True, slots=True)
class OperationDraft(UnverifiedContract):
    installation_id: str
    organization_id: str
    trust_generation: str
    ledger_incarnation: str
    request_id: str
    idempotency_key: str
    session_id: str
    broker_instance_id: str
    requester_person_id: str
    approver_person_ids: tuple[str, ...]
    sponsor_person_id: str
    requested_caller_service_id: str
    broker_service_id: str
    vault_service_id: str
    broker_certificate_sha256: str
    intent_id: str
    intent_scope_hash: str
    policy_revision: str
    policy_hash: str
    registry_revision: int
    registry_hash: str
    checkpoint_hash: str
    authority_materials_sha256: str
    target_id: str
    destination_epoch: int
    destination_scope_hash: str
    credential_secret_id: str
    credential_version: int
    wrapping_revision: int
    schema: str = DRAFT_SCHEMA
    operation: str = OPERATION
    crypto_profile: str = CRYPTO_PROFILE
    destination_scope_format: str = DESTINATION_FORMAT

    def __post_init__(self):
        for name in (
            "installation_id",
            "organization_id",
            "trust_generation",
            "ledger_incarnation",
            "request_id",
            "idempotency_key",
            "session_id",
            "broker_instance_id",
            "requester_person_id",
            "intent_id",
            "target_id",
            "credential_secret_id",
            "policy_revision",
        ):
            _uuid(getattr(self, name))
        require(
            type(self.approver_person_ids) is tuple and 1 <= len(self.approver_person_ids) <= 16
        )
        for person in self.approver_person_ids:
            _uuid(person)
        require(self.approver_person_ids == tuple(sorted(set(self.approver_person_ids))))
        # Distinct IDs do not prove distinct people, roles, quorum or authority.
        require(type(self.sponsor_person_id) is str)
        if self.sponsor_person_id:
            _uuid(self.sponsor_person_id)
        for name in ("requested_caller_service_id", "broker_service_id", "vault_service_id"):
            _service(getattr(self, name))
        for name in (
            "broker_certificate_sha256",
            "intent_scope_hash",
            "policy_hash",
            "registry_hash",
            "checkpoint_hash",
            "authority_materials_sha256",
            "destination_scope_hash",
        ):
            _sha(getattr(self, name))
        for name in (
            "registry_revision",
            "destination_epoch",
            "credential_version",
            "wrapping_revision",
        ):
            _version(getattr(self, name))
        require(type(self.schema) is str and self.schema == DRAFT_SCHEMA)
        require(type(self.operation) is str and self.operation == OPERATION)
        require(type(self.crypto_profile) is str and self.crypto_profile == CRYPTO_PROFILE)
        require(
            type(self.destination_scope_format) is str
            and self.destination_scope_format == DESTINATION_FORMAT
        )


@dataclass(frozen=True, slots=True)
class FullTranscript(UnverifiedContract):
    draft: OperationDraft
    operation_nonce: str = field(repr=False)
    authenticator_counter_baseline_hash: str
    issued_at: int
    not_before: int
    expires_at: int
    schema: str = TRANSCRIPT_SCHEMA

    def __post_init__(self):
        require(type(self.draft) is OperationDraft)
        self.draft.__post_init__()
        nonce = self.operation_nonce
        require(type(nonce) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce) is not None)
        decoded = base64.urlsafe_b64decode(nonce + "=")
        require(
            len(decoded) == 32 and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() == nonce
        )
        _sha(self.authenticator_counter_baseline_hash)
        for value in (self.issued_at, self.not_before, self.expires_at):
            _version(value)
        require(
            self.issued_at
            <= self.not_before
            < self.expires_at
            <= self.issued_at + MAX_NONCE_SECONDS
        )
        require(type(self.schema) is str and self.schema == TRANSCRIPT_SCHEMA)


def _draft_object(draft):
    require(type(draft) is OperationDraft)
    draft.__post_init__()
    value = {name: getattr(draft, name) for name in OperationDraft.__dataclass_fields__}
    value["approver_person_ids"] = list(draft.approver_person_ids)
    return value


def serialize_draft(draft):
    return canonical_v2(_draft_object(draft), MAX_DRAFT_BYTES)


def parse_draft(raw):
    return _draft_from_object(parse_object(raw, MAX_DRAFT_BYTES))


def _draft_from_object(value):
    require(type(value) is dict and set(value) == set(OperationDraft.__dataclass_fields__))
    require(type(value["approver_person_ids"]) is list)
    value = dict(value)
    value["approver_person_ids"] = tuple(value["approver_person_ids"])
    return OperationDraft(**value)


def _transcript_object(transcript):
    require(type(transcript) is FullTranscript)
    transcript.__post_init__()
    value = {name: getattr(transcript, name) for name in FullTranscript.__dataclass_fields__}
    value["draft"] = _draft_object(transcript.draft)
    return value


def serialize_transcript(transcript):
    return canonical_v2(_transcript_object(transcript), MAX_TRANSCRIPT_BYTES)


def parse_transcript(raw):
    value = parse_object(raw, MAX_TRANSCRIPT_BYTES)
    require(set(value) == set(FullTranscript.__dataclass_fields__))
    value["draft"] = _draft_from_object(value["draft"])
    return FullTranscript(**value)


def draft_hash(draft):
    return hashlib.sha256(DRAFT_DOMAIN + serialize_draft(draft)).hexdigest()


def body_hash(transcript):
    return hashlib.sha256(BODY_DOMAIN + serialize_transcript(transcript)).hexdigest()


def confirmation_challenge(transcript, *, person_id, role, decision):
    """Format a WebAuthn challenge; no membership, signature or approval is checked."""
    _uuid(person_id)
    require(type(role) is str and role in ("requester", "reviewer", "sponsor"))
    allowed = {
        "requester": {"launch"},
        "reviewer": {"approve", "refuse"},
        "sponsor": {"sponsor", "refuse"},
    }
    require(type(decision) is str and decision in allowed[role])
    value = {
        "schema": "pamolive.vault.confirmation-challenge/2",
        "body_hash": body_hash(transcript),
        "person_id": person_id,
        "role": role,
        "decision": decision,
    }
    return hashlib.sha256(CONFIRMATION_DOMAIN + canonical_v2(value, 4096)).digest()
