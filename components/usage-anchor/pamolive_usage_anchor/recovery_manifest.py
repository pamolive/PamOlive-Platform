"""Custodian-signed admission and rotation of exact v1 audit checkpoints."""

from dataclasses import asdict, dataclass

from . import codec
from .signed_anchor import _pinned_key, _verify_signature, verify_checkpoint

SCHEMA = "pamolive.vault.usage-recovery-manifest/1"
DOMAIN = b"pamolive.vault.usage-recovery-manifest.v1\0"
GENESIS = "0" * 64
MAX_BYTES = 24 * 1024
MAX_KEYS = 16
MAX_ADMISSIONS = 128
PROFILE = {"depth": 5, "nodes": 1200, "string": 86}


@dataclass(frozen=True, slots=True)
class RecoveryScope:
    organization_id: str
    installation_id: str
    context_id: str
    slot_sha256: str

    def __post_init__(self):
        codec.uuid(self.organization_id)
        codec.uuid(self.installation_id)
        codec.uuid(self.context_id)
        codec.digest(self.slot_sha256)

    @classmethod
    def from_checkpoint(cls, point):
        return cls(
            point.organization_id, point.installation_id, point.context_id, point.slot_sha256
        )


def _authorized(condition):
    codec.need(condition, "anchor_refused", 403)


def _content(body, governance_key, scope):
    codec.closed(body, {"schema", "scope", "revision", "previous_sha256", "keys", "admissions"})
    codec.need(body["schema"] == SCHEMA and type(scope) is RecoveryScope)
    _authorized(body["scope"] == asdict(scope))
    revision = codec.integer(body["revision"])
    previous = codec.digest(body["previous_sha256"])
    codec.need((revision == 1) == (previous == GENESIS))

    keys = body["keys"]
    codec.need(type(keys) is list and 1 <= len(keys) <= min(MAX_KEYS, revision))
    public_keys = [codec.unb64(key, 32) for key in keys]
    codec.need(all(len(key) == 32 for key in public_keys))
    _authorized(governance_key not in public_keys and len(set(public_keys)) == len(public_keys))

    entries = body["admissions"]
    codec.need(type(entries) is list and 1 <= len(entries) <= MAX_ADMISSIONS)
    admissions = {}
    for entry in entries:
        codec.closed(entry, {"checkpoint_sha256", "generation"})
        digest = codec.digest(entry["checkpoint_sha256"])
        codec.need(digest not in admissions)
        admissions[digest] = codec.integer(entry["generation"], 1, len(public_keys))
    codec.need(list(admissions) == sorted(admissions))
    return public_keys, admissions


def sign_manifest(body, *, governance_key, scope, sign):
    """Encode and validate an externally issued signature. This does not admit a revision."""
    codec.need(callable(sign))
    key = _pinned_key(governance_key)
    canonical = codec.encode(body, MAX_BYTES, **PROFILE)
    snapshot = codec.parse(canonical, MAX_BYTES, **PROFILE)
    _content(snapshot, governance_key, scope)
    message = DOMAIN + canonical
    signature = sign(message)
    _verify_signature(key, signature, message)
    return codec.encode({"body": snapshot, "signature": codec.b64(signature)}, MAX_BYTES, **PROFILE)


def _read(raw, governance_key, scope):
    key = _pinned_key(governance_key)
    envelope = codec.parse(raw, MAX_BYTES, **PROFILE)
    codec.closed(envelope, {"body", "signature"})
    body = envelope["body"]
    signature = codec.unb64(envelope["signature"], 64)
    _verify_signature(key, signature, DOMAIN + codec.encode(body, MAX_BYTES, **PROFILE))
    keys, admissions = _content(body, governance_key, scope)
    return body, keys, admissions


def _read_current(raw, current_sha256, governance_key, scope):
    codec.need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    _authorized(codec.sha(raw) == codec.digest(current_sha256))
    return _read(raw, governance_key, scope)


def _verify_point(checkpoint, digest, key, scope):
    point = verify_checkpoint(checkpoint, public_key=key, expected_sha256=digest)
    _authorized(RecoveryScope.from_checkpoint(point) == scope)
    return point


def _verify_admissions(checkpoints, admissions, keys, scope):
    _authorized(type(checkpoints) is dict and checkpoints.keys() == admissions.keys())
    for digest, generation in admissions.items():
        _verify_point(checkpoints[digest], digest, keys[generation - 1], scope)


def verify_initial_manifest(raw, *, checkpoints, governance_key, scope):
    """Verify revision one during independent commissioning. Return its pin."""
    body, keys, admissions = _read(raw, governance_key, scope)
    _authorized(body["revision"] == 1)
    _verify_admissions(checkpoints, admissions, keys, scope)
    return codec.sha(raw)


def verify_manifest_successor(
    current, proposed, *, current_sha256, checkpoints, governance_key, scope,
):
    """Verify a forward transition before the custodian updates its separate current pin."""
    before, old_keys, old_admissions = _read_current(current, current_sha256, governance_key, scope)
    after, new_keys, new_admissions = _read(proposed, governance_key, scope)
    _authorized(after["revision"] == before["revision"] + 1)
    _authorized(after["previous_sha256"] == current_sha256)
    _authorized(new_keys[: len(old_keys)] == old_keys and len(new_keys) <= len(old_keys) + 1)
    _authorized(old_admissions.items() <= new_admissions.items())
    additions = new_admissions.keys() - old_admissions.keys()
    _authorized(bool(additions))
    _authorized(all(new_admissions[digest] == len(new_keys) for digest in additions))
    _verify_admissions(checkpoints, dict.fromkeys(additions, len(new_keys)), new_keys, scope)
    return codec.sha(proposed)


def restore_checkpoint(
    manifest, checkpoint, *, current_sha256, checkpoint_sha256, governance_key, scope,
):
    """Verify the selected historical checkpoint under the independently pinned current manifest."""
    _, keys, admissions = _read_current(manifest, current_sha256, governance_key, scope)
    generation = admissions.get(codec.digest(checkpoint_sha256))
    _authorized(generation is not None)
    return _verify_point(checkpoint, checkpoint_sha256, keys[generation - 1], scope)
