"""Closed reception bindings. Shape checks alone never establish provenance.

The native caller must obtain verifier output from its own bounded, pinned gh
invocation. No JSON file or a producer-supplied verified flag is an authority.
"""

import hashlib
import json
import re
from datetime import datetime, timedelta

SCHEMA = "pamolive.build-dossier-reception/3"
PREDICATE = "https://pamolive.org/attestations/build-dossier-reception/v3"
ARTIFACT_MAX = 2 * 1024**3
TOTAL_MAX = 4 * 1024**3
SUBJECT = "build-dossier-index.json"
VERIFIER_MEDIA = "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
FALSE_CLAIM_NAMES = (
    "build_verified",
    "materials_complete",
    "qualification_verified",
    "compiler_execution_proved",
)
PRODUCER_FIELDS = {
    "repository",
    "repository_id",
    "owner_id",
    "commit",
    "tree",
    "ref",
    "event",
    "workflow_path",
    "workflow_sha256",
    "workflow_id",
    "run_id",
    "attempt",
    "conclusion",
}
RECEIVER_FIELDS = {
    "repository",
    "repository_id",
    "owner_id",
    "commit",
    "ref",
    "event",
    "workflow_id",
    "run_id",
    "attempt",
    "caller_workflow",
    "signer_workflow",
    "signer_commit",
}
ID_FIELDS = {"repository_id", "owner_id", "workflow_id", "run_id", "attempt"}


def need(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def false_claims():
    return dict.fromkeys(FALSE_CLAIM_NAMES, False)


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def load(raw, maximum=1048576, *, members=128, nodes=10000):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, "origin_json_budget")

    def pairs(rows):
        result = {}
        for key, item in rows:
            need(key not in result, "origin_json_duplicate")
            result[key] = item
        return result

    def constant(_):
        raise ValueError("origin_json_constant")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    count = 0

    def visit(item, depth=0):
        nonlocal count
        count += 1
        need(depth <= 32 and count <= nodes, "origin_json_shape_budget")
        if type(item) is dict:
            need(len(item) <= members, "origin_json_members")
            for key, member in item.items():
                need(type(key) is str and len(key) <= 256, "origin_json_key")
                visit(member, depth + 1)
        elif type(item) is list:
            need(len(item) <= members, "origin_json_members")
            for member in item:
                visit(member, depth + 1)
        elif type(item) is str:
            need(len(item) <= 262144, "origin_json_string")
        else:
            need(type(item) in (int, bool, type(None)), "origin_json_scalar")

    visit(value)
    return value


def identity(row, fields):
    need(type(row) is dict and set(row) == fields, "origin_identity_fields")
    for key, value in row.items():
        if key in ID_FIELDS:
            need(type(value) is int and 0 < value < 2**63, "origin_numeric_identity")
        else:
            need(type(value) is str and 0 < len(value) <= 512, "origin_identity_value")
    need(row["repository"] == "pamolive/PamOlive-Platform", "origin_repository")
    for key in ("commit", "tree", "signer_commit"):
        if key in row:
            need(re.fullmatch("[0-9a-f]{40}", row[key]), "origin_git_identity")
    if "workflow_sha256" in row:
        need(re.fullmatch("[0-9a-f]{64}", row["workflow_sha256"]), "origin_workflow_bytes")
    for key in ("workflow_path", "caller_workflow", "signer_workflow"):
        if key in row:
            need(
                re.fullmatch(r"\.github/workflows/[a-z0-9-]+\.yml", row[key]),
                "origin_workflow_path",
            )
    need(re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9/_-]{0,160}", row["ref"]), "origin_ref")


def check_index(
    raw,
    *,
    expected_producer,
    expected_receiver,
    expected_artifacts,
    policy_sha256,
    egress_profile_sha256,
):
    """Expectations come from the reviewed external policy/authenticated API."""
    identity(expected_producer, PRODUCER_FIELDS)
    identity(expected_receiver, RECEIVER_FIELDS)
    need(
        all(
            expected_producer[key] == expected_receiver[key]
            for key in ("repository", "repository_id", "owner_id")
        ),
        "origin_single_repository_authority",
    )
    need(expected_producer["event"] == "push", "origin_producer_event")
    need(expected_receiver["event"] == "workflow_dispatch", "origin_receiver_event")
    need(expected_producer["conclusion"] in {"success", "failure"}, "origin_producer_terminal")
    need(re.fullmatch("[0-9a-f]{64}", policy_sha256), "origin_policy_hash")
    need(
        type(egress_profile_sha256) is str and re.fullmatch("[0-9a-f]{64}", egress_profile_sha256),
        "origin_egress_profile_required",
    )
    need(
        type(expected_artifacts) is list and 1 <= len(expected_artifacts) <= 8,
        "origin_artifact_count",
    )
    seen = set()
    total = 0
    for row in expected_artifacts:
        need(
            type(row) is dict and set(row) == {"id", "name", "sha256", "bytes"},
            "origin_artifact_fields",
        )
        need(
            type(row["id"]) is int and 0 < row["id"] < 2**63 and row["id"] not in seen,
            "origin_artifact_id",
        )
        need(type(row["bytes"]) is int and 0 < row["bytes"] <= ARTIFACT_MAX, "origin_artifact_size")
        need(
            type(row["name"]) is str and re.fullmatch("[A-Za-z0-9._-]{1,160}", row["name"]),
            "origin_artifact_name",
        )
        need(
            type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
            "origin_artifact_digest",
        )
        seen.add(row["id"])
        total += row["bytes"]
    need(total <= TOTAL_MAX, "origin_artifact_total")
    expected = {
        "schema": SCHEMA,
        "producer": expected_producer,
        "receiver": expected_receiver,
        "artifacts": expected_artifacts,
        "reception_request_sha256": policy_sha256,
        "egress_profile_sha256": egress_profile_sha256,
        "claims": false_claims(),
    }
    value = load(raw)
    need(value == expected and raw == canonical(expected), "origin_index_binding")
    # JSON equality alone accepts bool/int aliases; compare canonical typed bytes too.
    return value


def expected_predicate(index, index_sha256):
    return {
        "schema": SCHEMA,
        "index_sha256": index_sha256,
        "reception_request_sha256": index["reception_request_sha256"],
        "egress_profile_sha256": index["egress_profile_sha256"],
        "producer_run_id": index["producer"]["run_id"],
        "producer_attempt": index["producer"]["attempt"],
        "receiver_run_id": index["receiver"]["run_id"],
        "receiver_attempt": index["receiver"]["attempt"],
        "scope": "authenticated-reception-only",
        "claims": false_claims(),
    }


def _check_native_verified_output(raw, index_raw, index):
    """Private postcondition of the native invocation, never a file-input CLI."""
    rows = load(raw, 8 * 1024**2)
    need(type(rows) is list and len(rows) == 1, "origin_verified_result_count")
    entry = rows[0]
    need(
        type(entry) is dict and set(entry) == {"attestation", "verificationResult"},
        "origin_verified_result_fields",
    )
    result = entry["verificationResult"]
    need(
        type(result) is dict
        and set(result)
        <= {"mediaType", "statement", "signature", "verifiedTimestamps", "verifiedIdentity"}
        and result.get("mediaType") == VERIFIER_MEDIA,
        "origin_verified_result_schema",
    )
    signature = result.get("signature")
    need(
        type(signature) is dict and set(signature) == {"certificate"},
        "origin_keyless_certificate_required",
    )
    cert = signature["certificate"]
    need(type(cert) is dict, "origin_certificate")
    receiver = index["receiver"]
    repository = receiver["repository"]
    owner = repository.split("/")[0]
    signer_uri = (
        f"https://github.com/{repository}/{receiver['signer_workflow']}@{receiver['signer_commit']}"
    )
    expected = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": signer_uri,
        "buildSignerURI": signer_uri,
        "buildSignerDigest": receiver["signer_commit"],
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": "https://github.com/" + repository,
        "sourceRepositoryIdentifier": str(receiver["repository_id"]),
        "sourceRepositoryOwnerURI": "https://github.com/" + owner,
        "sourceRepositoryOwnerIdentifier": str(receiver["owner_id"]),
        "sourceRepositoryDigest": receiver["commit"],
        "sourceRepositoryRef": receiver["ref"],
        "buildConfigURI": f"https://github.com/{repository}/{receiver['caller_workflow']}@{receiver['ref']}",
        "buildConfigDigest": receiver["commit"],
        "buildTrigger": receiver["event"],
        "runInvocationURI": f"https://github.com/{repository}/actions/runs/{receiver['run_id']}/attempts/{receiver['attempt']}",
        "sourceRepositoryVisibilityAtSigning": "public",
    }
    need(
        all(type(cert.get(key)) is str and cert[key] == value for key, value in expected.items()),
        "origin_certificate_binding",
    )
    times = result.get("verifiedTimestamps")
    need(type(times) is list and 1 <= len(times) <= 16, "origin_observed_time_required")
    tlog = False
    for row in times:
        need(
            type(row) is dict and set(row) == {"type", "uri", "timestamp"},
            "origin_observed_time_fields",
        )
        need(row["type"] in {"Tlog", "TimestampAuthority"}, "origin_observed_time_kind")
        need(type(row["uri"]) is str and 0 < len(row["uri"]) <= 2048, "origin_observed_time_uri")
        need(
            type(row["timestamp"]) is str and len(row["timestamp"]) <= 64,
            "origin_observed_time_format",
        )
        parsed = datetime.fromisoformat(row["timestamp"])
        need(
            parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0),
            "origin_observed_time_UTC",
        )
        tlog |= row["type"] == "Tlog"
    need(tlog, "origin_public_transparency_required")
    statement = result.get("statement")
    need(
        type(statement) is dict
        and set(statement) == {"_type", "subject", "predicateType", "predicate"},
        "origin_statement_fields",
    )
    need(
        statement["_type"] == "https://in-toto.io/Statement/v1"
        and statement["predicateType"] == PREDICATE,
        "origin_statement_type",
    )
    need(
        statement["subject"] == [{"name": SUBJECT, "digest": {"sha256": digest(index_raw)}}],
        "origin_subject_binding",
    )
    expected_body = expected_predicate(index, digest(index_raw))
    need(canonical(statement["predicate"]) == canonical(expected_body), "origin_predicate_binding")
    return {
        "signature_policy_postconditions_checked": True,
        "index_sha256": digest(index_raw),
        "receiver_run_id": receiver["run_id"],
        "receiver_attempt": receiver["attempt"],
        "scope": "authenticated-reception-only",
        "claims": false_claims(),
        "standalone_shape_check_is_not_cryptographic_verification": True,
    }
