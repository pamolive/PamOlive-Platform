"""Closed public projection of a completed synthetic restore; no cryptographic verifier."""

import json
import math
import os
import re
from pathlib import Path

TRUE_FIELDS = frozenset(
    {
        "audit_valid",
        "concurrent_source_write_isolated",
        "full_managed_model_manifest",
        "isolated_copy_removed",
        "key_companion_verified",
        "pam_live_trust_requires_independent_current_checkpoint",
        "postgresql_audit_guard",
        "source_archive_unchanged",
        "temporary_role_removed",
        "wrong_database_password_refused",
        "wrong_key_refused",
        "synthetic_source_removed",
    }
)
FALSE_FIELDS = frozenset({"production_database_replaced", "safe_to_serve"})
ZERO_FIELDS = frozenset({"pending_migrations", "permanent_containers_added", "unsealed_captures"})
COUNT_FIELDS = ZERO_FIELDS | frozenset(
    {
        "archive_bytes",
        "certificate_possession_proofs_checked",
        "encrypted_values_checked",
        "governance_exception_proofs_checked",
        "models_compared",
        "pam_trust_registries_verified",
        "provenance_receipts_checked",
        "sealed_captures_verified",
        "signed_proofs_checked",
        "legacy_events_checked",
        "legacy_v7_evaluations_checked",
        "pam_personal_authorizations_verified",
    }
)
DIRECTORY_FIELDS = frozenset({"encrypted_values", "facts", "mappings", "runs", "sources"})
ALL_FIELDS = (
    TRUE_FIELDS
    | FALSE_FIELDS
    | COUNT_FIELDS
    | frozenset(
        {
            "result",
            "application_image",
            "archive_sha256",
            "directory_evidence_checked",
            "seconds",
        }
    )
)
SHA256 = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)


def _count(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def public_restore_report(report):
    """Accept only closed facts after cleanup; upstream verifiers remain authoritative."""
    if type(report) is not dict or set(report) != ALL_FIELDS:
        raise ValueError("restore_public_report_fields")
    if type(report["result"]) is not str or report["result"] != "OK":
        raise ValueError("restore_public_report_result")
    if any(report[field] is not True for field in TRUE_FIELDS):
        raise ValueError("restore_public_report_positive_guard")
    if any(report[field] is not False for field in FALSE_FIELDS):
        raise ValueError("restore_public_report_scope")
    if any(not _count(report[field]) for field in COUNT_FIELDS):
        raise ValueError("restore_public_report_count")
    if any(report[field] != 0 for field in ZERO_FIELDS):
        raise ValueError("restore_public_report_zero_guard")
    seconds = report["seconds"]
    if type(seconds) not in {int, float} or not 0 <= seconds <= 86400 or not math.isfinite(seconds):
        raise ValueError("restore_public_report_seconds")
    digest, image = report["archive_sha256"], report["application_image"]
    if type(digest) is not str or not SHA256.fullmatch(digest):
        raise ValueError("restore_public_report_digest")
    if type(image) is not str or not image.startswith("sha256:") or not SHA256.fullmatch(image[7:]):
        raise ValueError("restore_public_report_image")
    directory = report["directory_evidence_checked"]
    if (
        type(directory) is not dict
        or set(directory) != DIRECTORY_FIELDS
        or any(not _count(v) for v in directory.values())
    ):
        raise ValueError("restore_public_report_directory")
    # Copy the closed nested projection; never stringify arbitrary errors/objects.
    return dict(
        report,
        directory_evidence_checked=dict(directory),
        schema="pamolive.synthetic-restore-report/1",
        qualification_scope="synthetic_restore_only",
    )


def write_public_restore_report(report, path):
    """Exclusive file, no directory creation/overwrite or private-artifact traversal."""
    data = (
        json.dumps(public_restore_report(report), sort_keys=True, allow_nan=False) + "\n"
    ).encode()
    if len(data) > 16384:
        raise ValueError("restore_public_report_budget")
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
