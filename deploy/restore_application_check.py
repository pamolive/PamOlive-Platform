"""Offline backup/restore checks. No Web server, jobs, migration or remote connector starts."""

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

FORMAT = "pamolive-restore-manifest/1"
RESTORE_NAME = r"pamolive_restore_check_[a-f0-9]{16}"


def restore_url(original, database, role, password):
    if not re.fullmatch(RESTORE_NAME, database) or role != database + "_role":
        raise ValueError("Invalid isolated restoration scope.")
    parsed = urlsplit(original)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname or not password:
        raise ValueError("PostgreSQL restoration configuration is required.")
    if {key.lower() for key, _ in parse_qsl(parsed.query)} & {
        "dbname",
        "database",
        "service",
        "servicefile",
    }:
        raise ValueError("Database routing overrides are forbidden.")
    hostname = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    authority = quote(role, safe="") + ":" + quote(password, safe="") + "@" + hostname
    if parsed.port:
        authority += ":" + str(parsed.port)
    return urlunsplit(parsed._replace(netloc=authority, path="/" + database, fragment=""))


def database_guard(expected, *, restored):
    from django.db import connection

    if connection.vendor != "postgresql" or connection.settings_dict["NAME"] != expected:
        raise RuntimeError("Wrong database configuration.")
    if restored and not re.fullmatch(RESTORE_NAME, expected):
        raise RuntimeError("The verifier refuses an installation database.")
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_user, session_user")
        actual, role, session_role = cursor.fetchone()
        if actual != expected:
            raise RuntimeError("Wrong database destination.")
        if restored:
            if role != expected + "_role" or session_role != role:
                raise RuntimeError(
                    "A dedicated login role is required, not SET ROLE from an administrator."
                )
            cursor.execute(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
                "rolbypassrls, rolinherit "
                "FROM pg_roles WHERE rolname = current_user"
            )
            if any(cursor.fetchone()):
                raise RuntimeError("The restore verifier must not have administrative privileges.")
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member "
                "WHERE r.rolname=current_user)"
            )
            if cursor.fetchone()[0]:
                raise RuntimeError("The restore login must not inherit another role's privileges.")
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_database d, "
                "LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) acl "
                "WHERE d.datname=current_database() AND acl.grantee=0 "
                "AND acl.privilege_type='CONNECT')"
            )
            if cursor.fetchone()[0]:
                raise RuntimeError("PUBLIC must not connect to the restored copy.")


def model_fingerprints(*, legacy_labels=None, transaction_started=False):
    from django.apps import apps
    from django.core.serializers.json import DjangoJSONEncoder
    from django.db import connection, transaction
    from django.db.migrations.recorder import MigrationRecorder

    def encode(value):
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value)
            return {"binary_sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
        return DjangoJSONEncoder().default(value)

    models = set(apps.get_models(include_auto_created=True))
    models.add(MigrationRecorder.Migration)
    result = {}
    with nullcontext() if transaction_started else transaction.atomic():
        if connection.vendor == "postgresql" and not transaction_started:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                cursor.execute("SET LOCAL lock_timeout = '1s'")
                cursor.execute("SET LOCAL statement_timeout = '30s'")
        for model in sorted(models, key=lambda item: item._meta.label):
            label = model._meta.label
            if (
                not model._meta.managed
                or model._meta.proxy
                or (legacy_labels is not None and label not in legacy_labels)
            ):
                continue
            excluded = (
                {"release_hash"}
                if legacy_labels is not None and label == "platform_core.ModuleActivation"
                else set()
            )
            fields = [
                field.attname for field in model._meta.concrete_fields if field.name not in excluded
            ]
            digest, count = hashlib.sha256(), 0
            for row in model._base_manager.order_by("pk").values(*fields).iterator(chunk_size=200):
                digest.update(b"\0")
                digest.update(
                    json.dumps(row, default=encode, sort_keys=True, separators=(",", ":")).encode()
                )
                count += 1
            result[label] = {"count": count, "sha256": digest.hexdigest()}
    if legacy_labels is not None and set(result) != set(legacy_labels):
        raise RuntimeError("The historical preservation manifest has unknown models.")
    return result


def compare_manifest(expected):
    if expected.get("format") == FORMAT:
        fingerprints = model_fingerprints()
        complete = True
    elif expected.get("format") == "pamolive-preservation/1":
        # Explicit compatibility with the historical deployment fingerprints.
        # They exclude one newly added column and do not include implicit M2Ms.
        fingerprints = model_fingerprints(legacy_labels=expected["fingerprints"])
        complete = False
    else:
        raise RuntimeError("Unknown preservation manifest format.")
    if fingerprints != expected.get("fingerprints"):
        raise RuntimeError("Restored application data differ from the supplied manifest.")
    return {"models_compared": len(fingerprints), "full_managed_model_manifest": complete}


def key_probe(archive_sha256):
    from platform_core.security import cipher

    if not re.fullmatch(r"[a-f0-9]{64}", archive_sha256):
        raise ValueError("An archive SHA-256 is required.")
    payload = b"pamolive.restore-key.v1\0" + archive_sha256.encode() + secrets.token_bytes(32)
    return {
        "archive_sha256": archive_sha256,
        "ciphertext": cipher().encrypt(payload).decode(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def snapshot_session():
    """Keep one read-only exported snapshot alive until pg_dump imports it."""
    from django.db import connection, transaction

    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            cursor.execute("SET LOCAL statement_timeout = '30s'")
            cursor.execute("SET LOCAL lock_timeout = '1s'")
            cursor.execute("SET LOCAL idle_in_transaction_session_timeout = '5min'")
            cursor.execute("SELECT pg_export_snapshot()")
            snapshot = cursor.fetchone()[0]
        manifest = {"format": FORMAT, "fingerprints": model_fingerprints(transaction_started=True)}
        print(json.dumps({"snapshot": snapshot, "manifest": manifest}, sort_keys=True), flush=True)
        archive_hash = sys.stdin.buffer.readline(128).decode().strip()
        print(json.dumps(key_probe(archive_hash), sort_keys=True), flush=True)


def verify_application(*, expected_manifest=None, probe=None, archive_sha256=""):
    from django.db import DatabaseError, connection, transaction
    from django.db.migrations.executor import MigrationExecutor
    from django.utils.crypto import constant_time_compare

    from platform_core.audit import verify_chain
    from platform_core.events import delivery_signature, event_signature
    from platform_core.models import (
        AccountSecurity,
        AuditEvent,
        EventDelivery,
        ModuleEvent,
        Organization,
    )
    from platform_core.oidc.restoration import verify_evidence
    from platform_core.security import cipher
    from platform_modules.approvals.models import ApprovalDecision
    from platform_modules.connectors.models import ProvisioningConnector
    from platform_modules.connectors.teamviewer_restoration import (
        verify_evidence as verify_teamviewer,
    )
    from platform_modules.identity.bindings import binding_signature
    from platform_modules.identity.models import LoginIdentityBinding
    from platform_modules.pam.mandates import decision_signature
    from platform_modules.pam.models import RecordingChunk, RelayConnection, SessionEndpoint
    from platform_modules.pam.sessions import chunk_digest, recording_seal

    # Keep the write/rollback probe safe even if an operator imports this helper
    # directly rather than invoking the guarded CLI entry point.
    database_guard(str(connection.settings_dict["NAME"]), restored=True)
    executor = MigrationExecutor(connection)
    if executor.migration_plan(executor.loader.graph.leaf_nodes()):
        raise RuntimeError("The restored schema and application image do not match.")
    known = set(executor.loader.disk_migrations)
    for migration in executor.loader.disk_migrations.values():
        known.update(migration.replaces or ())
    if set(executor.loader.applied_migrations) - known:
        raise RuntimeError("The backup contains migrations absent from the supplied image.")
    if not all(verify_chain(org) for org in Organization.objects.all()):
        raise RuntimeError("Restored audit chain is invalid.")
    result = {
        "audit_valid": True,
        "pending_migrations": 0,
        "encrypted_values_checked": 0,
        "signed_proofs_checked": 0,
    }
    encrypted, signed = verify_evidence()
    result["encrypted_values_checked"] += encrypted
    result["signed_proofs_checked"] += signed
    encrypted, signed = verify_teamviewer()
    result["encrypted_values_checked"] += encrypted
    result["signed_proofs_checked"] += signed
    for model, field in (
        (AccountSecurity, "encrypted_secret"),
        (ProvisioningConnector, "encrypted_token"),
        (SessionEndpoint, "encrypted_secret"),
    ):
        for value in model._base_manager.values_list(field, flat=True).iterator(chunk_size=100):
            if value:
                cipher().decrypt(value.encode() if isinstance(value, str) else bytes(value))
                result["encrypted_values_checked"] += 1
    for model, sign in (
        (LoginIdentityBinding, binding_signature),
        (ApprovalDecision, decision_signature),
        (ModuleEvent, event_signature),
        (EventDelivery, delivery_signature),
    ):
        queryset = model._base_manager.all()
        if model in (LoginIdentityBinding, ApprovalDecision):
            # Historical pre-attestation requests remain readable, not executable.
            queryset = queryset.exclude(signature="")
        for item in queryset.iterator(chunk_size=100):
            if not constant_time_compare(item.signature, sign(item)):
                raise RuntimeError("Restored signed evidence cannot be verified.")
            result["signed_proofs_checked"] += 1
    result.update(sealed_captures_verified=0, unsealed_captures=0)
    for relay in RelayConnection.unscoped.iterator(chunk_size=100):
        previous, sequence, size, elapsed = "", 0, 0, 0
        for chunk in (
            RecordingChunk.unscoped.filter(connection=relay)
            .order_by("sequence")
            .iterator(chunk_size=100)
        ):
            encrypted = bytes(chunk.encrypted_payload)
            if (
                chunk.sequence != sequence + 1
                or chunk.previous_hash != previous
                or chunk.elapsed_ms < elapsed
                or not 0 < chunk.payload_size <= 65536
                or len(encrypted) > 100000
                or not constant_time_compare(
                    chunk.chunk_hash,
                    chunk_digest(
                        relay,
                        chunk.sequence,
                        previous,
                        chunk.elapsed_ms,
                        chunk.payload_size,
                        encrypted,
                    ),
                )
            ):
                raise RuntimeError("Restored capture chain is invalid.")
            if len(cipher().decrypt(encrypted)) != chunk.payload_size:
                raise RuntimeError("Restored capture size is invalid.")
            result["encrypted_values_checked"] += 1
            sequence, previous, elapsed = chunk.sequence, chunk.chunk_hash, chunk.elapsed_ms
            size += chunk.payload_size
        if (sequence, previous, size) != (
            relay.recording_chunks,
            relay.recording_hash,
            relay.recording_bytes,
        ):
            raise RuntimeError("Restored capture prefix has missing data.")
        if relay.ended_at:
            anchor = (
                AuditEvent.objects.filter(
                    organization_id=relay.organization_id,
                    action="pam.relay.ended.v1",
                    object_type="pam.relayconnection",
                    object_id=str(relay.pk),
                )
                .order_by("-sequence")
                .first()
            )
            if not anchor or not constant_time_compare(
                anchor.metadata.get("recording_seal", ""), recording_seal(relay)
            ):
                raise RuntimeError("Restored capture ending is not authenticated.")
            result["sealed_captures_verified"] += 1
        else:
            result["unsealed_captures"] += 1
    event_id = AuditEvent.objects.values_list("pk", flat=True).first()
    if event_id is None:
        raise RuntimeError("A nonempty audit is required to exercise its PostgreSQL guard.")
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE platform_core_auditevent SET summary=summary WHERE id=%s", [event_id]
                )
            transaction.set_rollback(True)
    except DatabaseError as error:
        if getattr(error.__cause__, "sqlstate", None) != "P0001":
            raise RuntimeError(
                "Audit probe failed for a reason other than its append-only guard."
            ) from None
    else:
        raise RuntimeError("The restored PostgreSQL audit guard did not reject modification.")
    result["postgresql_audit_guard"] = True
    if probe:
        payload = cipher().decrypt(probe["ciphertext"].encode())
        if (
            probe.get("archive_sha256") != archive_sha256
            or not payload.startswith(b"pamolive.restore-key.v1\0" + archive_sha256.encode())
            or not constant_time_compare(
                hashlib.sha256(payload).hexdigest(), probe["payload_sha256"]
            )
        ):
            raise RuntimeError("Archive-bound key companion does not match.")
        result["key_companion_verified"] = True
    if expected_manifest:
        result.update(compare_manifest(expected_manifest))
    else:
        result.update(models_compared=0, full_managed_model_manifest=False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("manifest", "snapshot-session", "key-probe", "connection", "verify")
    )
    parser.add_argument("--database", default="")
    parser.add_argument("--role", default="")
    parser.add_argument("--archive-sha256", default="")
    args = parser.parse_args()
    phase = "configuration"
    try:
        if args.action in ("verify", "connection"):
            os.environ["DATABASE_URL"] = restore_url(
                os.environ.get("DATABASE_URL", ""),
                args.database,
                args.role,
                os.environ.pop("PAMOLIVE_RESTORE_PASSWORD", ""),
            )
            os.environ["PGCONNECT_TIMEOUT"] = "5"
        # Also permits a single read-only script bind into an older matching image.
        if Path("/app/config/settings.py").is_file():
            sys.path.insert(0, "/app")
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        import django

        django.setup()
        if args.action == "key-probe":
            result = key_probe(args.archive_sha256)
        else:
            phase = "database scope"
            database_guard(args.database, restored=args.action in ("verify", "connection"))
            phase = "offline application verification"
            if args.action == "snapshot-session":
                snapshot_session()
                return
            if args.action == "connection":
                result = {"scope_verified": True}
            elif args.action == "manifest":
                result = {"format": FORMAT, "fingerprints": model_fingerprints()}
            else:
                content = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
                if len(content) > 8 * 1024 * 1024:
                    raise ValueError("Verification input is too large.")
                bundle = json.loads(content or b"{}")
                result = verify_application(
                    expected_manifest=bundle.get("manifest"),
                    probe=bundle.get("key_probe"),
                    archive_sha256=args.archive_sha256,
                )
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        print(json.dumps({"result": "failed", "phase": phase, "error": type(error).__name__}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
