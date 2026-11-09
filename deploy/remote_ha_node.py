"""Private read-only probe executed as the application user in an existing node."""

import hashlib
import hmac
import json
import os
import re
import signal
import sys

POLICY = (
    "ALLOWED_HOSTS",
    "CONNECTOR_ALLOWED_HOSTS",
    "CONNECTOR_ALLOWED_NETWORKS",
    "CSRF_COOKIE_NAME",
    "CSRF_COOKIE_SECURE",
    "CSRF_TRUSTED_ORIGINS",
    "OIDC_ALLOWED_HOSTS",
    "OIDC_ALLOWED_NETWORKS",
    "OIDC_PUBLIC_ORIGIN",
    "PAM_ALLOWED_HOSTS",
    "PAM_ALLOWED_NETWORKS",
    "PAM_NETWORK_CONTEXT",
    "PAM_PUBLIC_ORIGIN",
    "PAM_TRUSTED_PROXY_NETWORKS",
    "SECURE_PROXY_SSL_HEADER",
    "SECURE_SSL_REDIRECT",
    "SESSION_COOKIE_NAME",
    "SESSION_COOKIE_SECURE",
    "SESSION_ENGINE",
    "TIME_ZONE",
)
FORMAT = "pamolive.remote-ha/1"


def canonical(value):
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    raise TypeError("Unsupported readiness setting.")


def transcript(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=canonical).encode()


def proof(secret, nonce, label):
    return hmac.new(
        secret.encode(), FORMAT.encode() + b"\x00" + label + nonce, hashlib.sha256
    ).hexdigest()


def lock_key(nonce):
    return int.from_bytes(hashlib.sha256(FORMAT.encode() + nonce).digest()[:8], "big", signed=True)


def readiness(nonce):
    from django.conf import settings
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    from platform_core.extensions.manifest import CORE_VERSION

    instance = os.environ.get("PAMOLIVE_INSTANCE_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", instance):
        raise RuntimeError("An explicit instance identifier is required.")
    if settings.DEBUG or settings.SESSION_ENGINE != "django.contrib.sessions.backends.db":
        raise RuntimeError("Unsupported debug mode or non-shared session backend.")
    for name in ("SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY"):
        key = os.environ.get(name, "")
        if len(key) < 32 or key != getattr(settings, name):
            raise RuntimeError("Explicit strong application keys are required.")
    if connection.vendor != "postgresql" or not connection.get_autocommit():
        raise RuntimeError("A PostgreSQL application connection is required.")
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT current_setting('server_version_num')::integer,
                   pg_is_in_recovery(),
                   current_setting('transaction_read_only') = 'on',
                   NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
                        OR r.rolreplication OR r.rolbypassrls),
                   NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid)
              FROM pg_roles r WHERE r.rolname = current_user
            """
        )
        version, recovery, read_only, restricted, independent = cursor.fetchone()
    if version < 160000 or recovery or read_only or not (restricted and independent):
        raise RuntimeError(
            "PostgreSQL must be a writable primary with a dedicated restricted role."
        )
    loader = MigrationExecutor(connection)
    if loader.migration_plan(loader.loader.graph.leaf_nodes()):
        raise RuntimeError("Pending migrations; do not qualify mixed schema versions.")
    policy = {key: getattr(settings, key) for key in POLICY}
    policy["extensions"] = [release.manifest.to_dict() for release in settings.PAMOLIVE_EXTENSIONS]
    return {
        "schema": FORMAT,
        "core_version": CORE_VERSION,
        "pg_version": version,
        "instance": proof(instance, nonce, b"instance"),
        "session_key": proof(settings.SECRET_KEY, nonce, b"session"),
        "encryption_key": proof(settings.PAMOLIVE_ENCRYPTION_KEY, nonce, b"encryption"),
        "policy": hmac.new(nonce, transcript(policy), hashlib.sha256).hexdigest(),
        "https_origin": settings.PAM_PUBLIC_ORIGIN.startswith("https://"),
    }


def exchange(connection, operation, nonce, *, read, emit):
    """Hold only a random transaction-level lock, never a business table or object."""
    from django.db import transaction

    if operation not in {"hold", "probe"}:
        raise RuntimeError("Unexpected qualification operation.")
    key = lock_key(nonce)
    snapshot = readiness(nonce)
    with transaction.atomic(using=connection.alias), connection.cursor() as cursor:
        cursor.execute("SET TRANSACTION READ ONLY")
        cursor.execute("SELECT pg_try_advisory_xact_lock(%s::bigint)", [key])
        locked = cursor.fetchone()[0] is True
        if operation == "hold":
            emit(dict(snapshot, locked=locked))
            if not locked or read().strip() != "release":
                raise RuntimeError("The controller did not confirm release.")
    if operation == "hold":
        emit({"released": True})
    else:
        emit(dict(snapshot, locked=locked))


def main():
    import django
    from django.db import connection

    def deadline(_signum, _frame):
        raise TimeoutError("Qualification deadline.")

    try:
        request = json.loads(sys.stdin.readline(256))
        if set(request) != {"operation", "nonce"} or not re.fullmatch(
            r"[a-f0-9]{64}", request["nonce"]
        ):
            raise RuntimeError("Invalid qualification challenge.")
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(45)
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        django.setup()
        exchange(
            connection,
            request["operation"],
            bytes.fromhex(request["nonce"]),
            read=lambda: sys.stdin.readline(32),
            emit=lambda value: print(json.dumps(value), flush=True),
        )
    except Exception:
        print('{"error":"node_not_ready"}', flush=True)
        raise SystemExit(1) from None
    finally:
        signal.alarm(0)
        connection.close()


if __name__ == "__main__":
    main()
