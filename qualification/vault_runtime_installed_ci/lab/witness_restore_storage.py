"""Restore sealed W01 SQL data into a fresh database in the owned W cluster."""

import re

from lab.restore_sql import check_result, local_argv, need
from lab.witness_postgres import restore_database

MAX_ARCHIVE = 1024 * 1024
OWNER = "usage_anchor_owner"
OBSERVER = "usage_anchor_observer"
TABLES = (
    "activation_challenges",
    "activations",
    "audit_events",
    "audit_heads",
    "contexts",
    "leases",
    "operations",
    "proof_uses",
    "quotas",
)
LOCAL = (
    "/bin/sh", "-ec", 'test "$(cat /proc/1/comm)" = postgres; exec "$@"',
    "witness-storage", "env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
    "PGCONNECT_TIMEOUT=3", "PGOPTIONS=-c statement_timeout=5s -c lock_timeout=2s",
)
PSQL = (
    "psql", "-X", "-w", "-qAt", "-v", "ON_ERROR_STOP=1", "-h",
    "/var/run/postgresql", "-p", "5432", "-U", "postgres",
)
SNAPSHOT = r"""
SELECT 'W01_STATE_SEALED' WHERE
 (SELECT count(*) FROM pam_usage_anchor.contexts WHERE serving_state='closed')=1
 AND (SELECT count(*) FROM pam_usage_anchor.contexts)=1
 AND (SELECT count(*) FROM pam_usage_anchor.leases
      WHERE serving_state='closed' AND epoch>1)=1
 AND (SELECT count(*) FROM pam_usage_anchor.leases)=1
 AND EXISTS(SELECT FROM pam_usage_anchor.operations
            WHERE state IN ('consumed_no_release','refused_no_release'))
 AND EXISTS(SELECT FROM pam_usage_anchor.audit_events);
WITH ns AS (
 SELECT oid, nspname, nspowner, nspacl FROM pg_namespace WHERE nspname='pam_usage_anchor'
), acl AS (
 SELECT 'schema' AS kind, nspname::text AS name, nspowner AS owner,
        coalesce(nspacl, acldefault('n', nspowner)) AS entries FROM ns
 UNION ALL
 SELECT 'table', relname::text, relowner, coalesce(relacl, acldefault('r', relowner))
 FROM pg_class JOIN ns ON relnamespace=ns.oid WHERE relkind='r'
 UNION ALL
 SELECT 'column', relname || '.' || attname, relowner, attacl
 FROM pg_attribute JOIN pg_class ON attrelid=pg_class.oid JOIN ns ON relnamespace=ns.oid
 WHERE relkind='r' AND attnum>0 AND NOT attisdropped AND attacl IS NOT NULL
 UNION ALL
 SELECT 'function', pg_proc.oid::regprocedure::text, proowner,
        coalesce(proacl, acldefault('f', proowner))
 FROM pg_proc JOIN ns ON pronamespace=ns.oid
 UNION ALL
 SELECT 'default', defaclobjtype::text, defaclrole, defaclacl
 FROM pg_default_acl JOIN ns ON defaclnamespace=ns.oid
)
SELECT encode(sha256(convert_to(string_agg(
 jsonb_build_array(kind,name,owner,entry::text)::text, E'\n'
 ORDER BY kind COLLATE "C",name COLLATE "C",owner,entry::text COLLATE "C"), 'UTF8')), 'hex')
FROM acl LEFT JOIN LATERAL unnest(entries) AS grant_entry(entry) ON true;
"""


class WitnessStorageRefused(ValueError):
    """Expose only the fixed phase, never SQL, row digests or tool output."""

    def __init__(self, phase):
        super().__init__("witness_storage_refused")
        self.phase = phase


def context(database):
    return (
        f"current_database()='{database}' AND session_user='postgres' "
        "AND current_user='postgres' AND inet_server_addr() IS NULL "
        "AND NOT pg_is_in_recovery() AND current_setting('port')='5432' "
        "AND current_setting('server_version_num')='170012' "
        "AND current_setting('data_directory')='/var/lib/postgresql/data' "
        "AND current_setting('hba_file')='/lab/pg_hba.conf'"
    )


def source_guard(original, restored):
    return f"""
SELECT 'W01_TARGET_ABSENT' WHERE
 (SELECT array_agg(datname::text ORDER BY datname::text COLLATE "C") FROM pg_database)
    =ARRAY['postgres','template0','template1','{original}']
 AND EXISTS(SELECT FROM pg_database WHERE datname='{original}'
            AND datdba='{OWNER}'::regrole AND datallowconn AND NOT datistemplate)
 AND NOT EXISTS(SELECT FROM pg_database WHERE datname='{restored}');
"""


def create_target(original, restored):
    # The database cannot accept clients until its restrictive CONNECT ACL exists.
    return rf"""
SELECT (({context("postgres")}) AND EXISTS(
 SELECT FROM pg_database WHERE datname='{original}' AND datdba='{OWNER}'::regrole
 ) AND NOT EXISTS(SELECT FROM pg_database WHERE datname='{restored}')) IS TRUE
 AS w01_can_create \gset
\if :w01_can_create
CREATE DATABASE "{restored}" OWNER {OWNER} TEMPLATE template0 ALLOW_CONNECTIONS false;
REVOKE ALL ON DATABASE "{restored}" FROM PUBLIC;
GRANT CONNECT ON DATABASE "{restored}" TO {OBSERVER};
ALTER DATABASE "{restored}" ALLOW_CONNECTIONS true;
\connect {restored} postgres /var/run/postgresql 5432
SELECT ({context(restored)}) IS TRUE AS w01_new_target \gset
\if :w01_new_target
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT 'W01_TARGET_FRESH' WHERE
 (SELECT array_agg(nspname::text ORDER BY nspname::text COLLATE "C") FROM pg_namespace)
   =ARRAY['information_schema','pg_catalog','pg_toast','public']
 AND NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace)
 AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace)
 AND NOT EXISTS(SELECT FROM pg_type WHERE typnamespace='public'::regnamespace);
\endif
\endif
"""


def observer_grants(restored):
    return f"""
SELECT 'W01_TARGET_READ_ONLY' WHERE EXISTS(
 SELECT FROM pg_database WHERE datname='{restored}' AND datdba='{OWNER}'::regrole
   AND datallowconn AND NOT datistemplate
   AND NOT EXISTS(SELECT FROM aclexplode(datacl) WHERE grantee=0)
) AND EXISTS(
 SELECT FROM pg_roles WHERE rolname='{OBSERVER}' AND rolcanlogin
   AND NOT (rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb
            OR rolreplication OR rolbypassrls)
   AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid)
) AND has_database_privilege('{OBSERVER}', current_database(), 'CONNECT')
 AND NOT has_database_privilege('{OBSERVER}', current_database(),
                               'CREATE,TEMPORARY,CONNECT WITH GRANT OPTION')
 AND NOT EXISTS(
 SELECT FROM pg_roles WHERE rolcanlogin AND rolname NOT IN ('postgres','{OBSERVER}')
   AND has_database_privilege(oid, current_database(), 'CONNECT')
) AND has_schema_privilege('{OBSERVER}', 'pam_usage_anchor', 'USAGE')
 AND NOT has_schema_privilege('{OBSERVER}', 'pam_usage_anchor', 'CREATE,USAGE WITH GRANT OPTION')
 AND NOT has_schema_privilege('{OBSERVER}', 'public', 'USAGE,CREATE')
 AND NOT EXISTS(
 SELECT FROM pg_class WHERE relnamespace='pam_usage_anchor'::regnamespace AND relkind='r'
   AND (NOT has_table_privilege('{OBSERVER}', oid, 'SELECT')
        OR has_table_privilege('{OBSERVER}', oid,
          'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN,SELECT WITH GRANT OPTION')
        OR has_any_column_privilege('{OBSERVER}', oid,
          'INSERT,UPDATE,REFERENCES,SELECT WITH GRANT OPTION'))
) AND NOT EXISTS(
 SELECT FROM pg_proc WHERE pronamespace='pam_usage_anchor'::regnamespace
   AND has_function_privilege('{OBSERVER}', oid, 'EXECUTE')
);
"""


def snapshot_sql():
    statements = [SNAPSHOT]
    for table in TABLES:
        statements.append(rf"""
SELECT encode(sha256(convert_to(coalesce(string_agg(row_json, E'\n'
 ORDER BY row_json COLLATE "C"), ''), 'UTF8')), 'hex')
FROM (
 SELECT to_jsonb(r)::text AS row_json FROM pam_usage_anchor.{table} AS r LIMIT 65
) AS bounded_rows
HAVING count(*)<=64;
""")
    return "".join(statements)


def restore_witness_storage(lab, item, spec, run_id):
    """Use only bounded bytes from one sealed source and the lab's local peer socket."""
    phase = "inputs"
    try:
        restored = restore_database(run_id)
        original = f"w01_{run_id}_wpg"
        need(restored == original + "_restored")
        need(re.fullmatch(r"pv-[0-9a-f]{32}", lab.reservation))
        need(run_id == lab.reservation[3:19])
        need(spec.role == "w-postgres" and spec.user == "999:999")
        need(spec.command == ("postgres", "-c", "config_file=/lab/postgresql.conf"))
        need(item["name"] == lab.reservation + "-w-postgres" and not item.get("removed"))
        need(re.fullmatch(r"[0-9a-f]{64}", item["identity"]))

        def execute(argv, *, data=None, cap=8192):
            # Lab.exec re-checks the exact owned, running CID and Docker profile.
            result = lab.exec(
                item, spec, *LOCAL, *argv, data=data, timeout=9, stdout_cap=cap,
                stdin_cap=MAX_ARCHIVE,
            )
            check_result(result, cap)
            need(result.stderr == b"")
            return result.stdout

        def sql(database, body, *, read_only=True):
            target = (*PSQL, "-d", database, "-f", "-")
            if read_only:
                body = (
                    "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
                    f"SET LOCAL search_path=pg_catalog;\n"
                    f"SELECT ({context(database)}) IS TRUE AS w01_storage_session \\gset\n"
                    "\\if :w01_storage_session\n" + body + "\\endif\nCOMMIT;\n"
                )
            return execute(target, data=body.encode("ascii"))

        def snapshot(database):
            output = sql(database, snapshot_sql())
            need(output.endswith(b"\n"))
            lines = output.splitlines()
            need(len(lines) == len(TABLES) + 2 and lines[0] == b"W01_STATE_SEALED")
            need(all(re.fullmatch(rb"[0-9a-f]{64}", value) for value in lines[1:]))
            return output

        phase = "source"
        need(sql("postgres", source_guard(original, restored)) == b"W01_TARGET_ABSENT\n")
        before = snapshot(original)

        phase = "archive"
        archive = execute(local_argv([
            "pg_dump", "-U", "postgres", "-d", original, "--format=custom",
            "--schema=pam_usage_anchor", "--strict-names", "--no-owner", "--no-comments",
            "--no-security-labels", "--no-tablespaces", "--no-publications",
            "--no-subscriptions", "--lock-wait-timeout=2s",
        ]), cap=MAX_ARCHIVE)
        need(archive.startswith(b"PGDMP") and len(archive) > 5)
        table_list = execute(("pg_restore", "--list"), data=archive, cap=32768)
        names = re.findall(rb"(?m)^\d+; \d+ \d+ TABLE DATA pam_usage_anchor (\w+) "
                           rb"usage_anchor_owner$", table_list)
        need(sorted(names) == [name.encode("ascii") for name in TABLES])
        need(table_list.count(b" TABLE DATA ") == len(TABLES))

        phase = "create"
        fresh = sql("postgres", create_target(original, restored), read_only=False)
        need(fresh == b"W01_TARGET_FRESH\n")

        phase = "restore"
        need(execute(local_argv([
            "pg_restore", "-U", "postgres", "--dbname=" + restored,
            "--role=" + OWNER, "--exit-on-error", "--single-transaction", "--no-owner",
            "--no-comments", "--no-security-labels", "--no-tablespaces",
        ]), data=archive) == b"")

        phase = "verify"
        need(snapshot(restored) == before and snapshot(original) == before)
        need(sql(restored, observer_grants(restored)) == b"W01_TARGET_READ_ONLY\n")
        return {
            "archive_verified": True,
            "distinct_database_created": True,
            "history_and_state_preserved": True,
            "read_only_grants_verified": True,
        }
    except Exception:
        raise WitnessStorageRefused(phase) from None
