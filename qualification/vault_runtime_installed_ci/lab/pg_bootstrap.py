"""Private PostgreSQL bootstrap guard for a newly allocated Vault test cluster.

The caller must verify the container, private mounts and empty initial PGDATA
before starting the pinned PostgreSQL image. This guard checks the running
server within the same psql submission as the existing provision SQL.
"""

import re

READY = b"VAULT_LAB_EMPTY_CLUSTER\nVAULT_LAB_SCHEMA_READY\n"
REFUSED = b"VAULT_LAB_CLUSTER_REFUSED\n"

# Keep the bind, data directory and version consistent with the dedicated
# container profile. Compare only the exact fresh initdb layout used by it.
CHECK_BLANK = b"""\\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog;
SET LOCAL statement_timeout = '3s';
SELECT (
    current_database() = 'postgres'
    AND current_user = 'vault_n0_admin'
    AND session_user = 'vault_n0_admin'
    AND inet_server_addr() IS NULL
    AND NOT pg_is_in_recovery()
    AND current_setting('server_version_num') = '170012'
    AND current_setting('data_directory') = '/var/lib/postgresql/data'
    AND current_setting('hba_file') = '/lab/pg_hba.conf'
    AND current_setting('ssl') = 'on'
    AND NOT EXISTS (
        SELECT FROM pg_stat_activity
        WHERE pid <> pg_backend_pid() AND backend_type IN ('client backend', 'walsender')
    )
    AND EXISTS (
        SELECT FROM pg_roles
        WHERE oid = 10 AND rolname = 'vault_n0_admin' AND rolsuper AND rolcanlogin
    )
    AND NOT EXISTS (SELECT FROM pg_roles WHERE oid >= 16384)
    AND (
        SELECT array_agg(datname::text ORDER BY datname) FROM pg_database
    ) = ARRAY['postgres', 'template0', 'template1']
    AND NOT EXISTS (
        SELECT FROM pg_database
        WHERE datdba <> 10
           OR datistemplate <> (datname <> 'postgres')
           OR datallowconn <> (datname <> 'template0')
           OR (datname = 'postgres' AND datacl IS NOT NULL)
    )
    AND (
        SELECT array_agg(nspname::text ORDER BY nspname) FROM pg_namespace
    ) = ARRAY['information_schema', 'pg_catalog', 'pg_toast', 'public']
    AND (
        SELECT array_agg(extname::text ORDER BY extname) FROM pg_extension
    ) = ARRAY['plpgsql']
    AND NOT EXISTS (
        SELECT FROM pg_class WHERE relnamespace = 'public'::regnamespace
    )
    AND NOT EXISTS (
        SELECT FROM pg_proc WHERE pronamespace = 'public'::regnamespace
    )
    AND NOT EXISTS (
        SELECT FROM pg_type WHERE typnamespace = 'public'::regnamespace
    )
) IS TRUE AS pamolive_empty \\gset
COMMIT;
\\if :pamolive_empty
\\echo VAULT_LAB_EMPTY_CLUSTER
"""


class BootstrapRefused(ValueError):
    """Closed diagnostic. The SQL input and private psql output stay private."""


def exec_args(container_id):
    """Arguments for the verified controller, with no host, DSN or credentials."""
    if not isinstance(container_id, str) or not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise BootstrapRefused("postgres container identity")
    return (
        "exec",
        "--interactive",
        "--user",
        "999:999",
        container_id,
        "/bin/sh",
        "-ec",
        'test "$(cat /proc/1/comm)" = postgres\n'
        "exec env -i PATH=/usr/local/bin:/usr/bin:/bin PGCONNECT_TIMEOUT=3 "
        "psql -X -w -qAt -v ON_ERROR_STOP=1 -h /var/run/postgresql "
        "-p 5432 -U vault_n0_admin -d postgres -f -",
    )


def guarded_sql(provision_sql):
    """Wrap the existing private provisioner bytes after their input checks."""
    if (
        not isinstance(provision_sql, bytes)
        or not 0 < len(provision_sql) <= 128 * 1024
        or not provision_sql.startswith(b"\\set ON_ERROR_STOP on\nCREATE ROLE ")
        or not provision_sql.endswith(b"\nSELECT 'VAULT_LAB_SCHEMA_READY';\n")
    ):
        raise BootstrapRefused("postgres provision input")
    return CHECK_BLANK + provision_sql + b"\\else\n\\echo VAULT_LAB_CLUSTER_REFUSED\n\\endif\n"


def require_success(returncode, stdout):
    """Refuse even exit zero unless the guard and schema both emit their marker."""
    if type(returncode) is not int or returncode != 0 or stdout != READY:
        if stdout == REFUSED:
            raise BootstrapRefused("postgres cluster precondition")
        raise BootstrapRefused("postgres provisioning unconfirmed")
