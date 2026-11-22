"""Data-only W01 PostgreSQL pair; no I/O, connection or implicit repair.

The trusted parent owns verified containers, fresh PGDATA, PKI creation, private
staging and local psql execution. Both read-only receipts must be accepted before
the first provision script can be taken. Each script repeats its fresh-cluster
guard immediately before its own writes. An interrupted/unknown/partial attempt
is abandoned; this API has no reset, retry, reopen or destructive cleanup path.
"""

import hashlib
import re
from dataclasses import dataclass, field
from types import MappingProxyType

SCHEMA_PINS = MappingProxyType({
    "witness": "5a87319a26fe9db826cbc82130f3dff06e9a5e3749b67e5c09ab40cc969bf188",
    "vault": "78cbd52dc5b30fa1139dedaf29b903fbd0becd5272d648ddd60ee35b4769a72f",
    "mirror": "a0dfe7c9ffb62787c500e81fb00efa1b964b8e31b019499f5a35d21b4b012534",
})
ROLES = MappingProxyType({
    "wpg": ("usage_anchor_runtime", "usage_anchor_admin", "usage_anchor_observer",
            "w_web_probe", "w_v_probe"),
    "vpg": ("vault_n0_runtime", "vault_n0_admin", "v_web_probe", "v_worker_probe"),
})
OWNERS = MappingProxyType({"wpg": "usage_anchor_owner", "vpg": "vault_n0_owner"})
HOSTS = MappingProxyType({"wpg": ("w-n0-db.test", "10.253.249.2"),
                          "vpg": ("v-n0-db.test", "10.253.249.5")})
ROLE_FLAGS = "NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
REFUSED = b"W01_CLUSTER_REFUSED\n"


class Refused(ValueError):
    def __init__(self):
        super().__init__("witness_postgres_refused")


def need(value):
    if not value:
        raise Refused()


def closed(value, fields):
    need(type(value) is dict and value.keys() == set(fields))


def identifier(value):
    need(type(value) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value))
    return '"' + value + '"'


def restore_database(run_id):
    need(type(run_id) is str and re.fullmatch(r"[a-f0-9]{16}", run_id))
    return f"w01_{run_id}_wpg_restored"


def password(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value))
    return "'" + value + "'"


@dataclass(frozen=True, repr=False)
class File:
    raw: bytes = field(repr=False)
    mode: int
    uid: int = 999
    gid: int = 999


@dataclass(frozen=True, repr=False)
class Cluster:
    role: str
    hostname: str
    address: str
    database: str
    files: object = field(repr=False)
    port: int = 5432
    uid: int = 999
    gid: int = 999
    pgdata: str = "/var/lib/postgresql/data"
    pgdata_mode: int = 0o700
    pgdata_tmpfs_bytes: int = 256 * 1024 * 1024
    socket_path: str = "/var/run/postgresql"
    server_version: int = 170012


def _blank_guard():
    # Exact initdb profile, same guarantees as the installed Vault guard, under
    # W01's explicit postgres/OID10 bootstrap identity. Never a shared database.
    return b"""\\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog;
SET LOCAL statement_timeout = '3s';
SELECT (
 current_database()='postgres' AND current_user='postgres' AND session_user='postgres'
 AND inet_server_addr() IS NULL AND NOT pg_is_in_recovery()
 AND current_setting('port')='5432'
 AND current_setting('server_version_num')='170012'
 AND current_setting('data_directory')='/var/lib/postgresql/data'
 AND current_setting('hba_file')='/lab/pg_hba.conf'
 AND current_setting('ssl')='on' AND current_setting('fsync')='on'
 AND current_setting('synchronous_commit')='on'
 AND NOT EXISTS (SELECT FROM pg_stat_activity WHERE pid<>pg_backend_pid()
   AND backend_type IN ('client backend','walsender'))
 AND EXISTS (SELECT FROM pg_roles WHERE oid=10 AND rolname='postgres'
   AND rolsuper AND rolcanlogin)
 AND NOT EXISTS (SELECT FROM pg_roles WHERE oid>=16384)
 AND (SELECT array_agg(datname::text ORDER BY datname) FROM pg_database)
   = ARRAY['postgres','template0','template1']
 AND NOT EXISTS (SELECT FROM pg_database WHERE datdba<>10
   OR datistemplate<>(datname<>'postgres') OR datallowconn<>(datname<>'template0')
   OR (datname='postgres' AND datacl IS NOT NULL))
 AND (SELECT array_agg(nspname::text ORDER BY nspname) FROM pg_namespace)
   = ARRAY['information_schema','pg_catalog','pg_toast','public']
 AND (SELECT array_agg(extname::text ORDER BY extname) FROM pg_extension)=ARRAY['plpgsql']
 AND NOT EXISTS (SELECT FROM pg_class WHERE relnamespace='public'::regnamespace)
 AND NOT EXISTS (SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace)
 AND NOT EXISTS (SELECT FROM pg_type WHERE typnamespace='public'::regnamespace)
) IS TRUE AS w01_blank \\gset
COMMIT;
"""


def _marker(run, role, phase):
    return f"W01_{run}_{role}_{phase}\n".encode("ascii")


def _preflight(run, cluster):
    return (_blank_guard() + b"\\if :w01_blank\n\\echo "
            + _marker(run, cluster.role, "EMPTY")
            + b"\\else\n\\echo W01_CLUSTER_REFUSED\n\\endif\n")


def _provision(run, cluster, secrets, schemas):
    role = cluster.role
    owner = identifier(OWNERS[role])
    admin = identifier(ROLES[role][1])
    database = identifier(cluster.database)
    statements = [f"CREATE ROLE {owner} NOLOGIN {ROLE_FLAGS};"]
    for login in ROLES[role]:
        statements.append(f"CREATE ROLE {identifier(login)} LOGIN {ROLE_FLAGS} "
                          f"PASSWORD {password(secrets[login])};")
    statements += [f"GRANT {owner} TO {admin};",
                   f"CREATE DATABASE {database} OWNER {owner} TEMPLATE template0;",
                   f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;"]
    for login in ROLES[role]:
        statements.append(f"GRANT CONNECT ON DATABASE {database} TO {identifier(login)};")
    # The target name is a closed ASCII identifier; no conninfo or external DSN.
    statements += [f"\\connect {cluster.database} postgres /var/run/postgresql 5432",
                   "SET search_path=pg_catalog;", "SET statement_timeout='3s';",
                   "REVOKE ALL ON SCHEMA public FROM PUBLIC;"]
    selected = ("witness",) if role == "wpg" else ("vault", "mirror")
    body = ("\n".join(statements) + "\n").encode("ascii")
    body += b"\n".join(schemas[name] for name in selected) + b"\n"
    if role == "wpg":
        body += b"""SET ROLE usage_anchor_owner;
GRANT USAGE ON SCHEMA pam_usage_anchor TO usage_anchor_observer;
GRANT SELECT ON ALL TABLES IN SCHEMA pam_usage_anchor TO usage_anchor_observer;
RESET ROLE;
"""
    result = (_blank_guard() + b"\\if :w01_blank\n" + body
              + b"\\echo " + _marker(run, role, "PROVISIONED")
              + b"\\else\n\\echo W01_CLUSTER_REFUSED\n\\endif\n")
    need(len(result) <= 128 * 1024)
    return result


class Pair:
    """Trusted-parent state machine; receipts are not database attestations.

    Parent must bind each receipt to its exact owned CID and checked psql I/O.
    Accessing private Python attributes is not a sandbox/security boundary.
    """

    __slots__ = ("run", "clusters", "_scripts", "_preflighted", "_done", "_pending", "_failed")

    def __init__(self, run, clusters, scripts):
        self.run = run
        self.clusters = MappingProxyType(clusters)
        self._scripts = scripts
        self._preflighted = set()
        self._done = []
        self._pending = None
        self._failed = False

    def __repr__(self):
        return "<W01 PostgreSQL pair>"

    @property
    def complete(self):
        return not self._failed and self._done == ["wpg", "vpg"]

    @property
    def failed(self):
        return self._failed

    def abort(self):
        self._failed = True

    def _require(self, value):
        if self._failed or not value:
            self.abort()
            raise Refused()

    def preflight_sql(self, role):
        self._require(type(role) is str and role in self.clusters
                      and not self._done and self._pending is None
                      and role not in self._preflighted)
        return _preflight(self.run, self.clusters[role])

    def accept_preflight(self, role, returncode, stdout):
        self._require(type(role) is str and role in self.clusters
                      and not self._done and self._pending is None
                      and role not in self._preflighted)
        self._require(type(returncode) is int and returncode == 0 and type(stdout) is bytes
                      and stdout == _marker(self.run, role, "EMPTY"))
        self._preflighted.add(role)

    def take_provision(self, role):
        expected = "wpg" if not self._done else "vpg"
        self._require(self._preflighted == {"wpg", "vpg"} and self._pending is None
                      and len(self._done) < 2 and role == expected)
        self._pending = role  # Before bytes escape: lost execution/ACK is not retryable.
        return self._scripts.pop(role)

    def accept_provision(self, role, returncode, stdout):
        self._require(type(role) is str and self._pending == role and role in self.clusters)
        self._require(type(returncode) is int and returncode == 0 and type(stdout) is bytes
                      and stdout == _marker(self.run, role, "PROVISIONED"))
        self._done.append(role)
        self._pending = None


def exec_args(container_id):
    """Arguments only; the trusted parent must verify CID/profile before exec."""
    need(type(container_id) is str and re.fullmatch(r"[a-f0-9]{64}", container_id))
    return ("exec", "--interactive", "--user", "999:999", container_id,
            "/bin/sh", "-ec", 'test "$(cat /proc/1/comm)" = postgres\n'
            "exec env -i PATH=/usr/local/bin:/usr/bin:/bin PGCONNECT_TIMEOUT=3 "
            "psql -X -w -qAt -v ON_ERROR_STOP=1 -h /var/run/postgresql "
            "-p 5432 -U postgres -d postgres -f -")


def prepare_pair(
    run_id, *, databases, credentials, tls, schemas, schema_pins,
    recovery=False, restore_witness=False,
):
    """Return inert private data only. PEM trust/identity is checked by real TLS.

    databases/credentials/tls use exact wpg/vpg keys. Credentials include postgres
    plus each role in ROLES. tls has ca/certificate/key bytes for each cluster.
    The recovery profile permits the observer at W's reserved service address.
    The restore profile adds an observer-only route to the reserved copy of W.
    No key/password is generated or read here; there is no inherited environment.
    """
    need(type(run_id) is str and re.fullmatch(r"[a-f0-9]{16}", run_id))
    need(type(recovery) is bool)
    need(type(restore_witness) is bool and (recovery or not restore_witness))
    closed(databases, ROLES)
    closed(credentials, ROLES)
    closed(tls, ROLES)
    closed(schemas, SCHEMA_PINS)
    closed(schema_pins, SCHEMA_PINS)
    need(schema_pins == dict(SCHEMA_PINS))
    checked_schemas = {}
    for name, digest in SCHEMA_PINS.items():
        raw = schemas[name]
        need(type(raw) is bytes and 0 < len(raw) <= 65536
             and hashlib.sha256(raw).hexdigest() == digest)
        checked_schemas[name] = raw
    clusters, scripts = {}, {}
    all_passwords = []
    for role in ("wpg", "vpg"):
        database = databases[role]
        need(database == f"w01_{run_id}_{role}")
        identifier(database)
        closed(credentials[role], {"postgres", *ROLES[role]})
        checked_credentials = dict(credentials[role])
        for value in checked_credentials.values():
            password(value)
            all_passwords.append(value)
        closed(tls[role], {"ca", "certificate", "key"})
        for raw in tls[role].values():
            need(type(raw) is bytes and 0 < len(raw) <= 16384 and raw.isascii()
                 and raw.startswith(b"-----BEGIN ") and raw.endswith(b"-----\n"))
        name, address = HOSTS[role]
        config = (f"listen_addresses='{address}'\nport=5432\nssl=on\n"
                  "ssl_cert_file='/lab/server.crt'\nssl_key_file='/lab/server.key'\n"
                  "hba_file='/lab/pg_hba.conf'\npassword_encryption='scram-sha-256'\n"
                  "fsync=on\nsynchronous_commit=on\nshared_buffers='16MB'\n"
                  "max_connections=16\nlog_statement='none'\nlog_min_messages='fatal'\n")
        hba = f"local postgres postgres peer\nlocal {database} postgres peer\n"
        restored = restore_database(run_id) if restore_witness and role == "wpg" else None
        if restored:
            hba += f"local {restored} postgres peer\n"
        hba += "local all all reject\n"
        for login in ROLES[role]:
            hba += f"hostssl {database} {login} 10.253.249.4/32 scram-sha-256\n"
        runtime_ip = "10.253.249.3" if role == "wpg" else "10.253.249.6"
        hba += f"hostssl {database} {ROLES[role][0]} {runtime_ip}/32 scram-sha-256\n"
        if recovery and role == "wpg":
            hba += f"hostssl {database} usage_anchor_observer {runtime_ip}/32 scram-sha-256\n"
        if restored:
            for address in (runtime_ip, "10.253.249.4"):
                hba += f"hostssl {restored} usage_anchor_observer {address}/32 scram-sha-256\n"
        hba += "host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"
        files = {
            "ca.crt": File(tls[role]["ca"], 0o444),
            "server.crt": File(tls[role]["certificate"], 0o444),
            "server.key": File(tls[role]["key"], 0o400),
            "initial-password": File(checked_credentials["postgres"].encode("ascii"), 0o400),
            "postgresql.conf": File(config.encode("ascii"), 0o444),
            "pg_hba.conf": File(hba.encode("ascii"), 0o444),
        }
        cluster = Cluster(role, name, address, database, MappingProxyType(files))
        clusters[role] = cluster
        scripts[role] = _provision(run_id, cluster, checked_credentials, checked_schemas)
    need(len(set(all_passwords)) == len(all_passwords))
    need(tls["wpg"]["key"] != tls["vpg"]["key"]
         and tls["wpg"]["certificate"] != tls["vpg"]["certificate"]
         and tls["wpg"]["ca"] != tls["vpg"]["ca"])
    return Pair(run_id, clusters, scripts)
