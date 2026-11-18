"""PG17.12 synthetic lab configuration DATA only; no SQL/Docker/process execution.

Trusted parent supplies the existing pinned fixture_stage primitives/reader,
pg_bootstrap module, verified installed schema/descriptor and new PKI materials.
The output is private data for that parent's independently owned allocation.
"""

import ast
import json
import re
from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import UUID

PG_IMAGE = (
    "docker.io/library/postgres@sha256:"
    "6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788"
)
SLOT_READY = b"VAULT_LAB_SLOT_READY\n"
DATABASE = re.compile(r"vault_n0_lab_[a-z0-9_]{1,48}")
HEX = re.compile(r"[0-9a-f]{64}")
ROLES = {
    "runtime": "vault_n0_runtime",
    "owner": "vault_n0_owner_lab_login",
    "web": "web_n0_lab",
    "worker": "worker_n0_lab",
}


def need(value, _reason=None):
    if not value:
        raise ValueError("vault_pg_stage_refused")


def load_public_pg(source, *, fixture_support, read_regular):
    """Reuse exact pg_files/provision_sql and the historical seed expression only."""
    raw = fixture_support.pinned_bytes(source, fixture_support.PKI_SHA256, read_regular)
    tree = ast.parse(raw)
    names = {"pg_files", "provision_sql"}
    functions = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    need(len(functions) == 2 and {node.name for node in functions} == names)
    fresh = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "fresh_files"
    )
    seeds = [
        node
        for node in fresh.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "seed"
    ]
    need(len(seeds) == 1)
    # The existing statement is preserved verbatim in AST, without invoking fresh_files.
    signature = ast.arguments(
        posonlyargs=[],
        args=[ast.arg(arg=name) for name in ("database", "model", "incarnation")],
        vararg=None,
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=None,
        defaults=[],
    )
    seed_function = ast.FunctionDef(
        name="commissioning_seed",
        args=signature,
        body=[seeds[0], ast.Return(value=ast.Name(id="seed", ctx=ast.Load()))],
        decorator_list=[],
        returns=None,
        type_comment=None,
        type_params=[],
    )
    module = ast.fix_missing_locations(
        ast.Module(body=[*functions, seed_function], type_ignores=[])
    )
    namespace = {"p": SimpleNamespace(need=need), "sha": fixture_support.sha}
    exec(compile(module, str(source), "exec", dont_inherit=True), namespace)
    return SimpleNamespace(
        **{name: namespace[name] for name in (*sorted(names), "commissioning_seed")}
    )


@dataclass(repr=False)
class PostgresStage:
    database: str = field(repr=False)
    files: dict = field(repr=False)
    guarded_sql: bytes = field(repr=False)
    passwords: dict = field(repr=False)
    sql_ca: bytes = field(repr=False)
    desired_profile: dict = field(repr=False)
    schema_sha256: str

    def __repr__(self):
        return f"PostgresStage(files={len(self.files)}, executed=False)"

    def public_summary(self):
        return {
            "schema": "pamolive.vault-synthetic-pg-stage-summary/1",
            "files": len(self.files),
            "server_version_required": 170012,
            "provisioned": False,
            "authority": False,
        }


def profile():
    """Requested settings, never an observation or permission to allocate objects."""
    return {
        "image": PG_IMAGE,
        "user": "999:999",
        "entrypoint": ["/usr/local/bin/docker-entrypoint.sh"],
        "environment": {
            "PGDATA": "/var/lib/postgresql/data",
            "POSTGRES_USER": "vault_n0_admin",
            "POSTGRES_DB": "postgres",
            "POSTGRES_PASSWORD_FILE": "/lab/admin.password",
            "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=trust",
        },
        "command": [
            "postgres",
            "-c",
            "shared_buffers=32MB",
            "-c",
            "max_connections=12",
            "-c",
            "work_mem=1MB",
            "-c",
            "ssl=on",
            "-c",
            "ssl_cert_file=/lab/pg-server.crt",
            "-c",
            "ssl_key_file=/lab/pg-server.key",
            "-c",
            "hba_file=/lab/pg_hba.conf",
            "-c",
            "log_statement=none",
            "-c",
            "log_connections=off",
        ],
        "tmpfs": {
            "/var/lib/postgresql/data": "rw,nosuid,nodev,size=268435456,mode=0700,uid=999,gid=999",
            "/var/run/postgresql": "rw,nosuid,nodev,size=8388608,mode=0755,uid=999,gid=999",
            "/tmp": "rw,noexec,nosuid,nodev,size=33554432,mode=1777",
        },
        "port_bindings": {},
        "publish_all_ports": False,
        "new_empty_pgdata_required": True,
        "exclusive_internal_network_required": True,
    }


def prepare_postgres(
    *,
    primitives,
    fixture_support,
    bootstrap,
    leaves,
    public,
    passwords,
    database,
    schema,
    descriptor,
):
    """Build four PG files and guarded SQL; neither creates nor reuses a cluster."""
    need(type(database) is str and DATABASE.fullmatch(database))
    need(type(passwords) is dict and set(passwords) == {"admin", *ROLES})
    need(all(type(value) is str and HEX.fullmatch(value) for value in passwords.values()))
    need(len(set(passwords.values())) == 5)
    need(type(schema) is bytes and 0 < len(schema) <= 65536)
    need(
        type(descriptor) is dict
        and descriptor.get("schema") == "pamolive.vault-runtime-installed-input/2"
    )
    expected = descriptor.get("sql_sha256")
    need(
        type(expected) is str
        and HEX.fullmatch(expected)
        and fixture_support.sha(schema) == expected
    )
    need(type(leaves) is dict and "pg" in leaves and type(leaves["pg"]) is dict)
    need(set(leaves["pg"]) == {"key", "pem", "der"})
    need(type(public) is dict and "SQL" in public)
    for raw in [*leaves["pg"].values(), public["SQL"]]:
        need(type(raw) is bytes and 0 < len(raw) <= 65536)
    files = primitives.pg_files(leaves, public, passwords, database)
    need(
        set(files)
        == {"lab/admin.password", "lab/pg-server.key", "lab/pg-server.crt", "lab/pg_hba.conf"}
    )
    for name, row in files.items():
        need(type(row) is tuple and len(row) == 4)
        data, mode, uid, gid = row
        need(type(data) is bytes and 0 < len(data) <= 65536)
        need(
            (mode, uid, gid)
            == ((0o600, 999, 999) if name.endswith((".key", ".password")) else (0o444, 0, 0))
        )
    # Narrow the historical local bootstrap rule; preserve the four hostssl rules exactly.
    hba, mode, uid, gid = files["lab/pg_hba.conf"]
    prefix = b"local all all trust\n"
    need(hba.startswith(prefix))
    restricted = (
        "local postgres vault_n0_admin trust\n"
        f"local {database} vault_n0_admin trust\n"
        "local all all reject\n"
    ).encode() + hba[len(prefix) :]
    files["lab/pg_hba.conf"] = restricted, mode, uid, gid
    provision = primitives.provision_sql(database, passwords, schema)
    guarded = bootstrap.guarded_sql(provision)
    return PostgresStage(
        database, files, guarded, dict(passwords), public["SQL"], profile(), expected
    )


def canonical_uuid(value):
    need(type(value) is str and str(UUID(value)) == value)
    return value


def json_file(files, name, maximum=65536):
    row = files[name]
    need(type(row) is tuple and len(row) == 4 and row[1:] == (0o444, 0, 0))
    raw = row[0]
    need(type(raw) is bytes and 0 < len(raw) <= maximum)

    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value)
            value[key] = item
        return value

    return json.loads(raw, object_pairs_hook=unique), raw


def commissioning_sql(
    *, postgres, stage, primitives, fixture_support, bootstrap, schema_returncode, schema_stdout
):
    """Validate the existing schema receipt/bindings before returning historical seed DATA."""
    bootstrap.require_success(schema_returncode, schema_stdout)
    need(DATABASE.fullmatch(postgres.database))
    commissioning = stage.commissioning
    need(
        type(commissioning) is dict
        and set(commissioning) == {"slot_id", "incarnation", "slot_sha256", "serving_state"}
    )
    slot_id = canonical_uuid(commissioning["slot_id"])
    incarnation = canonical_uuid(commissioning["incarnation"])
    need(commissioning["serving_state"] == "open")
    client_slot, raw = json_file(stage.client_files, "lab/slot.json")
    server_slot, server_raw = json_file(stage.server_files, "lab/slot.json")
    need(raw == server_raw and client_slot == server_slot)
    need(client_slot.get("schema") == "pamolive.vault.local-reservation-slot/1")
    need(
        client_slot["slot_id"] == slot_id
        and client_slot["expectations"]["ledger_incarnation"] == incarnation
    )
    need(fixture_support.sha(raw) == commissioning["slot_sha256"])
    need(len(stage.server_files) == 7 and len(stage.client_files) == 21)
    for files in (stage.server_files, stage.client_files):
        values, _ = json_file(files, "lab/manifest.json")
        need(values == fixture_support.manifest(files, commissioning["slot_sha256"]))
        need(values["schema"] == "pamolive.vault.synthetic-lab-inputs/1")
        need(
            values["slot_path"] == "/lab/slot.json"
            and values["slot_sha256"] == commissioning["slot_sha256"]
        )
        need(files["lab/sql-ca.pem"] == (postgres.sql_ca, 0o444, 0, 0))
    for role, user in ROLES.items():
        value, _ = json_file(stage.client_files, "lab/" + role + "-db.json")
        need(
            value
            == {
                "host": "vault-n0-db.test",
                "port": 5432,
                "dbname": postgres.database,
                "user": user,
                "password": postgres.passwords[role],
                "sslrootcert": "/lab/sql-ca.pem",
            }
        )
    need(stage.server_files["lab/runtime-db.json"] == stage.client_files["lab/runtime-db.json"])
    request, _ = json_file(stage.client_files, "lab/request.json")
    need(request["draft"]["ledger_incarnation"] == incarnation)
    model = SimpleNamespace(slot=SimpleNamespace(slot_id=slot_id), config_raw=raw)
    seed = primitives.commissioning_seed(postgres.database, model, incarnation)
    need(type(seed) is bytes and 0 < len(seed) <= 4096)
    need(seed.endswith(b"SELECT 'VAULT_LAB_SLOT_READY';\n"))
    return seed


def require_commissioned(returncode, stdout):
    """Closed marker only; parent still validates owned CID/profile and bounded IO."""
    need(type(returncode) is int and returncode == 0 and stdout == SLOT_READY)
