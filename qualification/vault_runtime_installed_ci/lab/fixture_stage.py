"""Synthetic server/client staging DATA only; no writes, SQL, service or network.

The parent supplies its existing bounded reader and installed-origin checks.
Only selected functions from pinned public PKI source are compiled; no historical
package_loader or controller is imported. The public signing fixture resolves
its imports in the separately verified installed environment, never source paths.
"""

import ast
import hashlib
import importlib.machinery
import importlib.util
import json
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

PKI_SHA256 = "000f66d8dd8bcc9d70764955f7aa0faaa0dd3168c0c7af6e4cf4cd0eabe2ec4c"
FIXTURE_SHA256 = "b555d9d01e693e728eb4f8121af25c76c56d4afde0fc85356d4410791dfd61e4"
PKI_FUNCTIONS = frozenset({"pem_key", "certificate", "tls_materials", "passwords"})
LEAVES = frozenset({"pg", "server", "client_a", "client_b", "unknown_ca", "expired", "future"})
AUTHORITIES = frozenset({"SQL", "Vault TLS", "Untrusted TLS"})
ROLES = {
    "runtime": "vault_n0_runtime",
    "owner": "vault_n0_owner_lab_login",
    "web": "web_n0_lab",
    "worker": "worker_n0_lab",
}


def need(value, _reason=None):
    if not value:
        raise ValueError("vault_fixture_stage_refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pinned_bytes(path, expected, read_regular):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(strict=True))
    raw = read_regular(path, 65536)
    need(type(raw) is bytes and 0 < len(raw) <= 65536 and sha(raw) == expected)
    return raw


def installed_crypto_backend():
    """Explicit future native preparation only; never called by module import."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    return dict(
        x509=x509,
        hashes=hashes,
        serialization=serialization,
        rsa=rsa,
        ExtendedKeyUsageOID=ExtendedKeyUsageOID,
        NameOID=NameOID,
        new_signing_key=ed25519.Ed25519PrivateKey.generate,
    )


def load_public_pki(source, *, read_regular, backend=None):
    """Reuse four exact public function bodies without importing their controller."""
    raw = pinned_bytes(source, PKI_SHA256, read_regular)
    tree = ast.parse(raw)
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in PKI_FUNCTIONS
    ]
    need(len(selected) == len(PKI_FUNCTIONS) and {node.name for node in selected} == PKI_FUNCTIONS)
    crypto = installed_crypto_backend() if backend is None else backend
    need(
        set(crypto)
        == {
            "x509",
            "hashes",
            "serialization",
            "rsa",
            "ExtendedKeyUsageOID",
            "NameOID",
            "new_signing_key",
        }
    )
    namespace = dict(
        UTC=UTC,
        datetime=datetime,
        timedelta=timedelta,
        secrets=secrets,
        p=SimpleNamespace(need=need),
        **crypto,
    )
    code = compile(
        ast.Module(body=selected, type_ignores=[]), str(source), "exec", dont_inherit=True
    )
    exec(code, namespace)
    return SimpleNamespace(
        **{name: namespace[name] for name in PKI_FUNCTIONS},
        new_signing_key=crypto["new_signing_key"],
    )


class CapturedPublicLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, name, path, body):
        super().__init__(name, path)
        self.body = body

    def get_code(self, fullname):
        return compile(self.body, self.path, "exec", dont_inherit=True)


def load_public_fixture(
    source, *, read_regular, verify_installed, new_signing_key, module_loader=None
):
    """Private fixture module, same public code; its imports must be installed.

    Parent's verify_installed callback performs the existing installed-file and
    effective/loaded-origin checks and returns the stable installed base path.
    A fresh module receives the historical random-key substitution, never a
    source package or modifications to a shared fixture module/sys.path.
    """
    raw = pinned_bytes(source, FIXTURE_SHA256, read_regular)
    before = verify_installed()
    need(before is not None and callable(new_signing_key))
    if module_loader is None:
        name = "_pamolive_private_installed_signing_fixture"
        loader = CapturedPublicLoader(name, str(source), raw)
        spec = importlib.util.spec_from_loader(name, loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    else:
        # Callable injection for stdlib-only preparation doubles, never a manifest option.
        module = module_loader(Path(source), raw)
    need(verify_installed() == before)
    need(callable(module.Fixture))
    module.key = lambda _label: new_signing_key()
    return module


@dataclass(repr=False)
class Stage:
    server_files: dict = field(repr=False)
    client_files: dict = field(repr=False)
    commissioning: dict = field(repr=False)
    expires_at: int

    def __repr__(self):
        return (
            f"Stage(server_files={len(self.server_files)}, client_files={len(self.client_files)})"
        )

    def public_summary(self):
        return {
            "schema": "pamolive.vault-synthetic-stage-summary/1",
            "server_files": len(self.server_files),
            "client_files": len(self.client_files),
            "provisioned": False,
            "service_started": False,
            "authority": False,
        }


def record(raw, mode=0o444, uid=0, gid=0):
    need(type(raw) is bytes and 0 < len(raw) <= 65536)
    need((mode, uid, gid) in {(0o444, 0, 0), (0o400, 1000, 1000)})
    return raw, mode, uid, gid


def manifest(files, slot_hash):
    """Every required field remains present; unused authority paths are unmounted."""

    def path(filename):
        return "/lab/" + (filename if "lab/" + filename in files else "not-mounted/" + filename)

    return {
        "schema": "pamolive.vault.synthetic-lab-inputs/1",
        "slot_path": path("slot.json"),
        "slot_sha256": slot_hash,
        "runtime_database_file": path("runtime-db.json"),
        "owner_database_file": path("owner-db.json"),
        "web_database_file": path("web-db.json"),
        "worker_database_file": path("worker-db.json"),
        "server_certificate": path("server.crt"),
        "server_key": path("server.key"),
        "client_ca": path("tls-ca.pem"),
        "server_ca": path("tls-ca.pem"),
        "client_a_certificate": path("client_a.crt"),
        "client_a_key": path("client_a.key"),
        "client_b_certificate": path("client_b.crt"),
        "client_b_key": path("client_b.key"),
        "client_a_der": path("client_a.der"),
        "client_b_der": path("client_b.der"),
        "request_file": path("request.json"),
        "port": 9443,
        "bind_host": "10.253.249.3",
        "server_host": "vault-n0.test",
        "bad_tls_clients": [
            {"case": name, "certificate": path(name + ".crt"), "private_key": path(name + ".key")}
            for name in ("unknown_ca", "expired", "future")
        ],
    }


def build_stage(*, fixture, leaves, public, passwords, database, now, new_uuid=uuid4):
    """Build only disjoint in-memory server/client file tables. No PG/SQL writer.

    leaves/public/passwords come from the pinned public PKI primitives. The parent
    uses those SAME new materials for PG provisioning; this function never reads
    or regenerates historical inputs. fixture is a newly loaded private module.
    """
    need(type(now) is int and now > 0)
    need(type(database) is str and re.fullmatch(r"vault_n0_lab_[a-z0-9_]{1,48}", database))
    need(type(passwords) is dict and set(passwords) == {"admin", *ROLES})
    need(
        all(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in passwords.values()
        )
        and len(set(passwords.values())) == 5
    )
    need(type(leaves) is dict and set(leaves) == LEAVES)
    need(type(public) is dict and set(public) == AUTHORITIES)
    for row in leaves.values():
        need(type(row) is dict and set(row) == {"key", "pem", "der"})
        for value in row.values():
            record(value)
    for value in public.values():
        record(value)
    need(leaves["client_a"]["key"] == leaves["client_b"]["key"])
    need(leaves["client_a"]["der"] != leaves["client_b"]["der"])
    # Same public Fixture/signatures and same changes as historical fresh_files.
    model = fixture.Fixture(now=now, der=leaves["client_a"]["der"])
    incarnation, slot_id = str(new_uuid()), str(new_uuid())
    model.expected["ledger_incarnation"] = incarnation
    model.config["slot_id"] = slot_id
    model.config["principals"][0]["certificate_sha256"].append(sha(leaves["client_b"]["der"]))
    model.draft = replace(model.draft, ledger_incarnation=incarnation)
    model.refresh()
    need(model.slot.slot_id == slot_id)
    slot_hash = sha(model.config_raw)
    shared = {
        "lab/slot.json": record(model.config_raw),
        "lab/sql-ca.pem": record(public["SQL"]),
        "lab/tls-ca.pem": record(public["Vault TLS"]),
    }
    connections = {
        "lab/" + name + "-db.json": record(
            encode(
                {
                    "host": "vault-n0-db.test",
                    "port": 5432,
                    "dbname": database,
                    "user": role,
                    "password": passwords[name],
                    "sslrootcert": "/lab/sql-ca.pem",
                }
            )
        )
        for name, role in ROLES.items()
    }
    server = {
        **shared,
        "lab/runtime-db.json": connections["lab/runtime-db.json"],
        "lab/server.key": record(leaves["server"]["key"], 0o400, 1000, 1000),
        "lab/server.crt": record(leaves["server"]["pem"]),
    }
    client = {**shared, **connections, "lab/request.json": record(model.request())}
    for name in ("client_a", "client_b", "unknown_ca", "expired", "future"):
        client["lab/" + name + ".key"] = record(leaves[name]["key"], 0o400, 1000, 1000)
        client["lab/" + name + ".crt"] = record(leaves[name]["pem"])
        if name in ("client_a", "client_b"):
            client["lab/" + name + ".der"] = record(leaves[name]["der"])
    server["lab/manifest.json"] = record(encode(manifest(server, slot_hash)))
    client["lab/manifest.json"] = record(encode(manifest(client, slot_hash)))
    need(len(server) == 7 and len(client) == 21)
    need(sum(len(row[0]) for row in server.values()) <= 4 * 1024**2)
    need(sum(len(row[0]) for row in client.values()) <= 4 * 1024**2)
    return Stage(
        server,
        client,
        {
            "slot_id": slot_id,
            "incarnation": incarnation,
            "slot_sha256": slot_hash,
            "serving_state": "open",
        },
        now + 40,
    )
