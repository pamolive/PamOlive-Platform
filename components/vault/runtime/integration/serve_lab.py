"""Future LAB startup ONLY; author never executes this. Root supplies reviewed local files."""

import argparse
import json
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pamolive_vault_runtime.bounded import closed, digest, json_object, need


def local_bytes(path, maximum):
    from pamolive_vault_runtime.slot import _read_ro

    raw, _ = _read_ro(Path(path), 0)
    need(len(raw) <= maximum)
    return raw


def lab_inputs(manifest):
    need(isinstance(manifest, Path) and manifest.is_absolute())
    raw = local_bytes(manifest, 32768)
    value = json_object(raw, 32768)
    closed(
        value,
        {
            "schema",
            "slot_path",
            "slot_sha256",
            "runtime_database_file",
            "owner_database_file",
            "web_database_file",
            "worker_database_file",
            "server_certificate",
            "server_key",
            "client_ca",
            "server_ca",
            "client_a_certificate",
            "client_a_key",
            "client_b_certificate",
            "client_b_key",
            "client_a_der",
            "client_b_der",
            "request_file",
            "port",
            "bad_tls_clients",
            "bind_host",
            "server_host",
        },
    )
    need(value["schema"] == "pamolive.vault.synthetic-lab-inputs/1")
    digest(value["slot_sha256"])
    need(type(value["port"]) is int and 1024 <= value["port"] <= 65535)
    need(type(value["bind_host"]) is str and value["bind_host"] in {"127.0.0.1", "10.253.249.3"})
    need(value["server_host"] in {"localhost", "vault-n0.test"})
    for name, path in value.items():
        if name not in {
            "schema",
            "slot_sha256",
            "port",
            "bad_tls_clients",
            "bind_host",
            "server_host",
        }:
            need(type(path) is str and Path(path).is_absolute() and ".." not in Path(path).parts)
            need(not path.startswith(("//", "\\\\")))
    rows = value["bad_tls_clients"]
    need(type(rows) is list and len(rows) == 3)
    need(
        {row.get("case") for row in rows if type(row) is dict}
        == {"unknown_ca", "expired", "future"}
    )
    for row in rows:
        closed(row, {"case", "certificate", "private_key"})
        for field in ("certificate", "private_key"):
            path = row[field]
            need(type(path) is str and Path(path).is_absolute() and ".." not in Path(path).parts)
            need(not path.startswith(("//", "\\\\")))
    return value


def connector(path, *, role):
    # No environment/default PG settings. Root provisions a NEW laboratory DB only.
    value = json_object(local_bytes(path, 8192), 8192)
    closed(value, {"host", "port", "dbname", "user", "password", "sslrootcert"})
    need(
        value["host"] in {"localhost", "vault-n0-db.test"}
        and type(value["dbname"]) is str
        and value["dbname"].startswith("vault_n0_lab_")
        and value["user"] == role
    )
    need(type(value["port"]) is int and 1024 <= value["port"] <= 65535)
    need(type(value["password"]) is str and 1 <= len(value["password"]) <= 256)
    need(type(value["sslrootcert"]) is str and Path(value["sslrootcert"]).is_absolute())
    args = dict(
        value,
        sslmode="verify-full",
        connect_timeout=3,
        options="-c search_path=pg_catalog -c statement_timeout=3000 -c lock_timeout=2000",
    )

    def connect():
        import psycopg

        return psycopg.connect(**args)

    return connect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-new-synthetic-lab", action="store_true", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    import uvicorn
    from pamolive_vault_runtime.assembly import application
    from pamolive_vault_runtime.transport import configuration, tls_context

    values = lab_inputs(args.manifest)
    app = application(
        slot_path=Path(values["slot_path"]),
        slot_sha256=values["slot_sha256"],
        connect=connector(values["runtime_database_file"], role="vault_n0_runtime"),
    )
    context = tls_context(
        certificate=values["server_certificate"],
        private_key=values["server_key"],
        client_ca=values["client_ca"],
    )
    try:
        uvicorn.Server(
            configuration(app, context, host=values["bind_host"], port=values["port"])
        ).run()
    finally:
        app.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"error": "lab_startup_refused", "authority": False}))
        raise SystemExit(1) from None
