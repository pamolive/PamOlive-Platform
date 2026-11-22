"""Start the installed W01 witness only on the owned synthetic network."""

import argparse
import json
import os
import re
import sys
from pathlib import Path

from support import need, read_regular, sha

from .witness_postgres import HOSTS

ROOT = Path("/lab")
SITE = Path("/opt/vault/lib/python3.12/site-packages")
SOURCE = Path("/witness/witness-source.sha256")


def serve(run, source_sha, *, recovery=False):
    need(os.getuid() == os.getgid() == 1000)
    need(sys.flags.isolated and sys.dont_write_bytecode and sys.prefix == "/opt/vault")
    need(re.fullmatch(r"[a-f0-9]{16}", run) is not None)
    need(re.fullmatch(r"[a-f0-9]{64}", source_sha) is not None)
    need(sha(read_regular(SOURCE, 16384)) == source_sha)
    os.environ.clear()
    os.environ.update(LANG="C.UTF-8", LC_ALL="C.UTF-8", PSYCOPG_IMPL="c")

    import pamolive_usage_anchor
    import pamolive_vault_runtime
    import psycopg
    import uvicorn
    from pamolive_usage_anchor.assembly import application, history_application
    from pamolive_usage_anchor.codec import Error
    from pamolive_usage_anchor.transport import configuration, tls_context

    for module in (pamolive_usage_anchor, pamolive_vault_runtime, psycopg, uvicorn):
        need(Path(module.__file__).resolve(strict=True).is_relative_to(SITE))
    need(psycopg.__version__ == "3.2.10" and psycopg.pq.__impl__ == "c")
    need(psycopg.pq.version() == 170012)

    bindings = json.loads(read_regular(ROOT / "bindings.json", 4096))
    fields = {"source_sha256", "slot_sha256"}
    if not recovery:
        fields.add("materials_sha256")
    need(type(bindings) is dict and set(bindings) == fields)
    need(bindings["source_sha256"] == source_sha)
    if not recovery:
        need(sha(read_regular(ROOT / "materials.bin", 65536)) == bindings["materials_sha256"])
    slot_sha = bindings["slot_sha256"]
    need(type(slot_sha) is str and re.fullmatch(r"[a-f0-9]{64}", slot_sha) is not None)

    database = json.loads(read_regular(ROOT / "runtime.json", 4096))
    expected = dict(
        host=HOSTS["wpg"][0],
        hostaddr=HOSTS["wpg"][1],
        port=5432,
        dbname=f"w01_{run}_wpg",
        user="usage_anchor_observer" if recovery else "usage_anchor_runtime",
    )
    need(type(database) is dict and set(database) == {*expected, "password"})
    need(all(database[name] == value for name, value in expected.items()))
    need(
        type(database["password"]) is str
        and re.fullmatch(r"[a-zA-Z0-9_-]{32,128}", database["password"]) is not None
    )

    options = "-c search_path=pg_catalog -c statement_timeout=3000 -c lock_timeout=2000"
    if recovery:
        options += " -c default_transaction_read_only=on"

    def connect():
        connection = psycopg.connect(
            **database,
            sslmode="verify-full",
            sslrootcert=str(ROOT / "sql-ca.crt"),
            channel_binding="require",
            connect_timeout=3,
            options=options,
        )
        try:
            need(connection.pgconn.ssl_in_use and not connection.autocommit)
            need(connection.info.user == expected["user"])
            need(connection.info.dbname == expected["dbname"])
            need(connection.info.server_version == 170012)
        except BaseException:
            connection.close()
            raise
        return connection

    context = tls_context(
        certificate=str(ROOT / "server.crt"),
        private_key=str(ROOT / "server.key"),
        client_ca=str(ROOT / "ca.crt"),
    )
    common = dict(
        slot_path=ROOT / "slot.json",
        slot_sha256=slot_sha,
        connect=connect,
        owner_uid=0,
    )
    try:
        if recovery:
            app = history_application(**common)
        else:
            app = application(materials_path=ROOT / "materials.bin", **common)
    except Error as error:
        if (error.code, error.status) == ("context_refused", 403):
            print("W01 witness context refused.", file=sys.stderr)
            return 43
        raise
    try:
        uvicorn.Server(configuration(app, context, host="10.253.249.3", port=9443)).run()
    finally:
        app.close()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--recovery", action="store_true")
    args = parser.parse_args()
    try:
        status = serve(args.run, args.source_sha, recovery=args.recovery)
    except Exception:
        print("W01 witness startup refused.", file=sys.stderr)
        raise SystemExit(42) from None
    raise SystemExit(status)
