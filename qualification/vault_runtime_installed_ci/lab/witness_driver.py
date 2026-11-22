"""Exercise the installed W service and two fresh synthetic PostgreSQL clusters."""

import argparse
import base64
import http.client
import importlib
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from .witness_postgres import HOSTS, OWNERS, ROLES

ROOT = Path("/witness")
MOUNT = Path("/lab")
WORK = Path("/work")
W_HOST = "witness.synthetic.invalid"
W_ADDRESS = "10.253.249.3"
W_PORT = 9443
TLS_EXPECTED = 170012
W_TABLES = (
    "operations",
    "proof_uses",
    "contexts",
    "quotas",
    "leases",
    "activations",
    "activation_challenges",
    "audit_heads",
    "audit_events",
)
V_TABLES = ("reservations", "usage_mirrors", "commissioned_state", "audit")
CASES = frozenset(
    {
        "vertical_positive",
        "vertical_negative",
        "runtime_sql_and_triggers",
        "terminal_null_shape",
        "mtls_no_client",
        "mtls_unknown_ca",
        "mtls_server_hostname",
        "mtls_principal_audiences",
        "identity_header_refused",
    }
)
TLS_ALERTS = {
    "SSLV3_ALERT_HANDSHAKE_FAILURE": "handshake_alert",
    "SSLV3_ALERT_BAD_CERTIFICATE": "bad_certificate_alert",
    "TLSV1_ALERT_UNKNOWN_CA": "unknown_ca_alert",
    "TLSV13_ALERT_CERTIFICATE_REQUIRED": "client_certificate_required_alert",
    "UNEXPECTED_EOF_WHILE_READING": "unexpected_eof",
}


def require(condition):
    if not condition:
        raise ValueError("witness_driver_refused")


class DatabaseCheckRefused(ValueError):
    def __init__(self, phase):
        super().__init__("witness_driver_database_check_refused")
        self.phase = phase


def connection_failure(error):
    """Project a libpq startup failure to a fixed category before reporting it."""
    message = str(error).lower()
    for category, patterns in (
        ("database_ca", ("root certificate file", "could not read certificate")),
        ("database_peer", ("certificate verify failed", "does not match host name")),
        ("database_channel_binding", ("could not find digest for nid", "channel binding")),
        ("database_tls", ("ssl error:", "tls alert", "does not support ssl", "ssl handshake")),
        ("database_authentication", ("password authentication failed", "password is required")),
        ("database_hba", ("pg_hba.conf",)),
        ("database_startup", ("fatal:",)),
        ("database_transport", ("connection refused", "timeout expired", "no route to host")),
    ):
        if any(pattern in message for pattern in patterns):
            return category
    return "database_other_connection"


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        + b"\n"
    )


def publish(name, raw):
    path = WORK / name
    pending = path.with_suffix(path.suffix + ".pending")
    with pending.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        require(stream.write(raw) == len(raw))
        stream.flush()
        os.fsync(stream.fileno())
    require(not path.exists() and not path.is_symlink())
    pending.rename(path)


def wait_for(name, timeout):
    path = WORK / name
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            row = path.lstat()
        except FileNotFoundError:
            time.sleep(0.075)
            continue
        require(stat.S_ISREG(row.st_mode) and stat.S_IMODE(row.st_mode) == 0o600)
        require(row.st_uid == row.st_gid == 1000 and row.st_nlink == 1 and row.st_size == 0)
        return
    raise ValueError("witness_driver_control_timeout")


def kernel():
    require(os.getresuid() == os.getresgid() == (1000, 1000, 1000))
    require(set(os.getgroups()) <= {1000})
    with Path("/proc/self/status").open("rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536)
    fields = dict(line.split(":", 1) for line in raw.decode("ascii").splitlines() if ":" in line)
    require(fields["NoNewPrivs"].strip() == "1")
    require(
        all(int(fields["Cap" + field], 16) == 0 for field in ("Inh", "Prm", "Eff", "Bnd", "Amb"))
    )


def installed(source_sha):
    from witness_wheel import PREFIX, SITE, pins, read_regular, sha, verify_install

    require(not sys.flags.optimize and sys.flags.isolated and sys.dont_write_bytecode)
    require(Path(sys.prefix) == PREFIX)
    require(sha(read_regular(ROOT / "witness-source.sha256", 16384)) == source_sha)
    verify_install()
    for name in (
        "pamolive_usage_anchor",
        "pamolive_vault_runtime",
        "pamolive_pam_trust_verifier",
        "pamolive_vault_contracts",
        "psycopg",
        "psycopg_c",
    ):
        module = importlib.import_module(name)
        require(Path(module.__file__).resolve(strict=True).is_relative_to(SITE))

    import psycopg

    require(
        (psycopg.__version__, psycopg.pq.__impl__, psycopg.pq.version())
        == ("3.2.10", "c", TLS_EXPECTED)
    )
    approved = pins(ROOT)
    fixtures = ROOT / "fixtures"
    paths = ("tests/fixtures.py", "integration/scenario.py", "integration/permissions.py")
    for name in paths:
        require(sha(read_regular(fixtures / name, 65536)) == approved[name])
        require(Path(name).stem not in sys.modules)
    sys.path[:0] = [str(fixtures / "tests"), str(fixtures / "integration")]
    modules = tuple(importlib.import_module(Path(name).stem) for name in paths)
    require(
        all(
            Path(module.__file__) == fixtures / name
            for module, name in zip(modules, paths, strict=True)
        )
    )
    return modules


def database_connectors(run):
    import psycopg
    from witness_wheel import read_regular

    raw = read_regular(MOUNT / "driver.json", 8192)
    config = json.loads(raw)
    require(encode(config) == raw)
    require(type(config) is dict and set(config) == {"run", "databases"} and config["run"] == run)
    databases = config["databases"]
    require(type(databases) is dict and set(databases) == set(ROLES))
    passwords, authorities, factories = set(), set(), {}

    def factory(row, uid, ca):
        def connect():
            try:
                conn = psycopg.connect(
                    host=row["host"],
                    hostaddr=row["hostaddr"],
                    dbname=row["dbname"],
                    port=5432,
                    user=uid,
                    password=row["credentials"][uid],
                    sslmode="verify-full",
                    sslrootcert=str(ca),
                    channel_binding="require",
                    connect_timeout=3,
                    options=(
                        "-c search_path=pg_catalog -c statement_timeout=3000 -c lock_timeout=2000"
                    ),
                )
            except psycopg.OperationalError as error:
                raise DatabaseCheckRefused(connection_failure(error)) from None
            except Exception:
                raise DatabaseCheckRefused("database_client") from None
            try:
                require(not conn.autocommit and conn.info.server_version == TLS_EXPECTED)
                require(
                    (
                        conn.info.dbname,
                        conn.info.user,
                        conn.info.host,
                        conn.info.hostaddr,
                        conn.info.port,
                    )
                    == (row["dbname"], uid, row["host"], row["hostaddr"], 5432)
                )
                return conn
            except Exception:
                conn.close()
                raise DatabaseCheckRefused("database_connection_binding") from None

        return connect

    for database, users in ROLES.items():
        row = databases[database]
        require(
            type(row) is dict and set(row) == {"host", "hostaddr", "port", "dbname", "credentials"}
        )
        require((row["host"], row["hostaddr"]) == HOSTS[database])
        require(type(row["port"]) is int and row["port"] == 5432)
        require(row["dbname"] == f"w01_{run}_{database}")
        require(type(row["credentials"]) is dict and set(row["credentials"]) == set(users))
        ca = MOUNT / (database + "-ca.crt")
        authorities.add(read_regular(ca, 16384))
        for user, password in row["credentials"].items():
            require(type(password) is str and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password))
            require(password not in passwords)
            passwords.add(password)
            factories[user] = factory(row, user, ca)
    require(len(authorities) == 2)
    return factories


def check_database_roles(run, factories):
    """Check actual endpoint, TLS and assigned membership before any fixture writes."""
    for database, users in ROLES.items():
        for user in users:
            try:
                connection = factories[user]()
            except DatabaseCheckRefused:
                raise
            except Exception:
                raise DatabaseCheckRefused("database_connection") from None
            try:
                with connection as conn, conn.cursor() as cursor:
                    cursor.execute(
                        """SELECT current_database(), current_user, session_user,
                              host(inet_server_addr()), inet_server_port(), ssl,
                              r.rolsuper, r.rolcreatedb, r.rolcreaterole,
                              r.rolreplication, r.rolbypassrls, r.rolinherit,
                              pg_has_role(current_user, %s, 'MEMBER')
                       FROM pg_stat_ssl JOIN pg_roles AS r ON r.rolname=current_user
                       WHERE pid=pg_backend_pid()""",
                        (OWNERS[database],),
                    )
                    actual = cursor.fetchone()
            except Exception:
                raise DatabaseCheckRefused("database_role_query") from None
            expected = (
                f"w01_{run}_{database}",
                user,
                user,
                HOSTS[database][1],
                5432,
                True,
                False,
                False,
                False,
                False,
                False,
                False,
                user == users[1],
            )
            if actual != expected:
                raise DatabaseCheckRefused("database_role_mismatch")


def public_certificate(certificate):
    from cryptography.hazmat.primitives import serialization

    return certificate.public_bytes(serialization.Encoding.PEM)


def private_key(key):
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def stage(fixture, source_sha):
    from witness_wheel import sha

    for name in ("vault", "activation"):
        publish(name + ".crt", public_certificate(getattr(fixture, name + "_cert")))
        publish(name + ".key", private_key(getattr(fixture, name + "_key")))
    files = {
        "slot.json": fixture.slot_raw,
        "materials.bin": fixture.materials,
        "server.crt": public_certificate(fixture.server_cert),
        "server.key": private_key(fixture.server_key),
        "ca.crt": public_certificate(fixture.ca_cert),
    }
    publish("ca.crt", files["ca.crt"])
    raw = encode(
        {
            "files": {
                name: base64.b64encode(value).decode("ascii") for name, value in files.items()
            },
            "bindings": {
                "source_sha256": source_sha,
                "slot_sha256": sha(files["slot.json"]),
                "materials_sha256": sha(files["materials.bin"]),
            },
        }
    )
    require(len(raw) <= 256 * 1024)
    publish("w-stage.json", raw)


def context(who=None):
    channel = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    channel.load_verify_locations(cafile=str(WORK / "ca.crt"))
    require(
        channel.check_hostname
        and channel.verify_mode == ssl.CERT_REQUIRED
        and channel.keylog_filename is None
    )
    if who is not None:
        channel.load_cert_chain(str(WORK / (who + ".crt")), str(WORK / (who + ".key")))
    return channel


def verify_server(expected_der, *, host=W_HOST, tls12=False):
    client = context("vault")
    if tls12:
        client.minimum_version = client.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((W_ADDRESS, W_PORT), timeout=3) as transport:
        with client.wrap_socket(transport, server_hostname=host) as channel:
            require(channel.getpeercert(binary_form=True) == expected_der)


def wait_server(expected_der, expires):
    while time.time() < expires:
        try:
            verify_server(expected_der)
            break
        except ConnectionRefusedError:
            time.sleep(0.10)
    require(time.time() < expires)
    endpoints = socket.getaddrinfo(W_HOST, W_PORT, type=socket.SOCK_STREAM)
    require({endpoint[4] for endpoint in endpoints} == {(W_ADDRESS, W_PORT)})


def denied_tls(expected_der, who, reasons, phase, advance):
    # In TLS 1.2, the client's synchronous handshake sees a peer rejection
    # before HTTP. In TLS 1.3 it may first surface on a later read or write.
    advance(phase + "_control_before")
    verify_server(expected_der, tls12=True)
    client = context(who)
    client.minimum_version = client.maximum_version = ssl.TLSVersion.TLSv1_2
    advance(phase + "_handshake")
    with socket.create_connection((W_ADDRESS, W_PORT), timeout=3) as transport:
        try:
            with client.wrap_socket(transport, server_hostname=W_HOST):
                raise ValueError("witness_driver_tls_admitted")
        except ConnectionResetError:
            # asyncio may abort after certificate verification, before
            # flushing the fatal alert. TCP was already connected here.
            pass
        except ssl.SSLError as error:
            aborted = isinstance(error, ssl.SSLEOFError) and (
                error.reason == "UNEXPECTED_EOF_WHILE_READING"
            )
            if not aborted and error.reason not in reasons:
                raise
    advance(phase + "_control_after")
    verify_server(expected_der, tls12=True)


def verify_transport(fixture, fixtures, server_der, clients, bind_raw, bound_raw, advance):
    from pamolive_usage_anchor import codec

    advance("forwarded_header")
    path = "/v1/operations/bind"
    for forwarded in (False, True):
        with closing(
            http.client.HTTPSConnection(W_HOST, W_PORT, context=context("vault"), timeout=3)
        ) as conn:
            conn.connect()
            require(conn.sock.getpeercert(binary_form=True) == server_der)
            conn.putrequest("POST", path, skip_accept_encoding=True)
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(bind_raw)))
            if forwarded:
                conn.putheader("X-Forwarded-Client-Cert", "SYNTHETIC-NOT-AN-IDENTITY")
            conn.endheaders(bind_raw)
            response = conn.getresponse()
            if forwarded:
                require(response.status == 400)
                require(
                    codec.parse(response.read(4097), 4096, special=True)
                    == {"error": "invalid_request", "authorized": False}
                )
            else:
                require(response.status == 200 and response.read(196609) == bound_raw)

    denied_tls(
        server_der,
        None,
        {
            "SSLV3_ALERT_HANDSHAKE_FAILURE",
        },
        "tls_no_client",
        advance,
    )
    advance("tls_unknown_ca")
    unknown_ca = fixtures.certificate_authority(fixture.now)
    key, certificate = fixtures.certificate(fixture.now, "urn:pamolive:unknown:w01", ca=unknown_ca)
    publish("unknown.crt", public_certificate(certificate))
    publish("unknown.key", private_key(key))
    denied_tls(
        server_der,
        "unknown",
        {
            "TLSV1_ALERT_UNKNOWN_CA",
            "SSLV3_ALERT_BAD_CERTIFICATE",
        },
        "tls_unknown_ca",
        advance,
    )
    advance("tls_wrong_hostname")
    try:
        verify_server(server_der, host="wrong.synthetic.invalid")
    except ssl.SSLCertVerificationError as error:
        require(error.verify_code == 62)
    else:
        raise ValueError("witness_driver_hostname_admitted")
    advance("principal_audiences")
    for who, path, body in (
        ("activation", "/v1/operations/bind", bind_raw),
        ("vault", "/v1/activations/begin", codec.encode({"person_id": fixtures.uid(20)}, 4096)),
    ):
        try:
            clients[who].request(path, body)
        except codec.Error as error:
            require(error.status == 403 and error.code == "caller_refused")
        else:
            raise ValueError("witness_driver_wrong_audience_admitted")


def snapshot(observer, vault):
    from psycopg import sql

    def columns(schema, tables):
        return sql.SQL(", ").join(
            sql.SQL("ARRAY(SELECT to_jsonb(t)::text FROM {} AS t ORDER BY 1 LIMIT 65)").format(
                sql.Identifier(schema, table)
            )
            for table in tables
        )

    def read(connect, schema, tables):
        with connect() as conn, conn.cursor() as cursor:
            cursor.execute(sql.SQL("SELECT {}").format(columns(schema, tables)))
            rows = cursor.fetchone()
            require(all(len(table) <= 64 for table in rows))
            return rows

    # Compare ordered row contents in RAM, including payloads, counters and
    # audit hashes, so changes without a row-count delta are also detected.
    return read(observer, "pam_usage_anchor", W_TABLES), read(vault, "vault_reservation", V_TABLES)


def run_cases(fixture, modules, factories, source_sha, advance):
    from cryptography.hazmat.primitives import serialization
    from pamolive_usage_anchor import codec
    from pamolive_usage_anchor.client import MTLSClient, VaultMirror
    from pamolive_vault_contracts import serialize_draft
    from pamolive_vault_runtime.admission import Reservations
    from pamolive_vault_runtime.ledger import PostgresLedger

    fixtures, scenario, permissions = modules
    server_der = fixture.server_cert.public_bytes(serialization.Encoding.DER)
    advance("witness_tls_ready")
    wait_server(server_der, fixture.now + 18)
    clients = {
        who: MTLSClient(
            host=W_HOST, port=W_PORT, context=context(who), server_der_sha256=codec.sha(server_der)
        )
        for who in ("vault", "activation")
    }
    runtime = factories["vault_n0_runtime"]
    observer = factories["usage_anchor_observer"]
    witness = factories["usage_anchor_runtime"]
    advance("witness_activation")
    scenario.activate_over_mtls(clients["activation"], fixture)
    require(time.time() < fixture.now + 24)
    advance("vertical_round_trip")
    observed = scenario.vertical_round_trip(
        fixture=fixture,
        witness_client=clients["vault"],
        vault_runtime_connect=runtime,
        witness_observer_connect=observer,
        advance=advance,
    )
    terminals = ["consumed_no_release", "refused_no_release"]
    require(
        observed["operations"]
        == [{"state": state, "retry_byte_exact": True, "authorized": False} for state in terminals]
    )
    with observer() as conn, conn.cursor() as cursor:
        cursor.execute("SELECT state,operation_id FROM pam_usage_anchor.operations ORDER BY state")
        rows = cursor.fetchall()
        require(len(rows) == 2 and [row[0] for row in rows] == terminals)
        consumed = rows[0][1]

    # Bind a third operation before the short signed lease expires. Probes below
    # work from committed rows and do not extend or refresh the authority.
    advance("pending_binding")
    draft = replace(fixture.draft, request_id=fixtures.uid(802), idempotency_key=fixtures.uid(803))
    chain, checkpoint = codec.parse_materials(fixture.materials)
    request = encode(
        {
            "draft": json.loads(serialize_draft(draft)),
            "registry_chain": [codec.b64(raw) for raw in chain],
            "checkpoint": codec.b64(checkpoint),
        }
    ).rstrip(b"\n")
    broker_der = fixture.broker_cert.public_bytes(serialization.Encoding.DER)
    pending = Reservations(
        fixtures.MemoryReader(scenario.vault_slot(fixture)), PostgresLedger(runtime)
    ).prepare(request, broker_der)
    bound_raw = VaultMirror(runtime, clients["vault"]).prepare_reserved(pending.reservation_id)
    bound = codec.parse(bound_raw, 196608, string=90000, special=True)
    with observer() as conn, conn.cursor() as cursor:
        cursor.execute(
            "SELECT binding FROM pam_usage_anchor.operations WHERE operation_id=%s",
            (bound["operation_id"],),
        )
        bind_raw = bytes(cursor.fetchone()[0])
    advance("database_snapshot")
    before = snapshot(observer, runtime)
    require(tuple(map(len, before[0][:2])) == (3, 5) and tuple(map(len, before[1][:2])) == (3, 3))

    verify_transport(fixture, fixtures, server_der, clients, bind_raw, bound_raw, advance)
    advance("witness_sql_permissions")
    credential = fixture.auths[fixtures.uid(20)]["id"]
    checks = permissions.role_boundaries(
        witness_runtime_connect=witness,
        forbidden_witness_connects=[factories["w_web_probe"], factories["w_v_probe"]],
        context_id=fixture.slot.context_id,
        credential_id=credential,
        operation_id=consumed,
    )
    require(
        checks["runtime_ddl_metadata_delete_denied"]
        is checks["terminal_and_counter_guards"]
        is checks["all_probes_rollback_only"]
        is True
    )
    require(checks["forbidden_principals"] == 2)
    permissions.terminal_shape_probe(witness, fixture.slot.context_id, bound["operation_id"])
    advance("vault_sql_permissions")
    permissions.denied(
        runtime,
        "SELECT reservation_id FROM vault_reservation.reservations"
        " WHERE reservation_id=%s FOR UPDATE",
        (pending.reservation_id,),
    )
    for role in ("v_web_probe", "v_worker_probe"):
        permissions.denied(factories[role], "SELECT * FROM vault_reservation.reservations")
        permissions.denied(factories[role], "SELECT * FROM vault_reservation.usage_mirrors")
    advance("snapshot_comparison")
    require(snapshot(observer, runtime) == before)
    return {
        "schema": "W01-results/2",
        "source_sha256": source_sha,
        "cases": dict.fromkeys(CASES, True),
        "postgres": {
            "clusters": 2,
            "version": TLS_EXPECTED,
            "verify_full": True,
            "channel_binding_required": True,
            "assigned_roles_verified": True,
            "vault_forbidden_roles": 2,
            "vault_reservation_lock_denied": True,
            "witness_forbidden_roles": 2,
        },
        "terminal_states": terminals,
        "stored_exact_retries": True,
        "operations": 3,
        "proof_uses": 5,
        "negative_probes_no_side_effect": True,
        "vault_listener_exercised": False,
        "W04_W08_executed": False,
        "secret_release": False,
        "authority": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    phase = "boundary"

    def advance(name):
        nonlocal phase
        phase = name

    try:
        os.environ.clear()
        os.environ.update(LANG="C.UTF-8", LC_ALL="C.UTF-8", PSYCOPG_IMPL="c")
        require(
            re.fullmatch(r"[a-f0-9]{16}", args.run)
            and re.fullmatch(r"[a-f0-9]{64}", args.source_sha)
        )
        kernel()
        phase = "installed_wheels"
        modules = installed(args.source_sha)
        phase = "database_configuration"
        factories = database_connectors(args.run)
        phase = "database_roles"
        check_database_roles(args.run, factories)
        phase = "initialized_publish"
        publish("initialized", b"W01_INITIALIZED\n")
        phase = "prepare_wait"
        wait_for("prepare", 45)
        phase = "fixture"
        fixture = modules[0].Fixture(now=int(time.time()))
        modules[1].seed_new_databases(
            witness_owner_connect=factories["usage_anchor_admin"],
            vault_owner_connect=factories["vault_n0_admin"],
            fixture=fixture,
        )
        stage(fixture, args.source_sha)
        phase = "execute_wait"
        wait_for("execute", max(0, fixture.now + 18 - time.time()))
        phase = "native_cases"
        report = run_cases(fixture, modules, factories, args.source_sha, advance)
        publish("public.json", encode(report))
        phase = "acknowledge"
        wait_for("acknowledge", 15)
    except Exception as error:
        # Keep the private tmpfs reachable just long enough for the controller
        # to read a fixed phase name. No exception or material leaves the role.
        try:
            if isinstance(error, DatabaseCheckRefused):
                phase = error.phase
            if phase.startswith("tls_"):
                if isinstance(error, ssl.SSLError):
                    kind = TLS_ALERTS.get(error.reason, "other_ssl_error")
                elif isinstance(error, TimeoutError):
                    kind = "timeout"
                elif isinstance(error, ConnectionResetError):
                    kind = "connection_reset"
                elif isinstance(error, OSError):
                    kind = "other_socket_error"
                else:
                    kind = "assertion"
                phase += ":" + kind
            publish("failed", (phase + "\n").encode("ascii"))
            wait_for("acknowledge", 15)
        except Exception:
            pass
        return 42
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
