"""Check PostgreSQL TLS and SCRAM from the exact CI runtime image."""

import argparse
import io
import json
import re
import secrets
import signal
import subprocess
import sys
import tarfile
import time
from datetime import UTC, datetime, timedelta

PG_IMAGE = (
    "docker.io/library/postgres@sha256:"
    "6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788"
)
PG_HOST = "sasl-postgres-fixture.test"
PG_USER = "pamolive_sasl_fixture"
PG_DATA = "/var/lib/postgresql/data"
LABEL = "org.pamolive.ci.sasl-postgres"
DOCKER = ("docker", "--host", "unix:///var/run/docker.sock")

SERVER = f"""
umask 077
timeout 25s sh -ec 'until [ -f /fixture/ready ]; do sleep 0.1; done'
timeout 20s initdb -D {PG_DATA} --username={PG_USER} --pwfile=/fixture/password \
    --auth-local=trust --auth-host=scram-sha-256
rm /fixture/password
exec postgres -D {PG_DATA} -c 'listen_addresses=*' -c ssl=on \
    -c unix_socket_directories=/var/run/postgresql \
    -c ssl_cert_file=/fixture/server.crt -c ssl_key_file=/fixture/server.key \
    -c hba_file=/fixture/pg_hba.conf -c log_statement=none -c log_connections=off
"""

CLIENT = f"""
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import psycopg

if os.getuid() != 1000 or os.getgid() != 1000 or psycopg.pq.__impl__ != 'c':
    raise SystemExit(1)

params = json.load(sys.stdin)
with TemporaryDirectory() as directory:
    ca = Path(directory) / 'ca.crt'
    ca.write_text(params['ca'], encoding='ascii')
    with psycopg.connect(
        host={PG_HOST!r}, port=5432, dbname='postgres', user={PG_USER!r},
        password=params['fixture_password'], sslmode='verify-full', sslrootcert=str(ca),
        channel_binding='require', require_auth='scram-sha-256', gssencmode='disable',
        connect_timeout=5, options='-c statement_timeout=5000', autocommit=True,
    ) as connection:
        row = connection.execute(
            "SELECT ssl, version, current_setting('server_version_num'), current_user "
            "FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()"
        ).fetchone()

if row is None or row[0] is not True or row[1] not in ('TLSv1.2', 'TLSv1.3'):
    raise SystemExit(1)
if row[2:] != ('170012', {PG_USER!r}):
    raise SystemExit(1)
"""


def tls_material() -> tuple[bytes, bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PamOlive CI SCRAM fixture CA")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PG_HOST)])
    # SCRAM channel binding uses the digest of the certificate's signature algorithm.
    common = (
        x509.CertificateBuilder()
        .issuer_name(ca_name)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
    )
    ca = (
        common.subject_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    certificate = (
        common.subject_name(server_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(PG_HOST)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        ca.public_bytes(serialization.Encoding.PEM),
        certificate.public_bytes(serialization.Encoding.PEM),
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def server_inputs(certificate: bytes, key: bytes, fixture_password: str) -> bytes:
    hba = f"local postgres {PG_USER} trust\nhostssl postgres {PG_USER} all scram-sha-256\n"
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as bundle:
        for name, data in (
            ("server.crt", certificate), ("server.key", key),
            ("password", (fixture_password + "\n").encode("ascii")),
            ("pg_hba.conf", hba.encode("ascii")),
        ):
            entry = tarfile.TarInfo(name)
            entry.mode = 0o600
            entry.size = len(data)
            bundle.addfile(entry, io.BytesIO(data))
    return archive.getvalue()


def docker(
    *arguments: str,
    data: bytes | None = None,
    timeout: float = 10,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*DOCKER, *arguments],
        input=data,
        stdin=subprocess.DEVNULL if data is None else None,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=check,
    )


def wait_for_postgres(container: str) -> bool:
    deadline = time.monotonic() + 30
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            probe = docker(
                "exec", container, "pg_isready", "-q", "-h", "/var/run/postgresql",
                "-U", PG_USER, "-d", "postgres", "-t", "2",
                timeout=min(3, remaining), check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        if probe.returncode == 0:
            return True
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    return False


def cleanup(run_label: str) -> bool:
    success = True
    for kind, remove_options in (("container", ("--force", "--volumes")), ("network", ())):
        try:
            listing = docker(
                kind, "ls", "--quiet", "--no-trunc",
                *(("--all",) if kind == "container" else ()),
                "--filter", f"label={run_label}", capture=True,
            )
            for resource in listing.stdout.splitlines():
                if not re.fullmatch(rb"[0-9a-f]{64}", resource):
                    success = False
                    continue
                removed = docker(kind, "rm", *remove_options, resource.decode("ascii"), check=False)
                success = success and removed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            success = False
    return success


def qualify(image_id: str) -> tuple[str, bool]:
    token = secrets.token_hex(12)
    name = f"pamolive-sasl-{token}"
    server = f"{name}-postgres"
    run_label = f"{LABEL}={token}"
    allocated = False
    phase = "image"
    cleaned = True
    try:
        actual = docker("image", "inspect", "--format", "{{.Id}}", image_id, capture=True).stdout
        if actual.strip() != image_id.encode("ascii"):
            return phase, cleaned
        docker("image", "inspect", PG_IMAGE)

        phase = "materials"
        ca, certificate, key = tls_material()
        fixture_password = secrets.token_hex(32)
        archive = server_inputs(certificate, key, fixture_password)
        client_inputs = json.dumps(
            {"ca": ca.decode("ascii"), "fixture_password": fixture_password}, separators=(",", ":")
        ).encode("ascii")

        phase = "network"
        allocated = True
        docker("network", "create", "--internal", "--label", run_label, name)

        phase = "server"
        docker(
            "create", "--name", server, "--label", run_label, "--pull", "never",
            "--network", name, "--network-alias", PG_HOST, "--user", "999:999", "--read-only",
            "--no-healthcheck", "--log-driver", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--entrypoint", "/bin/sh",
            "--cpus", "1", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "64",
            "--tmpfs", f"{PG_DATA}:size=256m,mode=0700,uid=999,gid=999,nosuid,nodev",
            "--tmpfs", "/fixture:size=1m,mode=0700,uid=999,gid=999,nosuid,nodev,noexec",
            "--tmpfs", "/var/run/postgresql:size=1m,mode=0700,uid=999,gid=999,nosuid,nodev,noexec",
            "--tmpfs", "/tmp:size=16m,mode=1777,nosuid,nodev,noexec",
            PG_IMAGE, "-ec", SERVER,
        )
        docker("start", server)
        docker(
            "exec", "-i", server, "/bin/sh", "-ec",
            "umask 077; tar -x -f - -C /fixture && touch /fixture/ready", data=archive,
        )

        phase = "server_ready"
        if wait_for_postgres(server):
            phase = "client"
            docker(
                "run", "-i", "--name", f"{name}-client", "--label", run_label,
                "--pull", "never", "--network", name, "--user", "1000:1000", "--read-only",
                "--no-healthcheck", "--log-driver", "none", "--cap-drop", "ALL",
                "--cpus", "1", "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "32",
                "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp:size=16m,mode=1777,nosuid,nodev,noexec",
                "--entrypoint", "python", image_id, "-I", "-B", "-c", CLIENT,
                timeout=15, data=client_inputs,
            )
            phase = "complete"
    except (ImportError, KeyboardInterrupt, OSError, ValueError, subprocess.SubprocessError):
        pass
    finally:
        if allocated:
            cleaned = cleanup(run_label)
    return phase, cleaned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, signal.default_int_handler)

    phase, cleaned = "image", True
    if sys.platform != "linux":
        phase = "runner_platform"
    elif re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id):
        phase, cleaned = qualify(args.image_id)
    ok = phase == "complete" and cleaned
    print(json.dumps({
        "schema": "pamolive.sasl-postgres-ci/1", "ok": ok,
        "phase": phase, "cleanup_ok": cleaned,
    }, separators=(",", ":")))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
