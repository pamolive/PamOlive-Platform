"""Qualify the exact local PamOlive image against a synthetic LDAP StartTLS peer."""

import argparse
import json
import re
import secrets
import subprocess
import sys
from pathlib import Path

DOCKER = ("docker", "--host", "unix:///var/run/docker.sock")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
STDIN_LIMIT = 8192
SCHEMA = "pamolive.ci-ldap-starttls/1"

# The launcher does not need to be present in the image being checked.
CLIENT = """
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import django
from django.test import override_settings

limit = int(sys.argv[1])
raw = sys.stdin.buffer.read(limit + 1)
if len(raw) > limit:
    raise SystemExit(1)
fixture = json.loads(raw)
host = "directory.invalid"
port = fixture["port"]
if type(port) is not int or not 1 <= port <= 65535:
    raise SystemExit(1)

sys.path.insert(0, "/app")
os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["LDAPNOINIT"] = "1"
django.setup()
from platform_modules.connectors import directory_adapters

def resolve_fixture(hostname, requested_port):
    # Mirror the directory wire-test resolver and preserve the TLS peer name.
    if (hostname, requested_port) != (host, port):
        raise directory_adapters.IntegrationFailure("address_not_authorized")
    return "127.0.0.1"

authority = f"{host}:{port}"
scope = {"base_dn": fixture["base_dn"], "bind_dn": fixture["bind_dn"]}
secret = {"bind_dn": fixture["bind_dn"], "password": fixture["password"]}
with TemporaryDirectory(prefix="ldap-ca-", dir="/tmp") as folder:
    ca_file = Path(folder) / "fixture.pem"
    ca_file.write_text(fixture["ca_pem"], encoding="ascii")
    with (
        override_settings(
            CONNECTOR_ALLOWED_HOSTS=(authority,),
            CONNECTOR_ALLOWED_NETWORKS=("127.0.0.1/32",),
            CONNECTOR_CA_BUNDLE=str(ca_file),
        ),
        patch.object(directory_adapters, "resolve_destination", new=resolve_fixture),
    ):
        destination = directory_adapters.normalize_destination(
            "ldap", f"ldap://{authority}", fixture["pin"], scope
        )
        result = directory_adapters.read_directory(
            provider="ldap", destination=destination, secret=secret
        )

if (
    result.synthetic is not True
    or result.page_count != 1
    or len(result.records) != 1
    or result.records[0]["uid"] != "fixture"
    or result.records[0]["enabled"] is not None
    or "ldap_group_memberships_unknown" not in result.limitations
):
    raise SystemExit(1)
"""


def require_image(image_id):
    observed = subprocess.check_output(
        [*DOCKER, "image", "inspect", "--format", "{{.Id}}", image_id],
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    if observed.strip() != image_id.encode("ascii"):
        raise ValueError("image_identity")


def successful_simple_binds(peer):
    peer.log.flush()
    with (peer.folder / "server.private.log").open(encoding="utf-8", errors="replace") as stream:
        log = stream.read(256 * 1024 + 1)
    if len(log) > 256 * 1024:
        raise ValueError("fixture_log_budget")
    return log.count(f'BIND dn="{peer.bind_dn}" mech=SIMPLE ')


def run_client(image_id, peer):
    with Path(peer.ca_file).open("r", encoding="ascii") as certificate:
        ca_pem = certificate.read(STDIN_LIMIT + 1)
    payload = json.dumps(
        {
            "port": peer.port,
            "base_dn": peer.base_dn,
            "bind_dn": peer.bind_dn,
            "password": peer.password,
            "pin": peer.pin,
            "ca_pem": ca_pem,
        },
        separators=(",", ":"),
    ).encode("ascii")
    if len(payload) > STDIN_LIMIT:
        raise ValueError("fixture_input_size")

    name = "pamolive-ldap-ci-" + secrets.token_hex(12)
    command = [
        *DOCKER,
        "run",
        "--name",
        name,
        "--rm",
        "--interactive",
        "--network",
        "host",
        "--pull",
        "never",
        "--user",
        "1000:1000",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "1",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--pids-limit",
        "32",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=1m,mode=1777",
        "--log-driver",
        "none",
        "--no-healthcheck",
        "--workdir",
        "/app",
        "--entrypoint",
        "/usr/local/bin/python",
        image_id,
        "-I",
        "-B",
        "-c",
        CLIENT,
        str(STDIN_LIMIT),
    ]
    try:
        subprocess.run(
            command,
            input=payload,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=55,
            check=True,
        )
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        subprocess.run(
            [*DOCKER, "container", "rm", "--force", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    image_id = args.image_id if IMAGE_ID.fullmatch(args.image_id) else ""
    report = {
        "schema": SCHEMA,
        "image_id": image_id,
        "result": "failed",
        "starttls_search": False,
        "authenticated_bind": False,
        "error": "image_identity",
    }
    try:
        if not image_id:
            raise ValueError("image_identity")
        if sys.platform != "linux":
            report["error"] = "runner_platform"
            raise RuntimeError("runner_platform")
        require_image(image_id)

        report["error"] = "fixture_startup"
        from tests.fixtures.ldap_directory import LdapDirectoryPeer

        peer = LdapDirectoryPeer()
        try:
            report["error"] = "authenticated_bind"
            before = successful_simple_binds(peer)
            report["error"] = "container_probe"
            run_client(image_id, peer)
            report["starttls_search"] = True
            report["error"] = "authenticated_bind"
            if successful_simple_binds(peer) != before + 1:
                raise RuntimeError("authenticated_bind")
            report["authenticated_bind"] = True
        finally:
            try:
                peer.close()
            except (OSError, subprocess.SubprocessError):
                report["error"] = "fixture_cleanup"
                raise
    except (ImportError, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        pass
    else:
        report.update(result="passed", error=None)

    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
