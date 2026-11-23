"""Own one synthetic PostgreSQL service in an isolated GitHub runner namespace."""

import json
import re
import secrets
import subprocess
import time
from contextlib import contextmanager

from qualification.p1g_headless.lab_support import fresh_write, need

IMAGE = ("docker.io/library/postgres@sha256:"
         "6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788")
DATABASE = "pamolive_p1g"
ACCOUNT = "p1g"
VERSION = "170012"
PASSWORD_PATH = "/run/pamolive-p1g-password"
OWNER_LABEL = "io.pamolive.p1g-postgres"
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
SANDBOX_PATH = re.compile(r"(?:/var)?/run/docker/netns/[0-9a-f]{12}")
INSPECT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"reference":{{json .Config.Image}},'
    '"config_id":{{json .Image}},"network_mode":{{json .HostConfig.NetworkMode}},'
    '"port_bindings":{{json .HostConfig.PortBindings}},"running":{{json .State.Running}},'
    '"publish_all":{{json .HostConfig.PublishAllPorts}},'
    '"sandbox":{{json .NetworkSettings.SandboxKey}},"privileged":{{json .HostConfig.Privileged}},'
    '"read_only":{{json .HostConfig.ReadonlyRootfs}}}'
)


def docker(private, args, *, timeout, code):
    result = subprocess.run(
        [*DOCKER, *args], check=False, timeout=timeout,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"HOME": str(private), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    need(result.returncode == 0 and len(result.stdout) <= 8192, code)
    return result.stdout


def admit(config, *, container_id, name, image_id):
    need(
        isinstance(config, dict) and config.get("id") == container_id
        and config.get("name") == "/" + name and config.get("reference") == IMAGE
        and config.get("config_id") == image_id and config.get("network_mode") == "none"
        and config.get("port_bindings") in (None, {}) and config.get("running") is True
        and config.get("publish_all") is False
        and config.get("privileged") is False and config.get("read_only") is True,
        "postgres_container_identity",
    )
    namespace = config.get("sandbox")
    need(isinstance(namespace, str) and SANDBOX_PATH.fullmatch(namespace),
         "postgres_namespace_path")
    return namespace


@contextmanager
def service(private, identity, receipt):
    password_file = private / "postgres-password"
    fresh_write(password_file, secrets.token_urlsafe(24).encode())
    owner = "pamolive-p1g-postgres-" + identity["run"] + "-" + identity["attempt"]
    owner_label = f"{OWNER_LABEL}={identity['revision']}-{identity['run']}-{identity['attempt']}"
    cidfile = private / "postgres.cid"
    docker(private, ["pull", "--quiet", "--platform", "linux/amd64", IMAGE],
           timeout=90, code="postgres_image_pull")
    image_id = docker(private, ["image", "inspect", "--format", "{{.Id}}", IMAGE],
                      timeout=10, code="postgres_image_inspect").decode("ascii").strip()
    need(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "postgres_image_identity")
    owned = None
    try:
        docker(private, [
            "run", "--detach", "--init", "--read-only", "--network", "none",
            "--memory", "768m", "--cpus", "1", "--pids-limit", "128",
            "--security-opt", "no-new-privileges", "--pull", "never",
            "--name", owner, "--cidfile", str(cidfile),
            "--label", owner_label,
            "--tmpfs", "/var/lib/postgresql/data:rw,size=512m,mode=0700",
            "--tmpfs", "/var/run/postgresql:rw,size=16m,mode=0775",
            "--tmpfs", "/tmp:rw,size=32m,nosuid,nodev",
            "--env", "POSTGRES_USER=" + ACCOUNT, "--env", "POSTGRES_DB=" + DATABASE,
            "--env", "POSTGRES_PASSWORD_FILE=" + PASSWORD_PATH,
            "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
            "--mount", f"type=bind,src={password_file},dst={PASSWORD_PATH},readonly",
            IMAGE, "-c", "listen_addresses=127.0.0.1",
        ], timeout=30, code="postgres_container_start")
        received = cidfile.read_text(encoding="ascii").strip()
        need(CONTAINER_ID.fullmatch(received), "postgres_container_id")
        owned = received
        inspect_args = ["inspect", "--type", "container", "--format", INSPECT, owned]

        def verify_container():
            raw = docker(private, inspect_args, timeout=8, code="postgres_container_inspect")
            return admit(json.loads(raw), container_id=owned, name=owner, image_id=image_id)

        sandbox = verify_container()
        receipt["postgres_container"] = {"reference": IMAGE, "config_id": image_id}
        yield sandbox, owned
        need(verify_container() == sandbox, "postgres_namespace_changed")
    finally:
        if owned is not None:
            removed = docker(private, ["rm", "--force", owned],
                             timeout=15, code="postgres_container_cleanup").decode("ascii").strip()
            need(removed == owned or removed == owner, "postgres_container_cleanup")
            remaining = docker(private, ["ps", "--all", "--quiet", "--no-trunc",
                                         "--filter", "id=" + owned],
                               timeout=8, code="postgres_container_cleanup")
            need(not remaining.strip(), "postgres_container_cleanup")
            receipt["postgres_container_removed"] = True


def read_loopback(private):
    password = (private / "postgres-password").read_text(encoding="ascii")
    need(re.fullmatch(r"[A-Za-z0-9_-]{32}", password), "postgres_fixture_password")
    query = "SELECT current_setting('server_version_num'),current_user,current_database(),"
    query += "host(inet_server_addr())"
    env = {
        "HOME": str(private), "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8",
        "PGPASSWORD": password, "PGCONNECT_TIMEOUT": "2",
    }
    command = ["/usr/bin/psql", "-XAtw", "-h", "127.0.0.1", "-p", "5432",
               "-U", ACCOUNT, "-d", DATABASE, "-c", query]
    deadline = time.monotonic() + 22
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                command,
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False, timeout=3,
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0:
            expected = f"{VERSION}|{ACCOUNT}|{DATABASE}|127.0.0.1\n".encode()
            need(result.stdout == expected, "postgres_loopback_identity")
            env.pop("PGPASSWORD")
            try:
                refused = subprocess.run(
                    command, env=env, stdin=subprocess.DEVNULL,
                    capture_output=True, check=False, timeout=3,
                )
            except subprocess.TimeoutExpired:
                raise ValueError("postgres_fixture_authentication") from None
            need(refused.returncode != 0 and not refused.stdout
                 and b"no password supplied" in refused.stderr, "postgres_fixture_authentication")
            return {"server_version_num": VERSION, "verified_loopback_SQL": True}
        time.sleep(0.3)
    raise ValueError("postgres_loopback_unavailable")
