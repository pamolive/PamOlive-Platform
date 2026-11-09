"""Read-only two-host PAM-olive preflight over pinned SSH host connections."""

import argparse
import json
import queue
import re
import secrets
import shlex
import subprocess
from pathlib import Path
from threading import Thread

FORMAT = "pamolive.remote-ha/1"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
INSPECT = (
    '{"container":{{json .Id}},"image":{{json .Image}},'
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"running":{{json .State.Running}},'
    '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}'
)


class CheckError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def identifier(value):
    require(bool(IDENTIFIER.fullmatch(value)), "Unsafe SSH alias, container or project identifier.")
    return value


class Node:
    def __init__(self, alias, container, project, ssh_config=None):
        self.alias, self.container, self.project = map(identifier, (alias, container, project))
        require(self.project.startswith("pamolive-"), "Use a PamOlive Compose project.")
        self.prefix = ["ssh", "-T"]
        if ssh_config:
            self.prefix += ["-F", str(Path(ssh_config).resolve(strict=True))]
        self.prefix += [
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=8",
            self.alias,
        ]

    def arguments(self, *arguments):
        return self.prefix + [shlex.join(arguments)]

    def run(self, *arguments, data=None, timeout=20):
        result = subprocess.run(
            self.arguments(*arguments), input=data, capture_output=True, text=True, timeout=timeout
        )
        require(result.returncode == 0, "An SSH command or application readiness probe failed.")
        return result.stdout

    def describe(self):
        identity = self.run("cat", "/etc/machine-id").strip()
        engine = self.run("docker", "info", "--format", "{{.ID}}").strip()
        info = json.loads(
            self.run("docker", "inspect", "--type=container", "--format", INSPECT, self.container)
        )
        require(
            re.fullmatch(r"[a-f0-9]{32}", identity), "No valid independent Linux host identity."
        )
        require(bool(engine) and len(engine) <= 128, "No valid Docker engine identity.")
        require(
            re.fullmatch(r"[a-f0-9]{64}", info["container"])
            and SHA.fullmatch(info["image"])
            and info["running"] is True
            and info["health"] == "healthy"
            and info["project"] == self.project
            and info["service"] == "web",
            "Expected healthy, scoped PAM-olive Compose web container not found.",
        )
        return dict(info, machine=identity, engine=engine)

    def worker_args(self, container_id):
        require(re.fullmatch(r"[a-f0-9]{64}", container_id), "Invalid inspected container ID.")
        return (
            "docker",
            "exec",
            "-i",
            "--user",
            "1000:1000",
            container_id,
            "python",
            "-m",
            "deploy.remote_ha_node",
        )

    def probe(self, container_id, nonce):
        payload = json.dumps({"operation": "probe", "nonce": nonce}) + "\n"
        return json.loads(self.run(*self.worker_args(container_id), data=payload))


def validate_peer(a, b):
    keys = {
        "schema",
        "core_version",
        "pg_version",
        "instance",
        "session_key",
        "encryption_key",
        "policy",
        "https_origin",
        "locked",
    }
    for peer in (a, b):
        require(
            peer.keys() == keys
            and type(peer["pg_version"]) is int
            and peer["pg_version"] >= 160000
            and type(peer["https_origin"]) is bool
            and type(peer["locked"]) is bool
            and all(
                re.fullmatch(r"[a-f0-9]{64}", peer[key])
                for key in ("instance", "session_key", "encryption_key", "policy")
            ),
            "Invalid application probe response.",
        )
    require(a["schema"] == b["schema"] == FORMAT, "Unsupported readiness protocol.")
    for key in (
        "core_version",
        "pg_version",
        "session_key",
        "encryption_key",
        "policy",
        "https_origin",
    ):
        require(a[key] == b[key], "Nodes differ on " + key + ".")
    require(
        a["instance"] != b["instance"], "Both nodes use the same application instance identifier."
    )


def shared_lock(first, second, a, b, nonce):
    with subprocess.Popen(
        first.arguments(*first.worker_args(a["container"])),
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as holder:
        output = queue.Queue()

        def reports():
            for line in holder.stdout:
                output.put(line)
            output.put("")

        Thread(target=reports, daemon=True).start()
        try:
            holder.stdin.write(json.dumps({"operation": "hold", "nonce": nonce}) + "\n")
            holder.stdin.flush()
            result = json.loads(output.get(timeout=25))
            require(result.get("locked") is True, "Node A did not acquire its random test lock.")
            blocked = second.probe(b["container"], nonce)
            validate_peer(result, blocked)
            require(
                blocked.get("locked") is False,
                "Node B did not observe the lock held by A; shared PostgreSQL is not proven.",
            )
            holder.stdin.write("release\n")
            holder.stdin.flush()
            require(
                json.loads(output.get(timeout=12)) == {"released": True}
                and holder.wait(timeout=10) == 0,
                "Node A did not confirm lock release.",
            )
        finally:
            if holder.poll() is None:
                holder.kill()
    acquired = second.probe(b["container"], nonce)
    validate_peer(result, acquired)
    require(
        all(blocked[key] == acquired[key] for key in blocked if key != "locked"),
        "Node B configuration changed during the lock exchange.",
    )
    require(acquired.get("locked") is True, "Node B could not acquire the released lock.")
    return result


def qualify(first, second):
    require(first.alias.lower() != second.alias.lower(), "Use two different SSH aliases.")
    a, b = first.describe(), second.describe()
    require(
        a["machine"] != b["machine"] and a["engine"] != b["engine"],
        "Two distinct Linux host and Docker engine identities are required.",
    )
    require(a["image"] == b["image"], "Nodes do not run the same image digest.")
    readiness = shared_lock(first, second, a, b, secrets.token_hex(32))
    require(first.describe() == a and second.describe() == b, "A node changed during the check.")
    return {
        "result": "OK",
        "scope": "read-only remote two-host preflight; no failover or workload qualification",
        "image": a["image"],
        "core_version": readiness["core_version"],
        "postgresql_version_num": readiness["pg_version"],
        "distinct_linux_hosts_and_engines": True,
        "distinct_instance_ids": True,
        "matching_keys_and_security_policy": True,
        "shared_writable_postgresql_lock_namespace": True,
        "https_origin_configured": readiness["https_origin"],
        "containers_restarted": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-a", required=True)
    parser.add_argument("--node-b", required=True)
    parser.add_argument("--container", default="pamolive-platform-web-1")
    parser.add_argument("--project", default="pamolive-platform")
    parser.add_argument("--ssh-config", type=Path)
    args = parser.parse_args(argv)
    try:
        first, second = (
            Node(alias, args.container, args.project, args.ssh_config)
            for alias in (args.node_a, args.node_b)
        )
        print(json.dumps(qualify(first, second), sort_keys=True))
    except CheckError as error:
        print(f"Preflight failed: {error}")
        return 1
    except (KeyError, OSError, ValueError, TypeError, queue.Empty, subprocess.SubprocessError):
        print(
            "Preflight failed: invalid response, unavailable peer or deadline; output suppressed."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
