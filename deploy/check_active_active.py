"""Disposable two-node qualification; Python 3.8+ and Docker Compose, no local Django.

The fixed Compose project is deliberately unrelated to production. Only its
nodes are killed/restarted, and an optional RDP peer is disposable.
The existing private test database is never dropped.
Captured Docker/HTTP output is not printed, because fixtures contain test credentials.
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import queue
import re
import struct
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from threading import Event, Thread
from urllib.parse import parse_qsl, urlencode, urlsplit

PROJECT = "pamolive-platform-ha-check"
HOST = "ha.pamolive.test"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def subprocess_category(error):
    """Return a fixed diagnostic label, never driver/command output or values."""
    details = getattr(error, "stderr", "") or ""
    if isinstance(details, bytes):
        details = details.decode(errors="replace")
    details = details.lower()
    for needle, label in (
        ("is not running", "container-not-running"),
        ("cannot open", "namespace-unavailable"),
        ("operation not permitted", "namespace-or-route-permission"),
        ("permission denied", "permission-denied"),
        ("file exists", "existing-route"),
        ("no such process", "missing-route"),
        ("no such file or directory", "missing-namespace-or-file"),
        ("command not found", "missing-command"),
        ("timed out", "timeout"),
        ("connection refused", "connection-refused"),
        ("invalid argument", "invalid-argument"),
        ("undefined variable", "undefined-variable"),
        ("error:", "subprocess-error"),
    ):
        if needle in details:
            return label
    if isinstance(error, subprocess.TimeoutExpired):
        return "timeout"
    return "unknown"


def validate_configuration(config, *, checkpoint_directory=None):
    services = config.get("services", {})
    require(set(services) == {"node-a", "node-b"}, "Unexpected qualification services.")
    urls, images = set(), set()
    for name, service in services.items():
        environment = service.get("environment", {})
        url = environment.get("DATABASE_URL", "")
        parsed = urlsplit(url)
        require(
            parsed.scheme in ("postgres", "postgresql")
            and re.fullmatch(r"/test_pamolive_ha(?:_[a-z0-9]{1,12})?", parsed.path)
            and not {key.lower() for key, _ in parse_qsl(parsed.query)}
            & {"dbname", "database", "service", "servicefile"},
            "Qualification refuses an installation database.",
        )
        require(environment.get("PAMOLIVE_HA_QUALIFICATION") == "1", "Missing qualification guard.")
        require(
            environment.get("PAMOLIVE_INSTANCE_ID") == "qualification-" + name[-1], "Wrong node ID."
        )
        require(service.get("restart") == "no", "Qualification must not restart a failed node.")
        ports = service.get("ports", [])
        require(
            len(ports) == 1 and ports[0].get("host_ip") == "127.0.0.1", "Non-private test port."
        )
        mounts = service.get("volumes", [])
        if checkpoint_directory is None:
            require(not mounts, "Qualification must not mount business files.")
        else:
            from .active_active_trust import CHECKPOINT_TARGET

            require(
                len(mounts) == 1 and mounts[0].get("type") == "bind"
                and mounts[0].get("read_only") is True
                and mounts[0].get("target") == CHECKPOINT_TARGET
                and Path(mounts[0].get("source", "")).resolve()
                == Path(checkpoint_directory).resolve(),
                "Only the exact generated public checkpoint directory may be mounted.",
            )
        urls.add(url)
        images.add(service.get("image"))
    require(len(urls) == len(images) == 1, "Nodes must share the same database and image.")
    first, second = (services[name]["environment"] for name in ("node-a", "node-b"))
    for key in ("SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY"):
        require(
            first.get(key) == second.get(key) and len(first.get(key, "")) >= 40,
            "Shared test keys required.",
        )
    if checkpoint_directory is not None:
        from .active_active_trust import CHECKPOINT_TARGET, INSTALLATION, ORIGIN, RP

        for key, expected in (
            ("PAM_TRUST_INSTALLATION_ID", INSTALLATION), ("PAM_TRUST_RP_ID", RP),
            ("PAM_TRUST_ORIGIN", ORIGIN), ("PAM_TRUST_CHECKPOINT_DIRECTORY", CHECKPOINT_TARGET),
        ):
            require(first.get(key) == second.get(key) == expected,
                    "Both nodes require the exact synthetic PAM trust configuration.")
        for key in ("PAM_TRUST_COMMISSIONING_KEYS", "PAM_TRUST_CHECKPOINT_KEYS"):
            require(first.get(key) == second.get(key) and bool(json.loads(first.get(key, "{}"))),
                    "Both nodes require identical public synthetic trust anchors.")


def validate_rdp_network(info, node_ids):
    require(
        info.get("Name") == PROJECT + "_default"
        and (info.get("Labels") or {}).get("com.docker.compose.project") == PROJECT
        and info.get("Driver") == "bridge"
        and len(set(node_ids)) == 2
        and set(info.get("Containers") or {}) == set(node_ids),
        "Wrong RDP test network scope.",
    )


def partition_scope(network, node_a, node_b, route):
    """Prove the exact disposable node endpoint carries the dedicated DB connection."""
    name = network.get("Name", "")
    network_id = network.get("Id", "")
    members = network.get("Containers") or {}
    a, b = (item["Id"] for item in (node_a, node_b))
    links_a, links_b = (item["NetworkSettings"]["Networks"] for item in (node_a, node_b))
    default = PROJECT + "_default"
    require(
        name != default
        and network.get("Driver") == "bridge"
        and re.fullmatch(r"[a-f0-9]{64}", network_id)
        and a != b
        and a in members
        and b in members
        and all(set(links) == {default, name} for links in (links_a, links_b))
        and all(links[name].get("NetworkID") == network_id for links in (links_a, links_b)),
        "The qualification database network must be a distinct shared bridge.",
    )
    addresses = {key: item.get("IPv4Address", "").split("/")[0] for key, item in members.items()}
    require(
        bool(route.get("client"))
        and route["client"] == links_a[name]["IPAddress"] == addresses[a]
        and bool(route.get("server"))
        and sum(value == route["server"] for value in addresses.values()) == 1
        and route["server"] not in (addresses[a], addresses[b]),
        "The live PostgreSQL route does not use the expected network endpoints.",
    )
    namespace, other_namespace = (
        item["NetworkSettings"].get("SandboxKey", "") for item in (node_a, node_b)
    )
    require(
        namespace != other_namespace
        and all(
            re.fullmatch(r"/(?:var/)?run/docker/netns/[a-f0-9]{12,64}", value)
            for value in (namespace, other_namespace)
        )
        and all(
            item.get("HostConfig", {}).get("NetworkMode") in (default, name)
            for item in (node_a, node_b)
        ),
        "The qualification requires two distinct Docker-managed network namespaces.",
    )
    return namespace, f"{ipaddress.IPv4Address(route['server'])}/32"


def safe_relay_state(values):
    """Expose only a bounded test state, never relay IDs or arbitrary strings."""
    if not isinstance(values, list) or len(values) != 5:
        return {"state": "unavailable"}
    status, owner, reason, complete, recorded = values
    statuses = ("pending", "connecting", "active", "ended", "failed")
    owners = ("qualification-a", "qualification-b")
    reasons = (
        "",
        "stop_requested",
        "relay_owner_lost",
        "native_error",
        "native_closed",
        "client_closed",
        "authority_lost",
        "relay_failed",
        "database_unavailable",
        "relay_shutdown",
        "ticket_expired",
        "input_rate_exceeded",
    )
    return {
        "status": status if status in statuses else "unknown",
        "owner": owner if owner in owners else "unknown",
        "reason": reason if reason in reasons else "other",
        "complete": complete if type(complete) is bool else None,
        "recorded": recorded if type(recorded) is bool else None,
    }


class CSRFParser(HTMLParser):
    token = None

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "input" and attributes.get("name") == "csrfmiddlewaretoken":
            self.token = attributes.get("value")


class Browser:
    def __init__(self):
        self.cookies = SimpleCookie()

    def request(self, port, path, *, fields=None, payload=None, bearer=None):
        headers = {
            "Host": HOST,
            "Cookie": "; ".join(item.OutputString(attrs=[]) for item in self.cookies.values()),
        }
        method, body = "GET", None
        if fields is not None:
            method, body = "POST", urlencode(fields)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if payload is not None:
            method, body = "POST", json.dumps(payload)
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    self.cookies.load(value)
            content = response.read(2 * 1024 * 1024).decode("utf-8", errors="strict")
            return response.status, response.getheader("Location"), content
        finally:
            connection.close()

    def post(self, port, path, fields):
        status, _, content = self.request(port, path if path == "/accounts/login/" else "/")
        require(status == 200, "Cannot load guarded form.")
        parser = CSRFParser()
        parser.feed(content)
        token = parser.token or self.cookies.get("pamolive_platform_csrftoken")
        if hasattr(token, "value"):
            token = token.value
        require(bool(token), "Missing CSRF token.")
        return self.request(port, path, fields={**fields, "csrfmiddlewaretoken": token})


def totp(secret, timestamp=None):
    timestamp = time.time() if timestamp is None else timestamp
    digest = hmac.new(
        base64.b32decode(secret), struct.pack(">Q", int(timestamp) // 30), hashlib.sha1
    ).digest()
    offset = digest[-1] & 15
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1000000:06d}"


class Qualification:
    def __init__(
        self, docker, env_file, *, native_pam=False, native_rdp=False, database_partition=False
    ):
        self.docker = docker
        self.prefix = [
            docker,
            "compose",
            "--env-file",
            str(env_file),
            "-p",
            PROJECT,
            "-f",
            str(Path(__file__).with_name("compose.active-active-check.yml")),
        ]
        self.stage = "configuration"
        self.started = False
        self.native_pam = native_pam
        self.native_rdp = native_rdp
        self.database_partition = database_partition
        self.authority = None
        self.trust_stop, self.trust_thread = Event(), None
        self.trust_error = None
        self.trust_organizations = {}
        self.secondary_failures = []

    def prepare_authority(self):
        from .active_active_trust import CHECKPOINT_TARGET, QualificationAuthority

        self.authority = QualificationAuthority()
        override = Path(self.authority.temporary.name) / "compose.public-trust.json"
        override.write_text(json.dumps({"services": {
            node: {"environment": self.authority.settings(), "volumes": [{
                "type": "bind", "source": str(self.authority.directory.resolve()),
                "target": CHECKPOINT_TARGET, "read_only": True,
            }]} for node in ("node-a", "node-b")
        }}), encoding="utf-8")
        self.prefix.extend(["-f", str(override)])

    def start_witness(self):
        def refresh():
            try:
                while not self.trust_stop.is_set():
                    heads = json.loads(self.compose(
                        "exec", "-T", "--user", "1000:1000", "node-b", "python", "-m",
                        "deploy.active_active_trust", timeout=20,
                        content=json.dumps({"organizations": list(self.authority.keys)}) + "\n",
                    ))
                    for head in heads:
                        self.authority.checkpoint(head)
                    self.trust_stop.wait(1)
            except Exception as error:
                self.trust_error = type(error).__name__

        self.trust_thread = Thread(target=refresh, daemon=True)
        self.trust_thread.start()

    def trust_signature(self, run, report):
        require(self.authority is not None and self.trust_error is None,
                "The external synthetic witness is unavailable.")
        organization = self.trust_organizations[run]
        if report.get("stage") == "trust-authenticate":
            return self.authority.authenticate(organization, report)
        return self.authority.sign_registry(organization, report["body"])

    def command(self, *arguments, timeout=90, content=None):
        return subprocess.run(
            arguments, check=True, capture_output=True, text=True, timeout=timeout, input=content
        ).stdout

    def compose(self, *arguments, timeout=90, content=None):
        return self.command(*self.prefix, *arguments, timeout=timeout, content=content)

    def node(self, name):
        identifier = self.compose("ps", "--all", "-q", name).strip()
        require(bool(identifier), "Missing qualification node.")
        data = json.loads(self.command(self.docker, "inspect", identifier))[0]
        labels = data["Config"]["Labels"]
        require(
            labels.get("com.docker.compose.project") == PROJECT
            and labels.get("com.docker.compose.service") == name,
            "Wrong container scope.",
        )
        return identifier, data

    def port(self, name):
        _, data = self.node(name)
        ports = (data["NetworkSettings"].get("Ports") or {}).get("8000/tcp") or []
        require(len(ports) == 1 and ports[0]["HostIp"] == "127.0.0.1", "Unsafe test listener.")
        return int(ports[0]["HostPort"])

    def wait_ready(self, name):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                port = self.port(name)
                if Browser().request(port, "/health/")[0] == 200:
                    return port
            except (OSError, RuntimeError, http.client.HTTPException):
                pass
            time.sleep(1)
        raise RuntimeError("Qualification node did not become ready.")

    def fixture(self, action, run="", *, node="node-b", content=None):
        arguments = [
            "exec",
            "-T",
            "--user",
            "1000:1000",
            node,
            "python",
            "-m",
            "deploy.active_active_fixture",
            action,
        ]
        if run:
            arguments.extend(["--run", run])
        if action == "prepare" and self.authority:
            organization = list(self.authority.keys)[len(self.trust_organizations)]
            arguments.extend(["--organization", organization])
        result = json.loads(self.compose(*arguments, content=content))
        if action == "prepare" and self.authority:
            self.trust_organizations[result["run"]] = result["organization"]
        return result

    def kill_node_a(self):
        identifier, _ = self.node("node-a")
        self.command(self.docker, "kill", "--signal", "KILL", identifier)

    def check_database_partition(self, network_name, b, browser, data, event):
        self.stage = "validate the dedicated PostgreSQL network path"
        _, node_a = self.node("node-a")
        _, node_b = self.node("node-b")
        network = json.loads(self.command(self.docker, "network", "inspect", network_name))[0]
        require(network.get("Name") == network_name, "Unexpected database network.")
        route = self.fixture("database-route", node="node-a")
        namespace, destination = partition_scope(network, node_a, node_b, route)
        route_command = ("sudo", "-n", "nsenter", f"--net={namespace}", "ip", "-4", "route")
        require(
            not self.command(*route_command, "show", "exact", destination).strip(),
            "Refusing to replace an existing database host route.",
        )
        baseline = self.fixture("inspect", data["run"])
        payload = {**event, "external_id": "ha-database-partition"}
        self.stage = "install unreachable route for the exact database address"
        rule = ("unreachable", destination, "proto", "static")
        self.command(*route_command, "add", *rule)
        primary_error = None
        try:
            self.stage = "inspect live node A with database address blocked"
            isolated = self.node("node-a")[1]
            require(
                isolated["Id"] == node_a["Id"]
                and isolated["NetworkSettings"]["SandboxKey"] == namespace
                and isolated["State"]["StartedAt"] == node_a["State"]["StartedAt"],
                "Node A did not remain alive in its private test network namespace.",
            )
            self.stage = "probe isolated A loopback HTTP health and ingestion"
            observed = self.fixture(
                "partition-probe",
                node="node-a",
                content=json.dumps({"event": payload, "token": data["source_token"]}),
            )
            require(
                observed["health"] == 503 and observed["ingest"] in (500, 503),
                "An isolated node must fail its health check and refuse writes.",
            )
            self.stage = "validate no isolated write and healthy surviving B"
            require(
                self.fixture("inspect", data["run"]) == baseline,
                "The rejected write changed authoritative state.",
            )
            require(
                Browser().request(b, "/health/")[0] == 200
                and browser.request(b, "/identities/")[0] == 200,
                "Node B became unavailable during node A's database partition.",
            )
            self.stage = "commit the same event on B during database isolation"
            status, _, response = Browser().request(
                b, "/api/v1/events/", payload=payload, bearer=data["source_token"]
            )
            require(status == 201, "Node B could not commit during node A's database partition.")
            event_id = json.loads(response)["event_id"]
        except BaseException as error:
            primary_error = error
            raise
        finally:
            previous_stage = self.stage
            self.stage = "remove only the installed database route"
            try:
                self.command(*route_command, "del", *rule)
            except Exception as cleanup_error:
                if primary_error is None:
                    raise
                # A vanished test namespace must not hide the probe failure
                # that caused cleanup. Do not touch another namespace/route.
                self.secondary_failures.append({
                    "stage": "remove only the installed database route",
                    "error": type(cleanup_error).__name__,
                    "category": subprocess_category(cleanup_error),
                })
            finally:
                if primary_error is not None:
                    self.stage = previous_stage
            if primary_error is None:
                self.stage = previous_stage
        self.stage = "original node A's published port becomes healthy again"
        a = self.wait_ready("node-a")
        returned = self.node("node-a")[1]
        require(
            returned["Id"] == node_a["Id"]
            and returned["NetworkSettings"]["SandboxKey"] == namespace
            and returned["State"]["StartedAt"] == node_a["State"]["StartedAt"],
            "Node A was restarted instead of recovering its database route.",
        )
        require(
            browser.request(a, "/identities/")[0] == 200,
            "The shared session did not survive the database partition.",
        )
        self.stage = "recovered node A deduplicates the committed event"
        status, _, response = Browser().request(
            a, "/api/v1/events/", payload=payload, bearer=data["source_token"]
        )
        require(
            status == 200 and json.loads(response)["event_id"] == event_id,
            "Node A did not deduplicate the event committed by node B.",
        )
        require(
            self.fixture("inspect", data["run"])
            == {
                **baseline,
                "events": baseline["events"] + 1,
                "received_audits": baseline["received_audits"] + 1,
            },
            "Recovery must preserve one event, one audit, and the other tenant's state.",
        )
        return {
            "isolated_health_unavailable": True,
            "isolated_write_refused": True,
            "surviving_node_committed": True,
            "original_node_rejoined_without_restart": True,
            "replay_deduplicated": True,
        }

    def native_ssh(self, run, browser):
        _, b = self.node("node-b")
        peer_ip = b["NetworkSettings"]["Networks"][PROJECT + "_default"]["IPAddress"]
        session = browser.cookies["pamolive_platform_session"].value
        csrf = browser.cookies["pamolive_platform_csrftoken"].value
        with subprocess.Popen(
            self.prefix
            + [
                "exec",
                "-T",
                "--user",
                "1000:1000",
                "node-b",
                "python",
                "-m",
                "deploy.active_active_ssh",
            ],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as worker:
            messages = queue.Queue()

            def read_reports():
                for line in worker.stdout:
                    report = json.loads(line)
                    if report.get("stage") in ("trust-sign", "trust-authenticate"):
                        worker.stdin.write(json.dumps(self.trust_signature(run, report)) + "\n")
                        worker.stdin.flush()
                        continue
                    messages.put(line)
                messages.put("")

            Thread(target=read_reports, daemon=True).start()
            try:
                worker.stdin.write(
                    json.dumps(dict(
                        run=run, peer_ip=peer_ip, session=session, csrf=csrf,
                        authority=self.authority.commissioning(self.trust_organizations[run]),
                    ))
                )
                worker.stdin.write("\n")
                worker.stdin.flush()
                first = json.loads(messages.get(timeout=160))
                if first.get("stage") == "failed":
                    self.stage = "native SSH: " + first["phase"] + " (" + first["error"] + ")"
                require(first == {"stage": "kill-node-a"}, "Native relay preparation failed.")
                self.stage = "native SSH on surviving node and durable orphan cleanup"
                self.kill_node_a()
                worker.stdin.write("node-a-killed\n")
                worker.stdin.flush()
                report = json.loads(messages.get(timeout=85))
                if report.get("stage") == "failed":
                    self.stage = "native SSH: " + report["phase"] + " (" + report["error"] + ")"
                require(report.pop("stage") == "complete", "Native relay fault check failed.")
                require(
                    set(report)
                    == {
                        "both_native_relays_active",
                        "shared_ticket_replay_refused",
                        "stopped_on_other_node",
                        "surviving_ssh_session_roundtrip",
                        "lost_relay_reaped_with_partial_capture",
                    }
                    and all(value is True for value in report.values()),
                    "Incomplete native relay proof.",
                )
                require(worker.wait(timeout=15) == 0, "Native relay fixture did not exit cleanly.")
                return report
            finally:
                if worker.poll() is None:
                    worker.kill()

    def native_rdp_check(self, run, browser):
        network = PROJECT + "_default"
        (info,) = json.loads(self.command(self.docker, "network", "inspect", network))
        validate_rdp_network(info, [self.node(name)[1]["Id"] for name in ("node-a", "node-b")])
        token = uuid.uuid4().hex
        name = PROJECT + "-rdp-" + token
        peer_args = [
            self.docker,
            "run",
            "--rm",
            "-i",
            "--pull",
            "never",
            "--name",
            name,
            "--label",
            "io.pamolive.ha-rdp=" + token,
            "--network",
            network,
            "--network-alias",
            "ha-rdp-fixture",
            "--init",
            "--user",
            "1000:1000",
            "--read-only",
            "--tmpfs",
            "/tmp:size=64m,mode=1777",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "-e",
            "PAMOLIVE_HA_RDP_PEER=1",
            "--entrypoint",
            "python",
            "pamolive-platform:native-test",
            "-m",
            "deploy.active_active_rdp",
            "peer",
        ]

        def database(action, payload):
            arguments = self.prefix + ["exec", "-T", "--user", "1000:1000", "node-b",
                                       "python", "-m", "deploy.active_active_rdp", action]
            with subprocess.Popen(arguments, text=True, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as helper:
                reports = queue.Queue()

                def read_helper():
                    for line in helper.stdout:
                        reports.put(line)
                    reports.put("")

                Thread(target=read_helper, daemon=True).start()
                try:
                    helper.stdin.write(json.dumps(payload) + "\n")
                    helper.stdin.flush()
                    deadline = time.monotonic() + 90
                    for _ in range(32):
                        line = reports.get(timeout=max(0.1, deadline - time.monotonic()))
                        require(bool(line), "The scoped RDP helper did not return a result.")
                        result = json.loads(line)
                        if result.get("stage") in ("trust-sign", "trust-authenticate"):
                            helper.stdin.write(json.dumps(self.trust_signature(run, result)) + "\n")
                            helper.stdin.flush()
                        else:
                            break
                    else:
                        raise RuntimeError("Too many synthetic RDP commissioning messages.")
                    require(helper.wait(timeout=15) == 0, "The scoped RDP helper failed.")
                finally:
                    if helper.poll() is None:
                        helper.kill()
            require(
                result.pop("stage") == {"prepare": "prepared", "state": "state"}[action],
                "RDP database fixture refused.",
            )
            return result

        def wait_state(organization, expected):
            deadline = time.monotonic() + 50
            actual = {}
            while time.monotonic() < deadline:
                result = database("state", {"organization": organization, "keys": list(expected)})
                actual = result.get("relays") or {}
                if actual == expected:
                    return
                if any(
                    safe_relay_state(actual.get(key)).get("status") in ("ended", "failed")
                    and actual[key] != value
                    for key, value in expected.items()
                ):
                    break
                time.sleep(0.5)
            print(
                json.dumps(
                    {
                        "rdp_state_mismatch": [
                            {
                                "slot": slot,
                                "expected": safe_relay_state(wanted),
                                "observed": safe_relay_state(actual.get(key)),
                            }
                            for slot, (key, wanted) in enumerate(expected.items(), 1)
                        ],
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            raise RuntimeError("Durable RDP state or recording did not match.")

        with subprocess.Popen(
            peer_args,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as worker:
            messages = queue.Queue()

            def receive_lines():
                for line in worker.stdout:
                    report = json.loads(line)
                    if report.get("stage") == "trust-authenticate":
                        worker.stdin.write(json.dumps(self.trust_signature(run, report)) + "\n")
                        worker.stdin.flush()
                        continue
                    messages.put(line)
                messages.put("")

            def receive(stage, timeout=120):
                data = json.loads(messages.get(timeout=timeout))
                if data.get("stage") == "failed":
                    self.stage = "RDP peer " + data["phase"] + " (" + data["error"] + ")"
                require(data.pop("stage") == stage, "Unexpected test-peer phase.")
                return data

            def send(line):
                worker.stdin.write(line + "\n")
                worker.stdin.flush()

            def validate_ids(report, names):
                require(
                    set(report) == set(names)
                    and all(str(uuid.UUID(value)) == value for value in report.values())
                    and len(set(report.values())) == len(names),
                    "Unexpected test relay identifiers.",
                )

            active_a = ["active", "qualification-a", "", False, True]
            active_b = ["active", "qualification-b", "", False, True]
            Thread(target=receive_lines, daemon=True).start()
            try:
                self.stage = "start isolated RDP peer and prepare pinned intents"
                ready = receive("ready", timeout=35)
                require(
                    set(ready) == {"pin", "password"}
                    and re.fullmatch(r"[0-9a-f]{64}", ready["pin"])
                    and re.fullmatch(r"[a-zA-Z0-9_-]{32}", ready["password"]),
                    "Unexpected RDP test credentials.",
                )
                prepared = database("prepare", {
                    "run": run, **ready,
                    "session": browser.cookies["pamolive_platform_session"].value,
                    "authority": self.authority.commissioning(self.trust_organizations[run]),
                })
                authenticator = prepared.pop("authenticator")
                validate_ids(prepared, ("organization", "intent_a", "intent_b"))
                org = prepared.pop("organization")
                send(
                    json.dumps(
                        {
                            **prepared,
                            "authenticator": authenticator,
                            "session": browser.cookies["pamolive_platform_session"].value,
                            "csrf": browser.cookies["pamolive_platform_csrftoken"].value,
                        }
                    )
                )
                self.stage = "two simultaneous recorded RDP sessions"
                both = receive("both-active")
                validate_ids(both, ("a", "b"))
                wait_state(org, {both["a"]: active_a, both["b"]: active_b})
                send("both-recorded")
                self.stage = "remote stop followed by a newly opened RDP relay"
                before = receive("kill-node-a")
                validate_ids(before, ("a", "b", "c"))
                require(
                    all(before[key] == value for key, value in both.items()),
                    "RDP relay identifiers changed.",
                )
                wait_state(
                    org,
                    {
                        before["a"]: ["ended", "qualification-a", "stop_requested", False, True],
                        before["b"]: active_b,
                        before["c"]: active_a,
                    },
                )
                self.kill_node_a()
                send("node-a-killed")
                self.stage = "RDP input on node B and orphaned partial recording on node A"
                surviving = receive("surviving", timeout=60)
                require(
                    surviving == {key: before[key] for key in ("b", "c")}, "Wrong surviving relays."
                )
                print(
                    "RDP node B accepted a post-fault key and returned the new target color.",
                    flush=True,
                )
                self.stage = "durable RDP survivor and orphan recording state"
                wait_state(
                    org,
                    {
                        before["b"]: active_b,
                        before["c"]: ["failed", "qualification-a", "relay_owner_lost", False, True],
                    },
                )
                send("orphan-verified")
                require(receive("complete", timeout=25) == {}, "Unexpected final RDP report.")
                require(worker.wait(timeout=15) == 0, "RDP peer did not exit cleanly.")
                return {
                    "both_pinned_rdp_nla_relays_recorded": True,
                    "shared_ticket_replay_refused": True,
                    "stopped_on_other_node": True,
                    "surviving_rdp_session_accepts_input": True,
                    "lost_relay_reaped_with_partial_capture": True,
                }
            finally:
                if worker.poll() is None:
                    try:
                        # Identify by the exact invocation label, never by a name alone.
                        peers = self.command(
                            self.docker,
                            "ps",
                            "-q",
                            "--filter",
                            "label=io.pamolive.ha-rdp=" + token,
                        ).splitlines()
                        if len(peers) == 1 and re.fullmatch(r"[0-9a-f]{12,64}", peers[0]):
                            self.command(self.docker, "stop", "-t", "3", peers[0], timeout=12)
                    finally:
                        if worker.poll() is None:
                            worker.kill()

    def execute(self):
        config = json.loads(self.compose("config", "--format", "json"))
        validate_configuration(config)
        if self.native_pam or self.native_rdp:
            self.prepare_authority()
            config = json.loads(self.compose("config", "--format", "json"))
            validate_configuration(config, checkpoint_directory=self.authority.directory)
        database_network = config.get("networks", {}).get("database", {})
        network_name = database_network.get("name", "")
        if self.database_partition:
            require(
                database_network.get("external") is True
                and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", network_name),
                "The partition requires an explicit external database bridge.",
            )
        existing = self.command(
            self.docker, "ps", "-aq", "--filter", "label=com.docker.compose.project=" + PROJECT
        )
        require(
            not existing.strip(),
            "Qualification project already exists; inspect it before retrying.",
        )
        self.started = True
        self.stage = "dedicated test schema migration"
        self.compose(
            "run",
            "--rm",
            "-T",
            "--user",
            "1000:1000",
            "node-b",
            "python",
            "-c",
            "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); "
            "import django; django.setup(); "
            "from deploy.active_active_fixture import require_test_database; "
            "require_test_database(); from django.core.management import call_command; "
            "call_command('migrate', interactive=False)",
            timeout=180,
        )
        self.stage = "two active runtimes"
        self.compose("up", "-d", "--no-build", timeout=120)
        a, b = self.wait_ready("node-a"), self.wait_ready("node-b")
        for name in ("node-a", "node-b"):
            self.compose("exec", "-T", name, "python", "-m", "deploy.check_runtime")
        require(
            self.node("node-a")[1]["Image"] == self.node("node-b")[1]["Image"],
            "Different node images.",
        )
        if self.authority:
            self.start_witness()
        data = self.fixture("prepare")
        browser = Browser()
        self.stage = "A login, B session and MFA replay rejection"
        code = totp(data["totp_secret"])
        credentials = {"username": data["username"], "password": data["password"], "otp": code}
        require(browser.post(a, "/accounts/login/", credentials)[0] == 302, "Node A login failed.")
        require(
            browser.request(b, "/identities/")[0] == 200,
            "Node B did not accept the shared session.",
        )
        require(
            Browser().post(b, "/accounts/login/", credentials)[0] == 200,
            "TOTP replay accepted on node B.",
        )
        self.stage = "personal recent MFA and module state across nodes"
        status, location, _ = browser.post(b, "/modules/intelligence/disable/", {})
        require(
            status == 302 and location == "/modules/", "Node B did not accept personal recent MFA."
        )
        require(
            browser.request(a, "/intelligence/")[0] == 403, "Node A retained a disabled module."
        )
        status, location, _ = browser.post(a, "/modules/intelligence/install/", {})
        require(
            status == 302 and location == "/modules/", "Node A could not reactivate the module."
        )
        require(
            browser.request(b, "/intelligence/")[0] == 200,
            "Node B did not see module reactivation.",
        )
        self.stage = "one-use recovery code across both nodes"
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    lambda port: Browser().post(
                        port, "/accounts/login/", {**credentials, "otp": data["recovery"]}
                    )[0],
                    (a, b),
                )
            )
        require(sorted(results) == [200, 302], "Recovery code was not consumed exactly once.")
        self.stage = "tenant switch and cross-tenant isolation"
        require(
            browser.post(a, "/organizations/switch/", {"organization": data["other_organization"]})[
                0
            ]
            == 302,
            "Organization switch failed.",
        )
        require(
            browser.request(b, "/records/identity/" + data["identity"] + "/")[0] == 404,
            "Foreign identity was exposed on node B.",
        )
        require(
            browser.post(b, "/organizations/switch/", {"organization": data["organization"]})[0]
            == 302,
            "Return to original organization failed.",
        )
        require(
            browser.request(a, "/records/identity/" + data["identity"] + "/")[0] == 200,
            "Node A did not see the organization switch.",
        )
        self.stage = "simultaneous source replay on both nodes"
        event = {
            "external_id": "ha-simultaneous",
            "identity": data["identity"],
            "resource": data["resource"],
            "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": "badge",
            "action": "badge.presented",
            "result": "success",
        }
        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(
                executor.map(
                    lambda port: Browser().request(
                        port, "/api/v1/events/", payload=event, bearer=data["source_token"]
                    ),
                    (a, b),
                )
            )
        require(
            sorted(item[0] for item in responses) == [200, 201],
            "Concurrent source replay was not deduplicated.",
        )
        require(
            len({json.loads(item[2])["event_id"] for item in responses}) == 1,
            "Replay produced two events.",
        )
        self.stage = "two durable job processes, one expiration"
        self.fixture("arm", data["run"])
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            state = self.fixture("inspect", data["run"])
            if state["grant_status"] == "revoked":
                break
            time.sleep(1)
        require(
            state["grant_status"] == "revoked"
            and state["grant_revocations"] == 1
            and state["grant_revision"] == 2,
            "Durable expiration was lost or duplicated.",
        )
        native = {}
        if self.native_pam:
            self.stage = "native SSH, one-use cross-node ticket and remote stop"
            native = self.native_ssh(data["run"], browser)
        else:
            self.kill_node_a()
        self.stage = "abrupt node A loss, authenticated node B continuation"
        require(
            browser.request(b, "/records/identity/" + data["identity"] + "/")[0] == 200,
            "Shared session did not survive node A loss.",
        )
        require(
            Browser().request(
                b,
                "/api/v1/events/",
                payload={**event, "external_id": "ha-after-loss"},
                bearer=data["source_token"],
            )[0]
            == 201,
            "Node B could not write after node loss.",
        )
        self.stage = "node A return and final proof verification"
        self.compose("start", "node-a", timeout=90)
        a = self.wait_ready("node-a")
        require(
            browser.request(a, "/identities/")[0] == 200,
            "Recovered node did not accept the existing session.",
        )
        state = self.fixture("inspect", data["run"])
        require(
            state
            == {
                "events": 2,
                "received_audits": 2,
                "other_events": 0,
                "grant_status": "revoked",
                "grant_revision": 2,
                "grant_revocations": 1,
                "audit_valid": True,
            },
            "Final shared state differs from expected proofs.",
        )
        partition = {}
        if self.database_partition:
            partition = self.check_database_partition(network_name, b, browser, data, event)
            a = self.port("node-a")
        native_rdp = {}
        if self.native_rdp:
            self.stage = "independent test organization for RDP"
            rdp_data = self.fixture("prepare")
            rdp_browser = Browser()
            require(
                rdp_browser.post(
                    a,
                    "/accounts/login/",
                    {
                        "username": rdp_data["username"],
                        "password": rdp_data["password"],
                        "otp": totp(rdp_data["totp_secret"]),
                    },
                )[0]
                == 302,
                "RDP test login failed.",
            )
            native_rdp = self.native_rdp_check(rdp_data["run"], rdp_browser)
            self.stage = "node A returns after RDP fault"
            self.compose("start", "node-a", timeout=90)
            a = self.wait_ready("node-a")
            require(
                rdp_browser.request(a, "/identities/")[0] == 200,
                "Recovered RDP node lost the shared session.",
            )
            require(
                self.fixture("inspect", rdp_data["run"])["audit_valid"], "RDP audit chain failed."
            )
        scope = ", ".join(
            ["HTTP", *(["native SSH"] if native else []), *(["native RDP"] if native_rdp else [])]
        )
        return {
            "result": "OK",
            "nodes": 2,
            "same_image": True,
            "shared_session": True,
            "cross_node_totp_replay_refused": True,
            "recovery_consumed_once": True,
            "personal_mfa_shared": True,
            "module_state_shared": True,
            "tenant_isolation": True,
            "concurrent_ingestion_deduplicated": True,
            "durable_expiration_once": True,
            "session_after_abrupt_node_loss": True,
            "write_after_node_loss": True,
            "session_after_node_return": True,
            "audit_valid": True,
            "native_ssh": native,
            "native_rdp": native_rdp,
            "database_partition": partition,
            "scope": scope + ", same-host fault injection; not VM/database HA or live PAM handover",
        }

    def cleanup(self):
        self.trust_stop.set()
        if self.trust_thread:
            self.trust_thread.join(timeout=25)
            require(not self.trust_thread.is_alive(), "The synthetic witness did not stop.")
        if self.started:
            self.compose("down", "--remove-orphans", timeout=120)
        if self.authority:
            self.authority.close()

    def preserve_failure(self, error):
        directory = Path(tempfile.mkdtemp(prefix="pamolive-ha-failure-"))
        os.chmod(directory, 0o700)
        items = {"stage.txt": self.stage + "\n" + type(error).__name__}
        if self.secondary_failures:
            items["secondary-failures.json"] = json.dumps(self.secondary_failures)
        if isinstance(error, subprocess.CalledProcessError):
            items["command.stderr.txt"] = error.stderr or ""
            items["command.stdout.txt"] = error.stdout or ""
        if isinstance(error, RuntimeError):
            items["assertion.txt"] = str(error)
        if self.started:
            for name in ("node-a", "node-b"):
                try:
                    identifier, _ = self.node(name)
                    process = subprocess.run(
                        [self.docker, "logs", "--tail", "160", identifier],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    items[name + ".log"] = process.stdout + process.stderr
                except Exception:
                    items[name + ".log"] = "Unable to collect this temporary node's log."
        for name, content in items.items():
            descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
        return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--native-pam", action="store_true")
    parser.add_argument("--native-rdp", action="store_true")
    parser.add_argument(
        "--database-partition",
        action="store_true",
        help="block the proved database address in node A's private Linux network namespace",
    )
    args = parser.parse_args()
    check = Qualification(
        args.docker,
        args.env_file.resolve(),
        native_pam=args.native_pam,
        native_rdp=args.native_rdp,
        database_partition=args.database_partition,
    )
    try:
        report = check.execute()
    except Exception as error:
        print(
            f"Active-active check failed at {check.stage} ({type(error).__name__}); "
            "captured output and credentials suppressed."
        )
        if isinstance(error, subprocess.CalledProcessError):
            print("Restricted subprocess category: " + subprocess_category(error))
        for secondary in check.secondary_failures:
            print("Secondary route cleanup category: " + secondary["category"])
        print("Private failure evidence: " + str(check.preserve_failure(error)))
        raise SystemExit(1) from None
    finally:
        try:
            check.cleanup()
        except Exception:
            print("Temporary qualification cleanup failed; inspect project " + PROJECT)
            raise SystemExit(1) from None
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
