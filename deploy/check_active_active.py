"""Disposable two-node qualification; Python 3.8+ and Docker Compose, no local Django.

The fixed Compose project is deliberately unrelated to production. Only its two
containers are killed/restarted. The existing private test database is never dropped.
Captured Docker/HTTP output is not printed, because fixtures contain test credentials.
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import queue
import re
import struct
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qsl, urlencode, urlsplit

PROJECT = "pamolive-platform-ha-check"
HOST = "ha.pamolive.test"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_configuration(config):
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
        require(not service.get("volumes"), "Qualification must not mount business files.")
        urls.add(url)
        images.add(service.get("image"))
    require(len(urls) == len(images) == 1, "Nodes must share the same database and image.")
    first, second = (services[name]["environment"] for name in ("node-a", "node-b"))
    for key in ("SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY"):
        require(
            first.get(key) == second.get(key) and len(first.get(key, "")) >= 40,
            "Shared test keys required.",
        )


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
    def __init__(self, docker, env_file, *, native_pam=False):
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

    def command(self, *arguments, timeout=90):
        return subprocess.run(
            arguments, check=True, capture_output=True, text=True, timeout=timeout
        ).stdout

    def compose(self, *arguments, timeout=90):
        return self.command(*self.prefix, *arguments, timeout=timeout)

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
        ports = data["NetworkSettings"]["Ports"]["8000/tcp"]
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

    def fixture(self, action, run=""):
        arguments = [
            "exec",
            "-T",
            "--user",
            "1000:1000",
            "node-b",
            "python",
            "-m",
            "deploy.active_active_fixture",
            action,
        ]
        if run:
            arguments.extend(["--run", run])
        return json.loads(self.compose(*arguments))

    def kill_node_a(self):
        identifier, _ = self.node("node-a")
        self.command(self.docker, "kill", "--signal", "KILL", identifier)

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
                    messages.put(line)
                messages.put("")

            Thread(target=read_reports, daemon=True).start()
            try:
                worker.stdin.write(
                    json.dumps(dict(run=run, peer_ip=peer_ip, session=session, csrf=csrf))
                )
                worker.stdin.write("\n")
                worker.stdin.flush()
                first = json.loads(messages.get(timeout=160))
                if first.get("stage") == "failed":
                    self.stage = "native SSH: " + first["phase"]
                require(first == {"stage": "kill-node-a"}, "Native relay preparation failed.")
                self.stage = "native SSH on surviving node and durable orphan cleanup"
                self.kill_node_a()
                worker.stdin.write("node-a-killed\n")
                worker.stdin.flush()
                report = json.loads(messages.get(timeout=85))
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

    def execute(self):
        validate_configuration(json.loads(self.compose("config", "--format", "json")))
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
            "scope": ("HTTP and native SSH" if native else "HTTP/application")
            + ", same-host fault injection; not VM/database HA or live PAM handover",
        }

    def cleanup(self):
        if self.started:
            self.compose("down", "--remove-orphans", timeout=120)

    def preserve_failure(self, error):
        directory = Path(tempfile.mkdtemp(prefix="pamolive-ha-failure-"))
        os.chmod(directory, 0o700)
        items = {"stage.txt": self.stage + "\n" + type(error).__name__}
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
    args = parser.parse_args()
    check = Qualification(args.docker, args.env_file.resolve(), native_pam=args.native_pam)
    try:
        report = check.execute()
    except Exception as error:
        print(
            f"Active-active check failed at {check.stage} ({type(error).__name__}); "
            "captured output and credentials suppressed."
        )
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
