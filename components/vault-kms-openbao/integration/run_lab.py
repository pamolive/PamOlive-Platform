"""Start and retire a fresh signed OpenBao process on the ephemeral Linux CI runner."""

import http.client
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ADDRESS = "127.0.0.1"
SERVER = "openbao-n0.test"
PORT = 8200
KEYS = ("tenant-a", "tenant-b")
LIMIT = 8192
HERE = Path(__file__).resolve().parent


def need(condition):
    if not condition:
        raise ValueError("synthetic_openbao_refused")


def command(argv, root, *, timeout=12):
    result = subprocess.run(
        argv,
        cwd=root,
        env=environment(root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    need(result.returncode == 0 and len(result.stdout) <= LIMIT)
    return result.stdout


def environment(root):
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root)}


def certs(root):
    sys.path.insert(0, str(HERE.parent / "tests"))
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from test_loopback import issue

    ca = issue(root, "lab-ca")
    foreign = issue(root, "foreign-ca")
    issue(root, SERVER, ca, ExtendedKeyUsageOID.SERVER_AUTH)
    issue(root, "administrator", ca, ExtendedKeyUsageOID.CLIENT_AUTH)
    issue(root, "client", ca, ExtendedKeyUsageOID.CLIENT_AUTH)
    issue(root, "foreign-client", foreign, ExtendedKeyUsageOID.CLIENT_AUTH)


class Administration:
    def __init__(self, root):
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.tls.hostname_checks_common_name = False
        self.tls.load_verify_locations(cafile=str(root / "lab-ca.crt"))
        self.tls.load_cert_chain(root / "administrator.crt", root / "administrator.key")
        self.token = None

    def request(self, method, path, payload=None, *, status=(200, 204)):
        headers = {"Connection": "close", "Content-Type": "application/json"}
        if self.token is not None:
            headers["X-Vault-Token"] = self.token
        wire = json.dumps(payload).encode("ascii") if payload is not None else None
        connection = http.client.HTTPConnection(SERVER, PORT, timeout=2)
        try:
            with socket.create_connection((ADDRESS, PORT), timeout=2) as raw:
                connection.sock = self.tls.wrap_socket(raw, server_hostname=SERVER)
                connection.request(method, "/v1/" + path, body=wire, headers=headers)
                with connection.getresponse() as response:
                    need(response.status in status)
                    body = response.read(LIMIT + 1)
                    need(len(body) <= LIMIT)
            return json.loads(body) if body else None
        finally:
            connection.close()

    def initialize(self):
        state = self.request("PUT", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        need(len(state["keys_base64"]) == 1 and type(state["root_token"]) is str)
        self.token = state["root_token"]
        return state["keys_base64"][0]

    def unseal(self, share):
        state = self.request("PUT", "sys/unseal", {"key": share})
        need(state["sealed"] is False)

    def read_key(self, name, min_encrypt):
        state = self.request("GET", "transit/keys/" + name)["data"]
        need(state["type"] == "aes256-gcm96" and state["name"] == name)
        need(
            all(
                state[key] is False
                for key in (
                    "derived",
                    "exportable",
                    "allow_plaintext_backup",
                    "deletion_allowed",
                )
            )
        )
        # Transit omits convergent_encryption in metadata for non-derived keys.
        need(state.get("convergent_encryption", False) is False)
        need(
            state["min_decryption_version"] == 1 and state["min_encryption_version"] == min_encrypt
        )
        need(state["latest_version"] == max(1, min_encrypt))

    def provision(self):
        self.request("POST", "sys/mounts/transit", {"type": "transit"})
        self.request("POST", "transit/config/keys", {"disable_upsert": True})
        need(self.request("GET", "transit/config/keys")["data"]["disable_upsert"] is True)
        tokens = []
        for key in KEYS:
            self.request("POST", "transit/keys/" + key, {"type": "aes256-gcm96"})
            self.read_key(key, 0)
            paths = [f"transit/{operation}/{key}" for operation in ("encrypt", "decrypt")]
            if key == KEYS[0]:
                paths.append("transit/encrypt/tenant-unprovisioned")
            rules = "\n".join(f'path "{path}" {{ capabilities = ["update"] }}' for path in paths)
            self.request("PUT", "sys/policies/acl/" + key, {"policy": rules})
            response = self.request(
                "POST",
                "auth/token/create",
                {
                    "policies": [key],
                    "no_default_policy": True,
                    "renewable": False,
                    "ttl": "5m",
                },
            )["auth"]
            need(response["policies"] == [key] and 0 < response["lease_duration"] <= 300)
            tokens.append(response["client_token"])
        return tokens

    def rotate(self):
        for key in KEYS:
            self.request("POST", "transit/keys/" + key + "/rotate", {})
            self.request(
                "POST",
                "transit/keys/" + key + "/config",
                {
                    "min_encryption_version": 2,
                    "min_decryption_version": 1,
                },
            )
            self.read_key(key, 2)


def reception(root, phase, expected):
    stdout = command(
        [
            sys.executable,
            "-I",
            "-B",
            str(HERE / "test_lab.py"),
            "--manifest",
            str(root / "manifest.json"),
            "--phase",
            phase,
            "--envelope",
            str(root / "old-envelope.json"),
        ],
        root,
    )
    result = json.loads(stdout)
    need(
        result
        == {
            "schema": "pamolive.openbao.synthetic-reception/1",
            "phase": phase,
            "tests": expected,
            "failures": 0,
            "errors": 0,
            "skips": 0,
            "ok": True,
            "authority": False,
            "kek_material_received": False,
        }
    )
    return result


def start(binary, root, config):
    with (root / "server-diagnostic.log").open("wb") as log:
        return subprocess.Popen(
            [str(binary), "server", "-config", str(config)],
            cwd=root,
            env=environment(root),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )


def startup_failure(root, server, error):
    if server.poll() is None:
        return (
            "seal_status_tls_refused"
            if isinstance(error, ssl.SSLError)
            else "seal_status_unconfirmed"
        )
    with (root / "server-diagnostic.log").open("rb") as log:
        raw = log.read(16 * 1024)
    for code, markers in (
        ("listener_address_in_use", (b"address already in use",)),
        ("listener_configuration", (b"initializing listener", b"TLS config")),
        ("storage_configuration", (b"storage backend", b"storage migration")),
        ("configuration_syntax", (b"Error parsing", b"Error loading configuration")),
    ):
        if any(marker in raw for marker in markers):
            return code
    return "openbao_exited"


def wait_for_seal_status(server, admin, *, initialized):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        need(server.poll() is None)
        try:
            state = admin.request("GET", "sys/seal-status")
        except (ConnectionError, TimeoutError):
            time.sleep(0.15)
        else:
            need(state["initialized"] is initialized and state["sealed"] is True)
            return
    need(False)


def stop(server):
    if server.poll() is not None:
        return False
    server.send_signal(signal.SIGTERM)
    try:
        return server.wait(timeout=12) == 0
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
        return False


def run(binary, root, report):
    report["phase"] = "fixtures"
    certs(root)
    storage = root / "storage"
    storage.mkdir(mode=0o700)
    config = root / "lab.hcl"
    config.write_text(
        f'''
disable_mlock = true
log_level = "error"
api_addr = "https://{SERVER}:{PORT}"
storage "file" {{ path = {json.dumps(str(storage))} }}
listener "tcp" {{
  address = "{ADDRESS}:{PORT}"
  tls_cert_file = {json.dumps(str(root / (SERVER + ".crt")))}
  tls_key_file = {json.dumps(str(root / (SERVER + ".key")))}
  tls_client_ca_file = {json.dumps(str(root / "lab-ca.crt"))}
  tls_require_and_verify_client_cert = true
  tls_min_version = "tls13"
  max_request_size = 8192
}}
''',
        encoding="ascii",
    )
    admin = Administration(root)
    report["phase"] = "launch"
    server = start(binary, root, config)
    try:
        report["phase"] = "initial_seal_status"
        wait_for_seal_status(server, admin, initialized=False)
        report["phase"] = "provisioning"
        share = admin.initialize()
        admin.unseal(share)
        token_a, token_b = admin.provision()
        (root / "token-a").write_text(token_a, encoding="ascii")
        (root / "token-b").write_text(token_b, encoding="ascii")
        (root / "manifest.json").write_text(
            json.dumps(
                {
                    "schema": "pamolive.openbao.synthetic-lab/1",
                    "synthetic": True,
                    "address": ADDRESS,
                    "server_name": SERVER,
                    "port": PORT,
                    "ca_file": "lab-ca.crt",
                    "cert_file": "client.crt",
                    "key_file": "client.key",
                    "bad_cert_file": "foreign-client.crt",
                    "bad_key_file": "foreign-client.key",
                    "token_a_file": "token-a",
                    "token_b_file": "token-b",
                }
            ),
            encoding="ascii",
        )
        report["phase"] = "before-rotation"
        report["receptions"].append(reception(root, "before-rotation", 1))
        report["phase"] = "rotation"
        admin.rotate()
        need(stop(server))
        report["phase"] = "persistent-restart"
        server = start(binary, root, config)
        wait_for_seal_status(server, admin, initialized=True)
        admin.unseal(share)
        for key in KEYS:
            admin.read_key(key, 2)
        report["phase"] = "after-rotation"
        report["receptions"].append(reception(root, "after-rotation", 3))
        admin.request("GET", "transit/keys/tenant-unprovisioned", status=(404,))
        report["phase"] = "revoked"
        admin.request("POST", "auth/token/revoke", {"token": token_a})
        report["receptions"].append(reception(root, "revoked", 1))
        report["phase"] = "complete"
    except Exception as error:
        if report["phase"] in {"initial_seal_status", "persistent-restart"}:
            report["failure"] = startup_failure(root, server, error)
        raise
    finally:
        report["server_stopped"] = stop(server)


def main():
    report = {
        "schema": "pamolive.openbao.synthetic-lab-receipt/1",
        "phase": "runner_input",
        "receptions": [],
        "server_stopped": False,
        "authority": False,
        "ok": False,
    }
    try:
        need(os.environ.get("GITHUB_ACTIONS") == "true" and sys.platform == "linux")
        temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        binary = Path(sys.argv[1]).resolve(strict=True)
        need(binary.name == "bao" and binary.parent.parent == temp)
        need(binary.parent.name.startswith("pamolive-openbao-") and binary.is_file())
        os.umask(0o077)
        with tempfile.TemporaryDirectory(dir=temp, prefix="pamolive-openbao-private-") as folder:
            run(binary, Path(folder), report)
        report["ok"] = report["phase"] == "complete" and report["server_stopped"]
    except Exception as error:
        if "failure" not in report:
            kind = type(error).__name__
            report["failure"] = (
                kind
                if kind
                in {
                    "ModuleNotFoundError",
                    "FileNotFoundError",
                    "PermissionError",
                    "SSLError",
                    "TimeoutError",
                    "OSError",
                    "ValueError",
                    "KeyError",
                }
                else "unclassified"
            )
    print(json.dumps(report, separators=(",", ":"), allow_nan=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
