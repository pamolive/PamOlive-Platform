"""Explicit synthetic OpenBao reception; never provisions or rotates a key.

Install the public envelope/provider packages first. A separate lab administrator
creates tenant-a and tenant-b (AES-256-GCM, non-exportable), update-only tokens,
and a mandatory-client-certificate listener. No administration token is accepted.
Token A also has update WITHOUT create on transit/encrypt/tenant-unprovisioned;
that key stays absent. The administrator independently confirms its GET404.

Run before-rotation with version1 active; it exclusively creates --envelope.
The administrator then rotates both keys to2, sets min_encryption_version=2 and
retains min_decryption_version=1. Run after-rotation with the SAME envelope.
Finally the administrator revokes token A; run revoked separately. The tests
never call rotation, key/configuration, export, token or other admin endpoints.

Manifest schema pamolive.openbao.synthetic-lab/1 has exactly: schema, synthetic
(true), address (127.0.0.1 or a host in10.253.249.0/28), server_name
(openbao-n0.test), port (8200 or8443), and relative paths ca_file, cert_file,
key_file, bad_cert_file, bad_key_file, token_a_file, token_b_file. All files and
--envelope stay below the manifest directory. Tokens/keys must be private on
POSIX. The bad certificate is issued by a DIFFERENT synthetic CA; the server CA
and SNI remain identical, so it is the server rejecting the client certificate.

This is a real network test ONLY when invoked explicitly with a manifest.
Source preparation uses inert data and doubles. No KEK is loaded; synthetic DEKs and
plaintext necessarily exist temporarily in the envelope client process. Passing
tests do not independently attest backend key exportability, administrator
separation, persistent rotation, service restoration or production isolation.
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

SCHEMA = "pamolive.openbao.synthetic-lab/1"
FILES = frozenset(
    {
        "ca_file",
        "cert_file",
        "key_file",
        "bad_cert_file",
        "bad_key_file",
        "token_a_file",
        "token_b_file",
    }
)
FIELDS = FILES | {"schema", "synthetic", "address", "server_name", "port"}
TOKEN = re.compile(r"[A-Za-z0-9._-]{1,1024}")
ROUTES = frozenset(
    f"/v1/transit/{op}/{key}"
    for op in ("encrypt", "decrypt")
    for key in ("tenant-a", "tenant-b", "tenant-unprovisioned")
)
PAYLOAD = b"PamOlive synthetic OpenBao integration value"
AAD = b"PamOlive synthetic OpenBao complete AAD\x00\xff"
DEK = b"synthetic-integration-DEK".ljust(32, b"!")


def require(value):
    if not value:
        raise ValueError("synthetic_lab_refused")


def pairs(items):
    result = dict(items)
    require(len(items) == len(result))
    return result


def parse_manifest(value):
    require(type(value) is dict and value.keys() == FIELDS)
    require(value["schema"] == SCHEMA and value["synthetic"] is True)
    require(type(value["address"]) is str)
    address = ipaddress.ip_address(value["address"])
    require(str(address) == value["address"])
    require(
        address == ipaddress.ip_address("127.0.0.1")
        or (address in ipaddress.ip_network("10.253.249.0/28") and int(address) % 16 not in (0, 15))
    )
    require(value["server_name"] == "openbao-n0.test")
    require(type(value["port"]) is int and value["port"] in (8200, 8443))
    for field in FILES:
        path = value[field]
        require(type(path) is str and 0 < len(path) <= 160)
        require(not path.startswith(("/", "\\")) and "\\" not in path and ":" not in path)
        require(all(part not in ("", ".", "..") for part in path.split("/")))
    require(len({value[field] for field in FILES}) == len(FILES))
    return value


def read_file(path, maximum, *, private=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum)
    if private and os.name == "posix":
        require(info.st_mode & 0o077 == 0 and info.st_uid == os.getuid())
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        current = os.fstat(stream.fileno())
        require(
            (current.st_dev, current.st_ino, current.st_size)
            == (info.st_dev, info.st_ino, info.st_size)
        )
        result = stream.read(maximum + 1)
        require(len(result) == info.st_size)
        return result


def load_manifest(path):
    path = Path(path).absolute()
    value = parse_manifest(json.loads(read_file(path, 8192), object_pairs_hook=pairs))
    root = path.parent.resolve(strict=True)
    paths = {}
    for field in FILES:
        candidate = root / value[field]
        require(candidate.resolve(strict=True).is_relative_to(root))
        require(not candidate.is_symlink())
        private = field in {"key_file", "bad_key_file", "token_a_file", "token_b_file"}
        raw = read_file(candidate, 65536 if "token" not in field else 1024, private=private)
        paths[field] = candidate
        if "token" in field:
            token = raw.decode("ascii")
            require(TOKEN.fullmatch(token) is not None)
            paths[field.replace("_file", "")] = token
    return SimpleNamespace(value=value, paths=paths, root=root)


class BackendObserver:
    """Minimal real HTTP witness: retain status/path only; never retain bodies.

    Used for negative ACL/upsert checks so a local mapping rejection cannot be
    reported as a backend403. Normal success uses the public TransitTransport.
    This accepts only the three fixed synthetic key routes, no arbitrary HTTP.
    """

    def __init__(self, config, certificate="valid"):
        require(certificate in ("valid", "missing", "bad"))
        self.config = config
        self.certificate = certificate
        self.statuses = []
        self.tls_attempted = False

    def post(self, path, token, body):
        require(path in ROUTES and type(token) is str and TOKEN.fullmatch(token))
        require(type(body) is bytes and 0 < len(body) <= 8192)
        config = self.config
        context = ssl.create_default_context(cafile=str(config.paths["ca_file"]))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        if self.certificate != "missing":
            prefix = "bad_" if self.certificate == "bad" else ""
            context.load_cert_chain(
                str(config.paths[prefix + "cert_file"]), str(config.paths[prefix + "key_file"])
            )
        value = config.value
        deadline = time.monotonic() + 3
        request = (
            f"POST {path} HTTP/1.1\r\nHost: {value['server_name']}:{value['port']}\r\n"
            f"X-Vault-Token: {token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection((value["address"], value["port"]), timeout=3) as raw:
            raw.settimeout(max(0.001, deadline - time.monotonic()))
            self.tls_attempted = True
            with context.wrap_socket(raw, server_hostname=value["server_name"]) as connection:
                require(connection.selected_alpn_protocol() in (None, "http/1.1"))
                require(bool(connection.getpeercert(binary_form=True)))
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                connection.sendall(request + body)
                header = bytearray()
                while not header.endswith(b"\r\n\r\n"):
                    require(len(header) < 8192 and time.monotonic() < deadline)
                    connection.settimeout(deadline - time.monotonic())
                    chunk = connection.recv(1)
                    require(bool(chunk))
                    header.extend(chunk)
                lines = bytes(header[:-4]).split(b"\r\n")
                require(re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2} [ -~]*", lines[0]))
                status = int(lines[0].split(b" ", 2)[1])
                headers = {}
                for line in lines[1:]:
                    key, separator, content = line.partition(b":")
                    key = key.lower()
                    require(separator and key not in headers)
                    headers[key] = content.strip()
                require(b"transfer-encoding" not in headers)
                length = headers.get(b"content-length", b"")
                require(re.fullmatch(rb"[0-9]{1,5}", length))
                require(int(length) <= 8192)
                response = bytearray()
                while len(response) < int(length):
                    require(time.monotonic() < deadline)
                    connection.settimeout(deadline - time.monotonic())
                    chunk = connection.recv(int(length) - len(response))
                    require(bool(chunk))
                    response.extend(chunk)
                self.statuses.append((path, status))
                if status != 200:
                    raise self.config.api.ProviderError()
                return bytes(response)


class RouteObserver:
    def __init__(self, delegate):
        self.delegate = delegate
        self.paths = []

    def post(self, path, token, body):
        require(path in ROUTES)
        self.paths.append(path)
        return self.delegate.post(path, token, body)


def public_api():
    import pamolive_vault_envelope as envelope
    from pamolive_vault_kms_openbao import TransitProvider, TransitTransport

    return SimpleNamespace(
        **{name: getattr(envelope, name) for name in envelope.__all__},
        TransitProvider=TransitProvider,
        TransitTransport=TransitTransport,
    )


class Reception(unittest.TestCase):
    config = None
    envelope_path = None

    def provider(self, version=2, *, key="tenant-a", token="a", observer=None):
        config = self.config
        api = config.api
        reference = api.KeyRef(
            str(UUID(int=1)),
            str(UUID(int=2)),
            "technical-credentials",
            "openbao-n0",
            "kek",
            version,
        )
        if observer is None:
            value = config.value
            transport = api.TransitTransport(
                value["address"],
                value["server_name"],
                value["port"],
                ca_file=str(config.paths["ca_file"]),
                cert_file=str(config.paths["cert_file"]),
                key_file=str(config.paths["key_file"]),
                timeout=3,
            )
            observer = RouteObserver(transport)
        provider = api.TransitProvider(
            reference,
            key,
            frozenset(range(1, version + 1)),
            observer,
            config.paths[f"token_{token}"],
        )
        return provider, reference, observer

    def binding(self):
        return self.config.api.Binding(
            str(UUID(int=1)),
            str(UUID(int=2)),
            "technical-credentials",
            str(UUID(int=3)),
            1,
            "ssh",
            "0" * 64,
        )

    def test_before_rotation(self):
        provider, reference, observer = self.provider(1)
        api = self.config.api
        original = api.seal_new_version(PAYLOAD, self.binding(), reference, provider)
        self.assertEqual(
            api.open_authorized_version(original, self.binding(), reference, provider), PAYLOAD
        )
        self.assertEqual(
            observer.paths, ["/v1/transit/encrypt/tenant-a", "/v1/transit/decrypt/tenant-a"]
        )
        raw = api.serialize_envelope(original)
        descriptor = os.open(
            self.envelope_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    def test_after_rotation(self):
        api = self.config.api
        saved = read_file(self.envelope_path, 65536, private=True)
        original = api.parse_envelope(saved)
        provider, reference, observer = self.provider(2)
        _, old_reference, _ = self.provider(1)
        self.assertEqual(
            api.open_authorized_version(original, self.binding(), old_reference, provider), PAYLOAD
        )
        latest = api.rewrap(original, self.binding(), old_reference, reference, provider)
        self.assertEqual(original.payload_ciphertext, latest.payload_ciphertext)
        self.assertEqual(original.payload_nonce, latest.payload_nonce)
        self.assertEqual(
            api.open_authorized_version(latest, self.binding(), reference, provider), PAYLOAD
        )
        self.assertEqual(api.serialize_envelope(original), saved)
        self.assertEqual(read_file(self.envelope_path, 65536, private=True), saved)
        self.assertTrue(
            all(
                path in {"/v1/transit/encrypt/tenant-a", "/v1/transit/decrypt/tenant-a"}
                for path in observer.paths
            )
        )
        version_observer = BackendObserver(self.config)
        old_provider, _, _ = self.provider(1, observer=version_observer)
        with self.assertRaises(api.ProviderError):
            old_provider.wrap_key(DEK, old_reference, AAD)
        self.assertEqual(version_observer.statuses, [("/v1/transit/encrypt/tenant-a", 400)])
        fresh = provider.wrap_key(DEK, reference, AAD)
        self.assertTrue(fresh.blob.startswith(b"vault:v2:"))
        aad_observer = BackendObserver(self.config)
        aad_provider, _, _ = self.provider(observer=aad_observer)
        with self.assertRaises(api.ProviderError):
            aad_provider.unwrap_key(fresh.blob, reference, AAD + b"altered")
        self.assertEqual(aad_observer.statuses, [("/v1/transit/decrypt/tenant-a", 400)])

    def test_backend_acl_and_no_upsert(self):
        api = self.config.api
        # B works on its own key, so a later403 is not merely an invalid token.
        own, own_ref, _ = self.provider(key="tenant-b", token="b")
        self.assertEqual(
            own.unwrap_key(own.wrap_key(DEK, own_ref, AAD).blob, own_ref, AAD).dek, DEK
        )
        active, reference, _ = self.provider()
        blob = active.wrap_key(DEK, reference, AAD).blob
        observer = BackendObserver(self.config)
        # Deliberately keep local A mapping; only backend ACL can reject token B.
        denied, _, _ = self.provider(token="b", observer=observer)
        with self.assertRaises(api.ProviderError):
            denied.wrap_key(DEK, reference, AAD)
        with self.assertRaises(api.ProviderError):
            denied.unwrap_key(blob, reference, AAD)
        self.assertEqual(
            observer.statuses,
            [("/v1/transit/encrypt/tenant-a", 403), ("/v1/transit/decrypt/tenant-a", 403)],
        )
        observer = BackendObserver(self.config)
        # Version1 would succeed if an unintended upsert created a fresh key;
        # version2 could instead yield400 after creating its initial version.
        missing, reference, _ = self.provider(1, key="tenant-unprovisioned", observer=observer)
        with self.assertRaises(api.ProviderError):
            missing.wrap_key(DEK, reference, AAD)
        self.assertEqual(len(observer.statuses), 1)
        self.assertEqual(observer.statuses[0][0], "/v1/transit/encrypt/tenant-unprovisioned")
        self.assertIn(observer.statuses[0][1], (400, 403))
        # The separate administrator must additionally verify key GET=404;
        # the runtime token never receives a key-read/administration capability.

    def test_server_requires_client_certificate(self):
        control, reference, _ = self.provider(key="tenant-b", token="b")
        control.wrap_key(DEK, reference, AAD)
        for certificate in ("missing", "bad"):
            observer = BackendObserver(self.config, certificate)
            with self.subTest(certificate=certificate), self.assertRaises(ssl.SSLError) as caught:
                observer.post(
                    "/v1/transit/encrypt/tenant-b",
                    self.config.paths["token_b"],
                    b'{"plaintext":"AA==","key_version":2}',
                )
            self.assertTrue(observer.tls_attempted)
            self.assertNotIsInstance(caught.exception, ssl.SSLCertVerificationError)
            self.assertEqual(observer.statuses, [])

    def test_revoked(self):
        control, reference, _ = self.provider(key="tenant-b", token="b")
        control.wrap_key(DEK, reference, AAD)
        observer = BackendObserver(self.config)
        revoked, _, _ = self.provider(observer=observer)
        with self.assertRaises(self.config.api.ProviderError):
            revoked.wrap_key(DEK, reference, AAD)
        original = self.config.api.parse_envelope(
            read_file(self.envelope_path, 65536, private=True)
        )
        _, old_reference, _ = self.provider(1)
        with self.assertRaises(self.config.api.ProviderError):
            self.config.api.open_authorized_version(
                original, self.binding(), old_reference, revoked
            )
        self.assertEqual(
            observer.statuses,
            [("/v1/transit/encrypt/tenant-a", 403), ("/v1/transit/decrypt/tenant-a", 403)],
        )


PHASES = {
    "before-rotation": ("test_before_rotation",),
    "after-rotation": (
        "test_after_rotation",
        "test_backend_acl_and_no_upsert",
        "test_server_requires_client_certificate",
    ),
    "revoked": ("test_revoked",),
}


class QuietResult(unittest.TestResult):
    """No exception formatting, traceback, token, body or filesystem path output."""

    def addError(self, test, err):
        self.errors.append((test.id().rsplit(".", 1)[-1], "error"))

    def addFailure(self, test, err):
        self.failures.append((test.id().rsplit(".", 1)[-1], "failure"))

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.addFailure(test, err)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--phase", required=True, choices=PHASES)
    parser.add_argument("--envelope", required=True)
    args = parser.parse_args()
    try:
        config = load_manifest(args.manifest)
        envelope_path = Path(args.envelope).absolute()
        require(envelope_path.parent.resolve(strict=True).is_relative_to(config.root))
        require(not envelope_path.is_symlink())
        config.api = public_api()
        Reception.config = config
        Reception.envelope_path = envelope_path
        result = QuietResult()
        unittest.TestSuite(Reception(name) for name in PHASES[args.phase]).run(result)
        ok = (
            result.wasSuccessful()
            and not result.skipped
            and result.testsRun == len(PHASES[args.phase])
        )
        report = {
            "schema": "pamolive.openbao.synthetic-reception/1",
            "phase": args.phase,
            "tests": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skips": len(result.skipped),
            "ok": ok,
            "authority": False,
            "kek_material_received": False,
        }
    except Exception:
        ok = False
        report = {
            "schema": "pamolive.openbao.synthetic-reception/1",
            "phase": args.phase,
            "ok": False,
            "authority": False,
            "error": "synthetic_lab_refused",
        }
    print(json.dumps(report, separators=(",", ":"), allow_nan=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
