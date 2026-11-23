"""Bind a Debian OpenSSL library pair to its SDK and local TLS 1.3 proof."""

import hashlib
import json
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

CHECKS = Path(__file__).resolve().parent
sys.path.insert(0, str(CHECKS))
from abi_data import elf_exports  # noqa: E402

BASELINE = "3.5.9-1~deb13u1"
CANDIDATE = BASELINE + "+pamolive1"
PACKAGES = ("libssl3t64", "libssl-dev", "openssl", "openssl-provider-legacy")
EVIDENCE = Path("/evidence")
LIB = Path("/usr/lib/x86_64-linux-gnu")
LIBRARIES = ("libcrypto.so.3", "libssl.so.3")
SDK = b"""#include <openssl/ssl.h>
int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) return 1;
    SSL_CTX_free(ctx);
    return 0;
}
"""


def native_version(version):
    fmt = "${source:Package}|${Version}|${Architecture}|${db:Status-Status}"
    for name in PACKAGES:
        result = subprocess.check_output(["dpkg-query", "-W", "-f=" + fmt, name], timeout=8)
        if result != f"openssl|{version}|amd64|installed".encode():
            raise ValueError("installed_version_mismatch")


def native_sdk_and_tls():
    with tempfile.TemporaryDirectory(prefix="pamolive-openssl-smoke-") as scratch:
        root = Path(scratch)
        binary, key, cert = (root / name for name in ("sdk", "fixture.key", "fixture.pem"))
        subprocess.run([
            "/usr/bin/cc", "-Wall", "-Wextra", "-Werror", "-x", "c", "-", "-o", str(binary),
            "-lssl", "-lcrypto",
        ], input=SDK, check=True, timeout=40)
        subprocess.run([str(binary)], check=True, timeout=10)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ed25519", "-noenc", "-days", "1",
            "-subj", "/CN=fixture.invalid", "-addext", "subjectAltName=DNS:fixture.invalid",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, timeout=15, capture_output=True)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(cert, key)
        client = ssl.create_default_context(cafile=cert)
        for context in (server, client):
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        inbound_s, outbound_s, inbound_c, outbound_c = (ssl.MemoryBIO() for _ in range(4))
        peers = (
            (server.wrap_bio(inbound_s, outbound_s, server_side=True), outbound_s, inbound_c),
            (client.wrap_bio(inbound_c, outbound_c, server_hostname="fixture.invalid"),
             outbound_c, inbound_s),
        )
        complete = set()
        for _ in range(20):
            for index, (peer, outgoing, destination) in enumerate(peers):
                if index not in complete:
                    try:
                        peer.do_handshake()
                        complete.add(index)
                    except ssl.SSLWantReadError:
                        pass
                if data := outgoing.read():
                    destination.write(data)
            if len(complete) == len(peers):
                break
        if complete != {0, 1} or any(peer.version() != "TLSv1.3" for peer, _, _ in peers):
            raise ValueError("tls13_handshake_refused")
    mappings = Path("/proc/self/maps").read_text().splitlines()
    loaded = {line.split(maxsplit=5)[-1] for line in mappings}
    if not all(str((LIB / library).resolve(strict=True)) in loaded for library in LIBRARIES):
        raise ValueError("openssl_provider_mapping_refused")
    providers = subprocess.check_output([
        "openssl", "list", "-providers", "-provider", "default", "-provider", "legacy",
    ], timeout=10)
    if providers.count(b"status: active") != 2:
        raise ValueError("openssl_provider_load_refused")


def capture(version):
    native_version(version)
    native_sdk_and_tls()
    result = {}
    for name in LIBRARIES:
        raw = (LIB / name).read_bytes()
        exports = elf_exports(raw)
        if exports["soname"] != name:
            raise ValueError("openssl_soname_mismatch")
        result[name] = dict(exports, sha256=hashlib.sha256(raw).hexdigest())
    return result


def record(name, data):
    with (EVIDENCE / name).open("x", encoding="ascii") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main(args):
    if args == ["stock"]:
        record("stock.json", capture(BASELINE))
        return
    if args != ["candidate"]:
        raise ValueError("mode_refused")
    before = json.loads((EVIDENCE / "stock.json").read_bytes())
    after = capture(CANDIDATE)
    for name in LIBRARIES:
        if before[name]["symbols"] != after[name]["symbols"]:
            raise ValueError("openssl_export_delta")
        if before[name]["sha256"] == after[name]["sha256"]:
            raise ValueError("openssl_library_unchanged")
    record("candidate.json", after)
    record("qualification.json", {
        "schema": "pamolive.openssl-trixie-backport-qualification/1",
        "baseline": BASELINE,
        "candidate": CANDIDATE,
        "exports_preserved": True,
        "native_sdk_and_tls13_verified": True,
        "archives": {name: sha(EVIDENCE / (name + ".deb")) for name in PACKAGES},
        "buildinfo_sha256": sha(EVIDENCE / "buildinfo"),
        "test_summary_sha256": sha(EVIDENCE / "test-summary.txt"),
    })


if __name__ == "__main__":
    main(sys.argv[1:])
