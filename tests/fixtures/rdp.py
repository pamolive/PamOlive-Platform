"""Headless test-only RDP/NLA fixture, without an OS login or shell."""

import asyncio
import ipaddress
import json
import os
import secrets
import signal
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BINARY = Path(os.environ.get("PAM_RDP_FIXTURE", "/opt/pamolive-test/rdp-fixture"))
HA_PORT = 23389
HA_NETWORKS = tuple(
    ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def isolated_bind(address):
    parsed = ipaddress.IPv4Address(address)
    if not any(parsed in network for network in HA_NETWORKS):
        raise ValueError("Only a specific private test interface may host the RDP fixture.")
    return str(parsed)


class RDPFixture:
    def __init__(self, *, redirect=False, expired=False, ha_bind=None):
        self.redirect, self.expired = redirect, expired
        self.ha_bind = isolated_bind(ha_bind) if ha_bind is not None else None
        self.password = secrets.token_urlsafe(24)
        self.process = self.reader = None
        self.events = []

    async def collect(self):
        async for line in self.process.stdout:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and "event" in value:
                self.events.append(value)

    async def wait(self, event, *, timeout=10, connection=None, after=0):
        async with asyncio.timeout(timeout):
            while True:
                for value in self.events[after:]:
                    if value["event"] == event and (
                        connection is None or value.get("connection") == connection
                    ):
                        return value
                if any(value["event"] == "context_failed" for value in self.events):
                    raise RuntimeError("RDP peer context initialization failed")
                if self.process.returncode is not None:
                    raise RuntimeError(
                        f"RDP fixture stopped before {event}: exit {self.process.returncode}"
                    )
                await asyncio.sleep(0.02)

    async def __aenter__(self):
        if not BINARY.is_file():
            raise RuntimeError("Test-only FreeRDP peer is missing")
        self.directory = tempfile.TemporaryDirectory(prefix="pamolive-rdp-fixture-")
        root = Path(self.directory.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAM-olive test peer")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + (timedelta(days=-1) if self.expired else timedelta(hours=1)))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256())
        )
        self.pin = cert.fingerprint(hashes.SHA256()).hex()
        key_path, cert_path = root / "key.pem", root / "cert.pem"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.log = tempfile.TemporaryFile()
        try:
            self.process = await asyncio.create_subprocess_exec(
                str(BINARY),
                str(cert_path),
                str(key_path),
                str(root / "SAM"),
                "redirect" if self.redirect else "display",
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "HOME": self.directory.name,
                    "WLOG_LEVEL": "ERROR",
                    "PAM_TEST_PASSWORD": self.password,
                    **({"PAM_TEST_HA_BIND": self.ha_bind} if self.ha_bind else {}),
                },
                stdout=asyncio.subprocess.PIPE,
                stderr=self.log,
                start_new_session=True,
            )
            self.reader = asyncio.create_task(self.collect())
            self.port = (await self.wait("ready"))["port"]
            if self.ha_bind and self.port != HA_PORT:
                raise RuntimeError("Wrong port for the isolated RDP fixture.")
            return self
        except BaseException:
            await self.__aexit__(*sys.exc_info())
            raise

    async def __aexit__(self, kind, value, traceback):
        if self.process:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except TimeoutError:
                os.killpg(self.process.pid, signal.SIGKILL)
                await self.process.wait()
        if self.reader:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
        if kind:
            self.log.seek(0, os.SEEK_END)
            self.log.seek(max(0, self.log.tell() - 4096))
            sys.stderr.write(self.log.read(4096).decode("utf-8", errors="replace"))
        self.log.close()
        self.directory.cleanup()
