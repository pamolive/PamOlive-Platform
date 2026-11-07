"""Pre-authentication server-identity probes. They do not test login credentials.

No password/private key is accepted here. A successful result must not be shown
as evidence of an authenticated session or successful privileged access.
"""

import asyncio
import hashlib
import re
import secrets
import ssl
import struct
from dataclasses import dataclass
from datetime import UTC, datetime

import asyncssh
from cryptography import x509

from .destination import TransportFailure, resolve_destination

PROBE_TIMEOUT = 8


@dataclass(frozen=True)
class ProbeResult:
    protocol: str
    hostname: str
    port: int
    address: str
    fingerprint: str
    observed_at: datetime
    tls_version: str = ""
    credentials_tested: bool = False


def ssh_host_key(value):
    try:
        if not isinstance(value, str) or len(value) > 16_384:
            raise ValueError
        key = asyncssh.import_public_key(value)
        if key.get_algorithm() not in {
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        }:
            # RSA is omitted until libssh2 negotiation is tested with SHA-2 only.
            raise ValueError
        return key
    except (ValueError, asyncssh.KeyImportError):
        raise TransportFailure("invalid_ssh_host_key") from None


def certificate_pin(value):
    if not isinstance(value, str) or len(value) > 103:
        raise TransportFailure("invalid_rdp_certificate_pin")
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return text
    if re.fullmatch(r"(?:[0-9a-f]{2}:){31}[0-9a-f]{2}", text):
        return text.replace(":", "")
    raise TransportFailure("invalid_rdp_certificate_pin")


async def probe_ssh(hostname, port, expected_host_key):
    expected = ssh_host_key(expected_host_key)
    target = await resolve_destination(hostname, port)
    algorithms = [expected.get_algorithm()]
    try:
        async with asyncio.timeout(PROBE_TIMEOUT):
            # Explicitly ignore local SSH config (ProxyCommand, agent, tunnels).
            # This helper performs key exchange only, never user authentication.
            observed = await asyncssh.get_server_host_key(
                target.address, target.port, config=None, server_host_key_algs=algorithms
            )
        if observed is None or not secrets.compare_digest(
            observed.public_data, expected.public_data
        ):
            raise TransportFailure("ssh_host_key_mismatch")
        return ProbeResult(
            "ssh",
            target.hostname,
            target.port,
            target.address,
            observed.get_fingerprint("sha256"),
            datetime.now(UTC),
        )
    except TransportFailure:
        raise
    except (OSError, asyncssh.Error, TimeoutError):
        raise TransportFailure("ssh_identity_probe_failed") from None


async def probe_rdp(hostname, port, expected_certificate):
    pin = certificate_pin(expected_certificate)
    target = await resolve_destination(hostname, port)
    writer = None
    try:
        async with asyncio.timeout(PROBE_TIMEOUT):
            reader, writer = await asyncio.open_connection(target.address, target.port)
            # X.224 negotiation: TLS + HYBRID + HYBRID_EX, never legacy RDP security.
            writer.write(bytes.fromhex("030000130ee00000000000010008000b000000"))
            await writer.drain()
            header = await reader.readexactly(4)
            if header != bytes.fromhex("03000013"):
                raise TransportFailure("invalid_rdp_negotiation")
            body = await reader.readexactly(15)
            if body[0] != 14 or body[1] != 0xD0 or body[7] != 2:
                raise TransportFailure("rdp_nla_required")
            if struct.unpack_from("<H", body, 9)[0] != 8:
                raise TransportFailure("invalid_rdp_negotiation")
            if struct.unpack_from("<I", body, 11)[0] not in (2, 8):
                raise TransportFailure("rdp_nla_required")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # Pinned DER fingerprint is the trust anchor, not a public CA/TOFU.
            # Check it below, before sending any CredSSP or account credentials.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            await writer.start_tls(
                context, server_hostname=target.hostname, ssl_handshake_timeout=5
            )
            tls = writer.get_extra_info("ssl_object")
            certificate = tls.getpeercert(binary_form=True)
            fingerprint = hashlib.sha256(certificate).hexdigest()
            if not secrets.compare_digest(pin, fingerprint):
                raise TransportFailure("rdp_certificate_mismatch")
            parsed = x509.load_der_x509_certificate(certificate)
            now = datetime.now(UTC)
            if not parsed.not_valid_before_utc <= now < parsed.not_valid_after_utc:
                raise TransportFailure("rdp_certificate_expired_or_not_yet_valid")
            return ProbeResult(
                "rdp",
                target.hostname,
                target.port,
                target.address,
                "sha256:" + fingerprint,
                now,
                tls.version(),
            )
    except TransportFailure:
        raise
    except (OSError, ValueError, asyncio.IncompleteReadError, TimeoutError):
        raise TransportFailure("rdp_identity_probe_failed") from None
    finally:
        if writer:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                pass
