"""Exercise the actual TLS transport with a disposable synthetic HTTPS peer."""

import ipaddress
import ssl
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pamolive_vault_envelope import ProviderError
from pamolive_vault_kms_openbao import TransitProvider, TransitTransport
from test_provider import NEW, TOKEN, TransitDouble


def issue(root, name, issuer=None, usage=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    not_before = datetime.now(UTC) - timedelta(minutes=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer[1].subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True)
    )
    if usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
    certificate = builder.sign(issuer[0] if issuer else key, hashes.SHA256())
    cert_path, key_path = root / (name + ".crt"), root / (name + ".key")
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return key, certificate, cert_path, key_path


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        response = self.server.transit.post(self.path, self.headers["X-Vault-Token"], body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


class LoopbackTests(unittest.TestCase):
    def test_tls_peer_and_mutual_authentication_are_enforced(self):
        with tempfile.TemporaryDirectory(prefix="pamolive-kms-tls-") as folder:
            root = Path(folder)
            ca = issue(root, "test-ca")
            outsider = issue(root, "untrusted-ca")
            host = "openbao-n0.test"
            server = issue(root, host, ca, ExtendedKeyUsageOID.SERVER_AUTH)
            client = issue(root, "vault-client", ca, ExtendedKeyUsageOID.CLIENT_AUTH)
            wrong = issue(root, "wrong-client", outsider, ExtendedKeyUsageOID.CLIENT_AUTH)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=str(ca[2]))
            context.load_cert_chain(str(server[2]), str(server[3]))
            context.set_alpn_protocols(["http/1.1"])
            address = ipaddress.IPv4Address("127.0.0.1")
            with ThreadingHTTPServer((str(address), 0), Handler) as http:
                http.transit = TransitDouble()
                http.socket = context.wrap_socket(http.socket, server_side=True)
                service = Thread(target=http.serve_forever, kwargs={"poll_interval": 0.05})
                service.start()
                try:

                    def provider(name, trust, principal):
                        transport = TransitTransport(
                            str(address),
                            name,
                            http.server_port,
                            ca_file=trust[2],
                            cert_file=principal[2],
                            key_file=principal[3],
                            timeout=2,
                        )
                        return TransitProvider(NEW, "tenant-one", frozenset({2}), transport, TOKEN)

                    good = provider(host, ca, client)
                    dek, aad = b"x" * 32, b"synthetic complete associated data"
                    wrapped = good.wrap_key(dek, NEW, aad)
                    self.assertEqual(good.unwrap_key(wrapped.blob, NEW, aad).dek, dek)
                    self.assertEqual(len(http.transit.calls), 2)
                    for subject, authority, principal in (
                        ("different.test", ca, client),
                        (host, outsider, client),
                        (host, ca, wrong),
                    ):
                        with self.subTest(subject=subject), self.assertRaises(ProviderError):
                            provider(subject, authority, principal).wrap_key(dek, NEW, aad)
                    self.assertEqual(len(http.transit.calls), 2)
                finally:
                    http.shutdown()
                    service.join(timeout=5)
                    self.assertFalse(service.is_alive())
