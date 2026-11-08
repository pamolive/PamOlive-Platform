"""Disposable HTTPS OIDC peer. No production credentials or external provider is used."""

import base64
import hashlib
import ipaddress
import json
import secrets
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def tls_material(directory):
    directory = Path(directory)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PamOlive disposable OIDC fixture")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "fixture-ca.pem", directory / "fixture-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context, str(cert_path)


class OIDCPeer:
    client_id = "https-fixture-client"
    client_secret = "https-fixture-confidential-secret"
    subject = "explicit-subject-not-an-email"

    def __init__(self, context):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = dict(
            jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True),
            kid="disposable-rsa-key",
            use="sig",
            alg="RS256",
        )
        self.codes, self.lock = {}, threading.Lock()
        self.exchanges = 0
        self.last_redirect = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.issuer = f"https://localhost:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def handler(self):
        peer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def json(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path == "/.well-known/openid-configuration":
                    return self.json(
                        200,
                        dict(
                            issuer=peer.issuer,
                            authorization_endpoint=peer.issuer + "/authorize",
                            token_endpoint=peer.issuer + "/token",
                            jwks_uri=peer.issuer + "/jwks",
                            response_types_supported=["code"],
                            id_token_signing_alg_values_supported=["RS256"],
                            token_endpoint_auth_methods_supported=["client_secret_basic"],
                            code_challenge_methods_supported=["S256"],
                        ),
                    )
                if parsed.path == "/jwks":
                    return self.json(200, {"keys": [peer.jwk]})
                if parsed.path != "/authorize":
                    return self.json(404, {})
                values = parse_qs(parsed.query)
                if (
                    any(len(items) != 1 for items in values.values())
                    or values.get("client_id") != [peer.client_id]
                    or values.get("response_type") != ["code"]
                    or values.get("redirect_uri") != [peer.redirect_uri]
                    or values.get("code_challenge_method") != ["S256"]
                    or not all(values.get(key) for key in ("nonce", "state", "code_challenge"))
                ):
                    return self.json(400, {"error": "invalid_authorization_request"})
                code = secrets.token_urlsafe(32)
                with peer.lock:
                    peer.codes[code] = {key: items[0] for key, items in values.items()}
                peer.last_redirect = values["redirect_uri"][0]
                self.send_response(302)
                self.send_header(
                    "Location",
                    peer.redirect_uri
                    + "?"
                    + urlencode(dict(code=code, state=values["state"][0], iss=peer.issuer)),
                )
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
                if self.path != "/token":
                    return self.json(404, {})
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 8192:
                    return self.json(400, {})
                values = parse_qs(self.rfile.read(length).decode())
                expected = (
                    "Basic "
                    + base64.b64encode(f"{peer.client_id}:{peer.client_secret}".encode()).decode()
                )
                with peer.lock:
                    original = peer.codes.pop(values.get("code", [""])[0], None)
                verifier = values.get("code_verifier", [""])[0]
                challenge = (
                    base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                    .decode()
                    .rstrip("=")
                )
                if (
                    not original
                    or not secrets.compare_digest(self.headers.get("Authorization", ""), expected)
                    or values.get("grant_type") != ["authorization_code"]
                    or values.get("redirect_uri") != [original["redirect_uri"]]
                    or challenge != original["code_challenge"]
                ):
                    return self.json(400, {"error": "invalid_grant"})
                peer.exchanges += 1
                token = jwt.encode(
                    dict(
                        iss=peer.issuer,
                        aud=peer.client_id,
                        sub=peer.subject,
                        nonce=original["nonce"],
                        iat=int(time.time()),
                        exp=int(time.time()) + 120,
                        email="not-an-account-mapping@example.test",
                        roles=["admin"],
                        amr=["mfa"],
                    ),
                    peer.key,
                    algorithm="RS256",
                    headers={"kid": peer.jwk["kid"]},
                )
                return self.json(200, {"id_token": token, "token_type": "Bearer"})

        return Handler
