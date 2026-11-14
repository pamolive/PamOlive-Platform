"""Loopback-only HTTPS Graph peer; credentials and data are synthetic."""

import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .oidc import tls_material


class _TLSServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # A client correctly refusing the leaf pin closes before HTTP. Hide only
        # that expected connection teardown; unexpected fixture errors remain.
        if isinstance(sys.exception(), (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class GraphPeer:
    def __init__(self, folder, tenant_id):
        context, self.ca_file = tls_material(folder)
        certificate = x509.load_pem_x509_certificate(Path(self.ca_file).read_bytes())
        self.pin = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
        self.tenant_id, self.requests, self.pages = tenant_id, [], []
        self.redirect = None
        self.server = _TLSServer(("127.0.0.1", 0), self.handler())
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://localhost:{self.server.server_port}/v1.0/users"
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

            def do_GET(self):
                # Never record the credential value, even in this fixture.
                peer.requests.append(
                    {
                        "target": self.path,
                        "authorization_present": bool(self.headers.get("Authorization")),
                    }
                )
                if peer.redirect:
                    self.send_response(302)
                    self.send_header("Location", peer.redirect)
                    self.end_headers()
                    return
                if urlsplit(self.path).path == "/v1.0/organization":
                    value = {"value": [{"id": peer.tenant_id}]}
                elif peer.pages:
                    value = peer.pages.pop(0)
                else:
                    value = {"value": []}
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler
