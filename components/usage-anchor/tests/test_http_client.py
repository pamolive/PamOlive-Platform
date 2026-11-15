"""Real client/stdlib/h11/ASGI parsing; fake TLS/socket/scheduler/Service only."""

import hashlib
import http.client
import ssl
import types
import unittest
from unittest.mock import patch

import h11
from pamolive_usage_anchor import http as server
from pamolive_usage_anchor.client import MTLSClient
from pamolive_usage_anchor.codec import Error

PEER = b"PUBLIC_SYNTHETIC_SERVER_DER"
CALLER = b"PUBLIC_SYNTHETIC_CALLER_DER"


def decode(raw):
    parser = h11.Connection(h11.SERVER, max_incomplete_event_size=8192)
    parser.receive_data(raw)
    request = parser.next_event()
    assert isinstance(request, h11.Request)
    body = b""
    while True:
        event = parser.next_event()
        if isinstance(event, h11.Data):
            body += bytes(event.data)
            assert len(body) <= 8192
        elif isinstance(event, h11.EndOfMessage):
            return [tuple(row) for row in request.headers], body
        else:
            raise AssertionError("complete synthetic request required")


def complete(coroutine):
    try:
        coroutine.send(None)
    except StopIteration:
        return
    finally:
        coroutine.close()
    raise AssertionError("unexpected scheduler suspension")


def route(headers, body, *, unbound=False):
    calls, events, receives = [], [], []

    class Recorder(server.Application):
        async def _run_route(self, path, raw, der):
            calls.append((path, raw, der))
            return 200, b'{"authorized":false}'

    app = Recorder(None)
    scope = {
        "type": "http",
        "scheme": "https",
        "http_version": "1.1",
        "method": "POST",
        "path": "/v1/operations/bind",
        "raw_path": b"/v1/operations/bind",
        "query_string": b"",
        "headers": headers,
    }

    async def receive():
        receives.append(True)
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(event):
        events.append(event)

    async def immediate(awaitable, timeout=None):
        return await awaitable

    try:
        endpoint = app if unbound else app.for_tls_peer(CALLER)
        with patch.object(server.asyncio, "wait_for", immediate):
            complete(endpoint(scope, receive, send))
        return {
            "status": events[0]["status"],
            "body": events[-1]["body"],
            "calls": calls,
            "receives": len(receives),
        }
    finally:
        app.close()


def request(*, pin=None, target="/v1/operations/bind", body=b"{}"):
    instances = []

    class Peer:
        def __init__(self):
            self.raw, self.closed = b"", False

        def getpeercert(self, *, binary_form):
            assert binary_form is True
            return PEER

        def sendall(self, raw):
            assert type(raw) is bytes and len(self.raw) + len(raw) <= 8192
            self.raw += raw

        def close(self):
            self.closed = True

    class Connection(http.client.HTTPConnection):
        # HTTPSConnection inherits this exact stdlib request/framing implementation.
        def __init__(self, host, port, *, context, timeout):
            super().__init__(host, port, timeout=timeout)
            self.peer, self.context = Peer(), context
            self.observed = None
            instances.append(self)

        def connect(self):
            self.sock = self.peer

        def getresponse(self):
            headers, raw = decode(self.peer.raw)
            self.observed = route(headers, raw)
            return types.SimpleNamespace(
                status=self.observed["status"],
                getheader=lambda key: "application/json",
                read=lambda cap: self.observed["body"][:cap],
            )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with patch("pamolive_usage_anchor.client.http.client.HTTPSConnection", Connection):
        client = MTLSClient(
            host="witness.synthetic.invalid",
            port=9443,
            context=context,
            server_der_sha256=pin or hashlib.sha256(PEER).hexdigest(),
        )
        try:
            status, result = client.request(target, body)
        except Error as error:
            status, result = error.status, None
    return status, result, instances


class HTTPClientTests(unittest.TestCase):
    def test_actual_client_wire_reaches_closed_server_without_negotiation(self):
        raw = b'{"public_synthetic":"byte-exact"}'
        status, response, instances = request(body=raw)
        self.assertEqual(status, 200)  # Parser/routing control only, not TLS/auth/SQL success.
        self.assertEqual(response, b'{"authorized":false}')
        self.assertEqual(len(instances), 1)
        connection = instances[0]
        headers, body = decode(connection.peer.raw)
        self.assertEqual(body, raw)
        self.assertEqual(
            [value for key, value in headers if key == b"content-length"], [str(len(raw)).encode()]
        )
        self.assertFalse(
            any(
                key in {b"accept-encoding", b"transfer-encoding", b"content-encoding"}
                for key, _ in headers
            )
        )
        self.assertEqual(connection.observed["calls"], [("/v1/operations/bind", raw, CALLER)])
        self.assertTrue(connection.peer.closed)

    def test_bad_pin_and_pre_route_bounds_never_send_HTTP(self):
        status, _, instances = request(pin="0" * 64)
        self.assertEqual(status, 403)
        self.assertEqual(instances[0].peer.raw, b"")
        self.assertTrue(instances[0].peer.closed)
        for target, body in (
            ("/not-a-route", b"{}"),
            ("/v1/operations/bind", b""),
            ("/v1/activations/begin", b"x" * 4097),
        ):
            with self.subTest(target=target, bytes=len(body)):
                status, _, instances = request(target=target, body=body)
                self.assertEqual(status, 400)
                self.assertEqual(instances, [])

    def test_server_profile_and_unbound_ASGI_remain_closed(self):
        headers = [
            (b"host", b"witness.synthetic.invalid"),
            (b"content-type", b"application/json"),
            (b"content-length", b"2"),
        ]
        for extra in (
            (b"accept-encoding", b"identity"),
            (b"content-encoding", b"gzip"),
            (b"transfer-encoding", b"chunked"),
            (b"x-forwarded-client-cert", b"SYNTHETIC"),
            (b"x-tenant", b"SYNTHETIC"),
            (b"content-type", b"application/json"),
        ):
            with self.subTest(header=extra[0]):
                observed = route(headers + [extra], b"{}")
                self.assertEqual(observed["status"], 400)
                self.assertEqual(observed["calls"], [])
                self.assertEqual(observed["receives"], 0)
        observed = route(headers, b"{}", unbound=True)
        self.assertEqual(observed["status"], 503)
        self.assertEqual(observed["calls"], [])
