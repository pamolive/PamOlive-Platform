"""Real h11 with inert socket/TLS/stream actors; no service or credentials.

These tests prove framing, bounds, deadlines and cleanup decisions. They do not
prove an OpenBao response or certificate-chain/SAN verification by a real TLS
pair; that requires the separately commissioned synthetic TLS qualification.
"""

import asyncio
import importlib.util
import ssl
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / "src/pamolive_vault_kms_openbao/transport.py"
SPEC = importlib.util.spec_from_file_location("_openbao_transport_under_test", SOURCE)
t = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(t)

BODY = b'{"plaintext":"SU5FUlQ="}'
ANSWER = b'{"data":{"ciphertext":"vault:v1:INERT"}}'
PATH = "/v1/transit/encrypt/key-1"
TOKEN = "INERT-PUBLIC-TEST-TOKEN"


def response(body=ANSWER, *, status=b"200 OK", headers=None):
    if headers is None:
        headers = [
            (b"Content-Type", b"application/json"),
            (b"Content-Length", str(len(body)).encode()),
            (b"Connection", b"close"),
        ]
    return (
        b"HTTP/1.1 "
        + status
        + b"\r\n"
        + b"".join(name + b": " + value + b"\r\n" for name, value in headers)
        + b"\r\n"
        + body
    )


class Socket:
    def __init__(self):
        self.closed = False
        self.blocking = None

    def setblocking(self, value):
        self.blocking = value

    def close(self):
        self.closed = True


class Reader:
    def __init__(self, raw, *, fragment=4096, delay=0):
        self.raw, self.fragment, self.delay = raw, fragment, delay
        self.requests = []

    async def read(self, cap):
        self.requests.append(cap)
        if self.delay:
            await asyncio.sleep(self.delay)
        size = min(cap, self.fragment)
        value, self.raw = self.raw[:size], self.raw[size:]
        return value


class Writer:
    def __init__(self, *, version="TLSv1.3", alpn="http/1.1", close_delay=0):
        self.tls = SimpleNamespace(version=lambda: version, selected_alpn_protocol=lambda: alpn)
        self.transport = SimpleNamespace(abort=self.abort)
        self.writes, self.closing, self.closed = [], False, False
        self.aborted, self.close_delay = False, close_delay

    def get_extra_info(self, name):
        assert name == "ssl_object"
        return self.tls

    def write(self, raw):
        self.writes.append(raw)

    async def drain(self):
        return None

    def close(self):
        self.closing = True

    def abort(self):
        self.aborted = self.closing = True

    async def wait_closed(self):
        if self.close_delay:
            await asyncio.sleep(self.close_delay)
        self.closed = True

    def is_closing(self):
        return self.closing


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.socket = Socket()
        self.reader = Reader(response())
        self.writer = Writer()
        self.connect = AsyncMock()
        self.opened = AsyncMock(side_effect=lambda **_: (self.reader, self.writer))
        self.factory = Mock(return_value=self.socket)
        for boundary in (
            patch.object(t, "_tls_context", return_value=object()),
            patch.object(t, "_new_socket", self.factory),
            patch.object(t, "_connect_socket", self.connect),
            patch.object(t.asyncio, "open_connection", self.opened),
        ):
            boundary.start()
            self.addCleanup(boundary.stop)
        self.client = t.TransitTransport(
            "127.0.0.1",
            "bao.lab.test",
            8200,
            ca_file="/ca.pem",
            cert_file="/client.pem",
            key_file="/key.pem",
        )

    def refused(self, path=PATH, token=TOKEN, body=BODY):
        with self.assertRaises(t.TransportError) as caught:
            self.client.post(path, token, body)
        error = caught.exception
        self.assertEqual(str(error), "openbao_transport_refused")
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        return error

    def test_success_is_one_numeric_connection_named_SNI_and_verified_close(self):
        self.assertEqual(self.client.post(PATH, TOKEN, BODY), ANSWER)
        self.assertEqual(self.factory.call_count, 1)
        self.assertEqual(self.connect.call_args.args[2], ("127.0.0.1", 8200))
        options = self.opened.call_args.kwargs
        self.assertEqual(options["server_hostname"], "bao.lab.test")
        self.assertNotIn("host", options)
        self.assertIs(options["sock"], self.socket)
        self.assertEqual(options["limit"], t.MAX_HEADERS)
        self.assertTrue(self.socket.closed and self.writer.closed)
        self.assertIs(self.socket.blocking, False)
        self.assertFalse(self.writer.aborted)
        wire = b"".join(self.writer.writes)
        self.assertIn(b"x-vault-token: " + TOKEN.encode() + b"\r\n", wire)
        self.assertIn(b"host: bao.lab.test:8200\r\n", wire)
        self.assertNotIn(b"cookie:", wire.lower())

    def test_ipv6_literal_has_no_scope_or_hostname_resolution(self):
        self.client = t.TransitTransport(
            "::1", "bao.lab.test", 8200, ca_file="/ca", cert_file="/cert", key_file="/key"
        )
        self.assertEqual(self.client.post(PATH, TOKEN, BODY), ANSWER)
        self.assertEqual(self.connect.call_args.args[2], ("::1", 8200))
        self.assertEqual(self.factory.call_args.args, (t.socket.AF_INET6,))

    def test_endpoint_validation_refuses_discovery_and_ambiguous_names(self):
        for address, name, port, timeout in (
            ("localhost", "bao.lab.test", 8200, 3),
            ("0.0.0.0", "bao.lab.test", 8200, 3),
            ("224.0.0.1", "bao.lab.test", 8200, 3),
            ("fe80::1%eth0", "bao.lab.test", 8200, 3),
            ("127.0.0.1", "127.0.0.1", 8200, 3),
            ("127.0.0.1", "bao.lab.test\r\n", 8200, 3),
            ("127.0.0.1", "*.lab.test", 8200, 3),
            ("127.0.0.1", "bao.lab.test", True, 3),
            ("127.0.0.1", "bao.lab.test", 8200, float("nan")),
            ("127.0.0.1", "bao.lab.test", 8200, 0),
        ):
            with self.subTest(address=address, name=name), self.assertRaises(t.TransportError):
                t.TransitTransport(
                    address,
                    name,
                    port,
                    ca_file="/ca",
                    cert_file="/cert",
                    key_file="/key",
                    timeout=timeout,
                )
        self.factory.assert_not_called()

    def test_path_token_and_body_refusals_precede_socket_creation(self):
        for path in (
            "/v1/sys/health",
            "/v1/transit/encrypt/../secret",
            "/v1/transit/encrypt/Upper",
            "/v1/transit/decrypt/key?x=y",
            "/v1/transit/encrypt/" + "k" * 64,
        ):
            self.refused(path=path)
        for token in ("", "x\r\nInjected: yes", "x y", "é", "x" * (t.MAX_TOKEN + 1)):
            self.refused(token=token)
        for body in (
            b"",
            b"x" * (t.MAX_BODY + 1),
            bytearray(BODY),
            b"[]",
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
        ):
            self.refused(body=body)
        self.factory.assert_not_called()

    def test_decrypt_route_and_exact_request_size_boundary(self):
        body = b'{"x":"' + b"a" * (t.MAX_BODY - 8) + b'"}'
        self.assertEqual(len(body), t.MAX_BODY)
        self.assertEqual(
            self.client.post("/v1/transit/decrypt/" + "k" * 63, "x" * t.MAX_TOKEN, body), ANSWER
        )

    def test_response_fragmentation_and_chunked_framing(self):
        self.reader = Reader(response(), fragment=3)
        self.assertEqual(self.client.post(PATH, TOKEN, BODY), ANSWER)
        self.reader = Reader(
            response(
                b"%x\r\n" % len(ANSWER) + ANSWER + b"\r\n0\r\n\r\n",
                headers=[
                    (b"Content-Type", b"application/json"),
                    (b"Transfer-Encoding", b"chunked"),
                ],
            )
        )
        self.writer = Writer()
        self.assertEqual(self.client.post(PATH, TOKEN, BODY), ANSWER)

    def test_redirect_error_and_informational_responses_are_not_retried(self):
        for status in (
            b"302 Found",
            b"403 Forbidden",
            b"500 Internal Server Error",
            b"100 Continue",
        ):
            self.reader = Reader(response(status=status))
            self.writer = Writer()
            self.refused()
            self.assertTrue(self.writer.aborted and self.socket.closed)
        self.assertEqual(self.opened.call_count, 4)

    def test_compression_cookie_and_content_type_refuse(self):
        variants = [
            [(b"Content-Type", b"text/plain")],
            [(b"Content-Type", b"application/json"), (b"Content-Encoding", b"gzip")],
            [(b"Content-Type", b"application/json"), (b"Set-Cookie", b"INERT")],
            [(b"Content-Type", b"application/json"), (b"Location", b"https://elsewhere.test")],
        ]
        for headers in variants:
            self.reader = Reader(response(headers=headers))
            self.writer = Writer()
            self.refused()

    def test_json_and_trailing_response_refuse_without_exposing_body(self):
        for raw in (b"INERT PRIVATE RESPONSE", b'{"x":1,"x":2}', b'{"x":1e999}', b"[]"):
            self.reader = Reader(response(raw))
            self.writer = Writer()
            self.refused()
        self.reader = Reader(response() + response())
        self.writer = Writer()
        self.refused()

    def test_body_header_and_parser_limits(self):
        body = b'{"x":"' + b"a" * (t.MAX_BODY - 7) + b'"}'
        self.reader = Reader(response(body))
        self.refused()
        self.reader = Reader(
            response(
                headers=[(b"Content-Type", b"application/json"), (b"X-Large", b"x" * t.MAX_HEADERS)]
            )
        )
        self.writer = Writer()
        self.refused()
        self.reader = Reader(response(status=b"200 " + b"x" * t.MAX_HEADERS))
        self.writer = Writer()
        self.refused()

    def test_incomplete_message_and_trailers_refuse(self):
        for raw in (
            response()[:-1],
            response(
                b"2\r\n{}\r\n0\r\nSecret: INERT\r\n\r\n",
                headers=[
                    (b"Content-Type", b"application/json"),
                    (b"Transfer-Encoding", b"chunked"),
                ],
            ),
        ):
            self.reader = Reader(raw)
            self.writer = Writer()
            self.refused()

    def test_tls_version_and_alpn_fail_before_writing_token(self):
        for writer in (Writer(version="TLSv1.2"), Writer(alpn="h2")):
            self.writer = writer
            self.refused()
            self.assertEqual(writer.writes, [])
            self.assertTrue(writer.aborted and self.socket.closed)

    def test_failed_connect_and_handshake_close_socket_and_scrub_exception(self):
        self.connect.side_effect = OSError("INERT PRIVATE CONNECT DETAIL")
        self.refused()
        self.assertTrue(self.socket.closed)
        self.opened.assert_not_called()
        self.connect.side_effect = None
        self.opened.side_effect = ssl.SSLError("INERT PRIVATE CERTIFICATE DETAIL")
        self.refused()
        self.assertTrue(self.socket.closed)

    def test_absolute_budget_includes_headers_body_and_close(self):
        self.client._timeout = 0.04
        self.reader = Reader(response(), fragment=1, delay=0.01)
        self.refused()
        self.assertTrue(self.writer.aborted and self.socket.closed)
        self.reader = Reader(response())
        self.writer = Writer(close_delay=0.1)
        self.refused()
        self.assertTrue(self.writer.aborted and self.socket.closed)

    def test_unacknowledged_close_is_never_success(self):
        self.writer.wait_closed = AsyncMock(side_effect=OSError("INERT PRIVATE CLOSE DETAIL"))
        self.refused()
        self.assertTrue(self.writer.aborted and self.socket.closed)

    def test_exact_response_boundary(self):
        body = b'{"x":"' + b"a" * (t.MAX_BODY - 8) + b'"}'
        self.assertEqual(len(body), t.MAX_BODY)
        self.reader = Reader(response(body))
        self.assertEqual(self.client.post(PATH, TOKEN, BODY), body)

    def test_wire_overhead_is_bounded_even_with_tiny_decoded_body(self):
        chunks = (b"1;pad=" + b"x" * 2048 + b"\r\n \r\n") * 13
        raw = response(
            chunks + b"2\r\n{}\r\n0\r\n\r\n",
            headers=[(b"Content-Type", b"application/json"), (b"Transfer-Encoding", b"chunked")],
        )
        self.reader = Reader(raw)
        self.refused()
        self.assertGreater(len(raw), t.MAX_WIRE)
        self.assertTrue(self.writer.aborted and self.socket.closed)

    def test_absolute_budget_also_covers_connect_and_handshake(self):
        self.client._timeout = 0.04

        async def slow(*_args, **_kwargs):
            await asyncio.sleep(0.1)

        self.connect.side_effect = slow
        self.refused()
        self.opened.assert_not_called()
        self.assertTrue(self.socket.closed)
        self.connect.side_effect = None
        self.opened.side_effect = slow
        self.refused()
        self.assertTrue(self.socket.closed)

    def test_active_event_loop_refuses_before_creating_coroutine(self):
        async def call():
            with patch.object(self.client, "_post") as coroutine:
                self.refused()
                coroutine.assert_not_called()

        asyncio.run(call())
        self.factory.assert_not_called()

    def test_cancellation_propagates_after_socket_cleanup(self):
        self.reader.read = AsyncMock(side_effect=asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            self.client.post(PATH, TOKEN, BODY)
        self.assertTrue(self.writer.aborted and self.socket.closed)


class TLSConfigurationTests(unittest.TestCase):
    def test_dedicated_store_SAN_mtls_and_no_prompt(self):
        context = Mock(options=0)
        ca, cert, key = (
            Path(__file__).resolve().parent / name
            for name in ("INERT-ca.pem", "INERT-client.pem", "INERT-key.pem")
        )
        with patch.object(t.ssl, "SSLContext", return_value=context) as factory:
            self.assertIs(t._tls_context(ca, cert, key), context)
        factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(context.check_hostname, True)
        self.assertIs(context.hostname_checks_common_name, False)
        self.assertIsNone(context.keylog_filename)
        context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        context.load_verify_locations.assert_called_once_with(cafile=str(ca))
        self.assertIs(context.load_cert_chain.call_args.kwargs["password"], t._no_password)
        with self.assertRaises(t.TransportError):
            t._no_password()
        context.load_default_certs.assert_not_called()

    def test_relative_TLS_file_is_not_a_default(self):
        with self.assertRaises(t.TransportError), patch.object(t.ssl, "SSLContext") as factory:
            t._tls_context("ca.pem", "/client.pem", "/key.pem")
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
