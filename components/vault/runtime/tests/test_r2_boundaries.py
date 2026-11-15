"""R2 resource/lifecycle regression cases, including both unchanged R1 failures."""

import importlib
import json
import ssl
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pamolive_vault_runtime import asgi, bounded, transport
from test_runtime import drive

ROOT = Path(__file__).resolve().parents[5]
OLD = Path(__file__).resolve().parent / "history/r1"
PACKAGE = "_reservation_r1_counterexample"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(OLD)]
sys.modules[PACKAGE] = package
old_json = importlib.import_module(PACKAGE + ".bounded")
old_transport = importlib.import_module(PACKAGE + ".transport")
WIDE = b'{"x":[' + b"[]," * 9000 + b"[]]}"


class JSONPrebudgetTests(unittest.TestCase):
    def before_decode(self, raw, maximum=3 * 1024**2):
        calls = []

        def profile(frame, event, function):
            if (
                event == "c_call"
                and getattr(function, "__self__", None) is raw
                and getattr(function, "__name__", "") == "decode"
            ):
                calls.append("UTF8 decode")
                raise AssertionError("UTF8 decode before resource refusal")

        previous = sys.getprofile()
        try:
            sys.setprofile(profile)
            with patch.object(
                bounded.json,
                "loads",
                side_effect=AssertionError("JSON decode before resource refusal"),
            ) as loads:
                with self.assertRaises(bounded.Refusal):
                    bounded.json_object(raw, maximum)
                loads.assert_not_called()
        finally:
            sys.setprofile(previous)
        self.assertEqual(calls, [])

    def test_exact_reviewed_27010_byte_9001_list_case_refuses_before_any_decode(self):
        self.assertEqual(len(WIDE), 27010)
        self.before_decode(WIDE)

    def test_original_R1_really_allocates_all_9001_children_then_refuses(self):
        decoded, real = [], json.loads

        def observed(*args, **kwargs):
            value = real(*args, **kwargs)
            decoded.append(len(value["x"]))
            return value

        with patch.object(old_json.json, "loads", side_effect=observed):
            with self.assertRaises(old_json.Refusal):
                old_json.json_object(WIDE, 3 * 1024**2)
        self.assertEqual(decoded, [9001])

    def test_wide_containers_strings_keys_and_primitives_pre_refuse(self):
        cases = [
            b'{"x":[' + b"0," * 8190 + b"0]}",
            b'{"x":[' + b'"s",' * 8190 + b'"s"]}',
            b"{" + b",".join(f'"k{i}":0'.encode() for i in range(4096)) + b"}",
            b'{"x":' + b"[" * 13 + b"]" * 13 + b"}",
            b'{"x":' + b"[" * 1000 + b"0" + b"]" * 1000 + b"}",
        ]
        for raw in cases:
            with self.subTest(bytes=len(raw)):
                self.before_decode(raw)

    def test_exact_nodes_and_depth_still_accepted_keys_count_as_nodes(self):
        raw = b'{"x":[' + b"0," * 8188 + b"0]}"  # 1 root + 1 key + 1 list + 8189 = 8192.
        self.assertEqual(len(bounded.json_object(raw, len(raw))["x"]), 8189)
        self.assertEqual(
            bounded.json_object(b'{"x":' + b"[" * 12 + b"]" * 12 + b"}", 128),
            json.loads(b'{"x":' + b"[" * 12 + b"]" * 12 + b"}"),
        )
        self.before_decode(b'{"x":[' + b"0," * 8189 + b"0]}")

    def test_escaped_braces_backslashes_quotes_UTF8_and_finite_types_are_data(self):
        value = {
            'quoted "key{}[]': [True, False, None, -123, 0, '\\"{}[]:' * 100],
            "é": {"decomposed": "E\u0301", "line": "a\nb\tc\r"},
        }
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.assertEqual(bounded.json_object(raw, len(raw)), value)
        self.assertEqual(
            bounded.json_object(b'{"\\u0078":"\\u005b\\u007b\\u0022"}', 100), {"x": '[{"'}
        )
        self.before_decode(raw, len(raw) - 1)

    def test_stdlib_retains_syntax_duplicate_and_nonfinite_authority(self):
        for raw in (
            b'{"x":1,"\\u0078":2}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b'{"x":1e999}',
            b'{"x":1.0}',
            b'{"x":' + b"9" * 5000 + b"}",
            b'{"x": [}',
            b'{"x":"\\q"}',
            b'{"x":"\xff"}',
        ):
            with self.subTest(raw_bytes=len(raw)), self.assertRaises(bounded.Refusal):
                bounded.json_object(raw, 16384)


class FakeTask:
    def add_done_callback(self, callback):
        self.callback = callback

    def finish(self):
        self.callback(self)


class FakeLoop:
    def __init__(self):
        self.created = 0
        self.tasks = []

    def create_task(self, coroutine, **kwargs):
        self.created += 1
        coroutine.close()  # Never run ASGI, SQL, executor, listener or an event loop.
        task = FakeTask()
        self.tasks.append(task)
        return task

    def finish(self):
        for task in self.tasks:
            task.finish()


class H11LifecycleTests(unittest.TestCase):
    def channel(self, der=b"synthetic-DER", mode=ssl.CERT_REQUIRED, tls_present=True, error=None):
        channel = MagicMock()
        tls = MagicMock(spec=ssl.SSLObject) if tls_present else None
        if tls is not None:
            tls.context.verify_mode = mode
            tls.getpeercert.return_value = der
            tls.getpeercert.side_effect = error
        channel.get_extra_info.side_effect = lambda key: {
            "ssl_object": tls,
            "sslcontext": tls.context if tls else None,
            "peername": ("127.0.0.1", 1234),
            "sockname": ("127.0.0.1", 9443),
        }.get(key)
        return channel

    def protocol(self, *, source=transport, application=None, shared=None):
        application = application if application is not None else object.__new__(asgi.Application)
        config = SimpleNamespace(
            loaded=True,
            loaded_app=application,
            h11_max_incomplete_event_size=8192,
            ws_protocol_class=None,
            root_path="",
            asgi_version="3.0",
            limit_concurrency=16,
            timeout_keep_alive=2,
            reset_contextvars=False,
        )
        state = SimpleNamespace(
            connections=set(), tasks=set(), default_headers=[], total_requests=0
        )
        loop = FakeLoop()
        protocol = source.protocol_class(application)(
            config, state, {} if shared is None else shared, _loop=loop
        )
        protocol.logger = SimpleNamespace(level=100, warning=MagicMock())
        return protocol, state, loop, config

    def test_original_R1_same_refusal_still_fails_actual_inherited_cleanup(self):
        protocol, state, _, _ = self.protocol(source=old_transport)
        channel = self.channel(der=b"x" * 16385)
        protocol.connection_made(channel)
        channel.close.assert_called_once()
        self.assertIsNone(protocol.transport)
        with self.assertRaisesRegex(AttributeError, "NoneType.*close"):
            protocol.connection_lost(None)
        self.assertEqual(state.connections, set())

    def test_refused_TLS_DER_and_error_callbacks_close_without_dispatch_or_leak(self):
        cases = (
            {"tls_present": False},
            {"mode": ssl.CERT_NONE},
            {"der": None},
            {"der": "not bytes"},
            {"der": b""},
            {"der": b"x" * 16385},
            {"error": ValueError("SYNTHETIC TLS ERROR")},
        )
        for case in cases:
            protocol, state, loop, _ = self.protocol()
            channel = self.channel(**case)
            with self.subTest(case=list(case)):
                protocol.connection_made(channel)
                self.assertIs(protocol.transport, channel)
                self.assertIn(protocol, state.connections)
                channel.close.assert_called_once()
                protocol.pause_writing()
                protocol.resume_writing()
                protocol.eof_received()
                protocol.data_received(
                    b"POST /v1/reservations HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n"
                )
                self.assertEqual(loop.created, 0)
                output = []

                async def send(message):
                    output.append(message)

                drive(protocol.app({}, None, send))
                self.assertEqual(output[0]["status"], 503)
                self.assertIn(b'"authorized":false', output[-1]["body"])
                protocol.connection_lost(None)
                self.assertEqual(state.connections, set())
                self.assertEqual(state.tasks, set())
                protocol.data_received(b"late bytes")
                self.assertEqual(loop.created, 0)

    def test_parser_error_after_bound_TLS_uses_real_H11_and_cleans_up(self):
        protocol, state, loop, _ = self.protocol()
        channel = self.channel()
        protocol.connection_made(channel)
        protocol.data_received(b"INVALID\r\n\r\n")
        self.assertEqual(loop.created, 0)
        channel.write.assert_called()
        self.assertIn(b"400", b"".join(call.args[0] for call in channel.write.call_args_list))
        protocol.connection_lost(None)
        self.assertEqual(state.connections, set())
        self.assertEqual(state.tasks, set())

    def test_valid_HTTP_parser_is_delegated_and_its_callback_cycle_cleans(self):
        protocol, state, loop, _ = self.protocol()
        channel = self.channel()
        protocol.connection_made(channel)
        protocol.data_received(
            b"POST /v1/reservations HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n"
        )
        self.assertEqual(loop.created, 1)
        self.assertEqual(protocol.scope["path"], "/v1/reservations")
        self.assertFalse(protocol.cycle.disconnected)
        protocol.connection_lost(None)
        self.assertTrue(protocol.cycle.disconnected)
        loop.finish()  # Explicitly complete the task fake after H11 registered its callback.
        self.assertEqual(state.connections, set())
        self.assertEqual(state.tasks, set())

    def test_two_connections_keepalive_closures_remain_per_connection_then_reset(self):
        application = object.__new__(asgi.Application)
        observed = []

        async def request(der, scope, receive, send):
            observed.append(der)

        application._request = request
        shared = {}
        first, first_state, _, first_config = self.protocol(application=application, shared=shared)
        second, second_state, _, second_config = self.protocol(
            application=application, shared=shared
        )
        first.connection_made(self.channel(b"first DER"))
        second.connection_made(self.channel(b"second DER"))
        for protocol in (first, second, first, second):
            drive(protocol.app({}, None, None))
        self.assertEqual(observed, [b"first DER", b"second DER"] * 2)
        self.assertIs(first_config.loaded_app, application)
        self.assertIs(second_config.loaded_app, application)
        self.assertEqual(shared, {})
        first.connection_lost(None)
        second.connection_lost(None)
        self.assertEqual((first_state.connections, second_state.connections), (set(), set()))
        self.assertFalse(first._peer_ready or second._peer_ready)
