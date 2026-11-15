"""Pure admission/transport/SQL-contract tests. No real TLS, SQL, listener or process."""

import copy
import importlib.util
import json
import ssl
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.x509.oid import ExtendedKeyUsageOID
from fixtures import NOW, Fixture, certificate, encode, uid
from pamolive_vault_runtime import admission, asgi, ledger, slot, transport
from pamolive_vault_runtime.bounded import Refusal, json_object, sha


class Sink:
    def __init__(self):
        self.calls = []

    def reserve(self, **kwargs):
        self.calls.append(kwargs)
        kwargs["recheck"]()  # Real crypto, not a verified DTO/boolean substitute.
        return ledger.Pending(uid(300), kwargs["now"], kwargs["end"])


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.sink = Sink()
        self.clock = NOW
        self.service = admission.Reservations(self.fixture.guard, self.sink, lambda: self.clock)

    def test_signed_current_materials_enter_pending_only(self):
        result = self.service.prepare(self.fixture.request(), self.fixture.der)
        self.assertEqual(
            result.public(),
            {
                "reservation_id": uid(300),
                "state": "pending_proofs",
                "issued_at": NOW,
                "expires_at": NOW + 30,
                "authorized": False,
            },
        )
        self.assertNotIn("nonce", result.public())
        self.assertNotIn("counter", json.dumps(result.public()))
        self.assertEqual(self.fixture.guard.checks, 3)
        self.assertEqual(
            self.sink.calls[0]["draft_sha256"],
            __import__("pamolive_vault_contracts").draft_hash(self.fixture.draft),
        )

    def test_every_server_expectation_substitution_refuses_before_ledger(self):
        for name, value in self.fixture.slot.expectations:
            with self.subTest(name=name):
                wrong = (
                    value + 1
                    if type(value) is int
                    else (
                        "other-service"
                        if name == "vault_service_id"
                        else (uid(999) if name in slot.UUID_FIELDS else "f" * 64)
                    )
                )
                draft = replace(self.fixture.draft, **{name: wrong})
                with self.assertRaises(Refusal):
                    self.service.prepare(self.fixture.request(draft), self.fixture.der)
        self.assertEqual(self.sink.calls, [])

    def test_principal_instance_certificate_and_claims_do_not_authenticate(self):
        for changes in (
            {"broker_service_id": "other"},
            {"requested_caller_service_id": "other"},
            {"broker_instance_id": uid(999)},
            {"broker_certificate_sha256": "f" * 64},
        ):
            with self.subTest(changes=changes), self.assertRaises(Refusal):
                self.service.prepare(
                    self.fixture.request(replace(self.fixture.draft, **changes)), self.fixture.der
                )
        with self.assertRaises(Refusal):
            self.service.prepare(self.fixture.request(), certificate(serial=2))
        self.assertEqual(self.sink.calls, [])

    def test_signatures_chain_checkpoint_and_independent_context_fail_before_sql(self):
        tests = []
        for section in ("signatures", "commissioning_signatures"):
            mutated = copy.deepcopy(self.fixture.envelope)
            first = next(iter(mutated[section]))
            mutated[section][first] = mutated[section][first][:-1] + (
                "A" if mutated[section][first][-1] != "A" else "B"
            )
            tests.append(mutated)
        for value in tests:
            self.fixture.envelope = value
            with self.assertRaises(Exception):
                self.service.prepare(self.fixture.request(), self.fixture.der)
        self.assertEqual(self.sink.calls, [])

    def test_checkpoint_freshness_at_40_seconds_and_slot_closed_by_time(self):
        self.clock = NOW + 40
        with self.assertRaises(Exception):
            self.service.prepare(self.fixture.request(), self.fixture.der)
        self.clock = NOW - 11
        with self.assertRaises(Refusal):
            self.service.prepare(self.fixture.request(), self.fixture.der)
        self.assertEqual(self.sink.calls, [])

    def test_modified_server_context_still_fails_real_V1_even_with_matching_draft(self):
        for field, value in (
            ("organization_id", uid(900)),
            ("trust_generation", uid(901)),
            ("registry_revision", 2),
            ("registry_hash", "f" * 64),
        ):
            fixture = Fixture()
            fixture.config["expectations"][field] = value
            fixture.refresh()
            draft = replace(fixture.draft, **{field: value})
            with self.subTest(field=field), self.assertRaises(Exception):
                admission.Reservations(fixture.guard, self.sink, lambda: NOW).prepare(
                    fixture.request(draft), fixture.der
                )
        for field in ("commissioning_keys", "checkpoint_keys"):
            fixture = Fixture()
            fixture.config[field][0]["public_key_hex"] = "f" * 64
            fixture.refresh()
            with self.subTest(field=field), self.assertRaises(Exception):
                admission.Reservations(fixture.guard, self.sink, lambda: NOW).prepare(
                    fixture.request(), fixture.der
                )
        fixture = Fixture()
        fixture.config["installation_p0"] = "opaque-E\u0301-P0"
        fixture.refresh()
        with self.assertRaises(Exception):
            admission.Reservations(fixture.guard, self.sink, lambda: NOW).prepare(
                fixture.request(), fixture.der
            )
        self.assertEqual(self.sink.calls, [])

    def test_short_checkpoint_expiry_caps_reservation_without_extending(self):
        self.clock = NOW + 25
        result = self.service.prepare(self.fixture.request(), self.fixture.der)
        self.assertEqual(result.expires_at, NOW + 40)

    def test_keepalive_revalidates_exact_leaf_and_validity_each_request(self):
        self.clock = NOW + 100
        with self.assertRaises(Refusal):
            self.service.prepare(self.fixture.request(), self.fixture.der)
        for changes in (
            {"after": NOW},
            {"before": NOW + 1},
            {"ca": True},
            {"eku": ExtendedKeyUsageOID.SERVER_AUTH},
            {"san": "urn:pamolive:broker:evil"},
        ):
            der = certificate(**changes)
            cfg = copy.deepcopy(self.fixture.config)
            cfg["principals"][0]["certificate_sha256"] = [sha(der)]
            raw = encode(cfg)
            configured = slot.parse_slot(raw, sha(raw))
            with self.subTest(changes=changes), self.assertRaises(Refusal):
                admission.authenticate(der, configured, NOW)

    def test_mutated_slot_before_ledger_or_at_recheck_refuses(self):
        changed = replace(self.fixture.slot, source_sha256="f" * 64)
        with patch.object(self.fixture.guard, "check", side_effect=[self.fixture.slot, changed]):
            with self.assertRaises(Refusal):
                self.service.prepare(self.fixture.request(), self.fixture.der)
        self.assertEqual(self.sink.calls, [])

    def test_expired_or_revoked_checkpoint_key_is_not_restored_by_valid_old_signature(self):
        self.fixture.config["checkpoint_keys"][0]["revoked_at"] = admission.utc_text(NOW)
        self.fixture.refresh()
        with self.assertRaises(Refusal):
            admission.Reservations(self.fixture.guard, self.sink, lambda: NOW).prepare(
                self.fixture.request(), self.fixture.der
            )
        self.assertEqual(self.sink.calls, [])

    def test_no_assembly_algorithm_or_business_approval_is_invented(self):
        # Person claims remain format values, without quorum or approval authority.
        draft = replace(
            self.fixture.draft, requester_person_id=uid(777), approver_person_ids=(uid(778),)
        )
        result = self.service.prepare(self.fixture.request(draft), self.fixture.der)
        self.assertFalse(result.public()["authorized"])
        self.assertEqual(self.sink.calls[0]["draft"].authority_materials_sha256, "5" * 64)

    def test_request_type_size_extra_fields_and_invalid_base64_are_closed(self):
        for value in (
            {},
            {"approved": True},
            {"draft": {}, "registry_chain": ["%%%"], "checkpoint": "A"},
        ):
            with self.subTest(value=value), self.assertRaises(Exception):
                self.service.prepare(encode(value), self.fixture.der)
        with self.assertRaises(Refusal):
            self.service.prepare(b"x" * (admission.MAX_REQUEST + 1), self.fixture.der)
        self.assertEqual(self.sink.calls, [])


class SlotTests(unittest.TestCase):
    def test_strict_config_pin_and_all_closed_fields(self):
        fixture = Fixture()
        with self.assertRaises(Refusal):
            slot.parse_slot(fixture.config_raw, "f" * 64)
        for name in fixture.config:
            modified = copy.deepcopy(fixture.config)
            modified.pop(name)
            raw = encode(modified)
            with self.subTest(name=name), self.assertRaises(Exception):
                slot.parse_slot(raw, sha(raw))
        modified = dict(fixture.config, approved=True)
        raw = encode(modified)
        with self.assertRaises(Refusal):
            slot.parse_slot(raw, sha(raw))

    def test_duplicate_nonfinite_unicode_and_float_types(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":1e999}', b'{"x":NaN}', b'{"x":1.0}', b'{"x":"\xff"}'):
            with self.subTest(raw=raw), self.assertRaises(Refusal):
                json_object(raw, 1024)
        fixture = Fixture()
        self.assertEqual(fixture.slot.installation_p0, "opaque-É-P0")
        self.assertNotEqual(fixture.slot.installation_p0, "opaque-E\u0301-P0")

    def test_duplicate_principal_cert_and_key_and_closed_recovery_refused(self):
        fixture = Fixture()
        for name in ("principals", "checkpoint_keys", "commissioning_keys"):
            modified = copy.deepcopy(fixture.config)
            modified[name].append(copy.deepcopy(modified[name][0]))
            raw = encode(modified)
            with self.subTest(name=name), self.assertRaises(Exception):
                slot.parse_slot(raw, sha(raw))
        fixture.config["serving_state"] = "closed"
        raw = encode(fixture.config)
        with self.assertRaises(Refusal):
            slot.parse_slot(raw, sha(raw))

    def test_slot_file_rechecks_same_bytes_and_filesystem_identity(self):
        fixture = Fixture()
        identity = ((1, 2), (("parent", (3, 4)),))
        with patch.object(slot, "_read_ro", return_value=(fixture.config_raw, identity)):
            guard = slot.SlotFile(__import__("pathlib").Path("/fixed"), sha(fixture.config_raw))
            self.assertEqual(guard.check(), fixture.slot)
        for raw, current in (
            (fixture.config_raw, ((9, 2), identity[1])),
            (fixture.config_raw + b" ", identity),
        ):
            with (
                patch.object(slot, "_read_ro", return_value=(raw, current)),
                self.assertRaises(Refusal),
            ):
                guard.check()


class SQLContractTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.peer = admission.authenticate(self.f.der, self.f.slot, NOW)
        self.cursor = MagicMock()
        self.conn = MagicMock()
        self.conn.__enter__.return_value = self.conn
        self.conn.cursor.return_value.__enter__.return_value = self.cursor
        self.connect = MagicMock(return_value=self.conn)
        self.db = ledger.PostgresLedger(self.connect)
        from pamolive_vault_contracts import draft_hash, serialize_draft

        self.raw = serialize_draft(self.f.draft)
        self.hash = draft_hash(self.f.draft)
        self.role = (True,) + (False,) * 13
        self.state = (uid(4), self.f.slot.source_sha256, "open")
        self.recheck = MagicMock(return_value=(NOW, NOW + 40, self.peer, self.f.slot))

    def reserve(self):
        return self.db.reserve(
            slot=self.f.slot,
            peer=self.peer,
            draft=self.f.draft,
            canonical_draft=self.raw,
            draft_sha256=self.hash,
            now=NOW,
            end=NOW + 30,
            recheck=self.recheck,
        )

    def existing(self):
        return (
            uid(300),
            NOW,
            NOW + 30,
            self.peer.certificate_sha256,
            self.hash,
            self.raw,
            self.f.slot.source_sha256,
            uid(4),
            uid(103),
            "pending_proofs",
        )

    def writes(self):
        return [
            call for call in self.cursor.execute.call_args_list if "INSERT INTO" in call.args[0]
        ]

    def test_insert_and_audit_same_transaction_and_stable_namespace(self):
        self.cursor.fetchone.side_effect = [self.role, self.state, None, (0,), (NOW,)]
        result = self.reserve()
        self.assertEqual((result.issued_at, result.expires_at), (NOW, NOW + 30))
        self.assertEqual(len(self.writes()), 2)
        params = self.writes()[0].args[1]
        self.assertEqual(
            params[1:6], (uid(2), uid(1), "broker-lab", self.f.draft.operation, uid(101))
        )
        self.assertNotIn(self.peer.certificate_sha256, params[1:6])
        self.assertEqual(len(params[12]), 32)
        self.assertEqual(self.recheck.call_count, 3)
        self.conn.transaction.assert_called_once()

    def test_retry_returns_original_without_nonce_generation_or_insert(self):
        self.cursor.fetchone.side_effect = [self.role, self.state, self.existing(), (NOW,)]
        with patch.object(
            ledger.secrets, "token_bytes", side_effect=AssertionError("retry nonce forbidden")
        ):
            self.assertEqual(self.reserve(), ledger.Pending(uid(300), NOW, NOW + 30))
        self.assertEqual(self.writes(), [])

    def test_each_retry_bound_value_divergence_conflicts_without_mutation(self):
        for index in range(3, 10):
            with self.subTest(index=index):
                row = list(self.existing())
                row[index] = b"other" if index == 5 else "different"
                self.cursor.fetchone.side_effect = [self.role, self.state, tuple(row)]
                with self.assertRaises(Refusal) as caught:
                    self.reserve()
                self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.writes(), [])

    def test_expired_retry_does_not_renew(self):
        row = list(self.existing())
        row[1:3] = [NOW - 31, NOW - 1]
        self.cursor.fetchone.side_effect = [self.role, self.state, tuple(row)]
        with self.assertRaises(Refusal) as caught:
            self.reserve()
        self.assertEqual(caught.exception.status, 410)
        self.assertEqual(self.writes(), [])

    def test_quota_and_closed_or_other_incarnation_stop_before_nonce(self):
        for state, count in (
            (self.state, 2),
            ((uid(999), self.f.slot.source_sha256, "open"), 0),
            ((uid(4), self.f.slot.source_sha256, "closed"), 0),
        ):
            self.cursor.fetchone.side_effect = [self.role, state, None, (count,)]
            with (
                patch.object(
                    ledger.secrets, "token_bytes", side_effect=AssertionError("nonce forbidden")
                ),
                self.assertRaises(Refusal),
            ):
                self.reserve()
        self.assertEqual(self.writes(), [])

    def test_all_forbidden_privilege_bits_and_missing_role_refuse(self):
        for index in range(14):
            row = list(self.role)
            row[index] = not row[index]
            self.cursor.fetchone.side_effect = [tuple(row)]
            with self.subTest(index=index), self.assertRaises(Refusal):
                self.reserve()
        self.cursor.fetchone.side_effect = [None]
        with self.assertRaises(Refusal):
            self.reserve()
        self.assertEqual(self.writes(), [])

    def test_prewrite_refusal_has_no_insert(self):
        self.cursor.fetchone.side_effect = [self.role, self.state, None, (0,)]
        self.recheck.side_effect = Refusal("context_refused", 403)
        with self.assertRaises(Refusal):
            self.reserve()
        self.assertEqual(self.writes(), [])

    def test_postwrite_expiry_requests_rollback_not_success(self):
        self.cursor.fetchone.side_effect = [self.role, self.state, None, (0,)]
        self.recheck.side_effect = [
            (NOW, NOW + 40, self.peer, self.f.slot),
            (NOW + 30, NOW + 40, self.peer, self.f.slot),
        ]
        with self.assertRaises(Refusal):
            self.reserve()
        self.assertEqual(len(self.writes()), 2)
        self.assertIs(self.conn.transaction.return_value.__exit__.call_args.args[0], Refusal)

    def test_commit_unknown_is_constant_unavailable_and_not_retried(self):
        self.cursor.fetchone.side_effect = [self.role, self.state, None, (0,), (NOW,)]
        self.conn.__exit__.side_effect = RuntimeError("PRIVATE DSN MARKER")
        with self.assertRaises(Refusal) as caught:
            self.reserve()
        self.assertEqual(str(caught.exception), "unavailable")
        self.assertIsNone(caught.exception.__context__)
        self.connect.assert_called_once()

    def test_startup_requires_exact_external_incarnation_and_never_repairs(self):
        self.cursor.fetchone.side_effect = [self.role, self.state]
        self.assertIsNone(self.db.startup(self.f.slot))
        self.assertEqual(self.writes(), [])
        for state in (
            None,
            (uid(999), self.f.slot.source_sha256, "open"),
            (uid(4), self.f.slot.source_sha256, "closed"),
        ):
            self.cursor.fetchone.side_effect = [self.role, state]
            with self.subTest(state=state), self.assertRaises(Refusal):
                self.db.startup(self.f.slot)
        self.assertEqual(self.writes(), [])


def drive(coroutine):
    """All awaited unit fakes complete inline. No event loop/self-pipe/socket created."""
    try:
        coroutine.send(None)
    except StopIteration as result:
        return result.value
    raise AssertionError("unit unexpectedly requested a real async operation")


class ASGITests(unittest.TestCase):
    def setUp(self):
        self.app = asgi.Application(None)
        self.addCleanup(self.app.close)
        self.output = []
        self.scope = {
            "type": "http",
            "scheme": "https",
            "http_version": "1.1",
            "method": "POST",
            "path": "/v1/reservations",
            "raw_path": b"/v1/reservations",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json"), (b"content-length", b"2")],
        }

    async def send(self, value):
        self.output.append(value)

    async def receive(self):
        return {"type": "http.request", "body": b"{}"}

    async def wait(self, awaitable, **kwargs):
        return await awaitable

    async def inline(self, raw, der):
        self.assertEqual((raw, der), (b"{}", b"DER"))
        return ledger.Pending(uid(300), NOW, NOW + 30)

    def request(self):
        with (
            patch.object(asgi.asyncio, "wait_for", self.wait),
            patch.object(self.app, "_run", self.inline),
        ):
            drive(self.app.for_tls_peer(b"DER")(self.scope, self.receive, self.send))
        return self.output[0]["status"]

    def test_bound_endpoint_success_and_unbound_scope_refusal(self):
        self.assertEqual(self.request(), 200)
        self.assertNotIn(b"nonce", self.output[-1]["body"])
        self.output = []
        self.scope["peer_certificate"] = b"DER"
        drive(self.app(self.scope, self.receive, self.send))
        self.assertEqual(self.output[0]["status"], 503)

    def test_forged_headers_and_duplicates_rejected_without_dispatch(self):
        for header in (
            (b"x-client-cert", b"DER"),
            (b"x-forwarded-proto", b"https"),
            (b"authorization", b"approved"),
            (b"content-type", b"application/json"),
        ):
            self.output = []
            self.scope["headers"] = [
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
                header,
            ]
            self.assertEqual(self.request(), 400)

    def test_wrong_path_method_query_http_and_body_lengths(self):
        for key, value in (
            ("scheme", "http"),
            ("method", "GET"),
            ("path", "/release"),
            ("raw_path", b"/v1/%72eservations"),
            ("query_string", b"tenant=x"),
        ):
            original = self.scope[key]
            self.scope[key], self.output = value, []
            self.assertEqual(self.request(), 400)
            self.scope[key] = original
        self.scope["headers"][-1] = (b"content-length", b"1")
        self.output = []
        self.assertEqual(self.request(), 400)

    def test_unexpected_error_never_exports_exception_or_draft(self):
        async def failure(raw, der):
            raise RuntimeError("PRIVATE MARKER")

        with (
            patch.object(asgi.asyncio, "wait_for", self.wait),
            patch.object(self.app, "_run", failure),
        ):
            drive(self.app.for_tls_peer(b"DER")(self.scope, self.receive, self.send))
        self.assertEqual(self.output[-1]["body"], b'{"error":"unavailable","authorized":false}')

    def test_chunk_budget_exact_and_plus_one_before_dispatch(self):
        for count, status in ((256, 200), (257, 400)):
            events = [{"type": "http.request", "body": b"{}", "more_body": True}]
            events += [
                {"type": "http.request", "body": b"", "more_body": True} for _ in range(count - 2)
            ]
            events += [{"type": "http.request", "body": b"", "more_body": False}]

            async def receive():
                return events.pop(0)

            self.output = []
            with (
                patch.object(asgi.asyncio, "wait_for", self.wait),
                patch.object(self.app, "_run", self.inline),
            ):
                drive(self.app.for_tls_peer(b"DER")(self.scope, receive, self.send))
            self.assertEqual(self.output[0]["status"], status)

    def test_timeout_keeps_capacity_until_actual_job_finishes(self):
        self.app.reservations = MagicMock()

        class Future:
            def add_done_callback(self, callback):
                self.callback = callback

            def cancelled(self):
                return False

            def exception(self):
                return None

        future = Future()
        permit = MagicMock()

        async def acquire():
            return True

        permit.acquire = acquire

        async def wait(awaitable, *, timeout):
            if timeout == 1:
                return await awaitable
            self.assertEqual(timeout, 8)
            raise TimeoutError

        loop = MagicMock()
        loop.run_in_executor.return_value = future
        with (
            patch.object(self.app, "_jobs", permit),
            patch.object(asgi.asyncio, "get_running_loop", return_value=loop),
            patch.object(asgi.asyncio, "wait_for", wait),
            patch.object(asgi.asyncio, "shield", side_effect=lambda item: item),
        ):
            with self.assertRaises(TimeoutError):
                drive(self.app._run(b"{}", b"DER"))
            permit.release.assert_not_called()
            future.callback(future)
            permit.release.assert_called_once()


class TransportTests(unittest.TestCase):
    def test_connection_local_closures_and_certrequired_without_global_mutation(self):
        application = MagicMock()
        application.for_tls_peer.side_effect = ["first closure", "second closure"]
        protocol = transport.protocol_class(application)
        objects = []
        for der in (b"first DER", b"second DER"):
            instance = protocol.__new__(protocol)
            channel = MagicMock()
            tls = MagicMock(spec=ssl.SSLObject)
            tls.context.verify_mode = ssl.CERT_REQUIRED
            tls.getpeercert.return_value = der
            channel.get_extra_info.return_value = tls
            with patch.object(transport.H11Protocol, "connection_made") as base:
                instance.connection_made(channel)
                base.assert_called_once_with(channel)
            channel.close.assert_not_called()
            tls.getpeercert.assert_called_once_with(binary_form=True)
            objects.append(instance)
        self.assertEqual([obj.app for obj in objects], ["first closure", "second closure"])
        self.assertEqual(application.for_tls_peer.call_count, 2)

    def test_missing_tls_certnone_missing_der_and_changed_server_version_no_connection(self):
        app = MagicMock()
        app.for_tls_peer.side_effect = Refusal("caller_refused", 403)
        cls = transport.protocol_class(app)
        for mode in (None, ssl.CERT_NONE, ssl.CERT_REQUIRED):
            channel = MagicMock()
            tls = None if mode is None else MagicMock(spec=ssl.SSLObject)
            if tls is not None:
                tls.context.verify_mode = mode
            channel.get_extra_info.return_value = tls
            instance = cls.__new__(cls)
            with patch.object(transport.H11Protocol, "connection_made") as base:
                instance.connection_made(channel)
            channel.close.assert_called_once()
            base.assert_called_once_with(channel)
        with (
            patch.object(transport.uvicorn, "__version__", "different"),
            self.assertRaises(Refusal),
        ):
            transport.protocol_class(app)

    def test_config_explicit_h11_factory_and_no_proxy_ws_or_autobackend(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_REQUIRED
        config = transport.configuration(MagicMock(), context)
        self.assertFalse(config.proxy_headers or config.http2 or config.reload or config.access_log)
        self.assertEqual((config.loop, config.ws, config.workers), ("asyncio", "none", 1))
        self.assertTrue(issubclass(config.http, transport.H11Protocol))
        self.assertIs(config.ssl_context_factory(config, lambda: None), context)
        self.assertTrue(config.is_ssl)

    def test_n0_binding_is_exact_in_configuration_and_lab_manifest(self):
        source = Path(__file__).resolve().parents[1] / "integration/serve_lab.py"
        spec = importlib.util.spec_from_file_location("_vault_bind_lab_fixture", source)
        lab = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lab)
        path = str(source)
        value = {
            name: path
            for name in (
                "slot_path",
                "runtime_database_file",
                "owner_database_file",
                "web_database_file",
                "worker_database_file",
                "server_certificate",
                "server_key",
                "client_ca",
                "server_ca",
                "client_a_certificate",
                "client_a_key",
                "client_b_certificate",
                "client_b_key",
                "client_a_der",
                "client_b_der",
                "request_file",
            )
        }
        value.update(
            schema="pamolive.vault.synthetic-lab-inputs/1",
            slot_sha256=sha(b"PUBLIC TEST ONLY slot pin"),
            port=9443,
            bind_host="127.0.0.1",
            server_host="vault-n0.test",
            bad_tls_clients=[
                {"case": case, "certificate": path, "private_key": path}
                for case in ("unknown_ca", "expired", "future")
            ],
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_REQUIRED
        for host in ("127.0.0.1", "10.253.249.3"):
            with self.subTest(allowed=host):
                config = transport.configuration(MagicMock(), context, host=host)
                self.assertEqual(config.host, host)
                with patch.object(
                    lab, "local_bytes", return_value=encode({**value, "bind_host": host})
                ):
                    self.assertEqual(lab.lab_inputs(source)["bind_host"], host)
        for host in (
            "0.0.0.0",
            "::",
            "::1",
            "localhost",
            "10.253.249.2",
            "10.0.0.1",
            "192.168.1.1",
            "8.8.8.8",
            "",
            "10.253.249.3 ",
            None,
            True,
            1,
            [],
            {},
        ):
            with self.subTest(refused=host):
                with self.assertRaises(Refusal):
                    transport.configuration(MagicMock(), context, host=host)
                with (
                    patch.object(
                        lab, "local_bytes", return_value=encode({**value, "bind_host": host})
                    ),
                    self.assertRaises(Refusal),
                ):
                    lab.lab_inputs(source)
