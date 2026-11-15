"""Real AUTH01 public signatures plus transaction/harness control regressions.

The SQL objects below are call/exception/clock spies, not a ledger fallback or
PostgreSQL permission/atomicity evidence. Production always uses psycopg.
"""

import copy
import importlib.util
import json
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fixtures import Fixture, MemoryReader, assertion, uid
from pamolive_usage_anchor import codec, ledger
from pamolive_usage_anchor.authority import Authority
from pamolive_usage_anchor.proofs import final_proofs
from pamolive_usage_anchor.service import Service
from pamolive_usage_anchor.slot import parse_slot
from pamolive_vault_contracts import (
    parse_transcript,
    serialize_draft,
)
from pamolive_vault_runtime.slot import EXPECTED_FIELDS

PATH = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "w1_permissions_r2", PATH / "integration/permissions.py"
)
permissions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(permissions)


class NoTransaction:
    def __init__(self):
        self.entries = 0

    def transaction(self, *args, **kwargs):
        self.entries += 1
        raise AssertionError("wrong intention must fail before SQL")


class IntentPinTests(unittest.TestCase):
    def test_public_auth01_four_real_proofs_no_longer_authorize_intention(self):
        raw = (PATH / "tests/golden/auth01-r1-public.json").read_bytes()
        self.assertEqual(
            codec.sha(raw), "4b2b4da37027b174c699ff2f0de57dfdddd4c0e231c13f1f9ca6b4a9026c856e"
        )
        public = json.loads(raw)
        old_slot = codec.parse(codec.unb64(public["slot_b64"], 65536), 65536, special=True)
        with self.assertRaises(codec.Error):
            parse_slot(codec.unb64(public["slot_b64"], 65536), public["slot_sha256"])
        # Commission the new W-only pin from the independent public intention,
        # never the draft; fresh valid V certificate metadata enables bind's
        # real caller checks without claiming a TLS handshake here.
        fixture = Fixture(now=public["synthetic_now"])
        slot_value = copy.deepcopy(old_slot)
        slot_value["intent_requester_person_id"] = public["intent_public_object"][
            "requester_person_id"
        ]
        for principal in slot_value["principals"]:
            if principal["audience"] == "usage-anchor.vault/1":
                principal["certificate_sha256"] = [codec.sha(fixture.vault_der)]
        slot_raw = codec.encode(slot_value, 65536, special=True)
        slot = parse_slot(slot_raw, codec.sha(slot_raw))
        authority = Authority(
            MemoryReader(slot),
            MemoryReader(codec.unb64(public["materials_b64"], codec.MAX_MATERIALS)),
        )
        _, head, _ = authority.current(fixture.now)
        transcript = parse_transcript(codec.unb64(public["transcript_b64"], 32768))
        final = codec.bundle(codec.unb64(public["bundle_b64"], 2097152))
        snap = codec.baseline(codec.unb64(public["baseline_b64"], 65536))
        selected = [
            (r["person_id"], r["role"], authority.credential(slot, head, r["person_id"]))
            for r in snap["activations"]
        ]
        states = {
            r["credential_id"]: {
                k: r[k] for k in ("sign_count", "state_version", "activation_version")
            }
            for r in snap["activations"]
        }
        # Four authentic signatures remain valid for the substituted transcript.
        # This crypto-only result is NOT the independent intention decision.
        state, _, uses = final_proofs(final, transcript, selected, states, True, 2)
        self.assertEqual((state, len(uses)), ("consumed_no_release", 4))
        self.assertEqual(transcript.draft.intent_id, public["same_intent_id"])
        self.assertEqual(transcript.draft.intent_scope_hash, public["same_intent_scope_hash"])
        self.assertNotEqual(transcript.draft.requester_person_id, slot.intent_requester_person_id)
        no_sql = NoTransaction()
        service = Service(authority, no_sql, lambda: fixture.now)
        request = codec.encode(
            {
                "draft_b64": codec.b64(serialize_draft(transcript.draft)),
                "reservation_id": uid(901),
                "nonce": transcript.operation_nonce,
                "issued_at": transcript.issued_at,
                "expires_at": transcript.expires_at,
            },
            32768,
            string=24000,
        )
        with self.assertRaises(codec.Error) as caught:
            service.dispatch("/v1/operations/bind", request, fixture.vault_der)
        self.assertEqual((caught.exception.code, caught.exception.status), ("context_refused", 403))
        self.assertEqual(no_sql.entries, 0)

    def test_required_canonical_pin_no_draft_default_or_shared_contract_change(self):
        f = Fixture()
        self.assertEqual(f.slot.intent_requester_person_id, f.intent["requester_person_id"])
        self.assertNotIn("intent_requester_person_id", EXPECTED_FIELDS)
        for bad in [None, True, 20, "", "00000000-0000-0000-0000-00000000001G"]:
            v = copy.deepcopy(f.slot_value)
            v["intent_requester_person_id"] = bad
            raw = codec.encode(v, 65536, special=True)
            with self.subTest(pin=bad), self.assertRaises(codec.Error):
                parse_slot(raw, codec.sha(raw))
        v = copy.deepcopy(f.slot_value)
        del v["intent_requester_person_id"]
        raw = codec.encode(v, 65536, special=True)
        with self.assertRaises(codec.Error):
            parse_slot(raw, codec.sha(raw))
        v["intent_requester_person_id"] = uid(
            3020
        )  # account alias is not the canonical intention owner
        raw = codec.encode(v, 65536, special=True)
        authority = Authority(
            MemoryReader(parse_slot(raw, codec.sha(raw))), MemoryReader(f.materials)
        )
        with self.assertRaises(codec.Error) as caught:
            authority.operation(f.draft, f.now)
        self.assertEqual(caught.exception.status, 403)


class Scope:
    def __init__(self, db, kind):
        self.db, self.kind = db, kind

    def __enter__(self):
        return self

    def __exit__(self, kind, error, tb):
        self.db.events.append((self.kind + "_exit", None if kind is None else kind.__name__))
        if self.kind == "transaction" and kind is None:
            self.db.events.append(("commit", self.db.clock))
            if self.db.lose_ack:
                raise RuntimeError("COMMIT_ACK_UNKNOWN")
        return False


class ClockDB:
    """Source-control spy only, never a PostgreSQL transaction model."""

    def __init__(self, f):
        self.f, self.clock, self.events, self.lose_ack = f, f.now, [], False
        self.advance = False

    def connect(self):
        return ClockConnection(self)


class ClockConnection(Scope):
    def __init__(self, db):
        super().__init__(db, "connection")

    def transaction(self):
        return Scope(self.db, "transaction")

    def cursor(self, **kwargs):
        return ClockCursor(self.db)


class ClockCursor(Scope):
    def __init__(self, db):
        super().__init__(db, "cursor")
        self.last = ""

    def execute(self, sql, params=()):
        self.last = " ".join(sql.split())
        self.db.events.append(("sql", self.last))
        if "FROM pam_usage_anchor.audit_heads" in self.last and self.db.advance:
            self.db.clock += 2

    def fetchone(self):
        f = self.db.f
        if "clock_timestamp()" in self.last:
            return {"now": self.db.clock}
        if "FROM pam_usage_anchor.contexts" in self.last:
            return {
                "installation_id": f.draft.installation_id,
                "tenant_id": f.draft.organization_id,
                "witness_incarnation": f.slot.witness_incarnation,
                "slot_sha256": f.slot.source_sha256,
                "serving_state": "open",
            }
        if "FROM pam_usage_anchor.quotas" in self.last:
            return {"service_id": "vault-w1"}
        if "FROM pam_usage_anchor.leases" in self.last:
            return {
                "serving_state": "open",
                "owner_der": codec.sha(f.vault_der),
                "epoch": 1,
                "incarnation": f.draft.ledger_incarnation,
                "issued_at": f.now,
                "expires_at": f.now + 30,
            }
        if "FROM pam_usage_anchor.audit_heads" in self.last:
            return {"seq": 0, "head_sha256": "0" * 64}
        raise AssertionError("unexpected SQL in clock spy")


class CommitGuardTests(unittest.TestCase):
    def test_real_ledger_clock100_deadline101_audit102_refuses_before_commit(self):
        f = Fixture()
        db = ClockDB(f)
        db.advance = True
        peer = f.slot.peer(f.vault_der, f.now, "usage-anchor.vault/1")
        service = Service(f.authority, ledger.PostgresLedger(db.connect), lambda: f.now)
        with patch.object(ledger, "role_guard"), self.assertRaises(codec.Error):
            with service.ledger.transaction(f.slot, peer, vault=True) as tx:
                tx.live(f.now, f.now + 1)
                tx.before_commit(lambda: service._check(f.slot, peer, f.vault_der, tx, f.now + 1))
                tx.audit("consumed_no_release", uid(999), f.now)
        self.assertFalse(any(e[0] == "commit" for e in db.events))
        sql = [e[1] for e in db.events if e[0] == "sql"]
        self.assertIn("clock_timestamp()", sql[-1])
        self.assertTrue(any("INSERT INTO pam_usage_anchor.audit_events" in x for x in sql[:-1]))

    def test_mutation_without_registered_callback_cannot_commit(self):
        f = Fixture()
        db = ClockDB(f)
        peer = f.slot.peer(f.vault_der, f.now, "usage-anchor.vault/1")
        with patch.object(ledger, "role_guard"), self.assertRaises(codec.Error):
            with ledger.PostgresLedger(db.connect).transaction(f.slot, peer, vault=True) as tx:
                tx.audit("bound", uid(999), f.now)
        self.assertFalse(any(e[0] == "commit" for e in db.events))

    def test_read_only_terminal_path_can_exit_without_mutation_guard(self):
        f = Fixture()
        db = ClockDB(f)
        peer = f.slot.peer(f.vault_der, f.now, "usage-anchor.vault/1")
        with patch.object(ledger, "role_guard"):
            with ledger.PostgresLedger(db.connect).transaction(f.slot, peer, vault=True):
                pass
        self.assertTrue(any(e[0] == "commit" for e in db.events))
        self.assertFalse(any(e[0] == "sql" and "clock_timestamp()" in e[1] for e in db.events))

    def test_commit_ack_unknown_is_not_treated_as_success(self):
        f = Fixture()
        db = ClockDB(f)
        db.lose_ack = True
        peer = f.slot.peer(f.vault_der, f.now, "usage-anchor.vault/1")
        with (
            patch.object(ledger, "role_guard"),
            self.assertRaisesRegex(RuntimeError, "COMMIT_ACK_UNKNOWN"),
        ):
            with ledger.PostgresLedger(db.connect).transaction(f.slot, peer, vault=True) as tx:
                tx.audit("bound", uid(999), f.now)
                tx.before_commit(lambda: tx.live(f.now, f.now + 30))


class RouteTrace:
    """Request/callback-order spy; mutations aren't SQL/atomicity evidence."""

    def __init__(self, f):
        self.f = f
        self.now = f.now
        self.events = []
        self.row = None
        self.challenge_row = None
        self.advance_audit = False
        self.advance_guard = False
        self.callback = None
        self.lose_ack = False
        self.lease = {"expires_at": f.now + 30}

    def live(self, now, end):
        codec.need(now < end, "expired", 410)
        self.events.append("live")

    def before_commit(self, callback):
        self.callback = callback
        self.events.append("registered")

    def operation(self, **kwargs):
        self.events.append("operation")
        return self.row

    def quota(self, *args, **kwargs):
        pass

    def states(self, selected, active=True):
        return {
            a["id"]: {"activation_version": 1, "state_version": 1, "sign_count": 0}
            for _, _, a in selected
        }

    def insert_operation(self, row):
        self.row = row
        self.events.append("insert")

    def finish_bind(self, row):
        self.row.update(state="pending_proofs")
        self.events.append("finish_bind")

    def insert_challenge(self, i, cred, binding, challenge, end):
        self.challenge_row = {
            "challenge_id": i,
            "credential_id": cred,
            "binding": binding,
            "challenge": challenge,
            "expires_at": end,
            "used_at": None,
            "certificate_sha256": codec.sha(self.f.activation_der),
            "service_id": "activation-w1",
        }

    def challenge(self, i):
        return self.challenge_row

    def activate(self, *args):
        self.events.append("activate")

    def terminal(self, row, state, bundle, digest, response, updated, uses):
        row.update(
            state=state, final_bundle=bundle, final_digest=digest, terminal_response=response
        )
        self.events.append("terminal")

    def audit(self, *args):
        self.events.append("audit")
        if self.advance_audit:
            self.now = self.f.now + 31


class RouteLedger:
    def __init__(self, trace):
        self.trace = trace

    @contextmanager
    def transaction(self, *args, **kwargs):
        t = self.trace
        t.callback = None
        try:
            yield t
            if t.advance_guard:
                t.now = t.f.now + 31
            if t.callback:
                t.events.append("guard")
                t.callback()
            t.events.append("exit")
            if t.lose_ack:
                raise RuntimeError("COMMIT_ACK_UNKNOWN")
        except BaseException:
            t.events.append("rollback")
            raise


class ServiceGuardWiringTests(unittest.TestCase):
    def setup_service(self):
        f = Fixture()
        t = RouteTrace(f)
        return f, t, Service(f.authority, RouteLedger(t), lambda: t.now)

    def bind_raw(self, f):
        return codec.encode(
            {
                "draft_b64": codec.b64(serialize_draft(f.draft)),
                "reservation_id": uid(901),
                "nonce": codec.b64(bytes(range(32))),
                "issued_at": f.now,
                "expires_at": f.now + 30,
            },
            32768,
            string=24000,
        )

    def assert_guard_after_audit(self, t):
        self.assertLess(t.events.index("audit"), t.events.index("registered"))
        self.assertLess(t.events.index("registered"), t.events.index("guard"))
        self.assertEqual(t.events[-1], "rollback")

    def test_begin_activation_final_guard_follows_audit(self):
        f, t, s = self.setup_service()
        t.advance_audit = True
        with self.assertRaises(codec.Error):
            s.begin_activation(codec.encode({"person_id": uid(20)}, 4096), f.activation_der)
        self.assert_guard_after_audit(t)

    def test_finish_activation_final_guard_follows_activation_and_audit(self):
        f, t, s = self.setup_service()
        _, response = s.begin_activation(
            codec.encode({"person_id": uid(20)}, 4096), f.activation_der
        )
        value = codec.parse(response, 4096, special=True)
        proof = codec.encode(
            assertion(f.keys[uid(20)], f.auths[uid(20)], codec.unb64(value["challenge"], 32)),
            65536,
            special=True,
        )
        request = codec.encode(
            {"challenge_id": value["challenge_id"], "assertion_b64": codec.b64(proof)},
            131072,
            string=90000,
        )
        t.events = []
        t.advance_audit = True
        with self.assertRaises(codec.Error):
            s.finish_activation(request, f.activation_der)
        self.assertLess(t.events.index("activate"), t.events.index("audit"))
        self.assert_guard_after_audit(t)

    def test_bind_mutation_and_pending_retry_have_final_guard(self):
        f, t, s = self.setup_service()
        t.advance_audit = True
        with self.assertRaises(codec.Error):
            s.bind(self.bind_raw(f), f.vault_der)
        self.assert_guard_after_audit(t)
        f, t, s = self.setup_service()
        s.bind(self.bind_raw(f), f.vault_der)
        t.events = []
        t.advance_guard = True
        with self.assertRaises(codec.Error):
            s.bind(self.bind_raw(f), f.vault_der)
        self.assertIn("registered", t.events)
        self.assertEqual(t.events[-1], "rollback")

    def test_both_consumption_terminals_guard_after_writes_and_audit(self):
        for negative in (False, True):
            with self.subTest(negative=negative):
                f, t, s = self.setup_service()
                _, raw = s.bind(self.bind_raw(f), f.vault_der)
                bound = codec.parse(raw, 196608, string=90000, special=True)
                transcript = parse_transcript(codec.unb64(bound["transcript_b64"], 32768))
                bundle = f.final_bundle(transcript, bound["operation_id"], negative=negative)
                t.events = []
                t.advance_audit = True
                with self.assertRaises(codec.Error):
                    s.consume(bundle, f.vault_der)
                self.assertLess(t.events.index("terminal"), t.events.index("audit"))
                self.assert_guard_after_audit(t)

    def test_exact_terminal_retry_skips_final_mutation_guard_after_expiry(self):
        f, t, s = self.setup_service()
        _, raw = s.bind(self.bind_raw(f), f.vault_der)
        bound = codec.parse(raw, 196608, string=90000, special=True)
        transcript = parse_transcript(codec.unb64(bound["transcript_b64"], 32768))
        bundle = f.final_bundle(transcript, bound["operation_id"], negative=True)
        _, terminal = s.consume(bundle, f.vault_der)
        t.events = []
        t.now = f.now + 50
        with patch.object(
            f.authority, "operation", side_effect=AssertionError("authority revival")
        ):
            self.assertEqual(s.consume(bundle, f.vault_der), (200, terminal))
        self.assertEqual(t.events, ["operation", "exit"])

    def test_unknown_commit_ack_is_public_503_after_last_guard(self):
        f, t, s = self.setup_service()
        t.lose_ack = True
        with self.assertRaises(codec.Error) as caught:
            s.dispatch("/v1/operations/bind", self.bind_raw(f), f.vault_der)
        self.assertEqual((caught.exception.code, caught.exception.status), ("unavailable", 503))
        self.assertLess(t.events.index("guard"), t.events.index("exit"))


class SQLFailure(Exception):
    def __init__(self, state):
        self.sqlstate = state


class Cancelled(BaseException):
    pass


class ProbeDB:
    """Native-probe SQL and exit spy; not evidence of real grants/constraints."""

    def __init__(self):
        self.events = []
        self.clock = 0
        self.lose_ack = False
        self.failure = None
        self.counter = 0
        self.operation_state = "consumed_no_release"
        self.counter_failure = SQLFailure("P0001")

    def connect(self):
        return ProbeConnection(self)


class ProbeConnection(Scope):
    def __init__(self, db):
        super().__init__(db, "connection")

    def transaction(self):
        return Scope(self.db, "transaction")

    def cursor(self, **kwargs):
        return ProbeCursor(self.db)


class ProbeCursor(Scope):
    def __init__(self, db):
        super().__init__(db, "cursor")
        self.rowcount = 1
        self.last = ""

    def execute(self, sql, params=()):
        self.last = " ".join(sql.split())
        self.db.events.append(("sql", self.last, params))
        if self.last == "TARGET" and self.db.failure:
            raise self.db.failure
        if self.last.startswith("UPDATE pam_usage_anchor.activations SET sign_count=1,"):
            self.db.counter = 1
        if self.last.startswith("UPDATE pam_usage_anchor.activations SET sign_count=0,"):
            if self.db.counter_failure is not None:
                raise self.db.counter_failure
        if "SET state='consumed_no_release'," in self.last:
            raise SQLFailure("23514")

    def fetchone(self):
        if "SELECT context_id" in self.last:
            return (uid(90),)
        if "SELECT sign_count,state_version,status" in self.last:
            return (self.db.counter, 1, "active")
        if "SELECT sign_count" in self.last:
            return (self.db.counter,)
        if "SELECT state,baseline" in self.last:
            return ("pending_proofs", b"B", b"T", "a" * 64, b"W0")
        if "SELECT state,final_bundle" in self.last:
            return (self.db.operation_state, b"F", "a" * 64, b"W1")
        raise AssertionError("unexpected probe read")


class ProbeRollbackTests(unittest.TestCase):
    def assert_rollback(self, db):
        self.assertFalse(any(e[0] == "commit" for e in db.events))
        exits = [e for e in db.events if e[0] in ("connection_exit", "transaction_exit")]
        self.assertTrue(exits)
        self.assertTrue(all(e[1] is not None for e in exits))

    def test_unexpected_allowed_statement_fails_after_rollback(self):
        db = ProbeDB()
        with self.assertRaisesRegex(AssertionError, "forbidden SQL unexpectedly succeeded"):
            permissions.denied(db.connect, "TARGET")
        self.assert_rollback(db)

    def test_expected_refusal_passes_only_after_rollback(self):
        db = ProbeDB()
        db.failure = SQLFailure("42501")
        permissions.denied(db.connect, "TARGET")
        self.assert_rollback(db)

    def test_unexpected_sqlstate_and_cancellation_propagate_with_rollback(self):
        for failure in (SQLFailure("23514"), Cancelled()):
            db = ProbeDB()
            db.failure = failure
            with self.assertRaises(type(failure)) as caught:
                permissions.denied(db.connect, "TARGET")
            self.assertIs(caught.exception, failure)
            self.assert_rollback(db)

    def test_setup_error_is_not_the_targeted_expected_refusal(self):
        db = ProbeDB()
        failure = SQLFailure("42501")

        def prepare(cursor):
            raise failure

        with self.assertRaises(SQLFailure) as caught:
            permissions.denied(db.connect, "TARGET", prepare=prepare)
        self.assertIs(caught.exception, failure)
        self.assert_rollback(db)

    def test_counter_probe_is_exact_positive1_to0_and_p0001(self):
        db = ProbeDB()
        permissions.counter_monotonicity_probe(db.connect, uid(90), "public-credential")
        self.assert_rollback(db)
        targets = [e[1] for e in db.events if e[0] == "sql" and "SET sign_count=0," in e[1]]
        self.assertEqual(len(targets), 1)
        self.assertIn("state_version=state_version+1", targets[0])
        self.assertIn("AND sign_count=1", targets[0])
        self.assertNotIn("sign_count-1", targets[0])

    def test_counter_probe_cannot_pass_on_range_check_or_allowed_decrease(self):
        for failure in (SQLFailure("23514"), None):
            db = ProbeDB()
            db.counter_failure = failure
            expected = SQLFailure if failure is not None else AssertionError
            with self.assertRaises(expected):
                permissions.counter_monotonicity_probe(db.connect, uid(90), "public-credential")
            self.assert_rollback(db)

    def test_nonterminal_operation_is_rejected_before_permission_writes(self):
        db = ProbeDB()
        db.operation_state = "pending_proofs"
        with self.assertRaises(AssertionError):
            permissions.role_boundaries(
                witness_runtime_connect=db.connect,
                forbidden_witness_connects=[],
                context_id=uid(90),
                credential_id="public",
                operation_id=uid(99),
            )
        self.assertFalse(
            any(
                e[0] == "sql" and e[1].startswith(("UPDATE", "DELETE", "CREATE")) for e in db.events
            )
        )
        self.assert_rollback(db)

    def test_native_shape_probes_cover_each_nullable_terminal_member(self):
        db = ProbeDB()
        permissions.terminal_shape_probe(db.connect, uid(90), uid(99))
        self.assert_rollback(db)
        params = [
            e[2] for e in db.events if e[0] == "sql" and "SET state='consumed_no_release'," in e[1]
        ]
        self.assertEqual(
            [(p[1], p[2]) for p in params],
            [(None, None), (None, b"public-probe"), ("0" * 64, None)],
        )
        sql = (PATH / "sql/schema.sql").read_text()
        terminal_branch = sql.split("OR (state IN ('consumed_no_release','refused_no_release')")[
            1
        ].split("UNIQUE(context_id")[0]
        for explicit in (
            "final_bundle IS NOT NULL",
            "final_digest IS NOT NULL",
            "terminal_response IS NOT NULL",
        ):
            self.assertIn(explicit, terminal_branch)
        self.assertIn("final_digest ~ '^[0-9a-f]{64}$'", terminal_branch)
        self.assertIn("octet_length(terminal_response) BETWEEN 1 AND 4096", terminal_branch)
