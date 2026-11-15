import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fixtures import Fixture, MemoryReader, assertion, uid
from pamolive_usage_anchor import codec
from pamolive_usage_anchor.authority import Authority
from pamolive_usage_anchor.proofs import final_proofs, verify
from pamolive_usage_anchor.slot import ReadOnly, parse_slot
from pamolive_vault_contracts import FullTranscript, confirmation_challenge


class CodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (Path(__file__).parent / "golden/codec.json").read_bytes()
        cls.g = json.loads(cls.raw)

    def test_independent_golden_byte_exact(self):
        self.assertEqual(
            codec.sha(self.raw), "bfd2db31fbaacf2500645439efc9a35738366c76fd14dfcbd407386aba30fcad"
        )

    def test_materials_frame_golden(self):
        m = self.g["materials"]
        docs = tuple(bytes.fromhex(x) for x in m["raw_documents_hex"])
        cp = bytes.fromhex(m["raw_checkpoint_hex"])
        frame = codec.materials_frame(docs, cp)
        self.assertEqual(frame.hex(), m["frame_hex"])
        self.assertEqual(codec.sha(frame), m["sha256"])
        self.assertEqual(codec.parse_materials(frame), (docs, cp))

    def test_materials_malformed_framing(self):
        for vector in self.g["structural_reject_vectors"]:
            with self.subTest(vector=vector["id"]), self.assertRaises(codec.Error):
                codec.parse_materials(bytes.fromhex(vector["frame_hex"]))

    def test_materials_budgets(self):
        for docs, cp in [
            ((), b"x"),
            ((b"x",) * 257, b"x"),
            ((b"x" * 2097153,), b"x"),
            ((b"x",), b"x" * 65537),
        ]:
            with self.assertRaises(codec.Error):
                codec.materials_frame(docs, cp)

    def test_baseline_golden(self):
        v = self.g["baseline"]
        raw = v["payload_utf8"].encode()
        self.assertEqual(codec.commitment(codec.BASELINE, raw), v["sha256"])
        codec.baseline(raw)

    def test_policy_golden(self):
        v = self.g["effective_policy"]
        self.assertEqual(
            codec.commitment(
                codec.EFFECTIVE, codec.encode(json.loads(v["payload_utf8"]), 4096, nodes=512)
            ),
            v["sha256"],
        )

    def test_bundle_golden_codec_only(self):
        v = self.g["final_bundle"]
        raw = v["payload_utf8"].encode()
        self.assertEqual(codec.sha(b"pamolive.vault.final-assertions.v1\0" + raw), v["sha256"])
        codec.bundle(raw)

    def test_json_bad_types_duplicates_aliases(self):
        for raw in [
            b'{"a":1,"a":2}',
            b'{"a":1,"\\u0061":2}',
            b'{"a":true}',
            b'{"a":null}',
            b'{"a":1.0}',
            b'{"a":-1}',
            b'{"a":NaN}',
            b'{"a":9223372036854775808}',
        ]:
            with self.subTest(raw=raw), self.assertRaises(codec.Error):
                codec.parse(raw, 100)

    def test_json_canonical_whitespace_order(self):
        for raw in [b'{ "a":1}', b'{"b":2,"a":1}', b'{"a":"\\u0062"}']:
            with self.assertRaises(codec.Error):
                codec.parse(raw, 100)

    def test_json_preallocation_depth_nodes(self):
        for raw in [
            b'{"a":' + b"[" * 20 + b"0" + b"]" * 20 + b"}",
            b'{"a":[' + b"0," * 3000 + b"0]}",
        ]:
            with self.assertRaises(codec.Error):
                codec.parse(raw, 10000)

    def test_base64_canonical(self):
        for val in ["YQ=", "YQ==", "YR", "", "../YQ", True]:
            with self.assertRaises(codec.Error):
                codec.unb64(val, 1024)

    def test_baseline_bounds_order_unicity(self):
        source = json.loads(self.g["baseline"]["payload_utf8"])
        for change in ["count", "order", "duplicate", "unknown"]:
            v = copy.deepcopy(source)
            if change == "count":
                v["activations"][0]["sign_count"] = 2**32
            if change == "order":
                v["activations"].reverse()
            if change == "duplicate":
                v["activations"].append(v["activations"][-1])
            if change == "unknown":
                v["approved"] = 1
            with self.assertRaises(codec.Error):
                codec.baseline(codec.encode(v, 65536))

    def test_bundle_role_decision_unicity(self):
        source = json.loads(self.g["final_bundle"]["payload_utf8"])
        for change in ["role", "duplicate", "order", "unknown"]:
            v = copy.deepcopy(source)
            if change == "role":
                v["assertions"][0]["role"] = "requester"
            if change == "duplicate":
                v["assertions"].append(v["assertions"][0])
            if change == "order":
                v["assertions"].reverse()
            if change == "unknown":
                v["approved"] = 1
            with self.assertRaises(codec.Error):
                codec.bundle(codec.encode(v, 2097152, string=90000))


class AuthorityAndProofs(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.slot, self.end, self.selected, self.policy, _ = self.f.authority.operation(
            self.f.draft, self.f.now
        )
        self.t = FullTranscript(
            self.f.draft,
            codec.b64(bytes(range(32))),
            "a" * 64,
            self.f.now,
            self.f.now,
            self.f.now + 30,
        )
        self.states = {a["id"]: {"sign_count": 0, "state_version": 1} for _, _, a in self.selected}

    def proofs(self, raw):
        return final_proofs(codec.bundle(raw), self.t, self.selected, self.states, True, 2)

    def test_real_p0_signed_chain_and_policy(self):
        self.assertEqual(self.policy["required_reviewers"], 2)
        self.assertEqual(len(self.selected), 4)
        self.assertEqual(self.end, self.f.now + 40)
        self.assertEqual(len(self.f.enrollment_evidence), 3)

    def test_real_webauthn_positive_zero_multi_role(self):
        state, updated, uses = self.proofs(self.f.final_bundle(self.t, uid(99)))
        self.assertEqual(state, "consumed_no_release")
        self.assertEqual(len(updated), 3)
        self.assertEqual(len(uses), 4)
        self.assertTrue(all(x == 0 for x in updated.values()))

    def test_real_negative_without_positive_quorum(self):
        state, updated, uses = self.proofs(self.f.final_bundle(self.t, uid(99), negative=True))
        self.assertEqual(state, "refused_no_release")
        self.assertEqual(len(updated), 1)
        self.assertEqual(len(uses), 1)

    def test_real_nonzero_multi_role_count(self):
        state, updated, _ = self.proofs(self.f.final_bundle(self.t, uid(99), count=5))
        self.assertEqual(state, "consumed_no_release")
        self.assertEqual(updated[self.f.auths[uid(21)]["id"]], 6)

    def test_c01_two_original_signed_serializations(self):
        for spaced in [False, True]:
            state, _, _ = self.proofs(self.f.final_bundle(self.t, uid(99), spaced=spaced))
            self.assertEqual(state, "consumed_no_release")

    def test_c01_signature_of_other_serialization_refuses(self):
        challenge = confirmation_challenge(
            self.t, person_id=uid(21), role="reviewer", decision="refuse"
        )
        first = assertion(self.f.keys[uid(21)], self.f.auths[uid(21)], challenge)
        other = assertion(self.f.keys[uid(21)], self.f.auths[uid(21)], challenge, spaced=True)
        other["response"]["signature"] = first["response"]["signature"]
        with self.assertRaises(codec.Error):
            verify(
                codec.encode(other, 65536, special=True),
                auth=self.f.auths[uid(21)],
                person_id=uid(21),
                organization_id=uid(2),
                challenge=challenge,
                current=0,
                allow_zero=True,
            )

    def test_client_duplicate_cross_origin_unknown(self):
        challenge = bytes(32)
        bad = [
            b'{"type":"webauthn.get","type":"webauthn.get"}',
            json.dumps(
                {
                    "type": "webauthn.get",
                    "challenge": codec.b64(challenge),
                    "origin": "https://confirm.pamolive.invalid",
                    "crossOrigin": True,
                }
            ).encode(),
            json.dumps(
                {
                    "type": "webauthn.get",
                    "challenge": codec.b64(challenge),
                    "origin": "https://confirm.pamolive.invalid",
                    "topOrigin": "https://evil.invalid",
                }
            ).encode(),
        ]
        for client in bad:
            value = assertion(
                self.f.keys[uid(21)], self.f.auths[uid(21)], challenge, client_raw=client
            )
            with self.assertRaises(codec.Error):
                verify(
                    codec.encode(value, 65536, special=True),
                    auth=self.f.auths[uid(21)],
                    person_id=uid(21),
                    organization_id=uid(2),
                    challenge=challenge,
                    current=0,
                    allow_zero=True,
                )

    def test_counter_regression_generic_no_quarantine(self):
        raw = self.f.final_bundle(self.t, uid(99), negative=True, count=4)
        self.states[self.f.auths[uid(21)]["id"]]["sign_count"] = 9
        before = copy.deepcopy(self.states)
        with self.assertRaises(codec.Error) as caught:
            self.proofs(raw)
        self.assertEqual((caught.exception.code, caught.exception.status), ("proof_refused", 403))
        self.assertEqual(self.states, before)

    def test_invalid_included_proof_rejects_negative_whole(self):
        v = codec.bundle(self.f.final_bundle(self.t, uid(99)))
        v["assertions"][1]["decision"] = "refuse"  # old approve signature no longer valid
        with self.assertRaises(codec.Error):
            self.proofs(codec.encode(v, 2097152, string=90000))
        self.assertTrue(all(x["sign_count"] == 0 for x in self.states.values()))

    def test_partial_positive_refuses(self):
        v = codec.bundle(self.f.final_bundle(self.t, uid(99)))
        v["assertions"] = v["assertions"][:1]
        with self.assertRaises(codec.Error):
            self.proofs(codec.encode(v, 2097152, string=90000))

    def test_altered_body_challenge_refuses(self):
        raw = self.f.final_bundle(self.t, uid(99))
        self.t = replace(self.t, operation_nonce=codec.b64(bytes([3]) * 32))
        with self.assertRaises(codec.Error):
            self.proofs(raw)

    def test_requester_refuse_rejected_by_codec(self):
        v = codec.bundle(self.f.final_bundle(self.t, uid(99)))
        v["assertions"][0]["decision"] = "refuse"
        with self.assertRaises(codec.Error):
            codec.bundle(codec.encode(v, 2097152, string=90000))

    def test_forged_slot_expectation_and_tenant(self):
        for field, val in [
            ("policy_hash", "0" * 64),
            ("organization_id", uid(77)),
            ("credential_version", 2),
            ("destination_scope_hash", "0" * 64),
        ]:
            with self.assertRaises(codec.Error):
                self.f.authority.operation(replace(self.f.draft, **{field: val}), self.f.now)

    def test_material_byte_substitution_refuses(self):
        f = self.f
        authority = Authority(f.guard, MemoryReader(f.materials + b"x"))
        with self.assertRaises(codec.Error):
            authority.current(f.now)

    def test_expired_checkpoint_and_revoked_external_key(self):
        with self.assertRaises(Exception):
            self.f.authority.current(self.f.now + 40)
        self.f.guard.value = replace(
            self.slot, checkpoint_keys=(replace(self.slot.checkpoint_keys[0], active=False),)
        )
        with self.assertRaises(Exception):
            self.f.authority.current(self.f.now)

    def test_scheduled_key_revocation_shortens_bound_window(self):
        from fixtures import utc

        key = replace(self.slot.checkpoint_keys[0], revoked_at=utc(self.f.now + 5))
        self.f.guard.value = replace(self.slot, checkpoint_keys=(key,))
        self.assertEqual(self.f.authority.current(self.f.now)[2], self.f.now + 5)

    def test_real_der_roles_not_headers(self):
        p = self.slot.peer(self.f.vault_der, self.f.now, "usage-anchor.vault/1")
        self.assertEqual(p.service_id, "vault-w1")
        with self.assertRaises(codec.Error):
            self.slot.peer(self.f.activation_der, self.f.now, "usage-anchor.vault/1")

    def test_unknown_der_is_caller_refused(self):
        with self.assertRaises(codec.Error) as caught:
            self.slot.peer(b"bad DER", self.f.now, "usage-anchor.vault/1")
        self.assertEqual((caught.exception.code, caught.exception.status), ("caller_refused", 403))

    def test_signed_unknown_policy_target_and_contract_fail_closed(self):
        from fixtures import raw_json
        from pamolive_vault_runtime.slot import EXPECTED_FIELDS

        for mutation in ("policy", "target", "contract"):
            with self.subTest(mutation=mutation):
                f = Fixture()
                chain, raw_cp = codec.parse_materials(f.materials)
                body = copy.deepcopy(f.head["body"])
                if mutation == "policy":
                    body["policy"]["unknown_rule"] = 1
                if mutation == "target":
                    body["targets"][uid(7)]["unknown_rule"] = 1
                if mutation == "contract":
                    body["targets"][uid(7)]["contract_id"] = uid(110)
                    body["targets"][uid(7)]["contract_authority"] = {
                        "revision": uid(111),
                        "hash": "e" * 64,
                    }
                head = f.sign(body)
                registry_hash = f.registry_hash(head)
                cp = json.loads(raw_cp)
                cp["body"]["registry_hash"] = registry_hash
                cp["signature"] = codec.b64(
                    f.cp_key.sign(
                        b"pamolive.pam.trust-checkpoint.v1\0"
                        + __import__("pamolive_vault_contracts").p0_canonical(cp["body"])
                    )
                )
                materials = codec.materials_frame((chain[0], raw_json(head)), raw_json(cp))
                draft = replace(
                    f.draft,
                    registry_hash=registry_hash,
                    checkpoint_hash=codec.sha(raw_json(cp)),
                    authority_materials_sha256=codec.sha(materials),
                    policy_hash=codec.sha(
                        __import__("pamolive_vault_contracts").p0_canonical(body["policy"])
                    ),
                )
                slot_v = copy.deepcopy(f.slot_value)
                slot_v["expectations"] = {k: getattr(draft, k) for k in EXPECTED_FIELDS}
                raw = codec.encode(slot_v, 65536, special=True)
                authority = Authority(
                    MemoryReader(parse_slot(raw, codec.sha(raw))), MemoryReader(materials)
                )
                # Signed corpus itself is valid V1; only its current W1 semantic profile is refused.
                authority.current(f.now)
                with self.assertRaises(codec.Error):
                    authority.operation(draft, f.now)

    def test_slot_unknown_and_no_posix_claim_on_windows(self):
        v = copy.deepcopy(self.f.slot_value)
        v["approved"] = True
        raw = codec.encode(v, 65536, special=True)
        with self.assertRaises(codec.Error):
            parse_slot(raw, codec.sha(raw))
        with patch("pamolive_usage_anchor.slot.os.name", "nt"), self.assertRaises(codec.Error):
            ReadOnly("C:/not-used", "0" * 64, 1024)

    def test_complete_snapshot_cas_including_absent_negative_members(self):
        from pamolive_usage_anchor.service import check_snapshot

        rows = []
        states = {}
        for person, role, auth in self.selected:
            row = {
                "person_id": person,
                "role": role,
                "credential_id": auth["id"],
                "activation_version": 1,
                "state_version": 1,
                "sign_count": 0,
            }
            rows.append(row)
            states[auth["id"]] = {"activation_version": 1, "state_version": 1, "sign_count": 0}
        snap = {"activations": rows}
        check_snapshot(snap, self.selected, states)
        # Even a credential absent from a one-reviewer negative bundle must CAS.
        states[self.f.auths[uid(20)]["id"]]["state_version"] = 2
        before = copy.deepcopy(states)
        with self.assertRaises(codec.Error) as caught:
            check_snapshot(snap, self.selected, states)
        self.assertEqual(caught.exception.code, "baseline_stale")
        self.assertEqual(states, before)

    def test_fresh_w_activation_real_signature_is_distinct_from_p0_possession(self):
        person = uid(21)
        challenge = hashlib.sha256(b"fresh W activation challenge").digest()
        raw = codec.encode(
            assertion(self.f.keys[person], self.f.auths[person], challenge), 65536, special=True
        )
        self.assertEqual(
            verify(
                raw,
                auth=self.f.auths[person],
                person_id=person,
                organization_id=uid(2),
                challenge=challenge,
                current=0,
                allow_zero=True,
            ),
            0,
        )
        old = self.f.enrollment_evidence[person]["possession"]
        with self.assertRaises(codec.Error):
            verify(
                codec.encode(old, 65536, special=True),
                auth=self.f.auths[person],
                person_id=person,
                organization_id=uid(2),
                challenge=challenge,
                current=0,
                allow_zero=True,
            )


class StructuralTests(unittest.TestCase):
    def test_no_release_or_quarantine_source(self):
        root = Path(__file__).resolve().parents[1] / "pamolive_usage_anchor"
        sources = "\n".join(p.read_text() for p in root.glob("*.py"))
        for forbidden in [
            "import django",
            "pamolive_vault_envelope",
            "open_authorized_version",
            "boto3",
        ]:
            self.assertNotIn(forbidden, sources)
        sql = (root.parent / "sql/schema.sql").read_text()
        self.assertIn("'refused_no_release'", sql)
        self.assertNotIn("quarantined_at", sql)

    def test_transport_reuses_exact_h11_adapter(self):
        from pamolive_usage_anchor import transport
        from pamolive_vault_runtime import transport as original

        self.assertIs(transport.protocol_class, original.protocol_class)
        self.assertIs(transport.configuration, original.configuration)

    def test_unbound_http_and_forged_identity_header_never_dispatch(self):
        from pamolive_usage_anchor.http import Application

        class Forbidden:
            def dispatch(self, *args):
                raise AssertionError("must not reach service")

        app = Application(Forbidden())
        emitted = []

        async def send(value):
            emitted.append(value)

        async def receive():
            raise AssertionError("must reject before body")

        def complete(coroutine):
            with self.assertRaises(StopIteration):
                coroutine.send(None)

        try:
            complete(app({}, receive, send))
            self.assertEqual(emitted[0]["status"], 503)
            emitted.clear()
            bound = app.for_tls_peer(b"raw leaf DER only in trusted adapter")
            complete(
                bound(
                    {
                        "type": "http",
                        "scheme": "https",
                        "http_version": "1.1",
                        "method": "POST",
                        "path": "/v1/operations/bind",
                        "raw_path": b"/v1/operations/bind",
                        "query_string": b"",
                        "headers": [(b"x-client-der", b"forged")],
                    },
                    receive,
                    send,
                )
            )
            self.assertEqual(emitted[0]["status"], 400)
        finally:
            app.close()

    def test_sql_real_implementation_not_memory_store(self):
        from pamolive_usage_anchor.ledger import PostgresLedger

        self.assertTrue(callable(PostgresLedger.transaction))
        source = (
            Path(__file__).resolve().parents[1] / "pamolive_usage_anchor/ledger.py"
        ).read_text()
        self.assertIn("clock_timestamp()", source)
        self.assertIn("SET LOCAL synchronous_commit=on", source)
        self.assertNotIn("SECURITY DEFINER", source)


if __name__ == "__main__":
    unittest.main()
