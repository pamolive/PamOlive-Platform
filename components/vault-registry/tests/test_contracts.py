"""Independent fixed vectors and hostile format changes; no authority is exercised."""

import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import pamolive_vault_contracts as contract  # noqa: E402
from pamolive_vault_contracts import canonical, contracts  # noqa: E402

GOLDEN = Path(__file__).parent / "golden"


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.draft_document = json.loads((GOLDEN / "draft.json").read_bytes())
        self.full_document = json.loads((GOLDEN / "full-transcript.json").read_bytes())
        self.hashes = json.loads((GOLDEN / "hashes.json").read_bytes())
        self.draft = contract.parse_draft((GOLDEN / "draft.json").read_bytes())
        self.full = contract.parse_transcript((GOLDEN / "full-transcript.json").read_bytes())

    def draft_parse(self, value):
        return contract.parse_draft(json.dumps(value).encode())

    def full_parse(self, value):
        return contract.parse_transcript(json.dumps(value).encode())

    def test_fixed_golden_draft_full_hashes_and_role_challenge(self):
        self.assertEqual(
            contract.serialize_draft(self.draft), (GOLDEN / "draft.canonical.utf8").read_bytes()
        )
        self.assertEqual(
            contract.serialize_transcript(self.full),
            (GOLDEN / "full-transcript.canonical.utf8").read_bytes(),
        )
        self.assertEqual(contract.draft_hash(self.draft), self.hashes["draft_hash"])
        self.assertEqual(contract.body_hash(self.full), self.hashes["body_hash"])
        self.assertEqual(
            contract.confirmation_challenge(
                self.full,
                person_id=self.draft.requester_person_id,
                role="requester",
                decision="launch",
            ).hex(),
            self.hashes["requester_challenge_hex"],
        )
        self.assertEqual(
            contract.final_assertions_digest((GOLDEN / "assertions.opaque.json").read_bytes()),
            self.hashes["final_assertions_digest"],
        )

    def test_p0_golden_unicode_no_normalization_datetime_uuid_and_domains(self):
        value = {
            "active": True,
            "issued_at": datetime.fromisoformat("2026-11-14T10:09:10.123456+02:00"),
            "label": "é|e\u0301|☃",
            "organization": UUID(int=2),
            "revision": 7,
        }
        expected = (GOLDEN / "p0.canonical.utf8").read_bytes()
        self.assertEqual(contract.p0_canonical(value), expected)
        self.assertIn("é|e\u0301|☃".encode(), expected)
        for function, key in (
            (contract.p0_registry_message, "p0_registry_message_sha256"),
            (contract.p0_checkpoint_message, "p0_checkpoint_message_sha256"),
        ):
            self.assertEqual(hashlib.sha256(function(value)).hexdigest(), self.hashes[key])
        self.assertNotEqual(
            contract.p0_registry_message(value), contract.p0_checkpoint_message(value)
        )
        self.assertEqual(contract.p0_canonical({"x": 1.5}), b'{"x":1.5}')
        with self.assertRaises(contract.ContractError):
            contract.p0_canonical({"date": datetime(2026, 1, 1)})

    def test_p0_target_scope_golden_has_exact_legacy_twelve_fields(self):
        expected_fields = {
            "organization",
            "endpoint",
            "epoch",
            "resource",
            "account",
            "username",
            "protocol",
            "hostname",
            "port",
            "domain",
            "auth_method",
            "fingerprint",
        }
        for protocol in ("ssh", "rdp"):
            value = json.loads((GOLDEN / ("p0-target-" + protocol + ".json")).read_bytes())
            self.assertEqual(set(value), expected_fields)
            self.assertEqual(
                contract.p0_canonical(value),
                (GOLDEN / ("p0-target-" + protocol + ".canonical.utf8")).read_bytes(),
            )

    def test_shared_references_refuse_during_stream_before_large_json_allocation(self):
        original = json.JSONEncoder.iterencode
        # All graphs satisfy _walk. P0 would expand >500 MiB with dumps(),
        # despite retaining just one shared string and a small reference list.
        cases = [
            (False, "x" * 65536, 8188, canonical.MAX_P0_BYTES),
            (False, "🧪" * 65536, 8188, canonical.MAX_P0_BYTES),
            (True, "x" * 4096, 500, contracts.MAX_DRAFT_BYTES),
        ]
        for ascii_only, shared, repetitions, maximum in cases:
            graph = {"items": [shared] * repetitions}
            canonical._walk(graph, ascii_only=ascii_only)
            if not ascii_only:
                self.assertGreater(len(shared.encode("utf8")) * repetitions, 500 * 1024**2)
            chunk_sizes = []

            def tracked(encoder, value):
                for chunk in original(encoder, value):
                    chunk_sizes.append(len(chunk.encode("utf8")))
                    yield chunk

            with (
                self.subTest(ascii=ascii_only, bytes_per_string=len(shared.encode("utf8"))),
                patch.object(json, "dumps", side_effect=AssertionError("must stream")),
                patch.object(json.JSONEncoder, "iterencode", tracked),
                self.assertRaises(contract.ContractError) as raised,
            ):
                if ascii_only:
                    canonical.canonical_v2(graph, maximum)
                else:
                    contract.p0_canonical(graph)
            self.assertEqual(str(raised.exception), "invalid_operation_contract")
            self.assertIsNone(raised.exception.__context__)
            self.assertGreater(sum(chunk_sizes), maximum)
            self.assertLessEqual(sum(chunk_sizes), maximum + max(chunk_sizes))
            self.assertLess(len(chunk_sizes), 100)
            self.assertLess(sum(chunk_sizes), 3 * 1024**2)

    def test_every_draft_field_substitution_changes_hash_or_refuses_closed_constant(self):
        constants = {"schema", "operation", "crypto_profile", "destination_scope_format"}
        for name, value in self.draft_document.items():
            changed = copy.deepcopy(self.draft_document)
            if type(value) is int:
                changed[name] = value + 1
            elif type(value) is list:
                changed[name] = [str(UUID(int=999))]
            elif name in constants:
                changed[name] = "unknown"
            elif len(value) == 64:
                changed[name] = "9" * 64
            elif len(value) == 36:
                changed[name] = str(UUID(int=999))
            else:
                changed[name] = "other-service"
            with self.subTest(field=name):
                if name in constants:
                    with self.assertRaises(contract.ContractError):
                        self.draft_parse(changed)
                else:
                    updated = self.draft_parse(changed)
                    self.assertNotEqual(
                        contract.draft_hash(updated), contract.draft_hash(self.draft)
                    )
                    self.assertNotEqual(
                        contract.body_hash(replace(self.full, draft=updated)),
                        contract.body_hash(self.full),
                    )

    def test_full_only_fields_change_body_and_challenge_without_changing_draft(self):
        baseline = replace(
            self.full, not_before=self.full.issued_at + 5, expires_at=self.full.issued_at + 20
        )
        changes = {
            "operation_nonce": base64.urlsafe_b64encode(b"n" * 32).rstrip(b"=").decode(),
            "authenticator_counter_baseline_hash": "2" * 64,
            "issued_at": baseline.issued_at + 1,
            "not_before": baseline.not_before + 1,
            "expires_at": baseline.expires_at + 1,
        }
        for name, value in changes.items():
            with self.subTest(field=name):
                updated = replace(baseline, **{name: value})
                self.assertEqual(
                    contract.draft_hash(updated.draft), contract.draft_hash(self.draft)
                )
                self.assertNotEqual(contract.body_hash(updated), contract.body_hash(baseline))
        with self.assertRaises(contract.ContractError):
            replace(self.full, schema="pamolive.privileged-operation/1")

    def test_draft_and_full_are_non_authorized_immutable_without_implicit_conversion(self):
        for value in (self.draft, self.full):
            self.assertIs(value.authorized, False)
            with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
                value.authorized = True
        with self.assertRaises(contract.ContractError):
            contract.serialize_draft(self.full)
        with self.assertRaises(contract.ContractError):
            contract.serialize_transcript(self.draft)
        self.assertFalse(hasattr(contract, "AuthorizedRelease"))
        self.assertFalse(
            any(
                name.startswith(("verify", "release", "register", "rewrap"))
                for name in contract.__all__
            )
        )

    def test_draft_has_no_server_fields_and_neither_body_can_contain_final_hash(self):
        names = (
            "operation_nonce",
            "issued_at",
            "not_before",
            "expires_at",
            "authenticator_counter_baseline_hash",
            "body_hash",
            "final_proof_bundle_sha256",
            "challenge",
            "authorized",
            "approved",
            "web_hmac",
        )
        for name in names:
            with self.subTest(field=name), self.assertRaises(contract.ContractError):
                self.draft_parse({**self.draft_document, name: "untrusted"})
        for name in ("body_hash", "final_proof_bundle_sha256", "challenge", "approved", "web_hmac"):
            with self.subTest(field=name), self.assertRaises(contract.ContractError):
                self.full_parse({**self.full_document, name: "untrusted"})
        before = contract.body_hash(self.full)
        self.assertNotEqual(
            contract.final_assertions_digest(b"unverified-a"),
            contract.final_assertions_digest(b"unverified-b"),
        )
        self.assertEqual(contract.body_hash(self.full), before)

    def test_missing_each_field_and_unknown_lookup_fields_are_refused(self):
        for document, parse in (
            (self.draft_document, self.draft_parse),
            (self.full_document, self.full_parse),
        ):
            for name in document:
                changed = dict(document)
                del changed[name]
                with self.subTest(field=name), self.assertRaises(contract.ContractError):
                    parse(changed)
            for name in ("jku", "x5u", "kid", "key_url", "provider_id", "public_key", "signature"):
                with self.subTest(field=name), self.assertRaises(contract.ContractError):
                    parse({**document, name: "https://untrusted.invalid/key"})

    def test_policy_and_generations_are_uuid_not_ordered_integer_versions(self):
        for name in ("policy_revision", "trust_generation", "ledger_incarnation"):
            for value in (1, True, "1", "{" + str(UUID(int=99)) + "}"):
                with self.subTest(field=name), self.assertRaises(contract.ContractError):
                    self.draft_parse({**self.draft_document, name: value})
        for name in (
            "registry_revision",
            "destination_epoch",
            "credential_version",
            "wrapping_revision",
        ):
            for value in (True, False, 1.0, "1", 0, -1, 2**63, str(UUID(int=99)), None):
                with (
                    self.subTest(field=name, value=value),
                    self.assertRaises(contract.ContractError),
                ):
                    self.draft_parse({**self.draft_document, name: value})
        with self.assertRaises(TypeError):
            _ = self.draft < replace(self.draft, trust_generation=str(UUID(int=999)))

    def test_service_certificate_and_identifier_strings_do_not_resolve_uris_or_unicode(self):
        for name in ("requested_caller_service_id", "broker_service_id", "vault_service_id"):
            for value in (
                "",
                "https://fixture.invalid",
                "file:///key",
                "../key",
                "é",
                "a\n",
                "a" * 65,
                None,
                True,
            ):
                with self.subTest(field=name), self.assertRaises(contract.ContractError):
                    self.draft_parse({**self.draft_document, name: value})
        for name in ("broker_certificate_sha256", "authority_materials_sha256"):
            for value in ("sha256:" + "a" * 64, "A" * 64, "a" * 63, "é" * 64, True):
                with self.subTest(field=name), self.assertRaises(contract.ContractError):
                    self.draft_parse({**self.draft_document, name: value})

    def test_approver_order_duplicate_and_mutable_inputs_are_not_normalized(self):
        for value in (
            [],
            self.draft_document["approver_person_ids"] * 2,
            list(reversed(self.draft_document["approver_person_ids"])),
            [str(UUID(int=n)) for n in range(17)],
            [True],
            None,
        ):
            with self.subTest(value=value), self.assertRaises(contract.ContractError):
                self.draft_parse({**self.draft_document, "approver_person_ids": value})
        with self.assertRaises(contract.ContractError):
            replace(self.draft, approver_person_ids=list(self.draft.approver_person_ids))

    def test_nonce_encoding_and_time_bounds_are_structural_not_live_freshness(self):
        for nonce in (
            self.full.operation_nonce + "=",
            self.full.operation_nonce[:-1] + "9",
            "a" * 42,
            "a" * 44,
            "é" * 43,
            b"a" * 43,
            None,
        ):
            with self.subTest(nonce=nonce), self.assertRaises(contract.ContractError):
                replace(self.full, operation_nonce=nonce)
        for changes in (
            {"expires_at": self.full.issued_at + 31},
            {"not_before": self.full.issued_at - 1},
            {"expires_at": self.full.not_before},
            {"issued_at": True},
            {"issued_at": 1.0},
            {"expires_at": "1800000030"},
        ):
            with self.subTest(changes=changes), self.assertRaises(contract.ContractError):
                replace(self.full, **changes)
        ancient = replace(self.full, issued_at=1, not_before=1, expires_at=31)
        self.assertFalse(
            contract.parse_transcript(contract.serialize_transcript(ancient)).authorized
        )

    def test_duplicates_escaped_key_aliases_floats_constants_unicode_and_budgets(self):
        for raw in (
            b'{"schema":1,"schema":2}',
            b'{"schema":1,"\\u0073chema":2}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":1.0}',
            b'{"value":' + b"1" * 1000 + b"}",
            b"\xff",
            b"[]",
            b"null",
            b'{"value":"\\ud800"}',
            b'{"value":"\\u0000"}',
            b'{"value":' + b"[" * 12 + b"0" + b"]" * 12 + b"}",
            json.dumps({"value": list(range(513))}).encode(),
        ):
            with self.subTest(raw=raw[:50]), self.assertRaises(contract.ContractError):
                contract.parse_draft(raw)
        for parse, maximum in (
            (contract.parse_draft, contracts.MAX_DRAFT_BYTES),
            (contract.parse_transcript, contracts.MAX_TRANSCRIPT_BYTES),
        ):
            for raw in (b" " * (maximum + 1), "{}", bytearray(b"{}"), b""):
                with self.subTest(type=type(raw)), self.assertRaises(contract.ContractError):
                    parse(raw)
        for raw in (b"", b"a" * (canonical.MAX_ASSERTIONS_BYTES + 1), "proof", bytearray(b"x")):
            with self.assertRaises(contract.ContractError):
                contract.final_assertions_digest(raw)

    def test_confirmation_role_person_decision_and_body_are_all_committed(self):
        original = contract.confirmation_challenge(
            self.full, person_id=self.draft.requester_person_id, role="requester", decision="launch"
        )
        for person, role, decision in (
            (str(UUID(int=999)), "requester", "launch"),
            (self.draft.requester_person_id, "reviewer", "approve"),
            (self.draft.requester_person_id, "reviewer", "refuse"),
        ):
            self.assertNotEqual(
                original,
                contract.confirmation_challenge(
                    self.full, person_id=person, role=role, decision=decision
                ),
            )
        for role, decision in (
            ("web", "approve"),
            ("requester", "approve"),
            ("reviewer", "launch"),
            ("sponsor", "launch"),
        ):
            with self.assertRaises(contract.ContractError):
                contract.confirmation_challenge(
                    self.full,
                    person_id=self.draft.requester_person_id,
                    role=role,
                    decision=decision,
                )

    def test_release_prepare_does_not_parse_other_operation_families(self):
        for operation in (
            "import",
            "register",
            "rewrap",
            "release",
            "consumed",
            "technical-credential.rewrap",
            "technical-credential.register",
        ):
            with self.subTest(operation=operation), self.assertRaises(contract.ContractError):
                self.draft_parse({**self.draft_document, "operation": operation})

    def test_clean_child_import_has_no_application_crypto_network_or_storage_modules(self):
        script = (
            "import sys; sys.path.insert(0, sys.argv[1]); import pamolive_vault_contracts as c; "
            "assert not any(n.startswith(('django','platform_core','platform_modules', "
            "'pamolive_vault_envelope','requests','http.client','socket','psycopg','sqlite3', "
            "'cryptography','webauthn')) for n in sys.modules); "
            "assert not hasattr(c, 'AuthorizedRelease')"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", script, str(SOURCE)],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
