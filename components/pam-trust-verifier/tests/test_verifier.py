import base64
import hashlib
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from pamolive_pam_trust_verifier import (
    CurrentContext,
    CurrentRegistry,
    ExternalKey,
    HistoricalContext,
    HistoricalRegistry,
    InvalidMaterials,
    _api,
    _codec,
    _context,
    _crypto,
    verify_archived_registry_chain,
    verify_current_registry_materials,
)
from pamolive_pam_trust_verifier._context import timestamp

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
OBSERVATIONS = []


def load(path):
    return json.loads(path.read_bytes())


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def keys(mapping):
    return tuple(
        ExternalKey(
            key_id=key_id,
            public_key=_crypto.decode(value["public_key"], length=32),
            active=value.get("active", True),
            not_before=value.get("not_before", ""),
            not_after=value.get("not_after", ""),
            revoked_at=value.get("revoked_at", ""),
        )
        for key_id, value in mapping.items()
    )


def context(value, current=True):
    common = dict(
        installation=value["installation"],
        organization=value["organization"],
        generation=value["expected_head"]["generation"],
        revision=value["expected_head"]["revision"],
        registry_hash=value["expected_head"]["registry_hash"],
        commissioning_keys=keys(value["commissioning_keys"]),
    )
    if current:
        return CurrentContext(
            **common,
            checkpoint_keys=keys(value["checkpoint_keys"]),
            now_utc=value["explicit_current_time"],
            registry_max_seconds=value["registry_max_seconds"],
            checkpoint_max_seconds=value["checkpoint_max_seconds"],
        )
    return HistoricalContext(**common)


def cases():
    root = FIXTURES / "original"
    yield (
        "root-original-positive",
        root,
        tuple(sorted((root / "chain").glob("*.json"))),
        root / "expected-context.json",
        root / "checkpoint.json",
        "accept",
    )
    root = FIXTURES / "adversarial"
    for row in load(root / "catalog.json")["cases"]:
        yield (
            row["case_id"],
            root,
            tuple(root / name for name in row["chain_files_in_supplied_order"]),
            root / row["context_file"],
            root / row["checkpoint_file"],
            row["expected_verdict"],
        )


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = tuple(cases())
        cls.root = FIXTURES / "original"
        cls.raw = tuple(path.read_bytes() for path in sorted((cls.root / "chain").glob("*.json")))
        cls.checkpoint = (cls.root / "checkpoint.json").read_bytes()
        cls.ctx = context(load(cls.root / "expected-context.json"))
        cls.hist = context(load(cls.root / "expected-context.json"), False)

    def rejected(self, callback, *args):
        with self.assertRaises(InvalidMaterials) as caught:
            callback(*args)
        self.assertEqual(str(caught.exception), _codec.ERROR)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_static_copies_closed_and_pinned(self):
        for name, expected_sha, total, _source in (
            (
                "original",
                "0abb0aab0f20deaec3e35d6394921f690d4b6d7beaef48910ce65ba8a954545a",
                17,
                "p2-r1b-public-corpus-20261114",
            ),
            (
                "adversarial",
                "896b58932cb1d1f9d4b430d1c363824cbd3c2fd08307eedf95bc23136f4c01dc",
                320,
                "p2-r1b-signed-adversarial-corpus-20261114",
            ),
        ):
            directory = FIXTURES / name
            raw_manifest = (directory / "manifest.json").read_bytes()
            self.assertEqual(hashlib.sha256(raw_manifest).hexdigest(), expected_sha)
            manifest = json.loads(raw_manifest)
            actual = {
                path.relative_to(directory).as_posix()
                for path in directory.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual, set(manifest["files"]) | {"manifest.json"})
            self.assertEqual(len(actual), total)
            for relative in actual:
                raw = (directory / relative).read_bytes()
                if relative != "manifest.json":
                    self.assertEqual(len(raw), manifest["files"][relative]["bytes"])
                    self.assertEqual(
                        hashlib.sha256(raw).hexdigest(), manifest["files"][relative]["sha256"]
                    )

    def test_twenty_current_verdicts_match_frozen_real_P0_run(self):
        observed_p0 = load(FIXTURES / "reference-p0-child-report.json")
        self.assertEqual(
            hashlib.sha256((FIXTURES / "reference-p0-child-report.json").read_bytes()).hexdigest(),
            "c608019c010966e41a3996669fd0fff3f28549d9bf35dfbd49b00dba894cb92a",
        )
        old = {
            row["case_id"]: row["observed_selected_functions_verdict"]
            for row in observed_p0["cases"]
        }
        accepted = rejected = 0
        for label, _, paths, ctx_path, cp_path, expected in self.rows:
            with self.subTest(case=label):
                try:
                    result = verify_current_registry_materials(
                        tuple(path.read_bytes() for path in paths),
                        cp_path.read_bytes(),
                        context(load(ctx_path)),
                    )
                except InvalidMaterials:
                    verdict = "reject"
                    rejected += 1
                else:
                    verdict = "accept"
                    accepted += 1
                    self.assertIs(type(result), CurrentRegistry)
                self.assertEqual(verdict, expected)
                self.assertEqual(verdict, old[label])
                OBSERVATIONS.append(
                    {
                        "case_id": label,
                        "library_verdict": verdict,
                        "previous_real_P0_verdict": old[label],
                        "matches": verdict == old[label],
                        "authority": False,
                    }
                )
        self.assertEqual((accepted, rejected), (3, 17))

    def test_archive_separates_checkpoint_failures(self):
        accepted = rejected = 0
        for label, _, paths, ctx_path, _, expected in self.rows:
            with self.subTest(case=label):
                should_accept = expected == "accept" or "checkpoint" in label
                if should_accept:
                    result = verify_archived_registry_chain(
                        tuple(path.read_bytes() for path in paths), context(load(ctx_path), False)
                    )
                    self.assertIs(type(result), HistoricalRegistry)
                    accepted += 1
                else:
                    self.rejected(
                        verify_archived_registry_chain,
                        tuple(path.read_bytes() for path in paths),
                        context(load(ctx_path), False),
                    )
                    rejected += 1
        self.assertEqual((accepted, rejected), (9, 11))

    def test_all_static_commitments_and_canonical_oracles(self):
        digests = canonicals = 0
        for label, directory, paths, _, cp_path, _ in self.rows:
            prefix = directory if label == "root-original-positive" else paths[0].parent.parent
            commitments = load(prefix / "commitments.json")
            for position, (path, commitment) in enumerate(zip(paths, commitments, strict=True), 1):
                envelope = load(path)
                self.assertEqual(_api.digest(envelope), commitment["registry_hash"])
                self.assertEqual(
                    hashlib.sha256(
                        _api.REGISTRY_DOMAIN + _codec.canonical(envelope["body"])
                    ).hexdigest(),
                    commitment["body_message_sha256"],
                )
                digests += 1
                stem = path.stem if label == "root-original-positive" else f"{position:02d}"
                for kind, value in (("body", envelope["body"]), ("envelope", envelope)):
                    self.assertEqual(
                        _codec.canonical(value),
                        (prefix / "canonical" / f"{stem}-{kind}.utf8").read_bytes(),
                    )
                    canonicals += 1
            self.assertEqual(
                _codec.canonical(load(cp_path)["body"]),
                (prefix / "canonical/checkpoint-body.utf8").read_bytes(),
            )
            canonicals += 1
        self.assertEqual((digests, canonicals), (72, 164))

    def test_186_static_signatures_are_mathematically_valid(self):
        total = 0
        for label, directory, paths, ctx_path, cp_path, _ in self.rows[1:]:
            mathematical = load(paths[0].parent.parent / "mathematical-signing-keys.json")[
                "entries"
            ]
            values = load(ctx_path)
            for path in paths:
                envelope = load(path)
                oracle = mathematical[path.relative_to(directory).as_posix()]
                message = _api.REGISTRY_DOMAIN + _codec.canonical(envelope["body"])
                for signer, signature in envelope["signatures"].items():
                    _crypto.verify(
                        _crypto.decode(
                            oracle["registry_signing_keys"][signer]["public_key"], length=32
                        ),
                        signature,
                        message,
                    )
                    total += 1
                for signer, signature in envelope["commissioning_signatures"].items():
                    _crypto.verify(
                        _crypto.decode(
                            values["commissioning_keys"][signer]["public_key"], length=32
                        ),
                        signature,
                        message,
                    )
                    total += 1
            cp = load(cp_path)
            _crypto.verify(
                _crypto.decode(values["checkpoint_keys"][cp["key_id"]]["public_key"], length=32),
                cp["signature"],
                _api.CHECKPOINT_DOMAIN + _codec.canonical(cp["body"]),
            )
            total += 1
        self.assertEqual(total, 186)

    def test_immutable_distinct_context_and_results(self):
        archived = verify_archived_registry_chain(self.raw, self.hist)
        current = verify_current_registry_materials(self.raw, self.checkpoint, self.ctx)
        self.assertNotIsInstance(archived, CurrentRegistry)
        self.assertNotIsInstance(current, HistoricalRegistry)
        for value in (archived, current, self.ctx, self.ctx.checkpoint_keys[0]):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, fields(value)[0].name, "forbidden mutation")
        for value in (archived, current):

            def immutable(item):
                self.assertIn(type(item), (bytes, str, int, tuple))
                if type(item) is tuple:
                    for child in item:
                        immutable(child)

            for field in fields(value):
                immutable(getattr(value, field.name))
        self.rejected(verify_archived_registry_chain, self.raw, self.ctx)
        self.rejected(verify_current_registry_materials, self.raw, self.checkpoint, self.hist)
        self.rejected(verify_current_registry_materials, archived, self.checkpoint, self.ctx)
        self.rejected(lambda: replace(archived, owner_counts={}))

    def test_context_strict_head_and_key_types(self):
        for field, value in (
            ("revision", True),
            ("revision", 4.0),
            ("organization", self.ctx.organization.upper().replace("a", "A") + "x"),
            ("registry_hash", "F" * 64),
            ("installation", " "),
            ("commissioning_keys", list(self.ctx.commissioning_keys)),
        ):
            self.rejected(lambda: replace(self.ctx, **{field: value}))
        for value in (bytearray(32), b"short", "x" * 32):
            self.rejected(ExternalKey, "fixture", value)
        self.rejected(lambda: replace(self.ctx, checkpoint_keys=self.ctx.checkpoint_keys * 2))
        self.rejected(lambda: replace(self.ctx, now_utc="2026-11-14T13:16:01+01:00"))
        self.rejected(lambda: replace(self.ctx, checkpoint_max_seconds=61))
        self.rejected(lambda: replace(self.ctx, registry_max_seconds=0))

    def test_external_context_mutations_rejected(self):
        for field, value in (
            ("organization", "00000000-0000-0000-0000-000000000065"),
            ("installation", "other-tenant-fixture"),
            ("generation", "00000000-0000-0000-0000-000000000099"),
            ("revision", 3),
            ("registry_hash", "0" * 64),
        ):
            self.rejected(
                verify_current_registry_materials,
                self.raw,
                self.checkpoint,
                replace(self.ctx, **{field: value}),
            )

    def test_archive_expiry_does_not_become_current(self):
        verify_archived_registry_chain(self.raw, self.hist)
        expired = replace(self.ctx, now_utc="2026-11-17T12:16:01+00:00")
        self.rejected(verify_current_registry_materials, self.raw, self.checkpoint, expired)

    def test_shorter_current_registry_TTL_is_deliberate_profile_restriction(self):
        verify_current_registry_materials(self.raw, self.checkpoint, self.ctx)
        shorter = replace(self.ctx, registry_max_seconds=86399)
        verify_archived_registry_chain(self.raw, self.hist)
        self.rejected(verify_current_registry_materials, self.raw, self.checkpoint, shorter)
        # The frozen P0 witness is only the default profile; no new recognized_registry run.

    def test_context_key_count_and_opaque_bounds(self):
        original = self.hist.commissioning_keys[0]
        sixty_four = (original,) + tuple(
            replace(original, key_id=f"public-alias-{i}") for i in range(63)
        )
        verify_archived_registry_chain(self.raw, replace(self.hist, commissioning_keys=sixty_four))
        self.rejected(
            lambda: replace(
                self.hist,
                commissioning_keys=sixty_four + (replace(original, key_id="public-extra"),),
            )
        )
        self.rejected(lambda: replace(original, key_id="k" * 129))
        self.rejected(lambda: replace(original, active=1))
        self.rejected(lambda: replace(self.hist, installation="i" * 129))
        self.rejected(lambda: replace(self.hist, installation="\ud800"))

    def test_UUID_length_precedes_parser_for_context_and_body(self):
        real_parser = _context.UUID
        observed_lengths = []

        def tracked_parser(value):
            observed_lengths.append(len(value))
            if len(value) != 36:
                raise ValueError("oversized UUID reached parser spy")
            return real_parser(value)

        with patch.object(_context, "UUID", side_effect=tracked_parser):
            for name in ("organization", "generation"):
                with self.subTest(context=name):
                    observed_lengths.clear()
                    self.rejected(lambda: replace(self.hist, **{name: "a" * 131073}))
                    self.assertTrue(all(length == 36 for length in observed_lengths))
            for field in ("generation", "person", "identity"):
                changed = json.loads(self.raw[0])["body"]
                if field == "generation":
                    changed["generation"] = "a" * 37
                elif field == "person":
                    person = next(iter(changed["persons"]))
                    changed["persons"]["a" * 37] = changed["persons"].pop(person)
                else:
                    person = next(iter(changed["persons"]))
                    changed["persons"][person]["identity_ids"] = ["a" * 37]
                with self.subTest(body=field):
                    observed_lengths.clear()
                    self.rejected(_codec.public_call, _api._validate_body, changed, self.hist)
                    self.assertTrue(all(length == 36 for length in observed_lengths))

    def test_default_empty_signature_map_is_in_V1_committed_document(self):
        envelope = json.loads(self.raw[1])
        envelope.pop("commissioning_signatures")
        raw = self.raw[:1] + (json.dumps(envelope, ensure_ascii=False).encode(),)
        ctx = replace(
            self.hist,
            generation=envelope["body"]["generation"],
            revision=2,
            registry_hash=_api.digest(envelope),
        )
        result = verify_archived_registry_chain(raw, ctx)
        self.assertEqual(
            result.canonical_head_envelope,
            (self.root / "canonical/02-public-bindings-envelope.utf8").read_bytes(),
        )
        self.assertEqual(dict(result.owner_counts)["credential"], 3)

    def test_unknown_signed_fields_are_preserved_without_lookup(self):
        body = load(self.root / "checkpoint.json")["body"]
        body["unknown_signed_fields"] = {
            "jku": "https://unreachable.fixture.invalid/key",
            "NFD": "cafe\u0301",
            "float": -0.0,
        }
        raw, ctx = self.signed_checkpoint(body, self.ctx)
        result = verify_current_registry_materials(self.raw, raw, ctx)
        self.assertIn(
            b'"jku":"https://unreachable.fixture.invalid/key"', result.canonical_checkpoint
        )
        self.assertIn("cafe\u0301".encode(), result.canonical_checkpoint)

    def test_keys_historical_active_and_period_boundaries(self):
        inactive = tuple(replace(key, active=False) for key in self.hist.commissioning_keys)
        verify_archived_registry_chain(self.raw, replace(self.hist, commissioning_keys=inactive))
        verify_current_registry_materials(
            self.raw, self.checkpoint, replace(self.ctx, commissioning_keys=inactive)
        )
        cp_time = load(self.root / "checkpoint.json")["body"]["issued_at"]
        for changes, accept in (
            ({"not_before": cp_time}, True),
            ({"not_after": cp_time}, False),
            ({"revoked_at": cp_time}, False),
            ({"active": False}, False),
        ):
            changed = replace(
                self.ctx,
                checkpoint_keys=tuple(replace(key, **changes) for key in self.ctx.checkpoint_keys),
            )
            if accept:
                verify_current_registry_materials(self.raw, self.checkpoint, changed)
            else:
                self.rejected(verify_current_registry_materials, self.raw, self.checkpoint, changed)

    def test_chain_order_suffix_and_duplicate_refused(self):
        for raw in (tuple(reversed(self.raw)), self.raw[1:], self.raw + (self.raw[-1],)):
            self.rejected(verify_archived_registry_chain, raw, self.hist)

    def test_signatures_scope_and_both_signature_sets_are_bound(self):
        original = json.loads(self.raw[-1])
        for field, value in original["body"]["targets"].items():
            for scoped in value["scope"]:
                changed = json.loads(self.raw[-1])
                old = changed["body"]["targets"][field]["scope"][scoped]
                changed["body"]["targets"][field]["scope"][scoped] = (
                    old + 1 if type(old) is int else str(old) + "-changed"
                )
                self.rejected(
                    verify_archived_registry_chain,
                    self.raw[:-1] + (json.dumps(changed, ensure_ascii=False).encode(),),
                    self.hist,
                )
        for section in ("signatures", "commissioning_signatures"):
            changed = json.loads(self.raw[-1])
            changed[section]["unknown-signer"] = next(iter(changed[section].values()))
            self.assertNotEqual(_api.digest(changed), _api.digest(original))
            self.rejected(
                verify_archived_registry_chain,
                self.raw[:-1] + (json.dumps(changed, ensure_ascii=False).encode(),),
                self.hist,
            )
        cp = load(self.root / "checkpoint.json")
        cp["signature"] = b64(bytes(64))
        self.rejected(
            verify_current_registry_materials, self.raw, json.dumps(cp).encode(), self.ctx
        )
        cp = load(self.root / "checkpoint.json")
        cp["key_id"] = "unconfigured-fixture-key"
        self.rejected(
            verify_current_registry_materials, self.raw, json.dumps(cp).encode(), self.ctx
        )

    def test_registry_revision_remains_strict_before_crypto(self):
        for value in (True, 1.0):
            changed = json.loads(self.raw[0])
            changed["body"]["revision"] = value
            with patch.object(
                _api, "verify", side_effect=AssertionError("must reject before crypto")
            ) as crypto:
                self.rejected(
                    verify_archived_registry_chain, (json.dumps(changed).encode(),), self.hist
                )
                crypto.assert_not_called()

    def test_raw_types_and_all_budgets_before_parser(self):
        big = b" " * (2 * 1024 * 1024)
        for raw in (
            list(self.raw),
            (bytearray(self.raw[0]),),
            (),
            (b"x",) * 257,
            (big + b" ",),
            (big,) * 17,
        ):
            with patch.object(
                _api, "parse", side_effect=AssertionError("parser must not run")
            ) as parser:
                self.rejected(verify_archived_registry_chain, raw, self.hist)
                parser.assert_not_called()
        with patch.object(
            _api, "parse", side_effect=AssertionError("parser must not run")
        ) as parser:
            self.rejected(verify_current_registry_materials, self.raw, b"x" * 65537, self.ctx)
            parser.assert_not_called()

    def test_depth_rejected_before_JSON_parser(self):
        raw = b"[" * 17 + b"0" + b"]" * 17
        with patch.object(
            _codec.json, "loads", side_effect=AssertionError("JSON parser must not run")
        ) as parser:
            self.rejected(_codec.public_call, _codec.parse, raw)
            parser.assert_not_called()
        self.assertEqual(
            _codec.parse(b"[" * 16 + b"0" + b"]" * 16), [[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]
        )

    def test_JSON_duplicates_escaped_aliases_and_malformed(self):
        for raw in (
            b'{"body":1,"body":2}',
            b'{"body":1,"\\u0062ody":2}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b'{"x":1e999}',
            b'{"x":',
            b'"\\ud800"',
        ):
            self.rejected(
                _codec.public_call, lambda data: _codec.canonical(_codec.parse(data)), raw
            )

    def test_nodes_strings_int64_and_finite_float_preservation(self):
        self.rejected(_codec.public_call, _codec.parse, b"[" + b"0," * 8192 + b"0]")
        self.rejected(_codec.public_call, _codec.parse, json.dumps("x" * 65537).encode())
        for value in (-(1 << 63), (1 << 63) - 1, -0.0, 1.25, 1e-20):
            self.assertEqual(
                _codec.canonical(_codec.parse(json.dumps({"unknown": value}).encode())),
                json.dumps(
                    {"unknown": value},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode(),
            )
        for value in (-(1 << 63) - 1, 1 << 63):
            self.rejected(_codec.public_call, _codec.parse, json.dumps(value).encode())

    def test_canonical_budget_before_retention_next_piece(self):
        emitted = []

        def chunks(*_args, **_kwargs):
            emitted.append(1)
            yield "x" * 129
            emitted.append(2)
            yield "never"

        with patch.object(_codec.json.JSONEncoder, "iterencode", chunks):
            self.rejected(_codec.public_call, _codec.canonical, {"a": 1}, 128)
        self.assertEqual(emitted, [1])

    def signed_checkpoint(self, body, ctx):
        # Supplementary local compatibility test, not an independent static oracle.
        key = ed25519.Ed25519PrivateKey.generate()
        encoded = b64(key.sign(_api.CHECKPOINT_DOMAIN + _codec.canonical(body)))
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        replacement = replace(ctx, checkpoint_keys=(ExternalKey("unit-witness", public),))
        raw = json.dumps(
            {"body": body, "key_id": "unit-witness", "signature": encoded}, ensure_ascii=False
        ).encode()
        return raw, replacement

    def test_signed_checkpoint_float_revision_V1_compatibility(self):
        body = load(self.root / "checkpoint.json")["body"]
        body["revision"] = 4.0
        body["unknown_signed_float"] = -0.0
        raw, ctx = self.signed_checkpoint(body, self.ctx)
        result = verify_current_registry_materials(self.raw, raw, ctx)
        self.assertIn(b'"revision":4.0', result.canonical_checkpoint)
        self.rejected(lambda: replace(ctx, revision=4.0))

    def test_signed_checkpoint_bool_revision1_V1_compatibility(self):
        first = json.loads(self.raw[0])
        ctx = replace(
            self.ctx,
            generation=first["body"]["generation"],
            revision=1,
            registry_hash=_api.digest(first),
        )
        body = load(self.root / "checkpoint.json")["body"]
        body.update(generation=ctx.generation, revision=True, registry_hash=ctx.registry_hash)
        raw, ctx = self.signed_checkpoint(body, ctx)
        result = verify_current_registry_materials(self.raw[:1], raw, ctx)
        self.assertIn(b'"revision":true', result.canonical_checkpoint)
        self.rejected(lambda: replace(ctx, revision=True))

    def test_timestamp_parser_compatibility_and_no_signed_normalization(self):
        self.assertEqual(
            timestamp("2026-1-2 3:4:5.12+01"), timestamp("2026-01-02T02:04:05.120000+00:00")
        )
        body = load(self.root / "checkpoint.json")["body"]
        original = timestamp(body["issued_at"])
        body["issued_at"] = original.astimezone(
            __import__("datetime").timezone(timedelta(hours=1))
        ).isoformat()
        raw, ctx = self.signed_checkpoint(body, self.ctx)
        result = verify_current_registry_materials(self.raw, raw, ctx)
        self.assertIn(body["issued_at"].encode(), result.canonical_checkpoint)

    def test_b64_distinct_V1_and_COSE_profiles(self):
        encoded = load(self.root / "chain/01-bootstrap.json")["body"]["custodians"]
        raw = next(iter(encoded.values()))["public_key"]
        self.assertEqual(_crypto.decode(raw), _crypto.decode(raw + "="))
        credential = json.loads(self.raw[1])["body"]["persons"]
        authenticator = next(
            row["authenticators"][0] for row in credential.values() if row["authenticators"]
        )
        self.rejected(
            _codec.public_call, _crypto.public_key_fingerprint, authenticator["public_key"] + "="
        )

    def test_maintained_ES256_EdDSA_RS256_and_unknown_algorithm(self):
        expected = load(self.root / "expected-context.json")["credential_spki_sha256"]
        for person in json.loads(self.raw[1])["body"]["persons"].values():
            for authenticator in person["authenticators"]:
                self.assertEqual(
                    _crypto.public_key_fingerprint(authenticator["public_key"]),
                    expected[authenticator["id"]],
                )
        for key, cose in (
            (ed25519.Ed25519PrivateKey.generate().public_key(), "EdDSA"),
            (rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(), "RS256"),
        ):
            if cose == "EdDSA":
                material = {
                    1: 1,
                    3: -8,
                    -1: 6,
                    -2: key.public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    ),
                }
            else:
                numbers = key.public_numbers()
                material = {
                    1: 3,
                    3: -257,
                    -1: numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"),
                    -2: numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"),
                }
            expected_hash = hashlib.sha256(
                key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).hexdigest()
            self.assertEqual(
                _crypto.public_key_fingerprint(b64(cbor2.dumps(material))), expected_hash
            )
            material[3] = -65535
            self.rejected(
                _codec.public_call, _crypto.public_key_fingerprint, b64(cbor2.dumps(material))
            )

    def test_error_constant_without_raw_data_or_exception_chain(self):
        marker = b"SYNTHETIC_RAW_MARKER_DO_NOT_LOG"
        with self.assertRaises(InvalidMaterials) as caught:
            verify_archived_registry_chain((marker,), self.hist)
        self.assertEqual(caught.exception.args, (_codec.ERROR,))
        self.assertNotIn(marker.decode(), repr(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_no_project_Django_or_Vault_import(self):
        self.assertFalse(
            any(
                name.startswith(("django", "platform_core", "platform_modules", "pamolive_vault"))
                for name in sys.modules
            )
        )
