"""Pure N0 tests. The in-memory KEK provider exists ONLY in this test directory."""

import copy
import hashlib
import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import pamolive_vault_envelope as vault
from pamolive_vault_envelope import envelope as implementation


class SyntheticMemoryProvider:
    """No production provider, network, SDK, automatic keys or fallback."""

    provider_id = "synthetic-memory-n0"

    def __init__(self, keys):
        if not keys or any(type(key) is not bytes or len(key) != 32 for key in keys.values()):
            raise ValueError("synthetic_key_material")
        self.keys = dict(keys)
        self.calls = []
        self.dek_hashes = []

    def wrap_key(self, dek, key_ref, context):
        self.calls.append(("wrap", key_ref, context))
        self.dek_hashes.append(hashlib.sha256(dek).digest())
        nonce = os.urandom(12)
        return vault.WrappedKey(
            key_ref, nonce + AESGCM(self.keys[key_ref]).encrypt(nonce, dek, context)
        )

    def unwrap_key(self, blob, key_ref, context):
        self.calls.append(("unwrap", key_ref, context))
        dek = AESGCM(self.keys[key_ref]).decrypt(blob[:12], blob[12:], context)
        return vault.UnwrappedKey(key_ref, dek)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.binding = vault.Binding(
            str(uuid4()),
            str(uuid4()),
            "technical-credentials",
            str(uuid4()),
            1,
            "ssh-password",
            "a" * 64,
        )
        self.key = vault.KeyRef(
            self.binding.installation_id,
            self.binding.organization_id,
            self.binding.domain,
            SyntheticMemoryProvider.provider_id,
            "synthetic-tenant-key",
            1,
        )
        self.next_key = replace(self.key, kek_version=2)
        self.provider = SyntheticMemoryProvider(
            {
                self.key: os.urandom(32),
                self.next_key: os.urandom(32),
            }
        )
        self.plaintext = b"Synthetic credential, never a real account password."

    def seal(self, **changes):
        return vault.seal_new_version(
            changes.get("plaintext", self.plaintext),
            changes.get("binding", self.binding),
            changes.get("key", self.key),
            changes.get("provider", self.provider),
        )

    def open(self, envelope, **changes):
        return vault.open_authorized_version(
            envelope,
            changes.get("binding", self.binding),
            changes.get("key", self.key),
            changes.get("provider", self.provider),
        )

    def roundtrip_document(self):
        return json.loads(vault.serialize_envelope(self.seal()))

    def test_roundtrip_immutable_typed_envelope_and_canonical_serialization(self):
        envelope = self.seal()
        serialized = vault.serialize_envelope(envelope)
        parsed = vault.parse_envelope(serialized)
        self.assertEqual(parsed, envelope)
        self.assertEqual(self.open(parsed), self.plaintext)
        self.assertEqual(vault.serialize_envelope(parsed), serialized)
        self.assertNotIn(self.plaintext, serialized)
        for value, name in (
            (envelope, "dek_id"),
            (envelope.binding, "secret_version"),
            (envelope.wrapping, "context_hash"),
            (self.key, "kek_version"),
        ):
            with self.subTest(type=type(value).__name__), self.assertRaises(FrozenInstanceError):
                setattr(value, name, "changed")

    def test_aes256_gcm_published_known_answer(self):
        # NIST GCM validation: AES-256, zero key/IV/plaintext, no AAD.
        expected = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
        actual = AESGCM(bytes(32)).encrypt(bytes(12), bytes(16), b"")
        self.assertEqual(actual, expected)
        self.assertEqual(AESGCM(bytes(32)).decrypt(bytes(12), expected, b""), bytes(16))

    def test_distinct_payload_and_wrap_context_match_closed_adr_fields(self):
        envelope = self.seal()
        context = json.loads(self.provider.calls[0][2])
        expected_payload = {
            "schema": "pamolive.vault-payload-aad/1",
            "envelope_schema": "pamolive.vault-envelope/1",
            "payload_algorithm": "AES-256-GCM",
            "binding": self.round_binding(),
            "dek_id": envelope.dek_id,
        }
        raw = json.dumps(
            expected_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        self.assertEqual(
            context,
            {
                "schema": "pamolive.vault-wrap-aad/1",
                "installation_id": self.binding.installation_id,
                "organization_id": self.binding.organization_id,
                "domain": self.binding.domain,
                "secret_id": self.binding.secret_id,
                "secret_version": 1,
                "dek_id": envelope.dek_id,
                "payload_aad_sha256": hashlib.sha256(raw).hexdigest(),
                "provider_id": self.key.provider_id,
                "kek_id": self.key.kek_id,
                "kek_version": 1,
            },
        )
        self.assertLessEqual(len(raw), 4096)
        self.assertLessEqual(len(self.provider.calls[0][2]), 4096)
        self.assertEqual(
            envelope.wrapping.context_hash, hashlib.sha256(self.provider.calls[0][2]).hexdigest()
        )

    def round_binding(self):
        return {
            name: getattr(self.binding, name)
            for name in (
                "installation_id",
                "organization_id",
                "domain",
                "secret_id",
                "secret_version",
                "purpose",
                "destination_scope_hash",
            )
        }

    def test_new_versions_receive_fresh_dek_id_key_and_nonce_without_sql_claim(self):
        first = self.seal()
        second = self.seal(binding=replace(self.binding, secret_version=2))
        self.assertNotEqual(first.dek_id, second.dek_id)
        self.assertNotEqual(first.payload_nonce, second.payload_nonce)
        self.assertNotEqual(self.provider.dek_hashes[0], self.provider.dek_hashes[1])
        # This API has no database and deliberately cannot deduplicate retries.
        third = self.seal()
        self.assertNotEqual(first, third)

    def test_expected_binding_substitutions_refused_before_provider_call(self):
        envelope = self.seal()
        for field, value in (
            ("installation_id", str(uuid4())),
            ("organization_id", str(uuid4())),
            ("secret_id", str(uuid4())),
            ("secret_version", 2),
            ("purpose", "different-purpose"),
            ("destination_scope_hash", "b" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(vault.EnvelopeError):
                before = len(self.provider.calls)
                self.open(envelope, binding=replace(self.binding, **{field: value}))
            self.assertEqual(len(self.provider.calls), before)

    def test_key_reference_changes_and_stale_wrapping_refused_before_unwrap(self):
        envelope = self.seal()
        for field, value in (
            ("provider_id", "another-provider"),
            ("kek_id", "another-key"),
            ("kek_version", 2),
            ("installation_id", str(uuid4())),
            ("organization_id", str(uuid4())),
        ):
            before = len(self.provider.calls)
            with self.subTest(field=field), self.assertRaises(vault.EnvelopeError):
                self.open(envelope, key=replace(self.key, **{field: value}))
            self.assertEqual(len(self.provider.calls), before)

    def test_domain_uuid_reference_and_integer_types_are_strict(self):
        for field, values in {
            "domain": ["user-vault", "recordings", "evidence-signing", "", None],
            "secret_version": [True, 0, -1, 1.0, "1", 2**63],
            "secret_id": [uuid4(), "0" * 32, "{" + str(uuid4()) + "}", None],
            "purpose": ["", "   ", "https://fixture.invalid", "../key", "a\n", "é", "x" * 65],
            "destination_scope_hash": ["", "A" * 64, "0" * 63, None],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(vault.EnvelopeError):
                    replace(self.binding, **{field: value})
        for field, value in (
            ("kek_version", True),
            ("kek_version", 2**63),
            ("provider_id", "a" * 65),
            ("kek_id", "b" * 129),
        ):
            with self.subTest(field=field), self.assertRaises(vault.EnvelopeError):
                replace(self.key, **{field: value})

    def test_plaintext_and_envelope_byte_budgets_before_provider(self):
        for value in (b"", b"x" * 65537, "text", bytearray(b"x"), None):
            with self.subTest(type=type(value).__name__), self.assertRaises(vault.EnvelopeError):
                self.seal(plaintext=value)
        self.assertEqual(self.provider.calls, [])
        envelope = self.seal(plaintext=b"x" * 65536)
        self.assertEqual(len(envelope.payload_ciphertext), 65552)
        self.assertEqual(len(self.open(envelope)), 65536)
        for raw in (b"x" * (131072 + 1), "{}", bytearray(b"{}"), b""):
            with self.subTest(type=type(raw).__name__), self.assertRaises(vault.EnvelopeError):
                vault.parse_envelope(raw)

    def test_json_duplicates_unknown_missing_null_and_nonfinite_are_rejected(self):
        value = self.roundtrip_document()
        raw = json.dumps(value).encode()
        malformed = [
            b'{"schema":"x","schema":"x"}',
            b"\xff",
            b'{"value":NaN}',
            b'{"value":1.0}',
            b'{"value":' + b"1" * 1000 + b"}",
        ]
        for field in value:
            changed = copy.deepcopy(value)
            changed[field] = None
            malformed.append(json.dumps(changed).encode())
            changed = copy.deepcopy(value)
            del changed[field]
            malformed.append(json.dumps(changed).encode())
        malformed.append(json.dumps({**value, "authorized": True}).encode())
        malformed.append(raw.replace(b'"binding": {', b'"binding": {"domain":"x",', 1))
        malformed.append(json.dumps({**value, "nested": [[[[[[[[[0]]]]]]]]]}).encode())
        malformed.append(json.dumps({**value, "members": list(range(129))}).encode())
        for index, document in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(vault.EnvelopeError):
                vault.parse_envelope(document)

    def test_closed_algorithm_wrap_schema_and_nested_types(self):
        value = self.roundtrip_document()
        changes = [
            ("schema", "pamolive.vault-envelope/2"),
            ("payload_algorithm", "AES-128-GCM"),
            ("binding", {**value["binding"], "authorized": True}),
            ("wrapping", {**value["wrapping"], "url": "https://fixture.invalid"}),
            ("wrapping", {**value["wrapping"], "schema": "unknown"}),
            ("wrapping", {**value["wrapping"], "kek_version": True}),
        ]
        for field, new in changes:
            with self.subTest(field=field, new=new), self.assertRaises(vault.EnvelopeError):
                vault.parse_envelope(json.dumps({**value, field: new}).encode())

    def test_base64url_padding_alphabet_aliases_lengths_and_blob_budget(self):
        value = self.roundtrip_document()
        mutations = []
        for field in ("payload_nonce", "payload_ciphertext"):
            for encoded in (value[field] + "=", "+///", "AA", "", "é", "a" * 90000):
                mutations.append({**value, field: encoded})
        # Same decoded blob byte but nonzero unused base64 bits: AB aliases AA.
        for blob in ("AB", "AA==", "a" * 21847):
            mutations.append({**value, "wrapping": {**value["wrapping"], "wrapped_dek": blob}})
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(vault.EnvelopeError):
                vault.parse_envelope(json.dumps(changed).encode())

    def test_ciphertext_nonce_tag_wrapped_key_and_context_bitflips_never_return_plaintext(self):
        envelope = self.seal()
        for field in ("payload_nonce", "payload_ciphertext"):
            value = getattr(envelope, field)
            changed = replace(envelope, **{field: bytes([value[0] ^ 1]) + value[1:]})
            with self.subTest(field=field), self.assertRaises(vault.EnvelopeError):
                self.open(changed)
        changed = replace(
            envelope,
            payload_ciphertext=envelope.payload_ciphertext[:-1]
            + bytes([envelope.payload_ciphertext[-1] ^ 1]),
        )
        with self.assertRaises(vault.EnvelopeError):
            self.open(changed)
        changed = replace(envelope, wrapping=replace(envelope.wrapping, context_hash="f" * 64))
        before = len(self.provider.calls)
        with self.assertRaises(vault.EnvelopeError):
            self.open(changed)
        self.assertEqual(len(self.provider.calls), before)
        blob = envelope.wrapping.wrapped_dek
        changed = replace(
            envelope,
            wrapping=replace(envelope.wrapping, wrapped_dek=bytes([blob[0] ^ 1]) + blob[1:]),
        )
        with self.assertRaises(vault.ProviderError):
            self.open(changed)

    def test_binding_transposition_with_metadata_rebuilt_still_fails_authentication(self):
        envelope = self.seal()
        changed_binding = replace(self.binding, secret_version=2)
        context = implementation._wrap_context(changed_binding, envelope.dek_id, self.key)
        changed = replace(
            envelope,
            binding=changed_binding,
            wrapping=replace(envelope.wrapping, context_hash=hashlib.sha256(context).hexdigest()),
        )
        with self.assertRaises(vault.ProviderError):
            self.open(changed, binding=changed_binding)

    def test_explicit_provider_missing_mismatch_failure_and_key_removed(self):
        for provider in (None, "", object()):
            with self.subTest(type=type(provider).__name__), self.assertRaises(vault.ProviderError):
                self.seal(provider=provider)
        envelope = self.seal()
        with patch.object(self.provider, "provider_id", "wrong-provider"):
            before = len(self.provider.calls)
            with self.assertRaises(vault.ProviderError):
                self.open(envelope)
            self.assertEqual(len(self.provider.calls), before)
        self.provider.keys.pop(self.key)
        with self.assertRaises(vault.ProviderError):
            self.open(envelope)

    def test_provider_return_types_dek_lengths_refs_and_wrapped_budgets_fail_closed(self):
        for value in (
            None,
            {"authorized": True},
            vault.WrappedKey(self.next_key, b"x"),
            vault.WrappedKey(self.key, b""),
            vault.WrappedKey(self.key, b"x" * 16385),
            vault.WrappedKey(self.key, bytearray(b"x")),
        ):
            with patch.object(self.provider, "wrap_key", return_value=value):
                with (
                    self.subTest(type=type(value).__name__),
                    self.assertRaises(vault.ProviderError),
                ):
                    self.seal()
        envelope = self.seal()
        for value in (
            None,
            {"dek": b"x" * 32},
            vault.UnwrappedKey(self.next_key, b"x" * 32),
            vault.UnwrappedKey(self.key, b"x" * 31),
            vault.UnwrappedKey(self.key, bytearray(b"x" * 32)),
        ):
            with patch.object(self.provider, "unwrap_key", return_value=value):
                with (
                    self.subTest(type=type(value).__name__),
                    self.assertRaises(vault.ProviderError),
                ):
                    self.open(envelope)
        with patch.object(
            self.provider, "unwrap_key", return_value=vault.UnwrappedKey(self.key, os.urandom(32))
        ):
            with self.assertRaises(vault.EnvelopeError):
                self.open(envelope)

    def test_provider_error_never_logs_or_chains_adapter_secret(self):
        marker = "synthetic-private-provider-diagnostic-never-export"
        out, err = io.StringIO(), io.StringIO()
        with (
            redirect_stdout(out),
            redirect_stderr(err),
            patch.object(self.provider, "wrap_key", side_effect=RuntimeError(marker)),
        ):
            with self.assertRaises(vault.ProviderError) as raised:
                self.seal()
        self.assertEqual(str(raised.exception), "provider_failure")
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(marker, out.getvalue() + err.getvalue() + repr(raised.exception))
        self.assertNotIn(self.plaintext.decode(), repr(self.seal()))
        self.assertNotIn(marker, repr(vault.UnwrappedKey(self.key, marker.encode())))

    def test_rewrap_authenticates_and_preserves_all_payload_bytes_and_dek(self):
        envelope = self.seal()
        raw_before = vault.serialize_envelope(envelope)
        old_hash = self.provider.dek_hashes[-1]
        changed = vault.rewrap(envelope, self.binding, self.key, self.next_key, self.provider)
        self.assertEqual(changed.binding, envelope.binding)
        self.assertEqual(changed.dek_id, envelope.dek_id)
        self.assertEqual(changed.payload_nonce, envelope.payload_nonce)
        self.assertEqual(changed.payload_ciphertext, envelope.payload_ciphertext)
        self.assertEqual(self.provider.dek_hashes[-1], old_hash)
        self.assertEqual(vault.serialize_envelope(envelope), raw_before)
        self.assertEqual(self.open(changed, key=self.next_key), self.plaintext)
        before = len(self.provider.calls)
        with self.assertRaises(vault.EnvelopeError):
            self.open(changed)
        self.assertEqual(len(self.provider.calls), before)
        # Historical recovery is explicit, not automatic fallback to old key.
        self.assertEqual(self.open(envelope), self.plaintext)

    def test_rewrap_bad_payload_does_not_call_destination_wrap(self):
        envelope = self.seal()
        changed = replace(
            envelope,
            payload_ciphertext=envelope.payload_ciphertext[:-1]
            + bytes([envelope.payload_ciphertext[-1] ^ 1]),
        )
        before_wraps = sum(call[0] == "wrap" for call in self.provider.calls)
        with self.assertRaises(vault.EnvelopeError):
            vault.rewrap(changed, self.binding, self.key, self.next_key, self.provider)
        self.assertEqual(sum(call[0] == "wrap" for call in self.provider.calls), before_wraps)

    def test_cross_provider_and_cross_tenant_rewrap_refused_before_key_operation(self):
        envelope = self.seal()
        for destination in (
            replace(self.next_key, provider_id="different-provider"),
            replace(self.next_key, organization_id=str(uuid4())),
        ):
            before = len(self.provider.calls)
            with self.subTest(key=destination), self.assertRaises(vault.EnvelopeError):
                vault.rewrap(envelope, self.binding, self.key, destination, self.provider)
            self.assertEqual(len(self.provider.calls), before)

    def test_synthetic_key_constructor_refuses_empty_invalid_and_string_material(self):
        for key in (b"", b"x" * 31, b"x" * 33, "x" * 32, bytearray(b"x" * 32)):
            with self.subTest(type=type(key).__name__), self.assertRaises(ValueError):
                SyntheticMemoryProvider({self.key: key})

    def test_maximum_opaque_blob_serializes_with_maximum_payload_inside_json_budget(self):
        envelope = self.seal(plaintext=b"x" * 65536)
        largest = replace(
            envelope, wrapping=replace(envelope.wrapping, wrapped_dek=os.urandom(16384))
        )
        raw = vault.serialize_envelope(largest)
        self.assertLessEqual(len(raw), 131072)
        self.assertEqual(vault.parse_envelope(raw), largest)
        # Parsing opaque bytes is not a claim that this provider can unwrap them.
        with self.assertRaises(vault.ProviderError):
            self.open(largest)

    def test_modified_dek_id_and_metadata_have_no_unauthorized_key_call(self):
        envelope = self.seal()
        altered = replace(envelope, dek_id=str(uuid4()))
        before = len(self.provider.calls)
        with self.assertRaises(vault.EnvelopeError):
            self.open(altered)
        self.assertEqual(len(self.provider.calls), before)
        with self.assertRaises(vault.EnvelopeError):
            replace(self.binding, secret_id="ABCDEFAB-1234-1234-1234-123456789ABC")
        with patch.object(implementation, "MAX_AAD", 1):
            with self.assertRaises(vault.EnvelopeError):
                self.seal()
        self.assertEqual(len(self.provider.calls), before)

    def test_new_wrapping_survives_old_key_unavailability_but_old_archive_does_not(self):
        original = self.seal()
        current = vault.rewrap(original, self.binding, self.key, self.next_key, self.provider)
        self.provider.keys.pop(self.key)
        self.assertEqual(self.open(current, key=self.next_key), self.plaintext)
        with self.assertRaises(vault.ProviderError):
            self.open(original)

    def test_provider_timeout_exception_and_property_failures_are_redacted(self):
        envelope = self.seal()
        with patch.object(self.provider, "unwrap_key", side_effect=TimeoutError("private-timeout")):
            with self.assertRaises(vault.ProviderError) as raised:
                self.open(envelope)
        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(str(raised.exception), "provider_failure")

        class BrokenAdapter:
            provider_id = self.key.provider_id

            @property
            def wrap_key(self):
                raise RuntimeError("synthetic-private-property")

            def unwrap_key(self, *_args):
                raise AssertionError("must not run")

        with self.assertRaises(vault.ProviderError) as raised:
            self.seal(provider=BrokenAdapter())
        self.assertIsNone(raised.exception.__context__)

    def test_no_application_framework_or_default_provider_is_imported(self):
        # Execute import in a clean child process; no inherited Django settings.
        import subprocess
        import sys

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import pamolive_vault_envelope; "
                "assert not any(n.startswith(('django', 'platform_core', 'platform_modules', "
                "'boto3', 'requests')) for n in sys.modules)",
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(child.returncode, 0)
        self.assertEqual(child.stdout, b"")
        self.assertEqual(child.stderr, b"")


if __name__ == "__main__":
    unittest.main()
