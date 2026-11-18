"""Inert transport plus a synthetic AEAD oracle for the provider contract."""

import base64
import json
import os
import unittest
from dataclasses import replace
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pamolive_vault_envelope import (
    Binding,
    KeyRef,
    ProviderError,
    open_authorized_version,
    rewrap,
    seal_new_version,
)
from pamolive_vault_kms_openbao import TransitProvider

OLD = KeyRef(str(UUID(int=1)), str(UUID(int=2)), "technical-credentials", "openbao-n0", "kek", 1)
NEW = replace(OLD, kek_version=2)
BINDING = Binding(
    OLD.installation_id,
    OLD.organization_id,
    OLD.domain,
    str(UUID(int=3)),
    1,
    "ssh",
    "0" * 64,
)
DEK = b"synthetic-dek-for-provider-tests"
TOKEN = "synthetic-provider-token"


class TransitDouble:
    def __init__(self):
        self.keys = {version: AESGCM(AESGCM.generate_key(256)) for version in (1, 2)}
        self.calls = []
        self.reply = None

    def post(self, path, token, body):
        value = json.loads(body)
        self.calls.append((path, token, value))
        if self.reply is not None:
            return self.reply()
        aad = base64.b64decode(value["associated_data"], validate=True)
        if path == "/v1/transit/encrypt/tenant-one":
            version = value["key_version"]
            plaintext = base64.b64decode(value["plaintext"], validate=True)
            nonce = os.urandom(12)
            blob = nonce + self.keys[version].encrypt(nonce, plaintext, aad)
            payload = {
                "ciphertext": f"vault:v{version}:" + base64.b64encode(blob).decode(),
                "key_version": version,
            }
        elif path == "/v1/transit/decrypt/tenant-one":
            _, version, ciphertext = value["ciphertext"].split(":")
            blob = base64.b64decode(ciphertext, validate=True)
            plaintext = self.keys[int(version[1:])].decrypt(blob[:12], blob[12:], aad)
            payload = {"plaintext": base64.b64encode(plaintext).decode()}
        else:
            raise AssertionError("unexpected synthetic route")
        return json.dumps({"data": payload, "warnings": None, "auth": None}).encode()


class TransitProviderTests(unittest.TestCase):
    def setUp(self):
        self.transport = TransitDouble()
        self.active = TransitProvider(NEW, "tenant-one", frozenset({1, 2}), self.transport, TOKEN)
        self.old = TransitProvider(OLD, "tenant-one", frozenset({1}), self.transport, TOKEN)
        self.dek = DEK.ljust(32, b"!")
        self.aad = b"exact binding bytes\x00\xff"

    def test_explicit_version_and_complete_aad_are_sent(self):
        wrapped = self.active.wrap_key(self.dek, NEW, self.aad)
        unwrapped = self.active.unwrap_key(wrapped.blob, NEW, self.aad)
        self.assertEqual(unwrapped.dek, self.dek)
        self.assertEqual(unwrapped.key_ref, NEW)
        self.assertEqual(
            [call[0] for call in self.transport.calls],
            [
                "/v1/transit/encrypt/tenant-one",
                "/v1/transit/decrypt/tenant-one",
            ],
        )
        self.assertTrue(all(call[1] == TOKEN for call in self.transport.calls))
        for _, _, body in self.transport.calls:
            self.assertEqual(base64.b64decode(body["associated_data"]), self.aad)
        self.assertEqual(self.transport.calls[0][2]["key_version"], 2)
        self.assertNotIn(TOKEN, repr(self.active))
        self.assertNotIn(self.dek.hex(), repr(unwrapped))

    def test_scope_substitutions_refuse_before_io(self):
        for field, value in (
            ("installation_id", str(UUID(int=4))),
            ("organization_id", str(UUID(int=4))),
            ("provider_id", "other-provider"),
            ("kek_id", "other-family"),
            ("kek_version", 3),
        ):
            with self.subTest(field=field), self.assertRaises(ProviderError):
                self.active.wrap_key(self.dek, replace(NEW, **{field: value}), self.aad)
        for context in (b"", b"x" * 4097, bytearray(b"mutable"), "string"):
            with self.subTest(context=type(context)), self.assertRaises(ProviderError):
                self.active.wrap_key(self.dek, NEW, context)
        self.assertEqual(self.transport.calls, [])

    def test_rotation_rewrap_preserves_old_data_and_forbids_old_wrap(self):
        original = seal_new_version(b"synthetic value", BINDING, OLD, self.old)
        self.assertEqual(
            open_authorized_version(original, BINDING, OLD, self.active), b"synthetic value"
        )
        latest = rewrap(original, BINDING, OLD, NEW, self.active)
        self.assertEqual(original.payload_ciphertext, latest.payload_ciphertext)
        self.assertEqual(original.payload_nonce, latest.payload_nonce)
        self.assertEqual(
            open_authorized_version(latest, BINDING, NEW, self.active), b"synthetic value"
        )
        with self.assertRaises(ProviderError):
            self.active.wrap_key(self.dek, OLD, self.aad)
        no_archive = replace(self.active, readable_versions=frozenset({2}))
        call_count = len(self.transport.calls)
        with self.assertRaises(ProviderError):
            open_authorized_version(original, BINDING, OLD, no_archive)
        self.assertEqual(len(self.transport.calls), call_count)

    def test_context_and_ciphertext_substitution_are_refused(self):
        wrapped = self.active.wrap_key(self.dek, NEW, self.aad)
        replacement = b"B" if wrapped.blob.endswith(b"A") else b"A"
        changed = wrapped.blob[:-1] + replacement
        for blob, aad in ((wrapped.blob, b"different"), (changed, self.aad)):
            with self.subTest(aad=aad), self.assertRaises(ProviderError):
                self.active.unwrap_key(blob, NEW, aad)
        before = len(self.transport.calls)
        with self.assertRaises(ProviderError):
            self.active.unwrap_key(wrapped.blob, OLD, self.aad)
        self.assertEqual(len(self.transport.calls), before)

    def test_malformed_or_inconsistent_reply_is_closed(self):
        valid = self.active.wrap_key(self.dek, NEW, self.aad).blob.decode()
        cases = [
            b'{"data":{},"data":{}}',
            b'{"data":{"key_version":NaN}}',
            b"x" * 8193,
            json.dumps({"data": {"key_version": True, "ciphertext": valid}}).encode(),
            json.dumps(
                {"data": {"key_version": 2, "ciphertext": valid.replace(":v2:", ":v1:")}}
            ).encode(),
            json.dumps(
                {"data": {"key_version": 2, "ciphertext": valid}, "warnings": ["warning"]}
            ).encode(),
            json.dumps({"data": {"key_version": 2, "ciphertext": valid[:-1] + "+" * 2}}).encode(),
        ]
        for response in cases:
            self.transport.reply = lambda response=response: response
            with self.subTest(response_len=len(response)), self.assertRaises(ProviderError):
                self.active.wrap_key(self.dek, NEW, self.aad)

    def test_malformed_plaintext_replies_and_transport_errors_are_private(self):
        wrapped = self.active.wrap_key(self.dek, NEW, self.aad)

        def fail():
            raise TimeoutError("synthetic detail that must remain private")

        for reply in (fail, lambda: b'{"data":{"plaintext":"SECRET"}}'):
            self.transport.reply = reply
            with self.assertRaises(ProviderError) as caught:
                self.active.unwrap_key(wrapped.blob, NEW, self.aad)
            self.assertEqual(str(caught.exception), "provider_failure")
            self.assertIsNone(caught.exception.__context__)

    def test_refuses_endpoint_aliases_empty_token_and_bad_version_configuration(self):
        for fields in (
            {"token": ""},
            {"token": "bad\r\nvalue"},
            {"remote_key": "../../different"},
            {"readable_versions": frozenset({1})},
            {"readable_versions": frozenset({2, 3})},
            {"readable_versions": frozenset({True, 2})},
        ):
            with self.subTest(fields=fields), self.assertRaises(ProviderError):
                replace(self.active, **fields)

    def test_inflight_limit_refuses_without_network_and_recovers(self):
        for _ in range(4):
            self.assertTrue(self.active._capacity.acquire(blocking=False))
        with self.assertRaises(ProviderError):
            self.active.wrap_key(self.dek, NEW, self.aad)
        self.assertEqual(self.transport.calls, [])
        for _ in range(4):
            self.active._capacity.release()
        self.assertTrue(self.active.wrap_key(self.dek, NEW, self.aad).blob.startswith(b"vault:v2:"))
