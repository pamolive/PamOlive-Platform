"""Offline history signature tests with independent synthetic Ed25519 keys."""

import unittest
from dataclasses import asdict, replace
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pamolive_usage_anchor import codec, signed_anchor
from pamolive_usage_anchor.audit_archive import ArchiveVerifier
from test_audit_archive import audit_rows, checkpoint, event, page, uid


def encode(value):
    return codec.encode(value, signed_anchor.MAX_ANCHOR_BYTES, **signed_anchor.PROFILE)


class SignedAnchorTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes_raw()
        self.rows = audit_rows([event("activation_challenge", uid(10))])
        self.checkpoint = checkpoint(self.rows)
        self.raw = self.sign(self.checkpoint)
        self.pin = codec.sha(self.raw)

    def sign(self, point):
        return signed_anchor.sign_checkpoint(point, public_key=self.public, sign=self.key.sign)

    def verify(self, raw, *, pin=None, public=None):
        return signed_anchor.verify_checkpoint(
            raw,
            public_key=self.public if public is None else public,
            expected_sha256=self.pin if pin is None else pin,
        )

    def parse(self):
        return codec.parse(self.raw, signed_anchor.MAX_ANCHOR_BYTES, **signed_anchor.PROFILE)

    def refused(self, operation, *args, **kwargs):
        with self.assertRaises(codec.Error) as failure:
            operation(*args, **kwargs)
        self.assertEqual(
            (failure.exception.code, failure.exception.status), ("anchor_refused", 403)
        )

    def test_signed_checkpoint_verifies_the_historical_archive(self):
        envelope = self.parse()
        expected_body = {
            "schema": "pamolive.vault.usage-audit-anchor/1",
            "key_sha256": codec.sha(self.public),
            "checkpoint": asdict(self.checkpoint),
        }
        self.assertEqual(envelope["body"], expected_body)
        self.key.public_key().verify(
            codec.unb64(envelope["signature"], 64),
            b"pamolive.vault.usage-audit-anchor.v1\0" + encode(expected_body),
        )
        point = self.verify(self.raw)
        verifier = ArchiveVerifier(point)
        verifier.accept(page(point, self.rows))
        self.assertEqual(verifier.finish(), self.checkpoint)

    def test_older_valid_signature_cannot_replace_freshly_retained_document(self):
        older = self.sign(checkpoint([]))
        self.assertEqual(self.verify(older, pin=codec.sha(older)), checkpoint([]))
        self.refused(self.verify, older)

    def test_external_digest_and_key_pins_are_required_independently(self):
        other_key = Ed25519PrivateKey.generate()
        other_public = other_key.public_key().public_bytes_raw()
        self.refused(self.verify, self.raw, public=other_public)
        self.refused(self.verify, self.raw, pin="f" * 64)
        self.refused(self.verify, self.raw, pin=self.pin.encode("ascii"))
        self.refused(self.verify, self.raw, pin=self.pin.upper())
        alternate = signed_anchor.sign_checkpoint(
            self.checkpoint, public_key=other_public, sign=other_key.sign
        )
        self.refused(self.verify, alternate, pin=codec.sha(alternate))
        self.assertEqual(
            self.verify(alternate, pin=codec.sha(alternate), public=other_public), self.checkpoint
        )

    def test_signer_callback_is_called_once_with_exact_canonical_message(self):
        signer = Mock(side_effect=self.key.sign)
        raw = signed_anchor.sign_checkpoint(self.checkpoint, public_key=self.public, sign=signer)
        self.assertEqual(raw, self.raw)
        signer.assert_called_once_with(signed_anchor.DOMAIN + encode(self.parse()["body"]))

    def test_wrong_key_lengths_and_types_are_refused_before_signing(self):
        signer = Mock(side_effect=self.key.sign)
        for key in (b"", self.public[:-1], self.public + b"0", bytearray(self.public), "invalid"):
            with self.subTest(key_type=type(key)):
                self.refused(
                    signed_anchor.sign_checkpoint, self.checkpoint, public_key=key, sign=signer
                )
                self.refused(
                    signed_anchor.verify_checkpoint,
                    self.raw,
                    public_key=key,
                    expected_sha256=self.pin,
                )
        signer.assert_not_called()

    def test_signer_output_requires_exact_signature_and_key(self):
        second_key = Ed25519PrivateKey.generate()
        for signer in (
            lambda _: b"",
            lambda _: b"x" * 64,
            lambda message: bytearray(self.key.sign(message)),
            second_key.sign,
        ):
            with self.subTest(signer=signer):
                self.refused(
                    signed_anchor.sign_checkpoint,
                    self.checkpoint,
                    public_key=self.public,
                    sign=signer,
                )

    def test_signature_is_refused_under_another_domain_or_changed_key_fingerprint(self):
        envelope = self.parse()
        body = envelope["body"]
        envelope["signature"] = codec.b64(
            self.key.sign(b"pamolive.pam.trust-checkpoint.v1\0" + encode(body))
        )
        outside_domain = encode(envelope)
        self.refused(self.verify, outside_domain, pin=codec.sha(outside_domain))
        body["key_sha256"] = "f" * 64
        envelope["signature"] = codec.b64(self.key.sign(signed_anchor.DOMAIN + encode(body)))
        changed_key_fingerprint = encode(envelope)
        self.refused(self.verify, changed_key_fingerprint, pin=codec.sha(changed_key_fingerprint))

    def test_signature_covers_tenant_installation_and_every_checkpoint_field(self):
        for change in (
            {"context_id": uid(20)},
            {"organization_id": uid(21)},
            {"installation_id": uid(22)},
            {"slot_sha256": "f" * 64},
            {"head_sha256": "5" * 64},
            {"last_seq": 2},
        ):
            with self.subTest(change=change):
                envelope = self.parse()
                envelope["body"]["checkpoint"] = asdict(replace(self.checkpoint, **change))
                modified = encode(envelope)
                self.refused(self.verify, modified, pin=codec.sha(modified))

    def test_invalid_signature_encodings_and_lengths_are_refused(self):
        for invalid in ("==", "a", "", codec.b64(b"x" * 63), 12):
            with self.subTest(signature=invalid):
                envelope = self.parse()
                envelope["signature"] = invalid
                raw = encode(envelope)
                self.refused(self.verify, raw, pin=codec.sha(raw))

    def test_noncanonical_open_or_partial_documents_are_refused(self):
        envelope = self.parse()
        extra_root = encode({**envelope, "authority": "current"})
        envelope["body"]["checkpoint"]["unexpected"] = "synthetic"
        extra_field = encode(envelope)
        for malformed in (
            b"",
            self.raw[:-1],
            self.raw + b"\n",
            self.raw.replace(b'"schema":', b'"schema":"unknown","schema":', 1),
            extra_root,
            extra_field,
            b"x" * (signed_anchor.MAX_ANCHOR_BYTES + 1),
        ):
            with self.subTest(size=len(malformed)), self.assertRaises(codec.Error):
                self.verify(malformed, pin=codec.sha(malformed))

    def test_signed_body_still_requires_valid_checkpoint_fields(self):
        envelope = self.parse()
        body = envelope["body"]
        body["checkpoint"]["last_seq"] = 0
        envelope["signature"] = codec.b64(self.key.sign(signed_anchor.DOMAIN + encode(body)))
        raw = encode(envelope)
        with self.assertRaises(codec.Error):
            self.verify(raw, pin=codec.sha(raw))
