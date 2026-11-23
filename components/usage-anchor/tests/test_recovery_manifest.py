import unittest
from dataclasses import asdict, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pamolive_usage_anchor import codec
from pamolive_usage_anchor import recovery_manifest as recovery
from pamolive_usage_anchor.audit_archive import Checkpoint
from pamolive_usage_anchor.signed_anchor import sign_checkpoint


class RecoveryManifestTests(unittest.TestCase):
    def setUp(self):
        self.governor, self.first, self.second = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.point = Checkpoint(
            "00000000-0000-0000-0000-000000000001",
            "1" * 64,
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003",
            4,
            "2" * 64,
        )
        self.scope = recovery.RecoveryScope.from_checkpoint(self.point)
        self.first_raw = self.anchor(self.first, self.point)
        self.facts = {"governance_key": self.public(self.governor), "scope": self.scope}
        self.initial = self.manifest(self.body([self.first], [(self.first_raw, 1)]))
        self.initial_pin = recovery.verify_initial_manifest(
            self.initial, checkpoints={codec.sha(self.first_raw): self.first_raw}, **self.facts
        )
        self.second_raw = self.anchor(self.second, self.point)

    @staticmethod
    def public(private):
        return private.public_key().public_bytes_raw()

    def anchor(self, private, checkpoint):
        return sign_checkpoint(checkpoint, public_key=self.public(private), sign=private.sign)

    def body(self, keys, admissions, *, revision=1, previous=recovery.GENESIS):
        return {
            "schema": recovery.SCHEMA,
            "scope": asdict(self.scope),
            "revision": revision,
            "previous_sha256": previous,
            "keys": [codec.b64(self.public(key)) for key in keys],
            "admissions": [
                {"checkpoint_sha256": digest, "generation": generation}
                for digest, generation in sorted((codec.sha(raw), gen) for raw, gen in admissions)
            ],
        }

    def manifest(self, body):
        return recovery.sign_manifest(body, sign=self.governor.sign, **self.facts)

    def proposed(self, admissions, keys=None):
        if keys is None:
            keys = [self.first, self.second]
        return self.manifest(self.body(keys, admissions, revision=2, previous=self.initial_pin))

    def verify_next(self, proposed, *additions):
        return recovery.verify_manifest_successor(
            self.initial, proposed, current_sha256=self.initial_pin,
            checkpoints={codec.sha(raw): raw for raw in additions}, **self.facts,
        )

    def restore(self, manifest, raw, current_pin, *, checkpoint_pin=None):
        return recovery.restore_checkpoint(
            manifest, raw, current_sha256=current_pin,
            checkpoint_sha256=checkpoint_pin or codec.sha(raw), **self.facts,
        )

    def test_rotation_preserves_old_and_new_exact_checkpoints(self):
        next_manifest = self.proposed([(self.first_raw, 1), (self.second_raw, 2)])
        pin = self.verify_next(next_manifest, self.second_raw)
        self.assertEqual(self.restore(next_manifest, self.first_raw, pin), self.point)
        self.assertEqual(self.restore(next_manifest, self.second_raw, pin), self.point)

    def test_admission_without_rotation_later_uses_only_the_active_generation(self):
        first_rotation = self.proposed([(self.first_raw, 1), (self.second_raw, 2)])
        rotation_pin = self.verify_next(first_rotation, self.second_raw)
        later_point = replace(self.point, last_seq=5)
        later_raw = self.anchor(self.second, later_point)
        next_manifest = self.manifest(self.body(
            [self.first, self.second], [(self.first_raw, 1), (self.second_raw, 2), (later_raw, 2)],
            revision=3, previous=rotation_pin,
        ))
        next_pin = recovery.verify_manifest_successor(
            first_rotation, next_manifest, current_sha256=rotation_pin,
            checkpoints={codec.sha(later_raw): later_raw}, **self.facts,
        )
        self.assertEqual(self.restore(next_manifest, later_raw, next_pin), later_point)

    def test_restore_requires_current_manifest_and_selected_exact_checkpoint(self):
        next_manifest = self.proposed([(self.first_raw, 1), (self.second_raw, 2)])
        pin = self.verify_next(next_manifest, self.second_raw)
        with self.assertRaises(codec.Error):
            self.restore(self.initial, self.first_raw, pin)
        with self.assertRaises(codec.Error):
            self.restore(
                next_manifest, self.second_raw, pin, checkpoint_pin=codec.sha(self.first_raw)
            )

    def test_new_admission_cannot_use_a_retired_key(self):
        earlier = self.anchor(self.first, replace(self.point, last_seq=3))
        next_manifest = self.proposed([(self.first_raw, 1), (self.second_raw, 2)])
        with self.assertRaises(codec.Error):
            self.restore(next_manifest, earlier, self.verify_next(next_manifest, self.second_raw))
        with self.assertRaises(codec.Error):
            self.verify_next(self.proposed([(self.first_raw, 1), (earlier, 1)]), earlier)

    def test_cannot_replace_historical_admissions_or_keys(self):
        for entries, keys in (
            ([(self.second_raw, 2)], None),
            ([(self.first_raw, 2)], None),
            ([(self.first_raw, 1)], [self.second]),
        ):
            with self.subTest(entries=len(entries), keys=keys is not None):
                with self.assertRaises(codec.Error):
                    self.verify_next(self.proposed(entries, keys))

    def test_verify_checks_checkpoint_scope_against_the_independent_scope(self):
        foreign = replace(self.point, organization_id="00000000-0000-0000-0000-000000000005")
        raw = self.anchor(self.second, foreign)
        next_manifest = self.proposed([(self.first_raw, 1), (raw, 2)])
        with self.assertRaises(codec.Error):
            self.verify_next(next_manifest, raw)
        with self.assertRaises(codec.Error):
            self.restore(next_manifest, raw, codec.sha(next_manifest))
        with self.assertRaises(codec.Error):
            recovery.verify_initial_manifest(
                self.initial, checkpoints={codec.sha(self.first_raw): self.first_raw},
                governance_key=self.public(self.governor),
                scope=recovery.RecoveryScope.from_checkpoint(foreign),
            )

    def test_manifest_signature_cannot_use_a_checkpoint_key(self):
        with self.assertRaises(codec.Error):
            recovery.verify_initial_manifest(
                self.initial, checkpoints={codec.sha(self.first_raw): self.first_raw},
                governance_key=self.public(self.first), scope=self.scope,
            )
        body = self.body([self.governor], [(self.first_raw, 1)])
        with self.assertRaises(codec.Error):
            self.manifest(body)

    def test_refuses_discontinuous_or_noncanonical_manifests(self):
        for revision, parent in ((3, self.initial_pin), (2, "f" * 64)):
            candidate = self.manifest(self.body(
                [self.first, self.second], [(self.first_raw, 1), (self.second_raw, 2)],
                revision=revision, previous=parent,
            ))
            with self.assertRaises(codec.Error):
                self.verify_next(candidate)
        with self.assertRaises(codec.Error):
            self.verify_next(self.initial + b"\n")

    def test_admission_requires_the_exact_bytes_signed_by_the_active_key(self):
        next_manifest = self.proposed([(self.first_raw, 1), (self.second_raw, 2)])
        with self.assertRaises(codec.Error):
            self.verify_next(next_manifest)
        wrong_key = self.anchor(self.first, replace(self.point, last_seq=3))
        with self.assertRaises(codec.Error):
            self.verify_next(self.proposed([(self.first_raw, 1), (wrong_key, 2)]), wrong_key)
        with self.assertRaises(codec.Error):
            self.verify_next(self.proposed([(self.first_raw, 1)]))
