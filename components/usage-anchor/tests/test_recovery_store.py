"""Check custody ordering and retry invariants with a portable filesystem double."""

import unittest
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pamolive_usage_anchor import codec, recovery_manifest, recovery_store, signed_anchor
from test_audit_archive import audit_rows, checkpoint, event, uid


class CustodyFiles:
    def __init__(self):
        self.objects = {}
        self.trace = []
        self.fail_sync_at = None

    @contextmanager
    def lock(self, *, write):
        try:
            yield 100
        except OSError:
            raise codec.Error("unavailable", 503) from None

    def _read(self, _fd, name, *, maximum=signed_anchor.MAX_ANCHOR_BYTES):
        if name not in self.objects:
            raise FileNotFoundError
        value = self.objects[name]
        assert len(value) <= maximum
        return value

    def _retain(self, fd, name, raw, *, maximum=signed_anchor.MAX_ANCHOR_BYTES):
        assert name not in self.objects or self._read(fd, name, maximum=maximum) == raw
        self.objects[name] = raw
        self.trace.append(("retain", name))

    @contextmanager
    def _staged_file(self, _fd, raw):
        self.objects["staged"] = raw
        self.trace.append(("stage", "staged"))
        yield "staged"

    def replace(self, source, destination, *, src_dir_fd, dst_dir_fd):
        assert src_dir_fd == dst_dir_fd == 100
        self.objects[destination] = self.objects.pop(source)
        self.trace.append(("replace", destination))

    def fsync(self, fd):
        assert fd == 100
        self.trace.append(("sync", fd))
        if len(self.trace) == self.fail_sync_at:
            raise OSError


class RecoveryStoreTests(unittest.TestCase):
    def setUp(self):
        self.governor, self.first, self.second = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.point = checkpoint(audit_rows([event("activation_challenge", uid(10))]))
        self.scope = recovery_manifest.RecoveryScope.from_checkpoint(self.point)
        self.facts = {"governance_key": self.public(self.governor), "scope": self.scope}
        self.store = recovery_store.RecoveryStore("/custody/recovery", owner_uid=1000, **self.facts)
        files = self.files = CustodyFiles()
        filesystem = SimpleNamespace(
            scandir=lambda fd: nullcontext(iter(files.objects)),
            replace=files.replace,
            fsync=files.fsync,
        )
        self.enterContext(patch.object(self.store, "_files", files))
        self.enterContext(patch.object(self.store, "_locked", files.lock))
        self.enterContext(patch.object(recovery_store, "os", filesystem))
        self.raw, pin = self.sign(self.first)
        self.initial_pin = self.store.commission(
            self.manifest([(pin, 1)]), checkpoints={pin: self.raw}
        )
        self.checkpoint_pin = pin
        self.files.trace.clear()

    @staticmethod
    def public(key):
        return key.public_key().public_bytes_raw()

    def sign(self, key):
        raw = signed_anchor.sign_checkpoint(self.point, public_key=self.public(key), sign=key.sign)
        return raw, codec.sha(raw)

    def manifest(self, entries, successor=None):
        keys = [self.first] if successor is None else [self.first, successor]
        body = {
            "schema": recovery_manifest.SCHEMA,
            "scope": asdict(self.scope),
            "revision": len(keys),
            "previous_sha256": recovery_manifest.GENESIS if successor is None else self.initial_pin,
            "keys": [codec.b64(self.public(key)) for key in keys],
            "admissions": [
                {"checkpoint_sha256": digest, "generation": generation}
                for digest, generation in sorted(entries)
            ],
        }
        return recovery_manifest.sign_manifest(body, sign=self.governor.sign, **self.facts)

    def propose(self, signer):
        raw, digest = self.sign(signer)
        manifest = self.manifest([(self.checkpoint_pin, 1), (digest, 2)], successor=signer)
        return manifest, {digest: raw}

    def advance(self, manifest, checkpoints):
        return self.store.advance(manifest, expected=self.initial_pin, checkpoints=checkpoints)

    def test_syncs_verified_objects_before_atomic_pointer_replacement(self):
        manifest, checkpoints = self.propose(self.second)
        pin = self.advance(manifest, checkpoints)
        digest, = checkpoints
        self.assertEqual(self.files.trace, [
            ("retain", digest + ".checkpoint"), ("retain", pin + ".manifest"), ("sync", 100),
            ("stage", "staged"), ("replace", "current"), ("sync", 100),
        ])
        for selected in (self.checkpoint_pin, digest):
            restored = self.store.restore(expected=pin, checkpoint_sha256=selected)
            self.assertEqual(restored, self.point)

    def test_failed_first_sync_keeps_previous_pin_and_exact_retry_can_publish(self):
        manifest, checkpoints = self.propose(self.second)
        self.files.fail_sync_at = 3
        with self.assertRaises(codec.Error) as error:
            self.advance(manifest, checkpoints)
        self.assertEqual(error.exception.status, 503)
        self.assertEqual(self.store.restore(
            expected=self.initial_pin, checkpoint_sha256=self.checkpoint_pin
        ), self.point)
        self.assertEqual(self.advance(manifest, checkpoints), codec.sha(manifest))

    def test_lost_commit_confirmation_requires_exact_verified_retry(self):
        manifest, checkpoints = self.propose(self.second)
        self.files.fail_sync_at = 6
        with self.assertRaises(codec.Error) as error:
            self.advance(manifest, checkpoints)
        self.assertEqual(error.exception.status, 503)
        self.files.trace.clear()
        self.files.fail_sync_at = None
        alternative, new_checkpoints = self.propose(Ed25519PrivateKey.generate())
        with self.assertRaises(codec.Error) as error:
            self.advance(alternative, new_checkpoints)
        self.assertEqual(error.exception.status, 409)
        with self.assertRaises(codec.Error):
            self.advance(manifest, {})
        self.assertEqual(self.advance(manifest, checkpoints), codec.sha(manifest))
        self.assertEqual(self.files.trace[-1], ("sync", 100))
        self.assertNotIn(("replace", "current"), self.files.trace)

    def test_nonempty_store_cannot_be_recommissioned_after_pointer_loss(self):
        self.files.objects.pop("current")
        manifest = self.manifest([(self.checkpoint_pin, 1)])
        with self.assertRaises(codec.Error) as error:
            self.store.commission(manifest, checkpoints={self.checkpoint_pin: self.raw})
        self.assertEqual(error.exception.status, 409)
        with self.assertRaises(codec.Error):
            self.store.restore(expected=self.initial_pin, checkpoint_sha256=self.checkpoint_pin)

    def test_current_pin_and_checkpoint_bytes_are_checked_at_reopen(self):
        manifest, checkpoints = self.propose(self.second)
        with self.assertRaises(codec.Error):
            self.advance(manifest, {"invalid-digest": next(iter(checkpoints.values()))})
        self.assertEqual(self.files.trace, [])
        pin = self.advance(manifest, checkpoints)
        with self.assertRaises(codec.Error) as error:
            self.store.restore(expected=self.initial_pin, checkpoint_sha256=self.checkpoint_pin)
        self.assertEqual(error.exception.status, 409)
        self.files.objects[self.checkpoint_pin + ".checkpoint"] = self.raw + b"\n"
        with self.assertRaises(codec.Error) as error:
            self.store.restore(expected=pin, checkpoint_sha256=self.checkpoint_pin)
        self.assertEqual(error.exception.status, 403)
