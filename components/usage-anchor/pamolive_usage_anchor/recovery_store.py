"""Durable local custody for one independently provisioned recovery scope."""

import os
import re
from contextlib import contextmanager

from . import codec, recovery_manifest
from .anchor_store import AnchorStore

CURRENT = "current"
PIN_BYTES = 65


def _snapshot(checkpoints):
    codec.need(type(checkpoints) is dict and len(checkpoints) <= recovery_manifest.MAX_ADMISSIONS)
    return {codec.digest(digest): raw for digest, raw in checkpoints.items()}


class RecoveryStore:
    """Use a private Linux directory on a local filesystem outside PITR custody."""

    def __init__(self, directory, *, owner_uid, governance_key, scope):
        codec.need(type(scope) is recovery_manifest.RecoveryScope)
        codec.need(type(governance_key) is bytes and len(governance_key) == 32)
        self._files = AnchorStore(directory, owner_uid=owner_uid)
        self._authority = {"governance_key": governance_key, "scope": scope}

    @contextmanager
    def _locked(self, *, write):
        with self._files._directory() as directory_fd:
            import fcntl

            mode = fcntl.LOCK_EX if write else fcntl.LOCK_SH
            fcntl.flock(directory_fd, mode | fcntl.LOCK_NB)
            yield directory_fd

    def _current_pin(self, fd):
        raw = self._files._read(fd, CURRENT, maximum=PIN_BYTES)
        codec.need(re.fullmatch(rb"[0-9a-f]{64}\n", raw), "unavailable", 503)
        return raw[:-1].decode("ascii")

    def _manifest(self, fd, pin):
        return self._files._read(fd, pin + ".manifest", maximum=recovery_manifest.MAX_BYTES)

    def _retain(self, fd, pin, manifest, checkpoints):
        for digest, raw in checkpoints.items():
            self._files._retain(fd, digest + ".checkpoint", raw)
        self._files._retain(fd, pin + ".manifest", manifest, maximum=recovery_manifest.MAX_BYTES)
        os.fsync(fd)

    def commission(self, manifest, *, checkpoints):
        """Publish a verified initial revision into an empty authorized directory."""
        checkpoints = _snapshot(checkpoints)
        pin = recovery_manifest.verify_initial_manifest(
            manifest, checkpoints=checkpoints, **self._authority
        )
        with self._locked(write=True) as fd:
            with os.scandir(fd) as entries:
                codec.need(next(entries, None) is None, "idempotency_conflict", 409)
            self._retain(fd, pin, manifest, checkpoints)
            self._files._retain(fd, CURRENT, (pin + "\n").encode("ascii"), maximum=PIN_BYTES)
            os.fsync(fd)
        return pin

    def advance(self, manifest, *, expected, checkpoints):
        """Compare and publish while holding the exclusive lock on the directory."""
        expected = codec.digest(expected)
        checkpoints = _snapshot(checkpoints)
        codec.need(type(manifest) is bytes and 0 < len(manifest) <= recovery_manifest.MAX_BYTES)
        proposed = codec.sha(manifest)
        with self._locked(write=True) as fd:
            current = self._current_pin(fd)
            codec.need(current in (expected, proposed), "idempotency_conflict", 409)
            pin = recovery_manifest.verify_manifest_successor(
                self._manifest(fd, expected), manifest,
                current_sha256=expected, checkpoints=checkpoints,
                **self._authority,
            )
            self._retain(fd, pin, manifest, checkpoints)
            if current != pin:
                with self._files._staged_file(fd, (pin + "\n").encode("ascii")) as staged:
                    os.replace(staged, CURRENT, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
        return pin

    def restore(self, *, expected, checkpoint_sha256):
        """Read the exact admitted checkpoint under the caller's independently retained pins."""
        expected = codec.digest(expected)
        checkpoint_sha256 = codec.digest(checkpoint_sha256)
        with self._locked(write=False) as fd:
            codec.need(self._current_pin(fd) == expected, "idempotency_conflict", 409)
            manifest = self._manifest(fd, expected)
            document = self._files._read(fd, checkpoint_sha256 + ".checkpoint")
            return recovery_manifest.restore_checkpoint(
                manifest, document, current_sha256=expected, checkpoint_sha256=checkpoint_sha256,
                **self._authority,
            )
