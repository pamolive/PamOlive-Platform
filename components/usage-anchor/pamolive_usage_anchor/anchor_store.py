"""Custodian-owned storage for independently pinned audit checkpoints."""

import os
import stat
import sys
from contextlib import contextmanager
from secrets import token_hex

from . import codec
from .audit_archive import Checkpoint
from .signed_anchor import MAX_ANCHOR_BYTES, verify_checkpoint


class AnchorStore:
    """Open a precommissioned Linux directory for each exact-digest operation."""

    def __init__(self, directory, *, owner_uid: int):
        path = os.fspath(directory)
        codec.need(type(path) is str and path.startswith("/"))
        parts = path[1:].split("/")
        codec.need(all(part and part not in (".", "..") and "\0" not in part for part in parts))
        codec.need(type(owner_uid) is int and 0 < owner_uid < 2**32 - 1)
        self._parts = tuple(parts)
        self._owner_uid = owner_uid

    @contextmanager
    def _directory(self):
        codec.need(
            sys.platform == "linux" and os.geteuid() == self._owner_uid, "unavailable", 503
        )
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open("/", flags)
            try:
                for part in self._parts:
                    current = os.fstat(fd)
                    codec.need(
                        current.st_uid in (0, self._owner_uid) and not current.st_mode & 0o022,
                        "unavailable",
                        503,
                    )
                    parent = fd
                    fd = os.open(part, flags, dir_fd=parent)
                    os.close(parent)
                leaf = os.fstat(fd)
                codec.need(
                    leaf.st_uid == self._owner_uid and stat.S_IMODE(leaf.st_mode) == 0o700,
                    "unavailable",
                    503,
                )
                yield fd
            finally:
                os.close(fd)
        except OSError:
            raise codec.Error("unavailable", 503) from None

    def _read(self, directory_fd, name, *, retained=None):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
        fd = os.open(name, flags, dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            codec.need(
                stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == self._owner_uid
                and 0 < info.st_size <= MAX_ANCHOR_BYTES,
                "unavailable",
                503,
            )
            data = bytearray()
            while len(data) <= MAX_ANCHOR_BYTES:
                block = os.read(fd, MAX_ANCHOR_BYTES + 1 - len(data))
                if not block:
                    break
                data.extend(block)
            codec.need(len(data) == info.st_size, "unavailable", 503)
            if retained is not None:
                codec.need(data == retained, "anchor_refused", 403)
                os.fsync(fd)
            return bytes(data)
        finally:
            os.close(fd)

    def load(self, *, public_key: bytes, expected_sha256: str) -> tuple[Checkpoint, bytes]:
        """Return a checkpoint only after verifying it against the caller's key and digest."""
        name = codec.digest(expected_sha256) + ".json"
        with self._directory() as directory_fd:
            raw = self._read(directory_fd, name)
        checkpoint = verify_checkpoint(raw, public_key=public_key, expected_sha256=expected_sha256)
        return checkpoint, raw

    def _publish(self, directory_fd, name, raw):
        temporary = ".pending-" + token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            try:
                os.fchmod(fd, 0o600)
                remaining = memoryview(raw)
                while remaining:
                    written = os.write(fd, remaining)
                    codec.need(written > 0, "unavailable", 503)
                    remaining = remaining[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(
                    temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                self._read(directory_fd, name, retained=raw)
        finally:
            os.unlink(temporary, dir_fd=directory_fd)

    def save(self, raw: bytes, *, public_key: bytes, expected_sha256: str) -> None:
        """Verify, publish without replacement, and flush the object's directory entry."""
        name = codec.digest(expected_sha256) + ".json"
        verify_checkpoint(raw, public_key=public_key, expected_sha256=expected_sha256)
        with self._directory() as directory_fd:
            try:
                self._read(directory_fd, name, retained=raw)
            except FileNotFoundError:
                self._publish(directory_fd, name, raw)
            os.fsync(directory_fd)
