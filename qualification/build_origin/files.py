"""Small control buffers and opaque FD streams. No ZIP parser exists here."""

import hashlib
import os
import stat
import time
from pathlib import Path

from .contract import need

CHUNK = 65536


def identity(row):
    return tuple(
        getattr(row, key)
        for key in (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def regular(row, maximum):
    need(
        stat.S_ISREG(row.st_mode)
        and row.st_nlink == 1
        and 0 <= row.st_size <= maximum
        and not getattr(row, "st_file_attributes", 0) & 1024,
        "origin_regular",
    )


def hash_fd(fd, expected_size, until=None):
    """Read the held descriptor, capped even if another writer grows the file."""
    before = os.fstat(fd)
    regular(before, expected_size)
    need(before.st_size == expected_size, "origin_fd_size")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while count < expected_size:
        need(until is None or time.monotonic() < until, "origin_local_IO_deadline")
        block = os.read(fd, min(CHUNK, expected_size - count))
        need(bool(block), "origin_fd_short")
        count += len(block)
        digest.update(block)
    need(not os.read(fd, 1), "origin_fd_excess")
    need(identity(before) == identity(os.fstat(fd)), "origin_fd_changed")
    return digest.hexdigest()


def read_control(path, maximum):
    path = Path(path)
    before = path.lstat()
    regular(before, maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need(identity(before) == identity(opened), "origin_open_changed")
        raw = bytearray()
        while len(raw) < opened.st_size:
            block = os.read(fd, min(CHUNK, opened.st_size - len(raw)))
            need(bool(block), "origin_control_short")
            raw.extend(block)
        need(not os.read(fd, 1), "origin_control_excess")
        need(
            identity(opened) == identity(os.fstat(fd)) == identity(path.lstat()),
            "origin_control_changed",
        )
        return bytes(raw)
    finally:
        os.close(fd)


def exclusive(path, raw, maximum=1048576):
    need(type(raw) is bytes and len(raw) <= maximum, "origin_write_budget")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            need(n > 0, "origin_short_write")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def tool_pin(path, expected_sha=None, owner=None):
    """No resolve/PATH aliases. Fresh VM/system toolchain remains explicit TCB."""
    path = Path(path)
    need(path.is_absolute(), "origin_tool_path")
    for parent in reversed(path.parents):
        row = parent.lstat()
        need(
            stat.S_ISDIR(row.st_mode)
            and row.st_uid in {0, os.getuid()}
            and not row.st_mode & 0o022,
            "origin_tool_parent",
        )
    row = path.lstat()
    regular(row, 128 * 1024**2)
    need(
        row.st_uid == (os.getuid() if owner is None else owner)
        and not row.st_mode & 0o6022
        and row.st_mode & 0o111,
        "origin_tool_mode",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(identity(row) == identity(os.fstat(fd)), "origin_tool_open")
        need(os.read(fd, 4) == b"\x7fELF", "origin_tool_ELF")
        sha = hash_fd(fd, row.st_size)
        need(identity(row) == identity(path.lstat()), "origin_tool_path_changed")
    finally:
        os.close(fd)
    need(expected_sha is None or sha == expected_sha, "origin_tool_hash")
    return {"path": str(path), "sha256": sha, "identity": list(identity(row))}
