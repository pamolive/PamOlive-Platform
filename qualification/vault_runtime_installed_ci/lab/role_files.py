"""Dedicated POSIX role mounts only; no CLI, service, archive or cleanup.

The trusted parent reserves and verifies Docker mounts before calling this
module. A reservation is (role, observed st_dev, observed st_ino), never a
manifest permission or an assertion that an arbitrary path is owned.
"""

import hashlib
import os
import stat
from contextlib import ExitStack

from .restore_inputs import RESTORE_CLIENT

MAX_FILE = 65536
MAX_TOTAL = 4 * 1024**2
MAX_OPERATIONS = 128
PUBLIC = (0o444, 0, 0)
KEY = (0o400, 1000, 1000)
PG_KEY = (0o600, 999, 999)
SHARED = {"slot.json": PUBLIC, "sql-ca.pem": PUBLIC, "tls-ca.pem": PUBLIC}
ROLE_FILES = {
    "pg": {
        "admin.password": PG_KEY,
        "pg-server.key": PG_KEY,
        "pg-server.crt": PUBLIC,
        "pg_hba.conf": PUBLIC,
    },
    "server": {
        **SHARED,
        "runtime-db.json": PUBLIC,
        "server.key": KEY,
        "server.crt": PUBLIC,
        "manifest.json": PUBLIC,
    },
    "client": {
        **SHARED,
        **{name + "-db.json": PUBLIC for name in ("runtime", "owner", "web", "worker")},
        "request.json": PUBLIC,
        **{
            name + suffix: attributes
            for name in ("client_a", "client_b", "unknown_ca", "expired", "future")
            for suffix, attributes in ((".key", KEY), (".crt", PUBLIC))
        },
        "client_a.der": PUBLIC,
        "client_b.der": PUBLIC,
        "manifest.json": PUBLIC,
    },
}


class RoleFilesRefused(ValueError):
    """Closed diagnostic; never includes material, paths or OS exception text."""


def need(value):
    if not value:
        raise RoleFilesRefused("vault_role_files_refused")


def validate(role, files, reservation, *, restore=False):
    """Validate the complete finite role table before any OS operation."""
    need(type(role) is str and role in ROLE_FILES)
    need(type(reservation) is tuple and len(reservation) == 3)
    need(reservation[0] == role)
    need(type(reservation[1]) is int and reservation[1] >= 0)
    need(type(reservation[2]) is int and reservation[2] > 0)
    need(type(restore) is bool and (not restore or role == "client"))
    expected = ROLE_FILES[role]
    if restore:
        expected = {**expected, **dict.fromkeys(RESTORE_CLIENT, PUBLIC)}
    need(type(files) is dict and len(files) == len(expected))
    need(set(files) == {"lab/" + name for name in expected})
    total, captured = 0, {}
    for filename, attributes in expected.items():
        row = files["lab/" + filename]
        need(type(row) is tuple and len(row) == 4)
        raw, mode, uid, gid = row
        need(type(raw) is bytes and 0 < len(raw) <= MAX_FILE)
        need(all(type(value) is int for value in (mode, uid, gid)))
        need((mode, uid, gid) == attributes)
        total += len(raw)
        need(total <= MAX_TOTAL)
        captured[filename] = row
    return captured


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def directory(info, *, mode=None):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0)
    need(not info.st_mode & 0o7022)
    if mode is not None:
        need(stat.S_IMODE(info.st_mode) == mode)


def names(o, fd, maximum):
    found = set()
    with o.scandir(fd) as entries:
        for entry in entries:
            need(type(entry.name) is str and entry.name not in found)
            found.add(entry.name)
            need(len(found) <= maximum)
    return found


def file_identity(info, attributes, size):
    mode, uid, gid = attributes
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    need((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid))
    need(info.st_size == size)
    return (*identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def write_file(o, root_fd, filename, row):
    raw, mode, uid, gid = row
    flags = o.O_RDWR | o.O_CREAT | o.O_EXCL | o.O_NOFOLLOW | o.O_CLOEXEC | o.O_NONBLOCK
    fd = o.open(filename, flags, 0o600, dir_fd=root_fd)
    try:
        before = o.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        need(before.st_uid == before.st_gid == 0 and before.st_size == 0)
        offset = 0
        for _ in range(MAX_OPERATIONS):
            if offset == len(raw):
                break
            count = o.write(fd, memoryview(raw)[offset:])
            need(type(count) is int and 0 < count <= len(raw) - offset)
            offset += count
        need(offset == len(raw))
        # The creator still owns the file here: CAP_FOWNER/DAC_OVERRIDE are unnecessary.
        o.fchmod(fd, mode)
        o.fchown(fd, uid, gid)
        o.fsync(fd)
        expected = file_identity(o.fstat(fd), (mode, uid, gid), len(raw))
        need(o.lseek(fd, 0, o.SEEK_SET) == 0)
        chunks, remaining = [], len(raw) + 1
        for _ in range(MAX_OPERATIONS):
            chunk = o.read(fd, min(8192, remaining))
            need(type(chunk) is bytes and len(chunk) <= min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
            need(remaining > 0)
        else:
            need(False)
        observed = b"".join(chunks)
        need(
            len(observed) == len(raw)
            and hashlib.sha256(observed).digest() == hashlib.sha256(raw).digest()
        )
        need(file_identity(o.fstat(fd), (mode, uid, gid), len(raw)) == expected)
        need(
            file_identity(
                o.stat(filename, dir_fd=root_fd, follow_symlinks=False), (mode, uid, gid), len(raw)
            )
            == expected
        )
        return expected
    finally:
        o.close(fd)


def stage_role(role, files, reservation, *, os_api=os, restore=False):
    """Stage one exact table into its already reserved /stage/<role> mount.

    os_api is a source-level actor seam, never an input/manifest option. Failure
    is not repaired: the parent must retire only its own dedicated allocation.
    """
    captured = validate(role, files, reservation, restore=restore)
    o = os_api
    try:
        need(o.name == "posix" and o.geteuid() == 0)
        flags = o.O_RDONLY | o.O_DIRECTORY | o.O_NOFOLLOW | o.O_CLOEXEC | o.O_NONBLOCK
        with ExitStack() as stack:
            slash = o.open("/", flags)
            stack.callback(o.close, slash)
            slash_info = o.fstat(slash)
            directory(slash_info)
            stage = o.open("stage", flags, dir_fd=slash)
            stack.callback(o.close, stage)
            stage_info = o.fstat(stage)
            directory(stage_info)
            before = o.stat(role, dir_fd=stage, follow_symlinks=False)
            directory(before, mode=0o700)
            need((before.st_dev, before.st_ino) == reservation[1:])
            root = o.open(role, flags, dir_fd=stage)
            stack.callback(o.close, root)
            need(identity(o.fstat(root)) == identity(before))

            def check_root(mode):
                need(identity(o.fstat(slash)) == identity(slash_info))
                need(identity(o.stat("/", follow_symlinks=False)) == identity(slash_info))
                need(identity(o.fstat(stage)) == identity(stage_info))
                need(
                    identity(o.stat("stage", dir_fd=slash, follow_symlinks=False))
                    == identity(stage_info)
                )
                opened = o.fstat(root)
                directory(opened, mode=mode)
                need((opened.st_dev, opened.st_ino) == reservation[1:])
                need(
                    identity(o.stat(role, dir_fd=stage, follow_symlinks=False)) == identity(opened)
                )

            check_root(0o700)
            need(not names(o, root, 0))
            observed = {}
            for filename, row in sorted(captured.items()):
                check_root(0o700)
                observed[filename] = write_file(o, root, filename, row)

            def check_files():
                need(names(o, root, len(captured)) == set(captured))
                for filename, row in captured.items():
                    raw, mode, uid, gid = row
                    need(
                        file_identity(
                            o.stat(filename, dir_fd=root, follow_symlinks=False),
                            (mode, uid, gid),
                            len(raw),
                        )
                        == observed[filename]
                    )

            check_files()
            check_root(0o700)
            o.fsync(root)
            o.fchmod(root, 0o555)
            o.fsync(root)
            check_root(0o555)
            check_files()
            check_root(0o555)
        return {
            "state": "ROLE_FILES_STAGED",
            "role": role,
            "files": len(captured),
            "authority": False,
        }
    except Exception:
        raise RoleFilesRefused("vault_role_files_refused") from None
