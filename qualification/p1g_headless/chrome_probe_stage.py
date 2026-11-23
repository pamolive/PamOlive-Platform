"""Materialize the admitted Chrome payload in a caller-owned private workspace."""

import hashlib
import os
import stat
from contextlib import contextmanager
from pathlib import PurePosixPath

from qualification.p1g_headless import chrome_bundle as bundle

HELPER = "chrome-sandbox"
DIRECTORY_MODE = 0o700


def _destination(destination, until):
    bundle.budget(until)
    path = PurePosixPath(destination)
    bundle.need(
        path.is_absolute() and path.name and ".." not in path.parts,
        "probe_stage_destination",
    )
    uid = os.getuid()
    bundle.need(uid != 0 and os.geteuid() == uid, "probe_stage_nonroot")
    return path, uid


@contextmanager
def _open(path, flags, mode=0, *, dir_fd=None):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _directory(path, uid, until, *, dir_fd=None):
    bundle.budget(until)
    with _open(path, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd) as fd:
        info = os.fstat(fd)
        bundle.need(
            stat.S_ISDIR(info.st_mode) and info.st_uid == uid
            and stat.S_IMODE(info.st_mode) == DIRECTORY_MODE,
            "probe_stage_private_directory",
        )
        original = bundle.directory_key(info)
        yield fd
        bundle.budget(until)
        bundle.need(
            original == bundle.directory_key(os.fstat(fd))
            == bundle.directory_key(os.stat(path, dir_fd=dir_fd, follow_symlinks=False)),
            "probe_stage_directory_changed",
        )
        bundle.budget(until)


def _children(names, until):
    """Index the admitted tree once, excluding the helper from the output."""
    bundle.need(type(names) is dict and 1 <= len(names) <= bundle.MAX_FILES,
                "probe_stage_inventory")
    directories = {name: {} for name, row in names.items() if row["type"] == "directory"}
    bundle.need("." in directories, "probe_stage_inventory")
    total = 0
    for name, row in names.items():
        bundle.budget(until)
        bundle.need(bundle.member_name(name) == name and row["name"] == name,
                    "probe_stage_inventory")
        size = row["bytes"]
        bundle.need(type(size) is int and 0 <= size <= bundle.MAX_FILE,
                    "probe_stage_inventory")
        total += size
        bundle.need(total <= bundle.MAX_TOTAL, "probe_stage_inventory")
        if name not in {".", HELPER}:
            path = PurePosixPath(name)
            parent = str(path.parent)
            bundle.need(parent in directories, "probe_stage_inventory")
            directories[parent][path.name] = name
    return directories


def _members(archive, names, until):
    matched = {}
    for member in archive:
        bundle.budget(until)
        name = bundle.member_name(member.name)
        if name != bundle.PREFIX and not name.startswith(bundle.PREFIX + "/"):
            continue
        relative = "." if name == bundle.PREFIX else name[len(bundle.PREFIX) + 1 :]
        row = names.get(relative)
        bundle.need(
            row is not None and relative not in matched
            and ((row["type"] == "regular" and member.isfile())
                 or (row["type"] == "directory" and member.isdir()))
            and not member.linkname
            and (member.uid, member.gid, member.mode, member.size)
            == (row["uid"], row["gid"], row["mode"], row["bytes"]),
            "probe_stage_metadata",
        )
        matched[relative] = member
    bundle.need(matched.keys() == names.keys(), "probe_stage_members")
    return matched


def _mode(row):
    return 0o500 if row["mode"] & stat.S_IXUSR else 0o400


def _payload(read, row, until, *, fd=None):
    digest = hashlib.sha256()
    remaining = row["bytes"]
    while True:
        bundle.budget(until)
        chunk = read(min(bundle.MAX_TAR_READ, remaining + 1))
        bundle.budget(until)
        if not chunk:
            break
        remaining -= len(chunk)
        bundle.need(remaining >= 0, "probe_stage_payload")
        digest.update(chunk)
        if fd is not None:
            bundle.need(os.write(fd, chunk) == len(chunk), "probe_stage_short_write")
            bundle.budget(until)
    bundle.need(remaining == 0 and digest.hexdigest() == row["sha256"], "probe_stage_payload")


def _leaf(info, uid, mode, size):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == mode and info.st_size == size)


def _copy(source, row, parent, child, uid, until):
    bundle.budget(until)
    with _open(child, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent) as fd:
        before = os.fstat(fd)
        bundle.need(_leaf(before, uid, 0o600, 0), "probe_stage_new_file")
        _payload(source.read, row, until, fd=fd)
        os.fchmod(fd, _mode(row))
        final = os.fstat(fd)
        bundle.need(
            _leaf(final, uid, _mode(row), row["bytes"])
            and (before.st_dev, before.st_ino) == (final.st_dev, final.st_ino)
            and bundle.file_key(final) == bundle.file_key(os.stat(
                child, dir_fd=parent, follow_symlinks=False,
            )),
            "probe_stage_file_changed",
        )
        bundle.budget(until)


def _materialize_directory(archive, names, members, children, name, root, uid, until):
    for child, relative in children[name].items():
        bundle.budget(until)
        row = names[relative]
        if row["type"] == "directory":
            os.mkdir(child, DIRECTORY_MODE, dir_fd=root)
            with _directory(child, uid, until, dir_fd=root) as fd:
                _materialize_directory(archive, names, members, children, relative, fd, uid, until)
        else:
            with archive.extractfile(members[relative]) as source:
                _copy(source, row, root, child, uid, until)


def materialize(stream, names, destination, *, until):
    """Copy admitted TAR members into a fresh destination; the caller owns cleanup."""
    path, uid = _destination(destination, until)
    children = _children(names, until)
    with bundle.checked_tar(stream, until=until) as archive:
        members = _members(archive, names, until)
        if HELPER in names:
            bundle.need(names[HELPER]["type"] == "regular", "probe_stage_helper")
            with archive.extractfile(members[HELPER]) as source:
                _payload(source.read, names[HELPER], until)
        with _directory(path.parent, uid, until) as workspace:
            os.mkdir(path.name, DIRECTORY_MODE, dir_fd=workspace)
            with _directory(path.name, uid, until, dir_fd=workspace) as root:
                _materialize_directory(archive, names, members, children, ".", root, uid, until)


def _verify_file(row, parent, child, uid, until):
    before = os.stat(child, dir_fd=parent, follow_symlinks=False)
    bundle.need(_leaf(before, uid, _mode(row), row["bytes"]), "probe_stage_file")
    original = bundle.file_key(before)
    with _open(child, os.O_RDONLY | os.O_NONBLOCK, dir_fd=parent) as fd:
        bundle.need(bundle.file_key(os.fstat(fd)) == original, "probe_stage_file_changed")
        _payload(lambda count: os.read(fd, count), row, until)
        bundle.need(
            original == bundle.file_key(os.fstat(fd))
            == bundle.file_key(os.stat(child, dir_fd=parent, follow_symlinks=False)),
            "probe_stage_file_changed",
        )
        bundle.budget(until)


def _verify_directory(names, children, name, root, uid, until):
    before = os.fstat(root)
    remaining = children[name].copy()
    with os.scandir(root) as entries:
        for entry in entries:
            bundle.budget(until)
            relative = remaining.pop(entry.name, None)
            bundle.need(relative is not None, "probe_stage_fileset")
            row = names[relative]
            if row["type"] == "directory":
                with _directory(entry.name, uid, until, dir_fd=root) as fd:
                    _verify_directory(names, children, relative, fd, uid, until)
            else:
                _verify_file(row, root, entry.name, uid, until)
    after = os.fstat(root)
    bundle.need(
        not remaining and (before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_mtime_ns, after.st_ctime_ns),
        "probe_stage_fileset",
    )


def verify_tree(names, destination, *, until):
    """Reopen and verify the exclusive non-root tree after materialization."""
    path, uid = _destination(destination, until)
    children = _children(names, until)
    with (
        _directory(path.parent, uid, until) as workspace,
        _directory(path.name, uid, until, dir_fd=workspace) as root,
    ):
        _verify_directory(names, children, ".", root, uid, until)
