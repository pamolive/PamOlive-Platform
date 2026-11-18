"""Authenticated TEST bundle DATA and exclusive staging; never a package install.

Only the reviewed Linux bootstrap calls stage(). Pure tests use in-memory TARs
and OS doubles. A pinned, explicitly commissioned profile must precede staging.
"""

import bisect
import hashlib
import json
import math
import os
import re
import stat
import tarfile
import time
from pathlib import Path, PurePosixPath

PROFILE_NAME = "chrome-bundle-profile.json"
PROFILE_SHA = "0c910d6ec74090281c1275e64b70fd498049cfc16d5547a0daa01263771eb6ee"
SCHEMA = "pamolive.chrome-test-bundle/3"
TREE_SCHEMA = "pamolive.chrome-bundle-inventory/1"
PROFILE_SCHEMA = "pamolive.chrome-test-bundle-profile/1"
PREFIX = "opt/google/chrome"
MAX_FILES = 20000
MAX_TOTAL = 1024**3
MAX_FILE = 512 * 1024**2
MAX_JSON = 4 * 1024**2
MAX_TAR_BYTES = MAX_TOTAL
MAX_TAR_HEADERS = 20000
MAX_TAR_READ = 65536
TAR_BLOCK = 512
TAR_TYPES = frozenset(
    (
        tarfile.REGTYPE,
        tarfile.AREGTYPE,
        tarfile.DIRTYPE,
        tarfile.SYMTYPE,
        tarfile.LNKTYPE,
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.FIFOTYPE,
    )
)
TAR_EXTENSIONS = frozenset(
    (
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.GNUTYPE_SPARSE,
    )
)


def need(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def unique(rows):
    result = {}
    for key, value in rows:
        need(key not in result, "bundle_duplicate_JSON")
        result[key] = value
    return result


def json_bytes(raw):
    need(type(raw) is bytes and len(raw) <= MAX_JSON, "bundle_JSON_budget")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: fail())


def fail():
    raise ValueError("bundle_nonfinite_JSON")


def sha_field(value):
    return type(value) is str and re.fullmatch("[a-f0-9]{64}", value) is not None


def budget(until, clock=time.monotonic):
    need(
        type(until) in (int, float) and math.isfinite(until) and clock() < until, "bundle_deadline"
    )


def run_name(env):
    values = [env.get(k) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    need(all(type(v) is str and re.fullmatch("[1-9][0-9]{0,19}", v) for v in values), "bundle_run")
    return "-".join(values)


def root_path(env):
    return Path("/usr/lib") / ("pamolive-p1g-chrome-" + run_name(env))


def member_name(name):
    need(type(name) is str and len(name) <= 512, "bundle_path")
    value = name.removeprefix("./").rstrip("/")
    if value in ("", ".") and name in (".", "./"):
        return "."
    need(
        re.fullmatch(r"[A-Za-z0-9_+@.,=/-]+", value) is not None
        and not value.startswith("/")
        and "//" not in value
        and not any(part in {"", ".", ".."} for part in value.split("/"))
        and str(PurePosixPath(value)) == value,
        "bundle_path",
    )
    return value


class TarReader:
    """Reject oversized parser requests before calling the underlying stream.

    Preflight seals all physical metadata blocks. A second parser cannot consume
    a replaced PAX/GNU header after validation, even if the stream changes.
    """

    def __init__(self, stream, until, clock):
        self.stream, self.until, self.clock = stream, until, clock
        self.headers, self.offsets, self.zero_start = {}, [], None
        self.sealed = False
        budget(until, clock)
        end = stream.seek(0, 2)
        budget(until, clock)
        need(
            type(end) is int and TAR_BLOCK <= end <= MAX_TAR_BYTES and end % TAR_BLOCK == 0,
            "bundle_tar_physical_budget",
        )
        self.size = end
        self.position = end
        self.seek(0)

    def tell(self):
        budget(self.until, self.clock)
        return self.position

    def seek(self, offset, whence=0):
        need(type(offset) is int and type(whence) is int and whence in (0, 1, 2), "bundle_tar_seek")
        target = offset + (self.position if whence == 1 else self.size if whence == 2 else 0)
        need(0 <= target <= self.size, "bundle_tar_seek")
        budget(self.until, self.clock)
        result = self.stream.seek(target, 0)
        budget(self.until, self.clock)
        need(type(result) is int and result == target, "bundle_tar_seek")
        self.position = target
        return target

    def read(self, count=-1):
        # Never clamp: a malicious/unsupported request must fail before the raw
        # stream is asked to allocate or read it.
        need(type(count) is int and 0 <= count <= MAX_TAR_READ, "bundle_tar_read_budget")
        budget(self.until, self.clock)
        start = self.position
        raw = self.stream.read(count)
        budget(self.until, self.clock)
        need(
            type(raw) is bytes and len(raw) <= min(count, self.size - start),
            "bundle_tar_read_shape",
        )
        if self.sealed and raw:
            end = start + len(raw)
            index = max(0, bisect.bisect_right(self.offsets, start) - 1)
            while index < len(self.offsets):
                offset = self.offsets[index]
                if offset >= end:
                    break
                left, right = max(start, offset), min(end, offset + TAR_BLOCK)
                if left < right:
                    need(
                        raw[left - start : right - start]
                        == self.headers[offset][left - offset : right - offset],
                        "bundle_tar_header_changed",
                    )
                index += 1
            if self.zero_start is not None and end > self.zero_start:
                tail = raw[max(0, self.zero_start - start) :]
                need(not any(tail), "bundle_tar_trailing_data")
        self.position += len(raw)
        return raw

    def exact(self, count):
        need(type(count) is int and 0 <= count <= MAX_TAR_READ, "bundle_tar_read_budget")
        raw = b""
        while len(raw) < count:
            block = self.read(count - len(raw))
            need(bool(block), "bundle_tar_truncated")
            raw += block
        return raw


def preflight_tar(reader):
    """Physical 512-byte walk before TarFile can process any extension.

    PAX/global/GNU longname/longlink/sparse are explicitly unsupported. Ordinary
    USTAR prefixes remain supported. No internal extension parser is invoked.
    """
    reader.seek(0)
    count, total, seen = 0, 0, set()
    while reader.tell() < reader.size:
        offset = reader.tell()
        block = reader.exact(TAR_BLOCK)
        reader.headers[offset] = block
        if block == b"\0" * TAR_BLOCK:
            second_offset = reader.tell()
            second = reader.exact(TAR_BLOCK)
            need(second == b"\0" * TAR_BLOCK, "bundle_tar_terminator")
            reader.headers[second_offset] = second
            reader.zero_start = offset
            while reader.tell() < reader.size:
                tail = reader.exact(min(MAX_TAR_READ, reader.size - reader.tell()))
                need(not any(tail), "bundle_tar_trailing_data")
            break
        count += 1
        need(count <= MAX_TAR_HEADERS, "bundle_tar_header_budget")
        kind = block[156:157]
        if kind in TAR_EXTENSIONS:
            label = {
                tarfile.XHDTYPE: "PAX",
                tarfile.XGLTYPE: "GLOBAL",
                tarfile.GNUTYPE_LONGNAME: "GNU_LONGNAME",
                tarfile.GNUTYPE_LONGLINK: "GNU_LONGLINK",
                tarfile.GNUTYPE_SPARSE: "GNU_SPARSE",
            }[kind]
            raise ValueError("bundle_tar_extensions_refused_" + label)
        need(kind in TAR_TYPES, "bundle_tar_type")
        try:
            member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        except (tarfile.HeaderError, UnicodeError, ValueError) as error:
            raise ValueError("bundle_tar_header") from error
        name = member_name(member.name)
        need(not member.name.endswith("/") or member.isdir(), "bundle_tar_path_type")
        need(name not in seen, "bundle_tar_collision")
        seen.add(name)
        need(type(member.size) is int and 0 <= member.size <= MAX_FILE, "bundle_tar_member_budget")
        need(
            type(member.uid) is int
            and type(member.gid) is int
            and 0 <= member.uid <= 2**32 - 1
            and 0 <= member.gid <= 2**32 - 1,
            "bundle_tar_header",
        )
        need(member.isfile() or member.size == 0, "bundle_tar_nonfile_payload")
        need(not member.sparse and not member.pax_headers, "bundle_tar_extensions_refused")
        total += member.size
        need(total <= MAX_TOTAL, "bundle_tar_physical_budget")
        padded = ((member.size + TAR_BLOCK - 1) // TAR_BLOCK) * TAR_BLOCK
        need(reader.tell() + padded <= reader.size - 2 * TAR_BLOCK, "bundle_tar_truncated")
        reader.seek(member.size, 1)
        padding = reader.exact(padded - member.size)
        need(not any(padding), "bundle_tar_padding")
    need(reader.zero_start is not None, "bundle_tar_terminator")
    reader.offsets = sorted(reader.headers)
    reader.sealed = True
    reader.seek(0)
    return {
        "physical_headers": count,
        "physical_bytes": reader.size,
        "declared_payload_bytes": total,
        "extensions_accepted": 0,
    }


def checked_tar(stream, *, until, clock=time.monotonic):
    """Context manager providing only the preflighted bounded TAR reader."""
    from contextlib import contextmanager

    reader = TarReader(stream, until, clock)
    preflight_tar(reader)

    @contextmanager
    def opened():
        reader.seek(0)
        with tarfile.open(fileobj=reader, mode="r:", encoding="utf-8", errors="strict") as archive:
            yield archive
        budget(until, clock)

    return opened()


def inventory(stream, package_sha, *, until, clock=time.monotonic):
    """Read authenticated payload TAR as DATA; no extraction or admission."""
    need(sha_field(package_sha), "bundle_package")
    budget(until, clock)
    seen, entries, declared, count = set(), [], 0, 0
    with checked_tar(stream, until=until, clock=clock) as archive:
        for member in archive:
            budget(until, clock)
            name = member_name(member.name)
            count += 1
            declared += member.size
            need(
                name not in seen
                and count <= MAX_FILES
                and 0 <= member.size <= MAX_FILE
                and declared <= MAX_TOTAL
                and not member.sparse,
                "bundle_archive_budget_or_collision",
            )
            seen.add(name)
            if name != PREFIX and not name.startswith(PREFIX + "/"):
                continue
            relative = "." if name == PREFIX else name[len(PREFIX) + 1 :]
            kind = (
                "regular"
                if member.isfile()
                else "directory"
                if member.isdir()
                else "symlink"
                if member.issym()
                else "hardlink"
                if member.islnk()
                else "unsupported"
            )
            row = {
                "name": relative,
                "type": kind,
                "uid": member.uid,
                "gid": member.gid,
                "mode": member.mode,
                "bytes": member.size,
            }
            if member.isfile():
                h, length = hashlib.sha256(), 0
                with archive.extractfile(member) as source:
                    while chunk := source.read(65536):
                        budget(until, clock)
                        length += len(chunk)
                        need(length <= member.size, "bundle_payload_size")
                        h.update(chunk)
                need(length == member.size, "bundle_payload_size")
                row["sha256"] = h.hexdigest()
            elif member.issym() or member.islnk():
                need(
                    type(member.linkname) is str and len(member.linkname) <= 512,
                    "bundle_link_budget",
                )
                # DATA only; links are deliberately not supported by staging v1.
                need(
                    not any(ord(c) < 32 or ord(c) > 126 for c in member.linkname),
                    "bundle_link_budget",
                )
                row["link"] = member.linkname
            entries.append(row)
    entries.sort(key=lambda row: row["name"])
    need(entries and len(entries) <= MAX_FILES, "bundle_missing")
    body = canonical(entries)
    need(len(body) <= MAX_JSON, "bundle_JSON_budget")
    budget(until, clock)
    return {
        "schema": TREE_SCHEMA,
        "package_sha256": package_sha,
        "tree_sha256": digest(body),
        "entries": entries,
        "admitted": False,
        "operational_GO": False,
    }


def admit(tree, profile_raw, profile_sha):
    """The source-pinned profile is an external decision, never observed DATA."""
    need(sha_field(profile_sha) and digest(profile_raw) == profile_sha, "bundle_profile_pin")
    profile = json_bytes(profile_raw)
    need(
        type(profile) is dict
        and set(profile)
        == {"schema", "commissioned", "package_sha256", "tree_sha256", "privileged_roles"}
        and profile["schema"] == PROFILE_SCHEMA
        and profile["commissioned"] is True,
        "bundle_profile_uncommissioned",
    )
    return _admitted_tree(tree, profile)


def _admitted_tree(tree, profile):
    """Shared exact-tree validation; authority is checked by each typed caller."""
    need(
        type(tree) is dict
        and set(tree)
        == {"schema", "package_sha256", "tree_sha256", "entries", "admitted", "operational_GO"}
        and tree["schema"] == TREE_SCHEMA
        and tree["admitted"] is tree["operational_GO"] is False
        and sha_field(tree["package_sha256"])
        and sha_field(tree["tree_sha256"])
        and tree["package_sha256"] == profile["package_sha256"]
        and tree["tree_sha256"] == profile["tree_sha256"] == digest(canonical(tree["entries"])),
        "bundle_profile_tree",
    )
    entries = tree["entries"]
    need(type(entries) is list and 1 <= len(entries) <= MAX_FILES, "bundle_tree_budget")
    need(type(profile["privileged_roles"]) is dict, "bundle_privileged_roles")
    need(set(profile["privileged_roles"]) <= {"chrome-sandbox"}, "bundle_privileged_roles")
    names, total, roles = {}, 0, {}
    for row in entries:
        need(type(row) is dict and type(row.get("name")) is str, "bundle_entry")
        name = row["name"]
        need((name == "." or member_name(name) == name) and name not in names, "bundle_entry_path")
        kind = row.get("type")
        need(kind in {"regular", "directory"}, "bundle_unsupported_entry")
        expected = {"name", "type", "uid", "gid", "mode", "bytes"} | (
            {"sha256"} if kind == "regular" else set()
        )
        need(
            set(row) == expected
            and row["uid"] == row["gid"] == 0
            and all(type(row[k]) is int for k in ("uid", "gid", "mode", "bytes")),
            "bundle_entry",
        )
        total += row["bytes"]
        need(0 <= row["bytes"] <= MAX_FILE and total <= MAX_TOTAL, "bundle_tree_budget")
        if kind == "directory":
            need(row["mode"] == 0o755 and row["bytes"] == 0, "bundle_directory_mode")
        else:
            need(name != "." and sha_field(row["sha256"]), "bundle_entry")
            if row["mode"] == 0o4755:
                need(name == "chrome-sandbox", "bundle_privileged_roles")
                roles[name] = {
                    "role": "setuid-sandbox-helper",
                    "sha256": row["sha256"],
                    "mode": 0o4755,
                }
            else:
                need(row["mode"] in {0o444, 0o555, 0o644, 0o755}, "bundle_file_mode")
        names[name] = row
    need(profile["privileged_roles"] == roles, "bundle_privileged_roles")
    need(
        names.get(".")
        == {"name": ".", "type": "directory", "uid": 0, "gid": 0, "mode": 0o755, "bytes": 0},
        "bundle_root_entry",
    )
    for name in names:
        if name == ".":
            continue
        for parent in PurePosixPath(name).parents:
            need(
                str(parent) in names and names[str(parent)]["type"] == "directory",
                "bundle_parent_entry",
            )
    need(
        "chrome" in names
        and names["chrome"]["type"] == "regular"
        and names["chrome"]["mode"] == 0o755
        and names["chrome"]["bytes"] > 4,
        "bundle_target",
    )
    return names


def directory_key(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid)


def file_key(row):
    return directory_key(row) + (row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def _close_owned(ops, fds):
    """Attempt every acquired FD once; any close uncertainty remains a refusal."""
    unknown = False
    for fd in reversed(fds):
        try:
            ops.close(fd)
        except BaseException:
            unknown = True
    need(not unknown, "bundle_FD_close_unknown")


def root_parents(path, ops=os):
    """Open the complete fixed parent chain through held directory FD anchors."""
    need(path == Path("/usr/lib"), "bundle_parent_path")
    fds, parent = [], None
    try:
        for part in ("/", "usr", "lib"):
            row = ops.stat(part, dir_fd=parent, follow_symlinks=False)
            need(
                stat.S_ISDIR(row.st_mode)
                and row.st_uid == row.st_gid == 0
                and not row.st_mode & 0o022,
                "bundle_root_parent",
            )
            fd = ops.open(
                part, ops.O_RDONLY | ops.O_DIRECTORY | ops.O_NOFOLLOW | ops.O_CLOEXEC, dir_fd=parent
            )
            fds.append(fd)
            need(
                directory_key(ops.fstat(fd))
                == directory_key(row)
                == directory_key(ops.stat(part, dir_fd=parent, follow_symlinks=False)),
                "bundle_parent_race",
            )
            parent = fd
        yield parent
    finally:
        _close_owned(ops, fds)


def open_child(parent, name, ops=os):
    row = ops.stat(name, dir_fd=parent, follow_symlinks=False)
    need(
        stat.S_ISDIR(row.st_mode) and row.st_uid == row.st_gid == 0 and not row.st_mode & 0o022,
        "bundle_directory",
    )
    fd = ops.open(
        name, ops.O_RDONLY | ops.O_DIRECTORY | ops.O_NOFOLLOW | ops.O_CLOEXEC, dir_fd=parent
    )
    try:
        need(
            directory_key(ops.fstat(fd))
            == directory_key(row)
            == directory_key(ops.stat(name, dir_fd=parent, follow_symlinks=False)),
            "bundle_directory_race",
        )
    except BaseException:
        ops.close(fd)
        raise
    return fd


def walk_parent(root_fd, name, ops=os):
    current, fds = root_fd, []
    try:
        for part in PurePosixPath(name).parts[:-1]:
            current = open_child(current, part, ops)
            fds.append(current)
        yield current
    finally:
        _close_owned(ops, fds)


def fresh_file(parent, name, body, mode, *, until, ops=os, clock=time.monotonic, _phase_a=None):
    budget(until, clock)
    fd = ops.open(
        name,
        ops.O_WRONLY | ops.O_CREAT | ops.O_EXCL | ops.O_NOFOLLOW | ops.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    try:
        row = ops.fstat(fd)
        need(
            stat.S_ISREG(row.st_mode)
            and row.st_uid == row.st_gid == 0
            and row.st_nlink == 1
            and row.st_size == 0,
            "bundle_new_file",
        )
        if _phase_a is not None:
            _phase_a.file(name, row, {"bytes": len(body), "sha256": digest(body), "mode": mode})
        budget(until, clock)
        need(ops.write(fd, body) == len(body), "bundle_short_write")
        if _phase_a is not None:
            budget(until, clock)
        ops.fsync(fd)
        budget(until, clock)
        ops.fchmod(fd, mode)
        need(
            file_key(ops.fstat(fd))
            == file_key(ops.stat(name, dir_fd=parent, follow_symlinks=False)),
            "bundle_new_file_race",
        )
        if _phase_a is not None:
            _phase_a.complete_file(name, ops.fstat(fd))
    finally:
        ops.close(fd)


def stage(
    stream, tree, profile_raw, profile_sha, env, bindings, *, until, ops=os, clock=time.monotonic,
    _phase_a=None,
):
    """Linux Root only; existing prefix is never adopted or repaired."""
    from contextlib import contextmanager

    need(ops.getuid() == ops.geteuid() == ops.getgid() == ops.getegid() == 0, "bundle_root_only")
    if _phase_a is None:
        names = admit(tree, profile_raw, profile_sha)
    else:
        _phase_a.validate(env, bindings)
        names = _phase_a.admit(tree, profile_raw, profile_sha)
    budget(until, clock)
    archive_context = checked_tar(stream, until=until, clock=clock)
    path = root_path(env)
    need(
        type(bindings) is dict
        and set(bindings)
        == {
            "revision",
            "pins_manifest_sha256",
            "context_receipt_sha256",
            "package_version",
            "signature",
            "key_scope",
            "root_interpreter",
        },
        "bundle_bindings",
    )
    need(
        type(bindings["revision"]) is str
        and re.fullmatch("[a-f0-9]{40}", bindings["revision"])
        and sha_field(bindings["pins_manifest_sha256"])
        and sha_field(bindings["context_receipt_sha256"]),
        "bundle_bindings",
    )
    root_fd = None
    with contextmanager(root_parents)(path.parent, ops) as parent:
        budget(until, clock)
        ops.mkdir(path.name, 0o700, dir_fd=parent)  # EXCLUSIVE: no exist_ok and no adoption.
        if _phase_a is not None:
            _phase_a.claimed(parent, path.name)
        root_fd = open_child(parent, path.name, ops)
        root_before = directory_key(ops.fstat(root_fd))
        try:
            if _phase_a is not None:
                _phase_a.bind(parent, root_fd, path.name)
            for name, row in sorted(
                names.items(), key=lambda item: (len(PurePosixPath(item[0]).parts), item[0])
            ):
                budget(until, clock)
                if name == "." or row["type"] != "directory":
                    continue
                with contextmanager(walk_parent)(root_fd, name, ops) as location:
                    budget(until, clock)
                    ops.mkdir(PurePosixPath(name).name, 0o700, dir_fd=location)
                    child = open_child(location, PurePosixPath(name).name, ops)
                    try:
                        if _phase_a is not None:
                            _phase_a.directory(name, ops.fstat(child))
                        budget(until, clock)
                        ops.fchmod(child, 0o755)  # Only this newly-created owned object.
                        if _phase_a is not None:
                            _phase_a.directory(name, ops.fstat(child))
                    finally:
                        ops.close(child)
            copied = set()
            with archive_context as archive:
                for member in archive:
                    budget(until, clock)
                    name = member_name(member.name)
                    if not name.startswith(PREFIX + "/"):
                        continue
                    relative = name[len(PREFIX) + 1 :]
                    if relative not in names or names[relative]["type"] != "regular":
                        continue
                    row = names[relative]
                    need(
                        member.isfile()
                        and not member.sparse
                        and relative not in copied
                        and member.size == row["bytes"]
                        and member.mode == row["mode"]
                        and member.uid == member.gid == 0,
                        "bundle_payload_changed",
                    )
                    with contextmanager(walk_parent)(root_fd, relative, ops) as location:
                        budget(until, clock)
                        fd = ops.open(
                            PurePosixPath(relative).name,
                            ops.O_WRONLY
                            | ops.O_CREAT
                            | ops.O_EXCL
                            | ops.O_NOFOLLOW
                            | ops.O_CLOEXEC,
                            0o600,
                            dir_fd=location,
                        )
                        try:
                            first = ops.fstat(fd)
                            need(
                                stat.S_ISREG(first.st_mode)
                                and first.st_uid == first.st_gid == 0
                                and first.st_nlink == 1
                                and first.st_size == 0,
                                "bundle_new_file",
                            )
                            if _phase_a is not None:
                                _phase_a.file(relative, first, row)
                            h, length, magic = hashlib.sha256(), 0, b""
                            with archive.extractfile(member) as source:
                                while chunk := source.read(65536):
                                    budget(until, clock)
                                    length += len(chunk)
                                    need(
                                        length <= row["bytes"]
                                        and ops.write(fd, chunk) == len(chunk),
                                        "bundle_short_write",
                                    )
                                    magic = (magic + chunk)[:4]
                                    h.update(chunk)
                            need(
                                length == row["bytes"] and h.hexdigest() == row["sha256"],
                                "bundle_payload_changed",
                            )
                            need(
                                relative not in {"chrome", "chrome-sandbox"} or magic == b"\x7fELF",
                                "bundle_role_ELF",
                            )
                            ops.fsync(fd)
                            budget(until, clock)
                            ops.fchmod(fd, row["mode"])
                            named = ops.stat(
                                PurePosixPath(relative).name, dir_fd=location, follow_symlinks=False
                            )
                            need(
                                file_key(ops.fstat(fd)) == file_key(named) and named.st_nlink == 1,
                                "bundle_new_file_race",
                            )
                            if _phase_a is not None:
                                _phase_a.complete_file(relative, named)
                        finally:
                            ops.close(fd)
                    copied.add(relative)
            need(
                copied == {name for name, row in names.items() if row["type"] == "regular"},
                "bundle_missing_file",
            )
            budget(until, clock)
            manifest = canonical(tree)
            receipt = {
                "schema": SCHEMA if _phase_a is None else _phase_a.STAGED_SCHEMA,
                "state": (
                    "STAGED_AUTHENTICATED_TEST_BUNDLE"
                    if _phase_a is None else "PRIVATE_STAGE_CLEANUP_ONLY"
                ),
                **bindings,
                "run": env["GITHUB_RUN_ID"],
                "attempt": env["GITHUB_RUN_ATTEMPT"],
                "package_sha256": tree["package_sha256"],
                "profile_sha256": profile_sha,
                "manifest_sha256": digest(manifest),
                "tree_sha256": tree["tree_sha256"],
                "prefix": str(path),
                "target": names["chrome"],
                "browser_executed": False,
                "all_OS_descendants_released": False,
                "operational_GO": False,
            }
            fresh_file(
                root_fd, ".bundle-manifest.json", manifest, 0o444,
                until=until, ops=ops, clock=clock,
                _phase_a=_phase_a,
            )
            fresh_file(
                root_fd,
                ".bundle-receipt.json",
                canonical(receipt),
                0o444,
                until=until,
                ops=ops,
                clock=clock,
                _phase_a=_phase_a,
            )
            need(
                directory_key(ops.fstat(root_fd))
                == root_before
                == directory_key(ops.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                "bundle_root_race",
            )
            budget(until, clock)
            ops.fsync(root_fd)
            budget(until, clock)
            if _phase_a is None:
                # Publish only after all bytes and receipts are complete.
                ops.fchmod(root_fd, 0o755)
            need(
                directory_key(ops.fstat(root_fd))
                == directory_key(ops.stat(path.name, dir_fd=parent, follow_symlinks=False))
                and stat.S_IMODE(ops.fstat(root_fd).st_mode)
                == (0o755 if _phase_a is None else 0o700),
                "bundle_root_race",
            )
            if _phase_a is not None:
                verify(
                    env, bindings, profile_raw, profile_sha, until=until,
                    ops=ops, clock=clock, _phase_a=_phase_a,
                )
                _phase_a.stage_verified(receipt)
        finally:
            try:
                if _phase_a is not None:
                    _phase_a.cleanup(parent, root_fd, path.name)
            finally:
                ops.close(root_fd)
    budget(until if _phase_a is None else _phase_a.until, clock)
    return receipt


def read_leaf(parent, name, cap, *, ops=os, until, clock=time.monotonic):
    budget(until, clock)
    before = ops.stat(name, dir_fd=parent, follow_symlinks=False)
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == before.st_gid == 0
        and before.st_nlink == 1
        and not before.st_mode & 0o022
        and 0 <= before.st_size <= cap,
        "bundle_leaf",
    )
    fd = ops.open(
        name, ops.O_RDONLY | ops.O_NOFOLLOW | ops.O_CLOEXEC | ops.O_NONBLOCK, dir_fd=parent
    )
    try:
        need(file_key(ops.fstat(fd)) == file_key(before), "bundle_leaf_race")
        result, count = [], 0
        while True:
            budget(until, clock)
            chunk = ops.read(fd, min(65536, cap + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            need(count <= cap, "bundle_leaf_budget")
            result.append(chunk)
        need(
            count == before.st_size
            and file_key(ops.fstat(fd))
            == file_key(before)
            == file_key(ops.stat(name, dir_fd=parent, follow_symlinks=False)),
            "bundle_leaf_race",
        )
        return b"".join(result), before
    finally:
        ops.close(fd)


def verify(
    env,
    bindings,
    profile_raw,
    profile_sha,
    *,
    until,
    ops=os,
    clock=time.monotonic,
    runtime_check=None,
    _phase_a=None,
):
    """Rehash every resource and exact metadata before/after a browser run."""
    from contextlib import contextmanager

    path = root_path(env)
    budget(until, clock)
    if _phase_a is not None:
        _phase_a.validate(env, bindings)
    need("root_interpreter" in bindings or callable(runtime_check), "bundle_root_runtime_checker")
    with contextmanager(root_parents)(path.parent, ops) as parent:
        root_fd = open_child(parent, path.name, ops)
        try:
            root_identity = directory_key(ops.fstat(root_fd))
            need(
                stat.S_IMODE(ops.fstat(root_fd).st_mode) == (0o755 if _phase_a is None else 0o700),
                "bundle_root_mode",
            )
            raw, receipt_row = read_leaf(
                root_fd, ".bundle-receipt.json", 32768, ops=ops, until=until, clock=clock
            )
            need(stat.S_IMODE(receipt_row.st_mode) == 0o444, "bundle_receipt_mode")
            receipt = json_bytes(raw)
            manifest_raw, manifest_row = read_leaf(
                root_fd, ".bundle-manifest.json", MAX_JSON, ops=ops, until=until, clock=clock
            )
            need(stat.S_IMODE(manifest_row.st_mode) == 0o444, "bundle_receipt_mode")
            tree = json_bytes(manifest_raw)
            names = (
                admit(tree, profile_raw, profile_sha)
                if _phase_a is None else _phase_a.admit(tree, profile_raw, profile_sha)
            )
            root_binding_keys = {
                "revision",
                "pins_manifest_sha256",
                "context_receipt_sha256",
                "package_version",
                "signature",
                "key_scope",
                "root_interpreter",
            }
            need(
                type(bindings) is dict
                and {
                    "revision",
                    "pins_manifest_sha256",
                    "context_receipt_sha256",
                    "package_version",
                }
                <= set(bindings)
                <= root_binding_keys,
                "bundle_bindings",
            )
            expected_keys = {
                "schema",
                "state",
                "run",
                "attempt",
                "package_sha256",
                "profile_sha256",
                "manifest_sha256",
                "tree_sha256",
                "prefix",
                "target",
                "browser_executed",
                "all_OS_descendants_released",
                "operational_GO",
                *root_binding_keys,
            }
            need(
                type(receipt) is dict
                and set(receipt) == expected_keys
                and receipt["schema"] == (SCHEMA if _phase_a is None else _phase_a.STAGED_SCHEMA)
                and receipt["state"] == (
                    "STAGED_AUTHENTICATED_TEST_BUNDLE"
                    if _phase_a is None else "PRIVATE_STAGE_CLEANUP_ONLY"
                )
                and receipt["run"] == env["GITHUB_RUN_ID"]
                and receipt["attempt"] == env["GITHUB_RUN_ATTEMPT"]
                and all(receipt[k] == value for k, value in bindings.items())
                and receipt["profile_sha256"] == profile_sha
                and receipt["manifest_sha256"] == digest(manifest_raw)
                and receipt["tree_sha256"] == tree["tree_sha256"]
                and receipt["package_sha256"] == tree["package_sha256"]
                and receipt["prefix"] == str(path)
                and receipt["target"] == names["chrome"]
                and receipt["browser_executed"]
                is receipt["all_OS_descendants_released"]
                is receipt["operational_GO"]
                is False,
                "bundle_receipt",
            )
            if runtime_check is not None:
                need(callable(runtime_check), "bundle_root_runtime_checker")
                runtime_check(receipt["root_interpreter"])
            seen = set()

            def descend(fd, prefix=""):
                budget(until, clock)
                actual = ops.listdir(fd)
                allowed = (
                    {name.split("/", 1)[0] for name in names if name != "."}
                    if not prefix
                    else {
                        name[len(prefix) + 1 :].split("/", 1)[0]
                        for name in names
                        if name.startswith(prefix + "/")
                    }
                )
                if not prefix:
                    allowed |= {".bundle-manifest.json", ".bundle-receipt.json"}
                need(
                    len(actual) == len(set(actual)) and set(actual) == allowed,
                    "bundle_unexpected_entry",
                )
                for child in sorted(allowed):
                    if not prefix and child in {".bundle-manifest.json", ".bundle-receipt.json"}:
                        continue
                    name = prefix + "/" + child if prefix else child
                    row = names[name]
                    if row["type"] == "directory":
                        child_fd = open_child(fd, child, ops)
                        try:
                            need(
                                stat.S_IMODE(ops.fstat(child_fd).st_mode) == row["mode"],
                                "bundle_resource_mode",
                            )
                            descend(child_fd, name)
                        finally:
                            ops.close(child_fd)
                    else:
                        hashed, magic, info = hash_leaf(
                            fd, child, MAX_FILE, ops=ops, until=until, clock=clock
                        )
                        need(
                            info.st_size == row["bytes"]
                            and hashed == row["sha256"]
                            and stat.S_IMODE(info.st_mode) == row["mode"],
                            "bundle_resource_changed",
                        )
                        need(
                            name not in {"chrome", "chrome-sandbox"} or magic == b"\x7fELF",
                            "bundle_role_ELF",
                        )
                    seen.add(name)

            descend(root_fd)
            need(seen == set(names) - {"."}, "bundle_resource_missing")
            need(
                directory_key(ops.fstat(root_fd))
                == root_identity
                == directory_key(ops.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                "bundle_root_race",
            )
            budget(until, clock)
            return path / "chrome", {
                "sha256": names["chrome"]["sha256"],
                "bytes": names["chrome"]["bytes"],
                "uid": 0,
                "mode": 0o755,
            }
        finally:
            ops.close(root_fd)


def hash_leaf(parent, name, cap, *, ops=os, until, clock=time.monotonic):
    """Bounded streaming hash: full Chrome ELF/resources are never buffered."""
    budget(until, clock)
    before = ops.stat(name, dir_fd=parent, follow_symlinks=False)
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == before.st_gid == 0
        and before.st_nlink == 1
        and not before.st_mode & 0o022
        and 0 <= before.st_size <= cap,
        "bundle_leaf",
    )
    fd = ops.open(
        name, ops.O_RDONLY | ops.O_NOFOLLOW | ops.O_CLOEXEC | ops.O_NONBLOCK, dir_fd=parent
    )
    try:
        need(file_key(ops.fstat(fd)) == file_key(before), "bundle_leaf_race")
        h, count, magic = hashlib.sha256(), 0, b""
        while True:
            budget(until, clock)
            chunk = ops.read(fd, min(65536, cap + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            need(count <= cap, "bundle_leaf_budget")
            magic = (magic + chunk)[:4]
            h.update(chunk)
        need(
            count == before.st_size
            and file_key(ops.fstat(fd))
            == file_key(before)
            == file_key(ops.stat(name, dir_fd=parent, follow_symlinks=False)),
            "bundle_leaf_race",
        )
        return h.hexdigest(), magic, before
    finally:
        ops.close(fd)
