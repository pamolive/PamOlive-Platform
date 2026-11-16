"""Bounded public source buffers and exact-context packaging adaptation.

This parser never extracts archives. Admission and compiler execution live elsewhere.
"""

import difflib
import gzip
import hashlib
import io
import json
import lzma
import re
import tarfile
from pathlib import PurePosixPath

LIMIT = 128 * 1024**2
VERSION = "1.22.3-0+pamolive1"
PURPOSE = "krb5-upstream-1.22.3-debian-packaging-1.22.1-3-v1"
PRIMARY = "C4493CB739F4A89F9852CBC20CBA08575F8372DF"


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    out = {}
    for key, value in rows:
        need(key not in out, "json_duplicate")
        out[key] = value
    return out


def json_value(raw):
    def invalid_constant(_value):
        raise ValueError("json_nonfinite")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def safe_name(name):
    need(type(name) is str, "archive_path_type")
    path = PurePosixPath(name)
    need(
        isinstance(name, str)
        and name
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in name.split("/"))
        and "\\" not in name
        and ":" not in name
        and all(32 <= ord(c) < 127 for c in name),
        "archive_path",
    )
    return name


def archive_buffers(raw, compression):
    need(compression in {"gz", "xz"}, "archive_compression")
    stream = (
        gzip.GzipFile(fileobj=io.BytesIO(raw))
        if compression == "gz"
        else lzma.LZMAFile(io.BytesIO(raw))
    )
    with stream:
        expanded = stream.read(LIMIT + 1)
    need(len(expanded) <= LIMIT, "archive_expansion")
    files, directories = {}, set()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for i, item in enumerate(archive):
            need(i < 20000, "archive_count")
            name = safe_name(item.name.rstrip("/") if item.isdir() else item.name)
            need(name not in files and name not in directories, "archive_duplicate")
            need(not item.pax_headers, "archive_pax")
            if item.isdir():
                directories.add(name)
                continue
            need(item.isreg() and 0 <= item.size <= 16 * 1024**2, "archive_type_size")
            stream = archive.extractfile(item)
            need(stream is not None, "archive_member")
            data = stream.read(item.size + 1)
            need(len(data) == item.size, "archive_member_size")
            files[name] = (data, 0o755 if item.mode & 0o111 else 0o644)
    need(files, "archive_empty")
    names = set(files) | directories
    for name in names:
        need(
            not any(str(parent) in files for parent in PurePosixPath(name).parents),
            "archive_parent_file",
        )
    return files


def patch_files(raw):
    """Parse this finite Debian quilt series, never shell or binary patches."""
    lines = raw.decode("utf-8", "strict").splitlines(keepends=True)
    files, current, index = [], None, 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("--- a/"):
            old = safe_name(line[6:].split()[0])
            index += 1
            need(index < len(lines) and lines[index].startswith("+++ b/"), "patch_pair")
            name = safe_name(lines[index][6:].split()[0])
            need(name == old, "patch_rename")
            current = {"name": name, "hunks": []}
            files.append(current)
        elif line.startswith("@@ "):
            need(current is not None, "patch_hunk_file")
            match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", line)
            need(match is not None, "patch_hunk_header")
            old_count = int(match[2] or "1")
            new_count = int(match[4] or "1")
            before, after = [], []
            old_seen = new_seen = 0
            while old_seen < old_count or new_seen < new_count:
                index += 1
                need(index < len(lines), "patch_hunk_truncated")
                part = lines[index]
                need(part and part[0] in " +-", "patch_hunk_line")
                if part[0] in " -":
                    before.append(part[1:])
                    old_seen += 1
                if part[0] in " +":
                    after.append(part[1:])
                    new_seen += 1
            need(old_seen == old_count and new_seen == new_count, "patch_hunk_count")
            current["hunks"].append((before, after))
        index += 1
    need(files and all(row["hunks"] for row in files), "patch_empty")
    need(len({row["name"] for row in files}) == len(files), "patch_duplicate_file")
    return files


def exact_context(lines, before, after):
    positions = [
        i for i in range(len(lines) - len(before) + 1) if lines[i : i + len(before)] == before
    ]
    need(before and len(positions) == 1, "patch_context_not_unique")
    start = positions[0]
    return lines[:start] + after + lines[start + len(before) :]


def transform(tree, patch, reverse=False):
    changed = dict(tree)
    for file in patch_files(patch):
        name = file["name"]
        need(name in tree, "patch_target_missing")
        lines = tree[name].decode("utf-8", "strict").splitlines(keepends=True)
        for before, after in file["hunks"]:
            lines = exact_context(lines, after if reverse else before, before if reverse else after)
        changed[name] = "".join(lines).encode()
    return changed


def classify(tree, patch):
    results = []
    for reverse in (False, True):
        try:
            results.append(transform(tree, patch, reverse))
        except ValueError:
            results.append(None)
    need((results[0] is None) != (results[1] is None), "patch_classification_unknown")
    return ("already_upstream", tree) if results[0] is None else ("apply", results[0])


def rebased_patch(before, after):
    out = []
    for name in sorted(before):
        if before[name] != after[name]:
            out.extend(
                difflib.unified_diff(
                    before[name].decode().splitlines(True),
                    after[name].decode().splitlines(True),
                    fromfile="a/" + name,
                    tofile="b/" + name,
                    n=3,
                )
            )
    return "".join(out).encode()
