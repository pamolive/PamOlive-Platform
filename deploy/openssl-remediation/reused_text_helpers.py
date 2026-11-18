"""Pure text helpers mechanically reused from reviewed3532232.

No archive, native or shell execution.
"""

import difflib
import hashlib
import json
import re
from pathlib import PurePosixPath


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


def fields(text):
    value, current = {}, None
    for line in text.splitlines():
        if line.startswith((" ", "\t")):
            need(current is not None, "control_continuation")
            value[current] += "\n" + line
        else:
            key, sep, content = line.partition(":")
            need(
                sep
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key)
                and key not in value
                and (not content or content.startswith(" ")),
                "control_fields",
            )
            value[key], current = content.removeprefix(" "), key
    return value


def checksums(text):
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        need(
            len(parts) == 3
            and re.fullmatch(r"[0-9a-f]{64}", parts[0])
            and parts[1].isdigit()
            and parts[2] not in out,
            "checksum_rows",
        )
        out[parts[2]] = (int(parts[1]), parts[0])
    return out
