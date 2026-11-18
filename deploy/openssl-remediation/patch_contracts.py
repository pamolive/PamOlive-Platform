"""Closed, bounded unified-diff contract. No shell, filesystem or patch process."""

import re

from reused_text_helpers import exact_context, need, safe_name, sha

MAX_PATCH = 2 * 1024**2
MAX_FILES = 128
MAX_HUNKS = 4096
MAX_LINES = 65536


def target(name):
    safe_name(name)
    need(
        len(name) <= 1024 and re.fullmatch(r"[A-Za-z0-9_.+/-]+", name),
        "patch_target_path",
    )
    return name


def closed_patch(raw):
    """Only existing-file plain unified diff; reject every unrepresented form."""
    need(
        type(raw) is bytes and 0 < len(raw) <= MAX_PATCH and b"\0" not in raw and b"\r" not in raw,
        "patch_physical_budget",
    )
    lines = raw.decode("utf-8", "strict").splitlines(keepends=True)
    need(
        len(lines) <= MAX_LINES and all(line.endswith("\n") for line in lines),
        "patch_line_budget",
    )
    rows, names, index, hunks = [], set(), 0, 0
    while index < len(lines):
        line = lines[index]
        need(
            line.startswith("--- a/") and line.endswith("\n"),
            "patch_closed_file_header",
        )
        old = target(line[6:-1])
        index += 1
        need(
            index < len(lines) and lines[index].startswith("+++ b/"),
            "patch_closed_pair",
        )
        name = target(lines[index][6:-1])
        need(
            old == name and name not in names and len(rows) < MAX_FILES,
            "patch_closed_target_unique",
        )
        names.add(name)
        row = {"name": name, "hunks": []}
        rows.append(row)
        index += 1
        old_end = new_end = -1
        while index < len(lines) and lines[index].startswith("@@ "):
            match = re.fullmatch(
                r"@@ -(\d{1,8})(?:,(\d{1,8}))? \+(\d{1,8})(?:,(\d{1,8}))? @@[^\n]*\n",
                lines[index],
            )
            need(match is not None, "patch_closed_hunk_header")
            old_start, new_start = int(match[1]), int(match[3])
            old_count, new_count = int(match[2] or "1"), int(match[4] or "1")
            # Pure insertion/deletion without existing unique context is deliberately unsupported.
            need(
                0 < old_start <= MAX_LINES
                and 0 < new_start <= MAX_LINES
                and 0 < old_count <= MAX_LINES
                and 0 < new_count <= MAX_LINES
                and old_start > old_end
                and new_start > new_end,
                "patch_closed_hunk_range",
            )
            before, after, old_seen, new_seen = [], [], 0, 0
            hunks += 1
            need(hunks <= MAX_HUNKS, "patch_hunk_budget")
            index += 1
            while old_seen < old_count or new_seen < new_count:
                need(index < len(lines), "patch_closed_hunk_truncated")
                part = lines[index]
                need(part[0] in " +-", "patch_closed_hunk_line")
                if part[0] in " -":
                    before.append(part[1:])
                    old_seen += 1
                if part[0] in " +":
                    after.append(part[1:])
                    new_seen += 1
                need(
                    old_seen <= old_count and new_seen <= new_count,
                    "patch_closed_hunk_count",
                )
                index += 1
            row["hunks"].append((before, after))
            old_end, new_end = old_start + old_count - 1, new_start + new_count - 1
        need(row["hunks"], "patch_closed_no_hunks")
    need(rows, "patch_closed_empty")
    return rows


def bound_patch(row, raw):
    need(sha(raw) == row["proposed_patch_sha256"], "patch_bytes_pin")
    parsed = closed_patch(raw)
    need(
        {r["name"] for r in parsed} == set(row["before"]) == set(row["after"]),
        "patch_target_inventory_not_exhaustive",
    )
    return parsed


def apply_bound(tree, row, raw):
    parsed = bound_patch(row, raw)
    need(
        all(name in tree and sha(tree[name]) == digest for name, digest in row["before"].items()),
        "debian_source_preimage",
    )
    result = dict(tree)
    for file in parsed:
        lines = result[file["name"]].decode("utf-8", "strict").splitlines(keepends=True)
        for before, after in file["hunks"]:
            lines = exact_context(lines, before, after)
        result[file["name"]] = "".join(lines).encode()
    need(
        all(sha(result[n]) == h for n, h in row["after"].items()),
        "debian_source_postimage",
    )
    return result
