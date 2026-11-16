"""Compare stage filesystem metadata after COPY; no origin/attestation claim."""

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

PRUNED = {"/dev", "/proc", "/sys", "/run", "/tmp", "/__pamolive_previous"}
INJECTED = {"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}
LIMIT = 100000


def metadata(root):
    root = Path(root)
    result, pending = {}, [(root, "/")]
    while pending:
        path, name = pending.pop()
        if name in INJECTED or name == "/__pamolive_previous":
            continue
        info = path.lstat()
        kind = stat.S_IFMT(info.st_mode)
        if kind not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
            raise ValueError("snapshot_special_file")
        row = {
            "type": kind,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
        }
        if stat.S_ISLNK(info.st_mode):
            row["target"] = os.readlink(path)
        if stat.S_ISREG(info.st_mode):
            row["bytes"] = info.st_size
        result[name] = row
        if len(result) > LIMIT:
            raise ValueError("snapshot_budget")
        if stat.S_ISDIR(info.st_mode) and name not in PRUNED:
            for child in path.iterdir():
                pending.append((child, name.rstrip("/") + "/" + child.name))
                if len(pending) + len(result) > LIMIT:
                    raise ValueError("snapshot_budget")
    return result


def difference_diagnostic(before, after):
    """Public numeric metadata only; no file bytes, raw path or symlink target."""
    result = {
        "schema": "pamolive.expat-snapshot-metadata-diagnostic/1",
        "diagnostic_only": True,
        "operational_GO": False,
        "code": "snapshot_metadata_changed",
        "input_shape_ok": False,
        "before_entries": None,
        "after_entries": None,
        "changed_entries": None,
        "record_limit": 24,
        "byte_limit": 16384,
        "records_truncated": False,
        "records": [],
    }
    if type(before) is not dict or type(after) is not dict or max(len(before), len(after)) > LIMIT:
        return result
    result["before_entries"], result["after_entries"] = len(before), len(after)
    paths = set(before) | set(after)
    if any(type(path) is not str or not path.startswith("/") or len(path) > 4096 for path in paths):
        return result
    labels = {
        "/": "root",
        "/app": "application_root",
        "/etc": "etc_root",
        "/usr": "usr_root",
        "/usr/local": "usr_local_root",
        "/usr/local/lib": "usr_local_lib",
        "/usr/local/lib/python3.12": "cpython312_stdlib",
        "/usr/local/lib/python3.12/site-packages": "cpython312_site_packages",
        "/usr/local/lib/python3.12/__pycache__": "cpython312_stdlib_cache",
        "/app/deploy/__pycache__": "application_deploy_cache",
        "/.dockerenv": "engine_marker",
        "/dev": "pruned_dev",
        "/proc": "pruned_proc",
        "/sys": "pruned_sys",
        "/run": "pruned_run",
        "/tmp": "pruned_tmp",
        "/usr/share/pamolive/expat4": "expat_evidence_root",
    }
    allowed = {"type", "mode", "uid", "gid", "bytes", "target"}
    maximums = {
        "type": 65535,
        "mode": 0o7777,
        "uid": 2**32 - 1,
        "gid": 2**32 - 1,
        "bytes": 2**63 - 1,
    }

    def numeric(row):
        if type(row) is not dict or len(row) > 6:
            return {}, False
        projected, valid = {}, not bool(set(row) - allowed)
        for name, maximum in maximums.items():
            if name not in row:
                continue
            value = row[name]
            okay = type(value) is int and 0 <= value <= maximum
            projected[name] = value if okay else None
            valid &= okay
        return projected, valid

    changed, all_valid = 0, True
    for path in sorted(paths):
        left, right = before.get(path), after.get(path)
        if path in before and path in after and left == right:
            continue
        changed += 1
        previous, valid_left = numeric(left) if path in before else ({}, True)
        following, valid_right = numeric(right) if path in after else ({}, True)
        all_valid &= valid_left and valid_right
        if len(result["records"]) >= result["record_limit"]:
            continue
        left_fields = set(left) if type(left) is dict and len(left) <= 6 else set()
        right_fields = set(right) if type(right) is dict and len(right) <= 6 else set()
        changed_fields = [
            name
            for name in sorted(allowed)
            if (
                (name in left_fields) != (name in right_fields)
                or name in left_fields
                and name in right_fields
                and left[name] != right[name]
            )
        ]
        if (left_fields | right_fields) - allowed:
            changed_fields.append("unknown_field")
        result["records"].append(
            {
                "path_label": labels.get(path, "other"),
                "path_sha256": hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest(),
                "change": "added"
                if path not in before
                else "removed"
                if path not in after
                else "changed",
                "changed_fields": changed_fields,
                "before_numeric": previous,
                "after_numeric": following,
            }
        )
    result["changed_entries"] = changed
    result["input_shape_ok"] = all_valid
    result["records_truncated"] = changed > len(result["records"])
    while len(json.dumps(result, sort_keys=True).encode("utf-8")) > result["byte_limit"]:
        result["records"].pop()
        result["records_truncated"] = True
    return result


def compare(source, target, *, diagnostic_sink=None):
    before, after = metadata(source), metadata(target)
    if before != after:
        if diagnostic_sink is not None:
            try:
                diagnostic_sink(difference_diagnostic(before, after))
            except Exception:
                pass  # Diagnostic failure must not replace the original refusal.
        raise ValueError("snapshot_metadata_changed")
    return {
        "schema": "pamolive.expat-runtime-snapshot/1",
        "metadata_equal": True,
        "entries": len(before),
        "fields": ["type", "mode", "uid", "gid", "target", "bytes"],
        "pruned_contents": sorted(PRUNED),
        "engine_injected_files": sorted(INJECTED),
        "content_hash_equality_proved": False,
        "hardlink_topology_proved": False,
        "base_origin_attested": False,
        "product_qualified": False,
        "operational_GO": False,
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        raise ValueError("usage_source_target_new_output")
    result = compare(
        argv[0],
        argv[1],
        diagnostic_sink=lambda value: print(json.dumps(value, sort_keys=True), flush=True),
    )
    with Path(argv[2]).open("x", encoding="utf8") as stream:
        json.dump(result, stream, sort_keys=True)
        stream.write("\n")
    Path(argv[2]).chmod(0o444)


if __name__ == "__main__":
    main()
