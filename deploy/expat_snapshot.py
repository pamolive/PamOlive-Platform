"""Compare stage filesystem metadata after COPY; no origin/attestation claim."""

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


def compare(source, target):
    before, after = metadata(source), metadata(target)
    if before != after:
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
    result = compare(argv[0], argv[1])
    with Path(argv[2]).open("x", encoding="utf8") as stream:
        json.dump(result, stream, sort_keys=True)
        stream.write("\n")
    Path(argv[2]).chmod(0o444)


if __name__ == "__main__":
    main()
