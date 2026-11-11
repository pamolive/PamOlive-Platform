"""Inspect an ephemeral CI runner's stock LDAP metadata before a traversal ACL.

Never reads data contents or changes permissions. Not a production operation.
"""

import argparse
import json
import os
import stat
import subprocess
from itertools import islice
from pathlib import Path


def check_entry(info, acl, actor_uid, actor_groups):
    if stat.S_ISLNK(info.st_mode) or not (
        stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
    ):
        raise ValueError("stock_ldap_special_entry")
    rows = [row.strip() for row in acl.splitlines() if row.strip()]
    if (len(rows) != 3 or {row.split(":")[0] for row in rows} != {"user", "group", "other"}
            or any(len(row.split(":")) != 3 or row.split(":")[1] for row in rows)):
        raise ValueError("stock_ldap_extended_acl")
    shift = 6 if info.st_uid == actor_uid else 3 if info.st_gid in actor_groups else 0
    if (info.st_mode >> shift) & 0o6:
        raise ValueError("stock_ldap_actor_read_or_write")
    if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111:
        raise ValueError("stock_ldap_executable_data")


def inspect_stock(actor_uid, actor_groups):
    if os.name != "posix" or os.geteuid() != 0 or actor_uid <= 0:
        raise ValueError("ephemeral_ci_root_inspection_required")
    pending, count = [Path("/var/lib/ldap")], 0
    while pending:
        path = pending.pop()
        count += 1
        if count > 256:
            raise ValueError("stock_ldap_metadata_budget")
        info = path.lstat()
        result = subprocess.run(
            ["/usr/bin/getfacl", "-cpn", "--", str(path)],
            capture_output=True, text=True, timeout=5, check=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if len(result.stdout) > 4096 or result.stderr:
            raise ValueError("stock_ldap_acl_metadata")
        check_entry(info, result.stdout, actor_uid, actor_groups)
        if stat.S_ISDIR(info.st_mode):
            children = list(islice(path.iterdir(), 257))
            if len(children) > 256:
                raise ValueError("stock_ldap_metadata_budget")
            pending.extend(children)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actor-uid", type=int, required=True)
    parser.add_argument("--actor-groups", required=True)
    args = parser.parse_args()
    try:
        groups = {int(value) for value in args.actor_groups.split(",")}
        if not groups or len(groups) > 64 or any(value < 0 for value in groups):
            raise ValueError("actor_groups")
        count = inspect_stock(args.actor_uid, groups)
    except (ValueError, OSError, subprocess.SubprocessError):
        print(json.dumps({"stock_isolated": False}))
        return 1
    print(json.dumps({"stock_isolated": True, "metadata_entries": count,
                      "data_contents_read": False, "permissions_changed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
