"""Externally commissioned setup authority; never taken from reception request DATA."""

import hashlib
import ipaddress
import os
import stat
from pathlib import Path

from . import contract as c
from .files import identity, read_control

PATHS = {
    "sudo": "/usr/bin/sudo",
    "ip": "/usr/bin/ip",
    "nft": "/usr/sbin/nft",
    "setpriv": "/usr/bin/setpriv",
    "python": "/usr/bin/python3.12",
    "install": "/usr/bin/install",
    "mkdir": "/usr/bin/mkdir",
    "rm": "/usr/bin/rm",
    "rmdir": "/usr/bin/rmdir",
}
DENIED = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


def decode(raw, expected_sha):
    c.need(type(expected_sha) is str and c.digest(raw) == expected_sha, "origin_Root_profile_hash")
    p = c.load(raw, 65536)
    c.need(
        type(p) is dict
        and set(p)
        == {
            "schema",
            "commissioned",
            "tools",
            "source_files",
            "dns_public_ipv4",
            "denied_ipv4",
            "subnet",
            "uid",
            "gid",
            "seccomp_sha256",
            "TCB",
            "budgets",
        }
        and p["schema"] == "pamolive.origin-root-egress-profile/1"
        and p["commissioned"] is True,
        "origin_Root_profile_commission",
    )
    c.need(p["TCB"] == "fresh-GitHub-Ubuntu24-amd64-vendor-packages", "origin_Root_profile_TCB")
    c.need(
        type(p["uid"]) is int
        and 0 < p["uid"] < 2**31
        and type(p["gid"]) is int
        and 0 < p["gid"] < 2**31,
        "origin_Root_profile_ids",
    )
    c.need(p["denied_ipv4"] == list(DENIED), "origin_Root_profile_denied")
    dns = ipaddress.IPv4Address(p["dns_public_ipv4"])
    c.need(
        str(dns) == p["dns_public_ipv4"]
        and dns.is_global
        and not any(dns in ipaddress.IPv4Network(n) for n in DENIED),
        "origin_public_DNS",
    )
    subnet = ipaddress.IPv4Network(p["subnet"])
    c.need(
        str(subnet) == p["subnet"]
        and subnet.prefixlen == 30
        and subnet.subnet_of(ipaddress.IPv4Network("198.18.0.0/15")),
        "origin_owned_subnet",
    )
    c.need(
        p["budgets"]
        == {
            "total": 600,
            "reserve": 30,
            "root_frontends": 48,
            "network_frontends": 64,
            "root_call_seconds": 10,
        }
        and all(type(v) is int for v in p["budgets"].values()),
        "origin_Root_budgets",
    )
    c.need(type(p["tools"]) is dict and set(p["tools"]) == set(PATHS), "origin_Root_tool_roles")
    for role, row in p["tools"].items():
        c.need(
            type(row) is dict
            and set(row)
            == {
                "path",
                "sha256",
                "bytes",
                "uid",
                "gid",
                "mode",
                "nlink",
                "supplier_package",
                "supplier_version",
            }
            and row["path"] == PATHS[role]
            and row["uid"] == row["gid"] == 0,
            "origin_Root_tool_fields",
        )
        c.need(
            all(type(row[k]) is int for k in ("bytes", "uid", "gid", "mode", "nlink"))
            and 4 <= row["bytes"] <= 128 * 1024**2
            and 1 <= row["nlink"] <= 4096,
            "origin_Root_tool_scalars",
        )
        c.need(
            row["mode"] in ({0o4755} if role == "sudo" else {0o755, 0o555})
            and (role in {"install", "mkdir", "rm", "rmdir"} or row["nlink"] == 1),
            "origin_Root_tool_mode",
        )
        c.need(
            type(row["sha256"]) is str
            and len(row["sha256"]) == 64
            and all(x in "0123456789abcdef" for x in row["sha256"]),
            "origin_Root_tool_sha",
        )
        for key in ("supplier_package", "supplier_version"):
            c.need(
                type(row[key]) is str
                and 0 < len(row[key]) <= 128
                and all(x.isalnum() or x in ".+-:~" for x in row[key]),
                "origin_Root_supplier_identity",
            )
    c.need(
        type(p["source_files"]) is dict and 1 <= len(p["source_files"]) <= 32, "origin_Root_sources"
    )
    for name, value in p["source_files"].items():
        c.need(
            type(name) is str
            and name.startswith("qualification/")
            and ".." not in name
            and name.endswith(".py")
            and type(value) is str
            and len(value) == 64
            and all(x in "0123456789abcdef" for x in value),
            "origin_Root_source_pin",
        )
    c.need(
        type(p["seccomp_sha256"]) is str and len(p["seccomp_sha256"]) == 64,
        "origin_Root_seccomp_pin",
    )
    return p


def tool(role, p):
    row = p["tools"][role]
    path = Path(PATHS[role])
    for parent in path.parents:
        st = parent.lstat()
        c.need(
            stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
            "origin_Root_tool_parent",
        )
    before = path.lstat()
    c.need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == before.st_gid == 0
        and stat.S_IMODE(before.st_mode) == row["mode"]
        and before.st_nlink == row["nlink"]
        and before.st_size == row["bytes"],
        "origin_Root_tool_metadata",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        c.need(identity(before) == identity(os.fstat(fd)), "origin_Root_tool_open")
        h, count = hashlib.sha256(), 0
        prefix = b""
        while count < before.st_size:
            b = os.read(fd, min(65536, before.st_size - count))
            c.need(bool(b), "origin_Root_tool_short")
            prefix = (prefix + b)[:20]
            count += len(b)
            h.update(b)
        c.need(
            not os.read(fd, 1)
            and prefix[:6] == b"\x7fELF\x02\x01"
            and prefix[18:20] == b"\x3e\x00"
            and h.hexdigest() == row["sha256"]
            and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
            "origin_Root_tool_bytes",
        )
    finally:
        os.close(fd)
    return {"path": str(path), "sha256": h.hexdigest(), "identity": list(identity(before))}


def sources(p, source):
    for name, expected in p["source_files"].items():
        c.need(
            c.digest(read_control(Path(source) / name, 131072)) == expected,
            "origin_Root_source_changed",
        )
