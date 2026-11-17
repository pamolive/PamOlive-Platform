"""Future GitHub Linux read-only DATA. No namespace/rules/sysctl/install mutation."""

import argparse
import hashlib
import os
import re
import stat
import sys
import time
from pathlib import Path

SOURCE = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(SOURCE))

from qualification.build_origin import contract as c  # noqa: E402
from qualification.build_origin import profile  # noqa: E402
from qualification.build_origin.commands import Commands  # noqa: E402
from qualification.build_origin.files import exclusive, identity, read_control  # noqa: E402


def budget(until_ns):
    c.need(type(until_ns) is int and time.monotonic_ns() < until_ns, "preflight_deadline")


def observed_tool(role, *, until_ns):
    budget(until_ns)
    path = Path(profile.PATHS[role])
    for parent in path.parents:
        budget(until_ns)
        info = parent.lstat()
        c.need(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "preflight_vendor_parent",
        )
    info = path.lstat()
    c.need(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == info.st_gid == 0
        and not info.st_mode & 0o022
        and 4 <= info.st_size <= 128 * 1024**2
        and 1 <= info.st_nlink <= 4096,
        "preflight_vendor_leaf",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        c.need(identity(info) == identity(os.fstat(fd)), "preflight_vendor_open")
        h, count, prefix = hashlib.sha256(), 0, b""
        while count < info.st_size:
            budget(until_ns)
            raw = os.read(fd, min(65536, info.st_size - count))
            c.need(bool(raw), "preflight_vendor_short")
            count += len(raw)
            h.update(raw)
            prefix = (prefix + raw)[:20]
        budget(until_ns)
        c.need(
            not os.read(fd, 1)
            and prefix[:6] == b"\x7fELF\x02\x01"
            and prefix[18:20] == b"\x3e\x00"
            and identity(info) == identity(os.fstat(fd)) == identity(path.lstat()),
            "preflight_vendor_ELF_stability",
        )
        budget(until_ns)
    finally:
        os.close(fd)
    return {
        "path": str(path),
        "sha256": h.hexdigest(),
        "bytes": info.st_size,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": info.st_nlink,
        "local_identity": list(identity(info)),
        "state": "UNAPPROVED_OBSERVATION",
    }


def proc_bytes(path, cap, *, until_ns):
    # Caller uses only finite literal public kernel metadata paths.
    c.need(
        path in {"/proc/sys/net/ipv4/ip_forward", "/proc/net/route", "/proc/net/ip_tables_names"},
        "preflight_proc_role",
    )
    budget(until_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        parts, total = [], 0
        while True:
            budget(until_ns)
            block = os.read(fd, min(65536, cap + 1 - total))
            budget(until_ns)
            if not block:
                break
            total += len(block)
            c.need(total <= cap, "preflight_proc_cap")
            parts.append(block)
        return b"".join(parts)
    finally:
        os.close(fd)


def route_projection(raw):
    c.need(type(raw) is bytes and len(raw) <= 65536, "preflight_route_budget")
    lines = raw.decode("ascii").splitlines()
    c.need(1 <= len(lines) <= 512 and lines[0].startswith("Iface\t"), "preflight_route_frame")
    defaults = []
    for line in lines[1:]:
        fields = line.split()
        c.need(
            len(fields) == 11 and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", fields[0]),
            "preflight_route_fields",
        )
        if fields[1] == "00000000" and fields[7] == "00000000":
            defaults.append(fields[0])
    c.need(len(defaults) == 1, "preflight_route_default_count")
    # No gateway, subnet, MAC or address is exported. Only a finite supported label.
    label = defaults[0] if defaults[0] in {"eth0", "ens5", "enp0s3"} else "OTHER_UNCOMMISSIONED"
    return {
        "route_rows": len(lines) - 1,
        "default_count": 1,
        "uplink_label": label,
        "uplink_label_sha256": c.digest(defaults[0].encode()),
        "raw_addresses_exported": False,
    }


def policy_projection(raw, legacy_names):
    value = c.load(raw, 2 * 1024**2, members=16384, nodes=200000)
    c.need(
        type(value) is dict and set(value) == {"nftables"} and type(value["nftables"]) is list,
        "preflight_nft_shape",
    )
    chains = []
    for row in value["nftables"]:
        chain = row.get("chain") if type(row) is dict else None
        if type(chain) is dict and chain.get("hook") == "forward":
            c.need(
                chain.get("type") == "filter"
                and chain.get("family") in {"ip", "ip6", "inet"}
                and "policy" in chain
                and chain["policy"] in {"accept", "drop"},
                "preflight_nft_chain",
            )
            chains.append(chain["policy"])
    legacy = [] if legacy_names is None else legacy_names.decode("ascii").splitlines()
    c.need(
        len(legacy) <= 32 and all(re.fullmatch(r"[A-Za-z0-9_]{1,32}", n) for n in legacy),
        "preflight_legacy_names",
    )
    # An accept policy does not prove that a rule permits the new veth. Unknown
    # legacy/rule effects remain explicit; no auto-insert or global alteration.
    classification = (
        "DROP_POLICY_OBSERVED" if "drop" in chains else "NO_DROP_POLICY_IN_NFT_SNAPSHOT"
    )
    return {
        "forward_base_chains": len(chains),
        "drop_policies": chains.count("drop"),
        "classification": classification,
        "legacy_filter_present": None if legacy_names is None else "filter" in legacy,
        "legacy_names_available": legacy_names is not None,
        "legacy_policy_known": False,
        "rules_can_still_deny": True,
        "owned_veth_connectivity_proved": False,
        "raw_rules_addresses_exported": False,
        "snapshot_sha256": c.digest(raw),
    }


def main():
    started_ns = time.monotonic_ns()
    until_ns = started_ns + 120_000_000_000
    work_ns = until_ns - 30_000_000_000
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("measure-vendor", "policies"))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--ack-trusted-public-vendor-TCB", action="store_true")
    ap.add_argument("--root-profile", type=Path)
    ap.add_argument("--root-profile-sha256")
    args = ap.parse_args()
    c.need(
        sys.platform == "linux"
        and os.getuid() != 0
        and sys.executable == profile.PATHS["python"]
        and sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY_ID") == "1449671447"
        and os.environ.get("GITHUB_REPOSITORY_OWNER_ID") == "305596298"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("PAMOLIVE_DISPOSABLE_ORIGIN_JOB") == "true",
        "preflight_fresh_GH_only",
    )
    os.umask(0o077)
    args.out.mkdir(mode=0o700)
    root = args.out.absolute()
    (root / "public").mkdir(mode=0o700)
    cmd = Commands(root, {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C", "LC_ALL": "C"})
    cmd.until = until_ns / 1_000_000_000
    result = {
        "schema": "pamolive.origin-tools-readonly-DATA/1",
        "state": "UNAPPROVED",
        "Root_approval_claimed": False,
        "setup_attempted": False,
        "namespaces_created": 0,
        "sysctl_or_rules_changed": False,
        "claims": c.false_claims(),
    }
    phase, active_role = "kernel_public", None
    try:
        budget(work_ns)
        forwarding = proc_bytes("/proc/sys/net/ipv4/ip_forward", 16, until_ns=work_ns)
        c.need(forwarding in {b"0\n", b"1\n"}, "preflight_forward_frame")
        result["forwarding_enabled"] = forwarding == b"1\n"
        result["routes"] = route_projection(proc_bytes("/proc/net/route", 65536, until_ns=work_ns))
        budget(work_ns)
        if args.mode == "measure-vendor":
            phase = "vendor_roles"
            c.need(
                args.ack_trusted_public_vendor_TCB
                and args.root_profile is None
                and args.root_profile_sha256 is None,
                "preflight_vendor_TCB_ack",
            )
            rows = {}
            for role in profile.PATHS:
                budget(work_ns)
                active_role = role
                before = observed_tool(role, until_ns=work_ns)
                version_arg = "-Version" if role == "ip" else "--version"
                stdout = cmd.run([profile.PATHS[role], version_arg], timeout=7, work=5, cap=16384)
                c.need(observed_tool(role, until_ns=work_ns) == before, "preflight_vendor_changed")
                first = stdout.split(b"\n", 1)[0]
                matches = re.findall(
                    rb"(?<![0-9])([0-9]+(?:\.[0-9]+){1,3}(?:p[0-9]+)?)(?![0-9])", first
                )
                if role == "ip":
                    selected = re.search(rb"iproute2[- ]([0-9]+(?:\.[0-9]+){1,3})", first)
                    c.need(selected is not None, "preflight_ip_version_shape")
                    version = selected.group(1)
                else:
                    c.need(len(matches) == 1, "preflight_version_shape")
                    version = matches[0]
                c.need(len(first) <= 512, "preflight_version_shape")
                before["version"] = version.decode("ascii")
                before["version_output_sha256"] = c.digest(stdout)
                rows[role] = before
                budget(work_ns)
            result["tools"] = rows
            result["root_policy_observation"] = "NOT_RUN_EXTERNAL_PINS_REQUIRED"
        else:
            phase, active_role = "root_policy_read", None
            c.need(
                args.root_profile is not None and not args.ack_trusted_public_vendor_TCB,
                "preflight_root_profile_required",
            )
            p = profile.decode(read_control(args.root_profile, 65536), args.root_profile_sha256)
            c.need(os.getuid() == p["uid"] and os.getgid() == p["gid"], "preflight_profile_job_ids")
            profile.sources(p, SOURCE)
            budget(work_ns)
            pins = {r: profile.tool(r, p) for r in ("sudo", "nft")}
            raw = cmd.run(
                [profile.PATHS["sudo"], "-n", "--", profile.PATHS["nft"], "-j", "list", "chains"],
                timeout=12,
                work=10,
                cap=2 * 1024**2,
            )
            c.need(
                all(profile.tool(r, p) == pin for r, pin in pins.items()), "preflight_root_postpins"
            )
            budget(work_ns)
            try:
                legacy = proc_bytes("/proc/net/ip_tables_names", 4096, until_ns=work_ns)
            except FileNotFoundError:
                legacy = None
            result["root_policy_observation"] = policy_projection(raw, legacy)
        budget(work_ns)
        encoded = c.canonical(result)
        budget(work_ns)
        exclusive(root / "public/readonly-DATA.json", encoded)
    except BaseException:
        exclusive(
            root / "public/failure.json",
            c.canonical(
                {
                    "schema": result["schema"],
                    "state": "UNKNOWN",
                    "setup_attempted": False,
                    "Root_approval_claimed": False,
                    "phase": phase,
                    "role": active_role,
                    "no_more_spawns": True,
                    "resources_released": False,
                    "claims": c.false_claims(),
                }
            ),
        )
        raise SystemExit(42) from None


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        sys.stderr.write("origin_readonly_preflight_refused\n")
        raise SystemExit(42) from None
