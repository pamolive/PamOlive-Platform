"""Linux candidate build. Source authentication precedes both archive parsers.

The output is ABI/package DATA. A separate Root v2 decision gates product use.
"""

import email.utils
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from abi_data import LIBRARIES, bind_old_product_baseline, capture, compare
from authenticate_upgrade import authenticate
from common import ENV, command, read, record, write_new
from policy import HERE, PATCH_PLAN_SHA256
from source_model import VERSION, archive_buffers, json_value, need, sha, transform
from tls_oracle import main as tls_oracle

RUNTIME = tuple(LIBRARIES)
SDK = (
    "krb5-multidev",
    "libkrb5-dev",
    "libgssrpc4t64",
    "libkadm5clnt-mit12",
    "libkadm5srv-mit12",
    "libkdb5-10t64",
)
BUILD_ENV = ENV | {
    "DEB_BUILD_MAINT_OPTIONS": "hardening=+all",
    "PYTHON": "/usr/bin/python3",
    "QUILT_PATCHES": "debian/patches",
    "QUILT_PATCH_OPTS": "--fuzz=0",
}


def prepared_buffers(captured, plan, rebased):
    upstream = archive_buffers(captured["krb5-1.22.3.tar.gz"], "gz")
    need(all(name.startswith("krb5-1.22.3/") for name in upstream), "upstream_root")
    tree = {name.removeprefix("krb5-1.22.3/"): raw for name, (raw, _) in upstream.items()}
    pkg = archive_buffers(captured["krb5_1.22.1-3.debian.tar.xz"], "xz")
    need(all(name.startswith("debian/") for name in pkg), "packaging_root")
    series = pkg["debian/patches/series"][0]
    need(
        sha(series) == plan["series_sha256"]
        and len(plan["series"]) == 16
        and [row["name"] for row in plan["series"]] == series.decode().splitlines(),
        "packaging_series",
    )
    need(
        all(
            sha(tree[name]) == digest
            for name, digest in plan["original_upstream_source_pins"].items()
        ),
        "upstream_source_pins",
    )
    required = []
    for row in plan["series"]:
        need(
            sha(pkg["debian/patches/" + row["name"]][0]) == row["original_sha256"],
            "original_patch_bytes",
        )
        need(all(sha(tree[p]) == digest for p, digest in row["before"].items()), "patch_preimage")
        if row["action"] in {"apply", "rebase_exact_source"}:
            name = row["rebased"]
            need(sha(rebased[name]) == row["rebased_sha256"], "rebased_patch_pin")
            tree = transform(tree, rebased[name])
            required.append(name)
        else:
            need(
                row["action"]
                in {
                    "already_upstream",
                    "omit_development_ignore_file",
                    "already_upstream_with_later_context_changes",
                    "omit_preserve_current_strict_hostname_policy",
                },
                "patch_unknown_action",
            )
        need(all(sha(tree[p]) == digest for p, digest in row["after"].items()), "patch_postimage")
    row = plan["test_compatibility"]
    name = row["name"]
    need(
        sha(rebased[name]) == row["sha256"]
        and all(sha(tree[p]) == h for p, h in row["before"].items()),
        "test_compat_preimage",
    )
    tree = transform(tree, rebased[name])
    need(all(sha(tree[p]) == h for p, h in row["after"].items()), "test_compat_postimage")
    required.append(name)
    return upstream, pkg, tree, required


def write_tree(folder, rows, strip=""):
    folder.mkdir(mode=0o700)
    for name, (raw, mode) in rows.items():
        path = folder / name.removeprefix(strip)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        write_new(path, raw, mode)


def keyring_facts(facts, stdout, stderr):
    need(
        type(facts["returncode"]) is int
        and facts["returncode"] == 1
        and type(facts["reason"]) is str
        and facts["reason"] == "nonzero_exit"
        and facts["exception_type"] is None
        and facts["cleanup_exception_type"] is None
        and facts["spawn_attempted"] is True
        and type(facts["pid"]) is int
        and facts["pid"] > 0
        and facts["owned_child_reaped"] is True
        and facts["drains_complete"] is True
        and facts["killed_owned_child"] is False,
        "keyring_H1_unknown",
    )
    need(
        stdout == b""
        and stderr == b"add_key: Operation not permitted\n"
        and type(facts["stdout_bytes"]) is int
        and facts["stdout_bytes"] == len(stdout)
        and type(facts["stderr_bytes"]) is int
        and facts["stderr_bytes"] == len(stderr),
        "keyring_refusal_shape",
    )


def keyring_probe(work):
    log = work / "keyring-probe"
    try:
        command(
            ["/usr/bin/keyctl", "add", "user", "pamolive-krb5-probe", "synthetic", "@p"],
            work,
            log,
            seconds=5,
        )
    except ValueError as exc:
        need(exc.args == ("child_failed_or_unknown",), "keyring_probe_unknown")
    else:
        raise ValueError("keyring_unexpected_permission")
    facts = json_value(read(log / "result.json", 32768))
    keyring_facts(facts, read(log / "stdout", 2 * 1024**2), read(log / "stderr", 2 * 1024**2))
    # procfs has st_size=0 despite contents; keep this exception fixed to this virtual file.
    with Path("/proc/self/status").open("rb") as stream:
        status = stream.read(65537)
    need(len(status) <= 65536, "proc_status_cap")
    need(
        re.search(rb"^Seccomp:\s+2$", status, re.M) is not None
        and sorted(p.name for p in Path("/sys/class/net").iterdir()) == ["lo"],
        "build_sandbox",
    )
    # Preserve UNKNOWN emitted by command() for normal nonzero; never relabel command success.
    return {
        "expected_nonzero_refusal": True,
        "command_success": False,
        "UNKNOWN_marker_retained": True,
        "facts": facts,
    }


def main(materials, output):
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    captured, auth = authenticate(Path(materials), work / "authentication")
    # No TAR parser, source extraction, or compiler can precede authenticate() returning.
    plan_raw = read(HERE / "patch-plan.json", 256 * 1024)
    need(sha(plan_raw) == PATCH_PLAN_SHA256, "packaging_adaptation_pin")
    plan = json_value(plan_raw)
    rebased = {p.name: read(p, 128 * 1024) for p in (HERE / "rebased-patches").iterdir()}
    upstream, pkg, expected_tree, required = prepared_buffers(captured, plan, rebased)
    before = capture(Path("/"))
    bind_old_product_baseline(before)
    record(output / "ABI-before.json", before)
    versions = command(
        ["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\n", *RUNTIME],
        work,
        work / "baseline-packages",
    )
    need(
        sorted(versions.decode().splitlines())
        == sorted(package + "\t1.21.3-5+deb13u1" for package in RUNTIME),
        "baseline_version",
    )
    source = work / "krb5-1.22.3"
    write_tree(source, upstream, "krb5-1.22.3/")
    # Rewrite selected packaging buffers before creating any path, never mutate signed archives.
    pkg = dict(pkg)
    pkg["debian/patches/series"] = (("\n".join(required) + "\n").encode(), 0o644)
    for name in required:
        pkg["debian/patches/" + name] = (rebased[name], 0o644)
    changelog = (
        f"krb5 ({VERSION}) trixie; urgency=high\n\n"
        "  * Candidate MIT 1.22.3 with reviewed Debian 1.22.1-3 packaging.\n\n"
        " -- PamOlive Qualification <qualification@pamolive.invalid>  "
        + email.utils.formatdate(1793923200, usegmt=True)
        + "\n\n"
    ).encode()
    pkg["debian/changelog"] = (changelog + pkg["debian/changelog"][0], 0o644)
    write_tree(source / "debian", {n.removeprefix("debian/"): row for n, row in pkg.items()})
    for index, name in enumerate(required):
        stdout = command(
            ["/usr/bin/quilt", "--quiltrc", "/dev/null", "push"],
            source,
            work / f"patch-{index + 1:02d}",
            seconds=30,
            env=BUILD_ENV,
        )
        stderr = read(work / f"patch-{index + 1:02d}" / "stderr", 2 * 1024**2)
        need(
            re.search(rb"\b(?:fuzz|offset)\b", stdout + stderr, re.I) is None, "patch_not_fuzz_zero"
        )
    for name in plan["original_upstream_source_pins"]:
        need(read(source / name, 16 * 1024**2) == expected_tree[name], "applied_source_bytes")
    capability = keyring_probe(work)
    command(
        ["/usr/bin/dpkg-buildpackage", "-B", "-us", "-uc", "-j1"],
        source,
        work / "dpkg-buildpackage",
        seconds=3000,
        cap=8 * 1024**2,
        env=BUILD_ENV,
    )
    tls_oracle(source, work / "TLS-hostname")
    regression = output / "ASN1-six-cases.json"
    command(
        [
            "/bin/sh",
            str(HERE / "check_krb5_asn1.sh"),
            "--phase",
            "patched",
            "--source",
            str(source / "src"),
            "--build",
            str(source / "build"),
            "--harness",
            str(HERE / "krb5_asn1_regression.c"),
            "--output",
            str(regression),
        ],
        work,
        work / "ASN1-six-cases",
        seconds=90,
        cap=4 * 1024**2,
    )
    actual = json_value(read(regression, 4 * 1024**2))
    need(
        actual["phase"] == "patched"
        and actual["case_count"] == 6
        and set(actual["cases"])
        == {"long_valid", "empty", "bad_tag", "truncated", "allocation_failure", "partial_cleanup"}
        and all(
            row["status"] == "passed" and row["live_allocations_after_cleanup"] == 0
            for row in actual["cases"].values()
        ),
        "ASN1_result",
    )
    root = output / "candidate-root"
    root.mkdir(mode=0o700)
    packages = {}
    for group, names in (("runtime", RUNTIME), ("sdk", SDK)):
        folder = output / group
        folder.mkdir(mode=0o700)
        for package in names:
            filename = f"{package}_{VERSION}_amd64.deb"
            raw = read(work / filename, 32 * 1024**2)
            write_new(folder / filename, raw, 0o444)
            packages[package] = {
                "file": filename,
                "bytes": len(raw),
                "sha256": sha(raw),
                "group": group,
                "version": VERSION,
            }
            if group == "runtime":
                command(
                    ["/usr/bin/dpkg-deb", "--extract", str(folder / filename), str(root)],
                    work,
                    work / ("unpack-" + package),
                    seconds=30,
                )
    after = capture(root)
    record(output / "ABI-candidate.json", after)
    try:
        compared = compare(before, after)
    except ValueError as exc:
        need(
            len(exc.args) == 1
            and exc.args[0]
            in {
                "ABI_library_set",
                "ABI_soname_changed",
                "ABI_row_shape",
                "ABI_duplicate",
                "ABI_old_export_changed",
            },
            "ABI_comparison_unknown",
        )
        # Retain measured ABI even when incompatible. Consumer install is then forbidden;
        # the workflow fails AFTER exporting the DATA artifact, never reports qualification.
        compared = {
            "schema": "pamolive.krb5-ABI-comparison-DATA/1",
            "all_old_exports_preserved": False,
            "refusal": exc.args[0],
            "candidate_profile_v2_admitted": False,
            "product_admission": False,
            "operational_GO": False,
        }
    record(output / "ABI-comparison-DATA.json", compared)
    record(
        output / "BUILD-DATA.json",
        {
            "schema": "pamolive.krb5-upgrade-build-DATA/1",
            "version": VERSION,
            "authentication": auth,
            "patch_plan_sha256": sha(read(HERE / "patch-plan.json", 256 * 1024)),
            "packages": packages,
            "keyring_capability": capability,
            "tests_enabled": True,
            "ASN1_six_case_file_sha256": sha(read(regression, 4 * 1024**2)),
            "TLS_matching_file_sha256": sha(
                read(work / "TLS-hostname/TLS-HOSTNAME-DATA.json", 65536)
            ),
            "TLS_partial_label_wildcard_policy_broadened": False,
            "upstream_test_log": "work/dpkg-buildpackage/stdout and stderr",
            "SDK_and_runtime_same_build": True,
            "ABI_baseline_matches_received_old_backport_export_contract": True,
            "legacy_profile_v1_version": "1.21.3-5+deb13u1+pamolive1",
            "historical_ASN1_patch_reapplied_to_1_22_3": False,
            "legacy_ASN1_harness_patch_field_is_historical_lineage": True,
            "ABI_comparison": compared,
            "candidate_profile_v2_admitted": False,
            "product_admission": False,
            "operational_GO": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_output")
    main(*sys.argv[1:])
