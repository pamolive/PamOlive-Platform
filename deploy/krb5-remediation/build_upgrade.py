"""Linux candidate build. Source authentication precedes both archive parsers.

The output is ABI/package DATA. A separate Root v2 decision gates product use.
"""

import email.utils
import io
import json
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

DPKG_REASONS = {
    "deadline_before_spawn",
    "stdout_overflow",
    "stderr_overflow",
    "combined_overflow",
    "stdout_read_contract",
    "stderr_read_contract",
    "stdout_drain_error",
    "stderr_drain_error",
    "timeout",
    "spawn_error",
    "controller_error",
    "reap_error",
    "group_cleanup_error",
    "drain_incomplete",
    "pipe_close_error",
    "nonzero_exit",
    "absolute_deadline_exceeded",
}


def dpkg_failure_markers(buffers):
    """Finite textual hints, not attribution or a tool-execution/ABI receipt."""
    rules = (
        (
            "checkbuilddeps",
            "BUILD_DEPENDENCIES_UNMET",
            rb"^dpkg-checkbuilddeps: error: unmet build dependencies:",
        ),
        (
            "checkbuilddeps",
            "BUILD_CONFLICTS",
            rb"^dpkg-checkbuilddeps: error: unmet build conflicts:",
        ),
        (
            "gensymbols",
            "SYMBOLS_ADDED",
            rb"^dpkg-gensymbols: (?:error|warning): some new symbols appeared",
        ),
        (
            "gensymbols",
            "SYMBOLS_REMOVED",
            rb"^dpkg-gensymbols: (?:error|warning): some symbols or patterns disappeared",
        ),
        (
            "gensymbols",
            "LIBRARIES_ADDED",
            rb"^dpkg-gensymbols: (?:error|warning): new libraries appeared",
        ),
        (
            "gensymbols",
            "LIBRARIES_REMOVED",
            rb"^dpkg-gensymbols: (?:error|warning): some libraries disappeared",
        ),
        (
            "gensymbols",
            "SYMBOLS_TEMPLATE_MISMATCH",
            rb"^dpkg-gensymbols: (?:error|warning): .{1,1024} doesn't match completely ",
        ),
        ("gensymbols", "GENSYMBOLS_ERROR", rb"^dpkg-gensymbols: error: "),
        (
            "compiler",
            "COMPILER_ERROR",
            rb"^[^:\r\n]{1,512}:[0-9]{1,8}(?::[0-9]{1,8})?: (?:fatal )?error: ",
        ),
        (
            "compiler",
            "COMPILER_DRIVER_ERROR",
            rb"^(?:x86_64-linux-gnu-)?(?:gcc(?:-14)?|g\+\+(?:-14)?|cc|cc1|cc1plus): "
            rb"(?:fatal )?error: ",
        ),
        ("linker", "LINKER_DRIVER_EXIT", rb"^collect2: error: ld returned [0-9]{1,3} exit status"),
        (
            "linker",
            "LINKER_UNDEFINED",
            rb"^(?:/usr/bin/)?(?:x86_64-linux-gnu-)?ld(?:\.bfd)?: .{0,1024}undefined reference to ",
        ),
        (
            "linker",
            "LINKER_CANNOT_FIND",
            rb"^(?:/usr/bin/)?(?:x86_64-linux-gnu-)?ld(?:\.bfd)?: cannot find ",
        ),
        (
            "debhelper",
            "DEBHELPER_ERROR",
            rb"^(?:dh|dh_auto_configure|dh_auto_build|dh_auto_test|dh_auto_install|dh_install|"
            rb"dh_missing|dh_makeshlibs|dh_shlibdeps|dh_strip|dh_gencontrol|dh_builddeb): error: ",
        ),
        ("dpkg", "DPKG_ERROR", rb"^dpkg-(?:buildpackage|source): error: "),
        (
            "make",
            "MAKE_ERROR",
            rb"^make(?:\[[0-9]{1,3}\])?: \*\*\* .{0,2048}Error [0-9]{1,3}(?: |$)",
        ),
    )
    need(
        set(buffers) == {"stdout", "stderr"}
        and all(type(raw) is bytes and len(raw) <= 8 * 1024**2 for raw in buffers.values()),
        "dpkg_diagnostic_buffers",
    )
    counts = {code: 0 for _, code, _ in rules}
    first, skipped, scanned, budget_exhausted = {}, 0, 0, False
    for stream in ("stdout", "stderr"):
        offset = 0
        for line_number, raw in enumerate(io.BytesIO(buffers[stream]), 1):
            if line_number > 100000:
                budget_exhausted = True
                break
            start = offset
            offset += len(raw)
            scanned += 1
            line = raw.removesuffix(b"\n").removesuffix(b"\r")
            if len(raw) > 8192 or any(byte < 32 and byte != 9 or byte == 127 for byte in line):
                skipped += 1
                continue
            if not line:
                continue
            for tool, code, pattern in rules:
                if re.match(pattern, line) is None:
                    continue
                counts[code] += 1
                if code not in first:
                    event = {
                        "tool_marker": tool,
                        "code": code,
                        "stream": stream,
                        "byte_offset": start,
                        "line_number": line_number,
                        "line_bytes": len(raw),
                        "line_sha256": sha(raw),
                        "severity_marker": "WARNING"
                        if line.startswith(b"dpkg-gensymbols: warning: ")
                        or tool == "linker"
                        and b": warning: undefined reference to " in line
                        else "ERROR",
                        "status_number": None,
                        "source_line": None,
                        "source_column": None,
                        "source_path_sha256": None,
                    }
                    status = (
                        re.search(rb" Error ([0-9]{1,3})(?: \([^)]{0,32}\))?$", line)
                        if code == "MAKE_ERROR"
                        else re.match(
                            rb"^collect2: error: ld returned ([0-9]{1,3}) exit status$", line
                        )
                        if code == "LINKER_DRIVER_EXIT"
                        else re.search(rb" subprocess returned exit status ([0-9]{1,3})$", line)
                        if code == "DPKG_ERROR"
                        else None
                    )
                    if status is not None and int(status[1]) <= 255:
                        event["status_number"] = int(status[1])
                    location = (
                        re.match(rb"([^:\r\n]{1,512}):([0-9]{1,8})(?::([0-9]{1,8}))?: ", line)
                        if code == "COMPILER_ERROR"
                        else None
                    )
                    if location is not None:
                        event.update(
                            source_path_sha256=sha(location[1]),
                            source_line=int(location[2]),
                            source_column=int(location[3]) if location[3] else None,
                        )
                    first[code] = event
                break
    # First preserve one event for every observed tool family. Thousands of
    # generic make errors cannot hide compiler or gensymbols markers.
    ordered = sorted(
        first.values(),
        key=lambda event: next(i for i, (_, code, _) in enumerate(rules) if code == event["code"]),
    )
    events, tools = [], set()
    for event in ordered:
        if event["tool_marker"] not in tools:
            events.append(event)
            tools.add(event["tool_marker"])
    for event in ordered:
        if len(events) == 8:
            break
        if event not in events:
            events.append(event)
    return {
        "schema": "pamolive.krb5-dpkg-text-markers/1",
        "parsed": True,
        "root_cause": "UNKNOWN",
        "text_markers_only": True,
        "counts": counts,
        "events": events,
        "event_limit": 8,
        "distinct_codes": len(first),
        "events_truncated": len(first) > len(events),
        "lines_scanned": scanned,
        "long_or_control_lines_skipped": skipped,
        "line_limit_per_stream": 100000,
        "line_budget_exhausted": budget_exhausted,
        "unrecognized_failure": not first,
        "tools_or_versions_authenticated_by_text": False,
        "operational_GO": False,
    }


def dpkg_failure_data(log):
    """Fixed-leaf DATA projection; no raw output, argv, exception or environment."""
    result = {
        "schema": "pamolive.krb5-dpkg-failure-diagnostic/1",
        "stage": "dpkg-buildpackage",
        "diagnostic_only": True,
        "classification": "H1_UNKNOWN",
        "facts_available": False,
        "facts": None,
        "tool_stability_proved": False,
        "operational_GO": False,
    }
    try:
        facts = json_value(read(log / "result.json", 16384))
        flags = (
            "spawn_attempted",
            "killed_owned_child",
            "owned_child_reaped",
            "drains_complete",
        )
        need(
            type(facts) is dict
            and set(facts)
            == {
                *flags,
                "pid",
                "returncode",
                "reason",
                "exception_type",
                "cleanup_exception_type",
                "stdout_bytes",
                "stderr_bytes",
            }
            and all(type(facts[name]) is bool for name in flags)
            and (facts["pid"] is None or type(facts["pid"]) is int and 0 < facts["pid"] < 2**31)
            and (
                facts["returncode"] is None
                or type(facts["returncode"]) is int
                and -(2**31) <= facts["returncode"] < 2**31
            )
            and all(
                type(facts[name]) is int and 0 <= facts[name] <= 8 * 1024**2
                for name in ("stdout_bytes", "stderr_bytes")
            ),
            "dpkg_diagnostic_shape",
        )
        reason = facts["reason"]
        need(
            reason is None or type(reason) is str and reason in DPKG_REASONS,
            "dpkg_diagnostic_shape",
        )
        projected = {
            name: facts[name]
            for name in (*flags, "pid", "returncode", "stdout_bytes", "stderr_bytes")
        }
        projected.update(
            reason=reason,
            exception_present=facts["exception_type"] is not None,
            cleanup_exception_present=facts["cleanup_exception_type"] is not None,
        )
        result.update(facts_available=True, facts=projected)
        normal = (
            facts["spawn_attempted"] is True
            and facts["pid"] is not None
            and type(facts["returncode"]) is int
            and facts["owned_child_reaped"] is facts["drains_complete"] is True
            and facts["killed_owned_child"] is False
            and facts["exception_type"] is facts["cleanup_exception_type"] is None
        )
        if reason in {"stdout_overflow", "stderr_overflow", "combined_overflow"}:
            result["classification"] = "OUTPUT_CAP_REFUSED"
        elif reason in {"timeout", "deadline_before_spawn", "absolute_deadline_exceeded"}:
            result["classification"] = "TIME_BUDGET_REFUSED"
        elif normal and reason == "nonzero_exit" and facts["returncode"] > 0:
            result["classification"] = "NORMAL_NONZERO"
        elif normal and reason == "nonzero_exit" and facts["returncode"] < 0:
            result["classification"] = "SIGNALLED"
        elif normal and reason is None and facts["returncode"] == 0:
            result["classification"] = "RC0_CALLER_REFUSAL"
    except (OSError, ValueError, TypeError):
        pass
    captured = {}
    for name in ("stdout", "stderr"):
        projected = {"available": False, "bytes": None, "sha256": None}
        try:
            raw = read(log / name, 8 * 1024**2)
            captured[name] = raw
            projected.update(available=True, bytes=len(raw), sha256=sha(raw))
        except (OSError, ValueError, TypeError):
            pass
        result[name] = projected
    counts_match = (
        all(
            result[name]["bytes"] == result["facts"][name + "_bytes"]
            for name in ("stdout", "stderr")
        )
        if result["facts_available"]
        and all(result[name]["available"] for name in ("stdout", "stderr"))
        else None
    )
    result["retained_counts_match"] = counts_match
    if counts_match is not True and result["classification"] in {
        "NORMAL_NONZERO",
        "SIGNALLED",
        "RC0_CALLER_REFUSAL",
    }:
        result["classification"] = "H1_UNKNOWN"
    result["failure_markers"] = (
        dpkg_failure_markers(captured)
        if result["classification"] == "NORMAL_NONZERO" and result["facts"]["returncode"] == 2
        else {
            "parsed": False,
            "root_cause": "UNKNOWN",
            "reason": "NORMAL_RC2_H1_NOT_RECEIVED",
            "operational_GO": False,
        }
    )
    return result


def dpkg_build(source, log):
    try:
        command(
            ["/usr/bin/dpkg-buildpackage", "-B", "-us", "-uc", "-j1"],
            source,
            log,
            seconds=3000,
            cap=8 * 1024**2,
            env=BUILD_ENV,
        )
    except BaseException:
        try:
            diagnostic = json.dumps(dpkg_failure_data(log), sort_keys=True)
            need(len(diagnostic.encode()) <= 8192, "dpkg_diagnostic_budget")
            print(diagnostic, flush=True)
        except BaseException:
            pass  # Diagnostics must never replace the original refusal.
        raise


def packaging_symbols(pkg):
    """Add one authenticated-upstream export to the exact Debian template."""
    name = "debian/libkrb5-3.symbols"
    need(type(pkg) is dict and name in pkg, "symbols_packaging_shape")
    row = pkg[name]
    need(type(row) is tuple and len(row) == 2, "symbols_packaging_shape")
    raw, mode = row
    need(
        type(raw) is bytes
        and type(mode) is int
        and mode == 0o644
        and sha(raw) == "7452b6b13d0a121d7034bc86ea50ad042761be2682319b2513b6f98db338b727",
        "symbols_template_preimage",
    )
    context = (
        b" k5_rc_get_name@krb5_3_MIT 1.18.2\n"
        b" k5_rc_resolve@krb5_3_MIT 1.18.2\n"
        b" k5_rc_store@krb5_3_MIT 1.20~beta1\n"
        b" k5_size_auth_context@krb5_3_MIT 1.18.2\n"
        b" k5_size_authdata@krb5_3_MIT 1.18.2\n"
    )
    need(raw.count(context) == 1, "symbols_template_context")
    replacement = context.replace(
        b" k5_size_auth_context@",
        b" k5_ser_unpack_len@krb5_3_MIT 1.22.3\n k5_size_auth_context@",
        1,
    )
    changed = raw.replace(context, replacement, 1)
    need(
        sha(changed) == "00b743262a79ae50cd189c488a25576c3d3d52d349d7b98e115c45b95bd97ab1",
        "symbols_template_postimage",
    )
    return {**pkg, name: (changed, mode)}


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
    return upstream, packaging_symbols(pkg), tree, required


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
    dpkg_build(source, work / "dpkg-buildpackage")
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
