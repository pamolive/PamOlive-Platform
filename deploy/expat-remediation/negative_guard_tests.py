"""Expected native compile refusals; never change common's UNKNOWN journal."""

import json
import stat
from pathlib import Path

from common import command, need, read, record, sha, write_new
from wide_test_port import BUNDLE

HEADER = "test_character_support.h"
CAP = 16384
EVIDENCE_FILES = ("intent.json", "pid.json", "result.json", "unknown.json", "stdout", "stderr")
FACT_KEYS = {
    "spawn_attempted",
    "pid",
    "returncode",
    "reason",
    "exception_type",
    "killed_owned_child",
    "owned_child_reaped",
    "drains_complete",
    "cleanup_exception_type",
    "stdout_bytes",
    "stderr_bytes",
}
PROBE = b'#include "test_character_support.h"\n'
FAKE = b"typedef signed short XML_Char;\ntypedef char XML_LChar;\n"
GUARDS = {
    "c99": '#error "ushort test port requires a C11 compiler, never wchar substitution"',
    "cxx": '#error "ushort test port is C11 only: C++ char16_t is a distinct type"',
    "xmlchar": 'static assertion failed: "XML_Char must remain unsigned short"',
}
SECONDARY = (
    'static assertion failed: "C11 char16_t must be type-compatible, not merely the same width"'
)
GUARD_LINES = {"c99": 24, "cxx": 22, "xmlchar": 30}


def json_value(body):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, "negative_json_duplicate")
            value[key] = item
        return value

    def constant(_):
        raise ValueError("negative_json_constant")

    need(isinstance(body, bytes) and len(body) <= CAP, "negative_json_budget")
    return json.loads(body, object_pairs_hook=pairs, parse_constant=constant)


def compiler_pin(entry):
    """Public compiler TCB, same root-owner boundary as common, measured twice."""
    need(entry in {"/usr/bin/gcc", "/usr/bin/g++"}, "negative_compiler_path")
    target = Path(entry).resolve(strict=True)

    def identity():
        row = target.stat()
        need(stat.S_ISREG(row.st_mode) and row.st_uid == 0, "negative_compiler_owner")
        return [
            row.st_dev,
            row.st_ino,
            row.st_mode,
            row.st_uid,
            row.st_gid,
            row.st_nlink,
            row.st_size,
            row.st_mtime_ns,
            row.st_ctime_ns,
        ]

    before = identity()
    digest = sha(read(target, 64 * 1024**2))
    need(
        identity() == before and Path(entry).resolve(strict=True) == target,
        "negative_compiler_unstable",
    )
    return {"target": str(target), "identity": before, "sha256": digest}


def diagnostics(body, case, header):
    rows = json_value(body)
    need(isinstance(rows, list) and 1 <= len(rows) <= 2, "negative_diagnostics_count")
    messages = []
    for row in rows:
        need(
            isinstance(row, dict) and row.get("kind") == "error" and row.get("children", []) == [],
            "negative_diagnostic_kind",
        )
        locations = row.get("locations")
        need(isinstance(locations, list) and len(locations) == 1, "negative_diagnostic_locations")
        caret = locations[0].get("caret", {})
        message = row.get("message")
        expected_line = 34 if case == "xmlchar" and message == SECONDARY else GUARD_LINES[case]
        need(
            caret.get("file") == str(header)
            and type(caret.get("line")) is int
            and caret["line"] == expected_line,
            "negative_diagnostic_header",
        )
        messages.append(message)
    need(messages.count(GUARDS[case]) == 1, "negative_guard_missing")
    allowed = [GUARDS[case]] + ([SECONDARY] if case == "xmlchar" else [])
    need(
        len(set(messages)) == len(messages) and all(m in allowed for m in messages),
        "negative_other_diagnostic",
    )
    return len(rows)


def lifecycle(facts, stdout, stderr, *, success=False):
    need(isinstance(facts, dict) and set(facts) == FACT_KEYS, "negative_facts_type")
    need(
        facts.get("spawn_attempted") is True
        and type(facts.get("pid")) is int
        and facts["pid"] > 0
        and facts.get("owned_child_reaped") is True
        and facts.get("drains_complete") is True
        and facts.get("killed_owned_child") is False
        and facts.get("exception_type") is None
        and facts.get("cleanup_exception_type") is None,
        "negative_h1_incomplete",
    )
    rc = facts.get("returncode")
    need(
        type(rc) is int
        and (
            (rc == 0 and facts.get("reason") is None)
            if success
            else (1 <= rc <= 255 and facts.get("reason") == "nonzero_exit")
        ),
        "negative_exit",
    )
    need(
        type(facts.get("stdout_bytes")) is int
        and facts["stdout_bytes"] == len(stdout)
        and type(facts.get("stderr_bytes")) is int
        and facts["stderr_bytes"] == len(stderr)
        and len(stdout) <= CAP
        and len(stderr) <= CAP,
        "negative_stream_facts",
    )


def positive_prerequisite(output):
    for name in ("helper-compile", "helper-run"):
        log = output / name
        out, err = read(log / "stdout", CAP), read(log / "stderr", CAP)
        facts = json_value(read(log / "result.json", CAP))
        lifecycle(facts, out, err, success=True)
        need(
            json_value(read(log / "pid.json", CAP)) == {"pid": facts["pid"]},
            "negative_positive_pid",
        )
        need(not (log / "unknown.json").exists(), "negative_positive_unknown")
        need(not err, "negative_positive_stderr")
    value = json_value(out)
    need(
        value.get("schema") == "pamolive.expat-ushort-helper/1"
        and value.get("passed") is True
        and value.get("helper_uses_heap") is False,
        "negative_positive_selftest",
    )


def expected_refusal(args, source, log, case, header, *, evidence=None):
    need(case in GUARDS, "negative_case")
    if evidence is not None:
        evidence = Path(evidence)
        need(
            evidence.name == case
            and evidence.parent.name == "negative-guard-evidence"
            and evidence.parent.is_dir()
            and not evidence.parent.is_symlink(),
            "negative_evidence_path",
        )
        need(not evidence.exists() and not evidence.is_symlink(), "negative_evidence_exists")
    before = compiler_pin(args[0])
    try:
        command(args, source, log, seconds=20, cap=CAP)
    except ValueError as error:
        need(str(error) == "child_failed_or_unknown", "negative_exception")
    else:
        raise ValueError("negative_unexpected_success")
    after = compiler_pin(args[0])
    need(after == before, "negative_compiler_changed")
    # Capture each whitelisted file once. Validation, hashes and exported DATA
    # all consume these same buffers, never a second pathname read.
    buffers = {name: read(log / name, CAP) for name in EVIDENCE_FILES}
    out, err = buffers["stdout"], buffers["stderr"]
    facts = json_value(buffers["result.json"])
    lifecycle(facts, out, err)
    need(not out, "negative_stdout")
    need(json_value(buffers["pid.json"]) == {"pid": facts["pid"]}, "negative_pid")
    intent = json_value(buffers["intent.json"])
    need(
        intent
        == {
            "state": "PENDING",
            "argv": args,
            "tool_target": before["target"],
            "tool_sha256": before["sha256"],
        },
        "negative_intent",
    )
    unknown = buffers["unknown.json"]
    need(json_value(unknown) == {"state": "UNKNOWN"}, "negative_unknown_journal")
    count = diagnostics(err, case, header)
    result = {
        "case": case,
        "expected_guard": True,
        "diagnostic_count": count,
        "exit_code": facts["returncode"],
        "h1": facts,
        "tool_before": before,
        "tool_after": after,
        "common_unknown_retained_sha256": sha(unknown),
        "compiler_command_succeeded": False,
    }
    if evidence is not None:
        evidence.mkdir(mode=0o700)
        for name, body in buffers.items():
            write_new(evidence / name, body)
        result["evidence"] = {
            "schema": "pamolive.expat-negative-evidence/1",
            "path": "negative-guard-evidence/" + case,
            "files": {
                name: {"bytes": len(body), "sha256": sha(body)} for name, body in buffers.items()
            },
        }
    return result


def check_negative_guards(source, output):
    source, output = Path(source), Path(output)
    header = read(source / "srcw/tests" / HEADER, CAP)
    need(sha(header) == BUNDLE[HEADER], "negative_header_pin")
    selftest = read(source / "srcw/tests/test_character_support_selftest.c", CAP)
    need(sha(selftest) == BUNDLE["test_character_support_selftest.c"], "negative_selftest_pin")
    positive_prerequisite(output)
    private = output / "work/negative-guards"
    private.mkdir(mode=0o700)
    evidence = output / "negative-guard-evidence"
    evidence.mkdir(mode=0o700)
    cases = []
    for case in GUARDS:
        directory = private / case
        directory.mkdir(mode=0o700)
        copy = directory / HEADER
        write_new(copy, header, 0o400)
        probe = directory / "probe.c"
        write_new(probe, PROBE, 0o400)
        if case == "xmlchar":
            write_new(directory / "expat.h", FAKE, 0o400)
        args = ["/usr/bin/g++" if case == "cxx" else "/usr/bin/gcc"]
        args += (
            ["-x", "c++", "-std=c++17"]
            if case == "cxx"
            else ["-std=c99" if case == "c99" else "-std=c11"]
        )
        args += [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-DXML_UNICODE",
            "-fdiagnostics-format=json",
            "-fdiagnostics-color=never",
            "-fsyntax-only",
            "-I" + str(directory),
            "-I" + str(source / "srcw/lib"),
            str(probe),
        ]
        cases.append(
            expected_refusal(
                args, source, directory / "command", case, copy, evidence=evidence / case
            )
        )
        need(read(copy, CAP) == header and read(probe, CAP) == PROBE, "negative_probe_changed")
        if case == "xmlchar":
            need(read(directory / "expat.h", CAP) == FAKE, "negative_fake_changed")
    record(
        output / "NEGATIVE-GUARDS.json",
        {
            "schema": "pamolive.expat-negative-guards/1",
            "state": "EXPECTED_REFUSALS_RECEIVED",
            "header_sha256": sha(header),
            "probe_sha256": sha(PROBE),
            "fake_header_sha256": sha(FAKE),
            "cases": cases,
            "common_commands_admitted": False,
            "operational_GO": False,
            "CVE_closed": False,
        },
    )
