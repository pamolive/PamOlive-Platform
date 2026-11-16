"""Linux matching oracle for preserved actual source bodies, without KDC contact."""

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import command, read, record, write_new
from policy import HERE
from source_model import json_value, need, sha


def helper_region(raw):
    start = raw.index(b"/* Return the passed-in character, lower-cased")
    end = raw.index(b"static int\nverify_callback", start)
    return raw[start:end]


def verify_contract(raw, old):
    new = helper_region(raw)
    need(
        new.count(b"const X509 *x") == 5 and new.replace(b"const X509 *x", b"X509 *x") == old,
        "TLS_old_hostname_contract",
    )
    return new


def compile_failure_data(log):
    """Public TLS C compiler/linker only, following Expat publish_build_failure.

    Shared command captures are unchanged. This is diagnostic DATA, never success
    or proof of tool stability. No argv, environment or GPG/DEB log is read.
    """
    packet = {
        "schema": "pamolive.krb5-tls-compile-diagnostic/1",
        "scope": "PUBLIC_TLS_C_COMPILER_LINKER_ONLY",
        "stage": "TLS-hostname-compile",
        "state": "FAILED_OR_UNKNOWN",
        "classification": "H1_UNKNOWN",
        "diagnostic_only": True,
        "tool_stability_proved": False,
        "operational_GO": False,
        "root_cause": "UNKNOWN",
        "tail_raw_total_cap": 8192,
        "tail_priority": ["stderr", "stdout"],
        "facts": None,
    }
    captured = {}
    for name, cap in (("result.json", 4096), ("stdout", 2 * 1024**2), ("stderr", 2 * 1024**2)):
        try:
            raw = read(log / name, cap)
            need(type(raw) is bytes and len(raw) <= cap, "TLS_compile_capture_budget")
            captured[name] = raw
            packet[name] = {"available": True, "bytes": len(raw), "sha256": sha(raw)}
        except (OSError, ValueError, TypeError):
            packet[name] = {"available": False}
    try:
        facts = json_value(captured["result.json"])
        flags = {"spawn_attempted", "killed_owned_child", "owned_child_reaped", "drains_complete"}
        need(
            type(facts) is dict
            and set(facts)
            == flags
            | {
                "pid",
                "returncode",
                "reason",
                "exception_type",
                "cleanup_exception_type",
                "stdout_bytes",
                "stderr_bytes",
            },
            "TLS_compile_H1_shape",
        )
        need(
            all(type(facts[k]) is bool for k in flags)
            and all(
                type(facts[k]) is int and 0 <= facts[k] <= 2 * 1024**2
                for k in ("stdout_bytes", "stderr_bytes")
            )
            and (facts["pid"] is None or type(facts["pid"]) is int and 0 < facts["pid"] < 2**31)
            and (
                facts["returncode"] is None
                or type(facts["returncode"]) is int
                and -(2**31) <= facts["returncode"] < 2**31
            )
            and (facts["reason"] is None or type(facts["reason"]) is str),
            "TLS_compile_H1_shape",
        )
        packet["facts"] = {
            k: facts[k] for k in flags | {"pid", "returncode", "stdout_bytes", "stderr_bytes"}
        }
        packet["facts"].update(
            reason=facts["reason"]
            if facts["reason"]
            in {
                None,
                "nonzero_exit",
                "timeout",
                "stdout_overflow",
                "stderr_overflow",
                "combined_overflow",
            }
            else "OTHER_H1_REASON",
            exception_present=facts["exception_type"] is not None,
            cleanup_exception_present=facts["cleanup_exception_type"] is not None,
        )
        counts_match = all(
            k in captured and len(captured[k]) == facts[k + "_bytes"] for k in ("stdout", "stderr")
        )
        packet["retained_counts_match"] = counts_match
        normal = (
            facts["spawn_attempted"] is True
            and facts["pid"] is not None
            and facts["owned_child_reaped"] is facts["drains_complete"] is True
            and facts["killed_owned_child"] is False
            and facts["exception_type"] is facts["cleanup_exception_type"] is None
        )
        if normal and counts_match and type(facts["returncode"]) is int:
            if facts["reason"] == "nonzero_exit" and facts["returncode"] > 0:
                packet["classification"] = "NORMAL_NONZERO"
            elif facts["reason"] == "nonzero_exit" and facts["returncode"] < 0:
                packet["classification"] = "SIGNALLED"
            elif facts["reason"] is None and facts["returncode"] == 0:
                packet["classification"] = "RC0_CALLER_REFUSAL"
    except (KeyError, ValueError, TypeError, RecursionError):
        pass
    remaining = 8192
    for name in ("stderr", "stdout"):
        if name not in captured:
            continue
        data = captured[name]
        take = min(len(data), remaining)
        tail = data[len(data) - take :] if take else b""
        remaining -= take
        packet[name].update(
            tail_offset=len(data) - take,
            tail_bytes=take,
            tail_sha256=sha(tail),
            tail_base64=base64.b64encode(tail).decode("ascii"),
        )
    return packet


def compile_checked(args, cwd, log, seconds=60):
    try:
        return command(args, cwd, log, seconds=seconds)
    except BaseException:
        try:
            diagnostic = json.dumps(compile_failure_data(log), sort_keys=True)
            need(len(diagnostic.encode()) <= 16384, "TLS_compile_public_output_budget")
            print(diagnostic, flush=True)
        except BaseException:
            pass  # Diagnostic or console failure must never replace the original refusal.
        raise


def main(source, work):
    source, work = Path(source), Path(work)
    work.mkdir(mode=0o700)
    raw = read(source / "src/plugins/tls/k5tls/openssl.c", 1024**2)
    old = read(HERE / "TLS-old-hostname-contract.DATA.inc", 32768)
    helpers = verify_contract(raw, old)
    preamble = (
        b'#include "k5-int.h"\n#include "k5-utf8.h"\n#include <arpa/inet.h>\n'
        b"#include <openssl/x509.h>\n#include <openssl/x509v3.h>\n"
    )
    write_new(work / "hostname-helpers.inc", preamble + helpers)
    binary = work / "hostname-oracle"
    compile_checked(
        [
            "/usr/bin/cc",
            "-std=c99",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(source / "src/include"),
            "-I" + str(source / "build/include"),
            "-I" + str(work),
            str(HERE / "tls_hostname_oracle.c"),
            "-lssl",
            "-lcrypto",
            "-o",
            str(binary),
        ],
        work,
        work / "compile",
        seconds=60,
    )
    result = json_value(command([str(binary)], work, work / "run", seconds=10))
    need(
        result == {"cases": 12, "passed": 12, "certificate_chain_verified": False},
        "TLS_matching_result",
    )
    record(
        work / "TLS-HOSTNAME-DATA.json",
        {
            "actual_source_sha256": sha(raw),
            "actual_helper_region_sha256": sha(helpers),
            "old_helper_region_sha256": sha(old),
            "matching": result,
            "certificate_chain_or_AD_interop": "NOT_EXECUTED",
            "partial_label_wildcards_admitted": False,
            "operational_GO": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_configured_source_new_work")
    main(*sys.argv[1:])
