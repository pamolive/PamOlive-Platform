"""Controlled stdout exporter: no run on import; qualifier remains byte-pinned."""

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import json
import math
import os
import stat
import sys
from pathlib import Path

QUALIFIER_SHA = "649ac99037fc41fa24b80fe93bd6833dd968dbdbaf879f51127d25972b5f4878"
ADAPTER_PLAN_SHA = "46b9bc5562fc33a9c4081293ff5a6f002eca3714e0e209bbcd9b359e5832ccf1"
PAYLOAD_SHA = "3628a50534a0bb37c142ffcee201ca3aaa232d926d13db65b552033627d1c340"
MATERIALS_SHA = "9984894027d99aa19b51625f1f73ee106272635120d832d7d1fede94243b9d74"
WORK = Path("/work/installed-verifier")
PACKET_MAX = 480 * 1024
EXECUTION_MAX = 320 * 1024
SUCCESS = "INSTALLED_VERIFIER_30_MATCHES_CANDIDATE_PUBLIC_FIXTURES"
EXECUTION_KEYS = frozenset(
    {
        "schema",
        "state",
        "authority",
        "build_verified",
        "attestation_verified",
        "processes",
        "package_version",
        "tests_expected",
        "source_manifest_sha256",
        "materials_plan_sha256",
        "source_payload",
        "public_wheels",
        "built_wheel",
        "venvs",
        "tests",
        "source_test_fallback",
        "new_P0_run",
        "context_administration",
        "full_P0_acceptance",
        "proof_of_possession_or_MFA_or_counters",
        "inputs_after_hashes_unchanged",
        "staged_inputs_hashes_unchanged",
        "elapsed_seconds",
        "no_index_is_not_OS_network_isolation",
        "hard_resource_quota_claimed",
        "exception_type",
    }
)
FORBIDDEN_EXPORT_KEYS = {
    "stdout",
    "stderr",
    "logs",
    "env",
    "secret",
    "password",
    "private_key",
    "wheel_bytes",
}


class Refusal(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def shape(value):
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        need(nodes <= 25000 and depth <= 24, "PUBLIC_STRUCTURE")
        if type(item) is dict:
            need(len(item) <= 2048, "PUBLIC_MAP")
            for key, child in item.items():
                need(
                    type(key) is str and len(key) <= 512 and key not in FORBIDDEN_EXPORT_KEYS,
                    "PUBLIC_KEY",
                )
                pending.append((child, depth + 1))
        elif type(item) is list:
            need(len(item) <= 2048, "PUBLIC_LIST")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            need(len(item) <= 4096, "PUBLIC_STRING")
        elif type(item) is float:
            need(math.isfinite(item), "PUBLIC_NUMBER")
        else:
            need(item is None or type(item) in (bool, int), "PUBLIC_TYPE")


def encode(value, maximum=PACKET_MAX):
    shape(value)
    chunks, total = [], 0
    for chunk in json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).iterencode(value):
        data = chunk.encode("utf-8")
        need(total + len(data) + 1 <= maximum, "PUBLIC_OUTPUT_BUDGET")
        total += len(data)
        chunks.append(data)
    return b"".join(chunks) + b"\n"


def parse(raw, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, "PUBLIC_INPUT_BUDGET")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= 24, "PUBLIC_INPUT_DEPTH")
        elif byte in (93, 125):
            depth -= 1

    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "PUBLIC_DUPLICATE")
            result[key] = value
        return result

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique,
        parse_constant=lambda _: need(False, "PUBLIC_NONFINITE"),
    )
    shape(value)
    return value


def regular(path, maximum):
    path = Path(path)
    for parent in path.parents:
        need(stat.S_ISDIR(parent.lstat().st_mode), "PUBLIC_PARENT_ALIAS")
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum,
        "PUBLIC_FILE_TYPE_SIZE",
    )
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        need(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size)
            and stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1,
            "PUBLIC_OPEN_IDENTITY",
        )
        raw = stream.read(maximum + 1)
    need(len(raw) == before.st_size and len(raw) <= maximum, "PUBLIC_READ_BUDGET")
    return raw


class Capture:
    def __init__(self, maximum, retain):
        self.maximum, self.retain, self.total, self.chunks = maximum, retain, 0, []

    def write(self, text):
        need(type(text) is str and len(text) <= self.maximum, "PARENT_TEXT_BUDGET")
        raw = text.encode("utf-8")
        need(self.total + len(raw) <= self.maximum, "PARENT_OUTPUT_BUDGET")
        self.total += len(raw)
        if self.retain:
            self.chunks.append(raw)
        return len(text)

    def flush(self):
        return None

    def bytes(self):
        return b"".join(self.chunks)


def profile(status, mounts):
    values = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    need(
        values["Uid"].split() == ["1000"] * 4 and values["Gid"].split() == ["1000"] * 4,
        "ENTRY_UID_GID",
    )
    need(values["NoNewPrivs"].strip() == "1", "ENTRY_NNP")
    need(set(values["Groups"].split()) <= {"1000"}, "ENTRY_GROUPS")
    need(
        all(
            int(values[key].strip(), 16) == 0
            for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")
        ),
        "ENTRY_CAPS",
    )
    table = {line.split()[1]: line.split() for line in mounts.splitlines()}
    need("ro" in table["/"][3].split(","), "ENTRY_ROOT_RO")
    for target in ("/controller", "/source", "/materials"):
        need("ro" in table[target][3].split(","), "ENTRY_INPUT_RO")
    for target in ("/work", "/tmp"):
        need(
            table[target][2] == "tmpfs"
            and {"rw", "nosuid", "nodev"} <= set(table[target][3].split(",")),
            "ENTRY_TMPFS",
        )
    need(
        "noexec" not in table["/work"][3].split(",") and "noexec" in table["/tmp"][3].split(","),
        "ENTRY_TMPFS_EXEC",
    )


def check_execution(value):
    need(type(value) is dict and set(value) <= EXECUTION_KEYS, "PUBLIC_EXECUTION_SCHEMA")
    need(
        value.get("schema") == "pamolive.public-pam-verifier-installed-qualification/1",
        "PUBLIC_EXECUTION_TYPE",
    )
    need(
        value.get("authority") is False
        and value.get("build_verified") is False
        and value.get("attestation_verified") is False,
        "PUBLIC_EXECUTION_AUTHORITY",
    )
    need(
        value.get("source_manifest_sha256") == PAYLOAD_SHA
        and value.get("materials_plan_sha256") == MATERIALS_SHA,
        "PUBLIC_EXECUTION_PINS",
    )
    shape(value)
    return value


def parse_summary(raw):
    value = parse(raw, 8192)
    need(
        type(value) is dict
        and set(value) == {"state", "methods", "authority"}
        and value["state"] == SUCCESS
        and type(value["methods"]) is int
        and value["methods"] == 30
        and value["authority"] is False,
        "PARENT_SUMMARY",
    )
    return value


def success(value, summary):
    check_execution(value)
    need(summary == {"state": SUCCESS, "methods": 30, "authority": False}, "PARENT_SUMMARY")
    need(
        value["state"] == SUCCESS
        and type(value["tests_expected"]) is int
        and value["tests_expected"] == 30
        and value["inputs_after_hashes_unchanged"] is True
        and value["staged_inputs_hashes_unchanged"] is True
        and value["source_test_fallback"] is False
        and value["new_P0_run"] is False,
        "PUBLIC_SUCCESS_UNPROVEN",
    )
    tests = value["tests"]
    need(all(type(count) is int for count in tests["tests"].values()), "PUBLIC_TEST_COUNT_TYPES")
    need(
        tests["tests"] == {"run": 30, "failures": 0, "errors": 0, "skips": 0}, "PUBLIC_TEST_COUNTS"
    )
    need(
        len(tests["case_comparisons"]) == 20
        and all(row["matches"] is True for row in tests["case_comparisons"]),
        "PUBLIC_COMPARISONS",
    )
    for child in (*value["venvs"].values(), tests):
        need(
            not child["forbidden_attempts"]
            and len(child["intentional_guard_probes"]) == 6
            and all(
                type(count) is int and count == 1
                for count in child["intentional_guard_probes"].values()
            ),
            "PUBLIC_GUARD_COUNTS",
        )
    need(
        len(value["venvs"]["build"]["venv"]["distributions"]) == 4
        and len(value["venvs"]["verifier"]["venv"]["distributions"]) == 11,
        "PUBLIC_DISTRIBUTIONS",
    )
    need(
        0 < len(value["processes"]) <= 32
        and all(
            type(row["returncode"]) is int
            and row["returncode"] == 0
            and row["reason"] is None
            and row["owned_child_reaped"] is True
            and row["drains_complete"] is True
            for row in value["processes"]
        ),
        "PUBLIC_PROCESSES",
    )


def load_qualifier(raw, pathname="/controller/qualify_installed.py"):
    need(sha(raw) == QUALIFIER_SHA, "QUALIFIER_PIN")

    class Loader(importlib.machinery.SourceFileLoader):
        def get_code(self, _fullname):
            return compile(raw, pathname, "exec", dont_inherit=True)

    name = "p2_ci_pinned_qualifier"
    loader = Loader(name, pathname)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def packet(execution, execution_raw, summary, code, exception_type=None):
    return {
        "schema": "pamolive.p2-installed-stdout-public/1",
        "phase": "installed_public_v1_materials_only",
        "ok": code == "INSTALLED_PUBLIC_FIXTURES_PASS",
        "code": code,
        "qualifier_sha256": QUALIFIER_SHA,
        "adapter_plan_sha256": ADAPTER_PLAN_SHA,
        "payload_manifest_sha256": PAYLOAD_SHA,
        "materials_plan_sha256": MATERIALS_SHA,
        "execution_sha256": sha(execution_raw) if execution_raw else None,
        "execution_bytes": len(execution_raw) if execution_raw else None,
        "execution": execution,
        "parent_summary": summary,
        "exception_type": exception_type,
        "authority": False,
        "build_verified": False,
        "attestation_verified": False,
        "full_P0_acceptance": False,
        "human_independence": False,
        "Vault_binding": False,
    }


def main():
    execution, raw, summary, caught = None, None, None, None
    code = "ENTRY_REFUSED"
    output, discarded = Capture(8192, True), Capture(8192, False)
    try:
        profile(Path("/proc/self/status").read_text(), Path("/proc/mounts").read_text())
        qualifier = load_qualifier(regular("/controller/qualify_installed.py", 1024 * 1024))
        sys.argv = [
            "qualify_installed.py",
            "run",
            "--plan-sha256",
            ADAPTER_PLAN_SHA,
            "--source",
            "/source",
            "--materials",
            "/materials",
            "--work",
            str(WORK),
        ]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(discarded):
            qualifier.main()
        summary = parse_summary(output.bytes())
        code = "QUALIFIER_COMPLETED_EXPORT_PENDING"
    except BaseException as error:
        caught = (
            type(error).__name__
            if type(error).__name__
            in {"Refusal", "ValueError", "OSError", "SystemExit", "MemoryError"}
            else "QualificationFailure"
        )
    try:
        raw = regular(WORK / "execution.json", EXECUTION_MAX)
        execution = check_execution(parse(raw, EXECUTION_MAX))
        if caught is None:
            success(execution, summary)
            code = "INSTALLED_PUBLIC_FIXTURES_PASS"
        else:
            code = "QUALIFIER_FAILED"
    except BaseException:
        execution, raw = None, None
        code = "PUBLIC_EXECUTION_UNAVAILABLE_OR_REFUSED"
    result = packet(execution, raw, summary, code, caught)
    try:
        encoded = encode(result)
    except BaseException:
        result = packet(None, None, None, "PUBLIC_EXPORT_BUDGET_REFUSED")
        encoded = encode(result)
    sys.__stdout__.buffer.write(encoded)
    sys.__stdout__.buffer.flush()  # Export occurs while /work tmpfs still exists.
    raise SystemExit(0 if result["ok"] else 42)


if __name__ == "__main__":
    main()
