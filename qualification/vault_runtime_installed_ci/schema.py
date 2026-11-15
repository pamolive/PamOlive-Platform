"""Closed installed-Vault reports; no service, SQL or authority format."""

import hashlib
import json
import math
import re

CHILD = "pamolive.vault-runtime-installed-child/2"
PACKET = "pamolive.vault-runtime-installed-ci-packet/1"
MAX_CHILD = 320 * 1024
MAX_PACKET = 480 * 1024
MODULES = {
    "pamolive_vault_runtime": 8,
    "pamolive_vault_contracts": 3,
    "pamolive_pam_trust_verifier": 6,
}
FAILURES = {"NONE", "ENVIRONMENT", "ORIGIN", "FILES", "GUARD", "TESTS", "UNCLASSIFIED"}
ATTEMPTS = {
    "import.driver",
    "import.application_or_SDK",
    "socket.constructor",
    "DNS",
    "socket.connect",
    "sqlite3.connect",
    "subprocess.Popen",
    "file.mutation",
    "file.descriptor_open",
    "file.unresolved_path",
    "file.open_arguments",
    "file.write",
    "file.global_site",
    "file.read_outside_roots",
    "external.audit",
}
PROBES = {
    "socket.constructor",
    "DNS",
    "sqlite3.connect",
    "subprocess.Popen",
    "import.driver",
    "file.read_outside_roots",
}


def need(value):
    if not value:
        raise ValueError("vault_installed_schema_refused")


def digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def shape(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(count <= 8192 and depth <= 12)
        if type(item) is dict:
            need(len(item) <= 256)
            for key, child in item.items():
                need(type(key) is str and 0 < len(key) <= 128)
                pending.append((child, depth + 1))
        elif type(item) is list:
            need(len(item) <= 256)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            need(len(item) <= 4096)
        elif type(item) is int:
            need(-(2**63) <= item < 2**63)
        elif type(item) is float:
            need(-900 <= item <= 900 and math.isfinite(item))
        else:
            need(item is None or type(item) is bool)


def encode(value, maximum=MAX_CHILD):
    need(type(maximum) is int and 0 < maximum <= MAX_PACKET)
    shape(value)
    parts, size = [], 0
    for part in json.JSONEncoder(allow_nan=False, separators=(",", ":")).iterencode(value):
        raw = part.encode("utf-8")
        need(size + len(raw) + 1 <= maximum)
        parts.append(raw)
        size += len(raw)
    return b"".join(parts) + b"\n"


def parse(raw, maximum=MAX_CHILD):
    need(type(maximum) is int and 0 < maximum <= MAX_PACKET)
    need(type(raw) is bytes and 0 < len(raw) <= maximum)
    # Resource prepass only; stdlib retains syntax/UTF8 authority. Count all
    # string/container/scalar starts before decode/allocation, including keys.
    quoted = escaped = scalar = False
    depth = tokens = 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted, scalar = True, False
            tokens += 1
        elif byte in (91, 123):
            depth += 1
            tokens += 1
            scalar = False
        elif byte in (93, 125):
            depth -= 1
            scalar = False
        elif byte in b" \t\r\n,:":
            scalar = False
        elif not scalar:
            scalar = True
            tokens += 1
        need(depth <= 12 and tokens <= 8192)

    def unique(items):
        result = {}
        for key, child in items:
            need(key not in result)
            result[key] = child
        return result

    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _: need(False)
    )
    shape(value)
    return value


def counters(value, names):
    need(type(value) is dict and set(value) <= names)
    need(all(type(number) is int and 0 < number <= 64 for number in value.values()))


def child(value, expected_distributions):
    shape(value)
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "state",
            "authority",
            "venv",
            "installed",
            "tests",
            "attempts",
            "probes",
            "input_sha256",
            "elapsed_seconds",
            "failure_code",
            "exception_type",
        }
    )
    need(value["schema"] == CHILD and value["authority"] is False)
    need(type(value["state"]) is str and value["state"] in {"FAILED", "INSTALLED_RUNTIME_52_PASS"})
    need(digest(value["input_sha256"]))
    elapsed = value["elapsed_seconds"]
    need(type(elapsed) in (int, float) and 0 <= elapsed <= 900 and math.isfinite(elapsed))
    need(type(value["failure_code"]) is str and value["failure_code"] in FAILURES)
    need(
        value["exception_type"] is None
        or type(value["exception_type"]) is str
        and value["exception_type"] in {"ValueError", "ForbiddenIO", "AssertionError", "Other"}
    )
    counters(value["attempts"], ATTEMPTS)
    counters(value["probes"], PROBES)
    if value["venv"] is not None:
        need(type(value["venv"]) is dict and set(value["venv"]) == {"distributions", "origins"})
        need(value["venv"]["distributions"] == expected_distributions)
        origins = value["venv"]["origins"]
        need(type(origins) is dict and set(origins) == set(MODULES))
        for module, path in origins.items():
            need(
                type(path) is str
                and path == "lib/python3.12/site-packages/" + module + "/__init__.py"
            )
    if value["installed"] is not None:
        need(
            type(value["installed"]) is dict
            and set(value["installed"]) == {"modules", "files_matched", "sql_sha256", "site_PTH"}
        )
        need(value["installed"]["modules"] == MODULES)
        need(
            type(value["installed"]["files_matched"]) is int
            and 17 <= value["installed"]["files_matched"] <= 128
        )
        need(digest(value["installed"]["sql_sha256"]))
        need(type(value["installed"]["site_PTH"]) is int and value["installed"]["site_PTH"] == 0)
    if value["tests"] is not None:
        need(
            type(value["tests"]) is dict
            and set(value["tests"]) == {"run", "failures", "errors", "skips"}
        )
        need(all(type(number) is int and 0 <= number <= 52 for number in value["tests"].values()))
    if value["state"] == "INSTALLED_RUNTIME_52_PASS":
        need(value["failure_code"] == "NONE" and value["exception_type"] is None)
        need(not value["attempts"] and value["probes"] == dict.fromkeys(PROBES, 1))
        need(value["venv"] is not None and value["installed"] is not None)
        need(value["tests"] == {"run": 52, "failures": 0, "errors": 0, "skips": 0})
    else:
        need(value["failure_code"] != "NONE")
    return value


def packet(value, expected_distributions, code, *, expected_input_sha256, expected_sql_sha256):
    need(digest(expected_input_sha256) and digest(expected_sql_sha256))
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "ok",
            "authority",
            "child",
            "child_sha256",
            "child_bytes",
            "source_sha256",
            "attestation_verified",
        }
    )
    need(
        value["schema"] == PACKET
        and value["authority"] is False
        and value["attestation_verified"] is False
    )
    need(
        type(value["ok"]) is bool
        and digest(value["child_sha256"])
        and digest(value["source_sha256"])
    )
    need(type(value["child_bytes"]) is int and 0 < value["child_bytes"] <= MAX_CHILD)
    child(value["child"], expected_distributions)
    canonical = encode(value["child"])
    need(value["child_bytes"] == len(canonical))
    need(value["child_sha256"] == hashlib.sha256(canonical).hexdigest())
    success = value["child"]["state"] == "INSTALLED_RUNTIME_52_PASS"
    if success:
        need(value["child"]["input_sha256"] == expected_input_sha256)
        need(value["child"]["installed"]["sql_sha256"] == expected_sql_sha256)
    need(
        type(code) is int and code in (0, 42) and value["ok"] is success and (code == 0) is success
    )
    return value
