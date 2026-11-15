"""Phase2 workload envelope: early failure has no invented child observation."""

import schema
from adapter_v2 import distributions
from support import load, need, sha
from wheel_gate import PACKAGES

EXECUTION = "pamolive.vault-installed-workload-execution/2"
PACKET = "pamolive.vault-installed-workload-packet/2"
PHASES = {
    "venv-build",
    "venv-runtime",
    "no-pip-build",
    "no-pip-runtime",
    "bootstrap-build",
    "bootstrap-runtime",
    "install-build",
    "pipcheck-build",
    "probe-build",
    "wheel-verifier",
    "wheel-contracts",
    "wheel-runtime",
    "install-public",
    "install-internal",
    "pipcheck-runtime",
    "child52",
}


def execution(value, *, expected_source, expected_input, expected_sql, expected_materials):
    need(
        all(
            schema.digest(item)
            for item in (expected_source, expected_input, expected_sql, expected_materials)
        )
    )
    schema.shape(value)
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "state",
            "source_sha256",
            "materials_sha256",
            "processes",
            "build_environment",
            "built_wheels",
            "records",
            "pip_checks",
            "child",
            "input_sha256",
            "inputs_unchanged",
            "failure",
            "secondary_failure",
            "authority",
            "attestation_verified",
        }
    )
    need(
        value["schema"] == EXECUTION
        and value["authority"] is False
        and value["attestation_verified"] is False
    )
    need(value["source_sha256"] == expected_source and value["input_sha256"] == expected_input)
    need(value["materials_sha256"] == expected_materials)
    need(
        type(value["inputs_unchanged"]) is bool
        and type(value["state"]) is str
        and value["state"] in {"FAILED", "INSTALLED_VAULT_WORKLOAD_PASS"}
    )
    need(
        value["secondary_failure"]
        in (None, "INPUTS_CHANGED_OR_UNKNOWN", "REPORT_PERSISTENCE_FAILED")
    )
    if value["failure"] is not None:
        failure = value["failure"]
        need(type(failure) is dict and set(failure) == {"phase", "code", "exception_type"})
        need(
            type(failure["phase"]) is str
            and failure["phase"] in PHASES | {"prepare", "preflight", "post-check"}
        )
        need(
            type(failure["code"]) is str
            and failure["code"] in {"OWNED_PROCESS_FAILED", "DATA_OR_ENVIRONMENT_REFUSED"}
        )
        need(
            type(failure["exception_type"]) is str
            and failure["exception_type"] in {"Failed", "ValueError", "AssertionError", "Other"}
        )
    need(type(value["processes"]) is list and len(value["processes"]) <= 24)
    phases = []
    control = load("controller.py")
    for process in value["processes"]:
        need(
            type(process) is dict
            and set(process) == (control.IO_FIELDS - {"operation"}) | {"phase"}
        )
        need(
            type(process["phase"]) is str
            and process["phase"] in PHASES
            and process["phase"] not in phases
        )
        phases.append(process["phase"])
        # Failed observations may be unreaped/undrained; they are never success.
        for key in (
            "spawn_attempted",
            "owned_child_reaped",
            "drains_complete",
            "killed_owned_child",
        ):
            need(type(process[key]) is bool)
        for key in ("pid", "returncode"):
            need(
                process[key] is None
                or type(process[key]) is int
                and -(2**31) <= process[key] < 2**31
            )
        for key in ("stdout_bytes", "stderr_bytes"):
            need(type(process[key]) is int and 0 <= process[key] <= 8192)
        reasons = {
            "nonzero_exit",
            "timeout",
            "spawn_error",
            "controller_error",
            "reap_error",
            "drain_incomplete",
            "pipe_close_error",
            "stdout_overflow",
            "stderr_overflow",
            "stdout_read_contract",
            "stderr_read_contract",
            "stdout_drain_error",
            "stderr_drain_error",
        }
        need(
            process["reason"] is None
            or type(process["reason"]) is str
            and process["reason"] in reasons
        )
        exceptions = {
            "OSError",
            "ValueError",
            "RuntimeError",
            "AssertionError",
            "TypeError",
            "AttributeError",
            "TimeoutExpired",
            "FileNotFoundError",
            "PermissionError",
            "ProcessLookupError",
            "BrokenPipeError",
        }
        for key in ("exception_type", "cleanup_exception_type"):
            need(process[key] is None or type(process[key]) is str and process[key] in exceptions)
    need(type(value["pip_checks"]) is dict and set(value["pip_checks"]) == {"build", "runtime"})
    need(all(type(flag) is bool for flag in value["pip_checks"].values()))
    if value["build_environment"] is not None:
        need(
            type(value["build_environment"]) is dict
            and value["build_environment"]
            == {"pip": "26.3", "setuptools": "84.2.1", "wheel": "0.48.0", "packaging": "26.3"}
        )
    names = {name for name, _ in PACKAGES.values()}
    for collection, required in (
        (
            "built_wheels",
            {
                "name",
                "version",
                "wheel_sha256",
                "wheel_bytes",
                "wheel_RECORD_checked",
                "source_notice_metadata_exact",
            },
        ),
        (
            "records",
            {
                "name",
                "version",
                "RECORD_sha256",
                "files_checked",
                "wheel_source_notice_and_metadata_bound",
                "generated_pip_files_exact",
                "SQL_only_known_data_relocation",
            },
        ),
    ):
        need(type(value[collection]) is list and len(value[collection]) <= 3)
        seen = set()
        for item in value[collection]:
            need(type(item) is dict and set(item) == required)
            need(
                type(item["name"]) is str
                and item["name"] in names
                and item["name"] not in seen
                and item["version"] == "0.1.0a1"
            )
            seen.add(item["name"])
            if collection == "built_wheels":
                need(
                    schema.digest(item["wheel_sha256"])
                    and type(item["wheel_bytes"]) is int
                    and 0 < item["wheel_bytes"] <= 2 * 1024**2
                )
                need(
                    item["wheel_RECORD_checked"] is True
                    and item["source_notice_metadata_exact"] is True
                )
            else:
                need(schema.digest(item["RECORD_sha256"]) and type(item["files_checked"]) is int)
                expected_counts = dict(
                    zip(
                        (PACKAGES[kind][0] for kind in ("runtime", "verifier", "contracts")),
                        (17, 16, 11),
                        strict=True,
                    )
                )
                need(item["files_checked"] == expected_counts[item["name"]])
                need(item["wheel_source_notice_and_metadata_bound"] is True)
                need(
                    item["generated_pip_files_exact"]
                    == ["INSTALLER", "REQUESTED", "direct_url.json"]
                )
                need(
                    item["SQL_only_known_data_relocation"]
                    is (item["name"] == PACKAGES["runtime"][0])
                )
    if value["child"] is not None:
        schema.child(value["child"], distributions())
        need(value["child"]["input_sha256"] == expected_input)
    if value["state"] == "INSTALLED_VAULT_WORKLOAD_PASS":
        need(
            value["failure"] is None
            and value["secondary_failure"] is None
            and value["inputs_unchanged"]
        )
        need(set(phases) == PHASES and len(phases) == len(PHASES))
        for process in value["processes"]:
            need(
                control.io_record_released(
                    {
                        "operation": "run",
                        **{key: child for key, child in process.items() if key != "phase"},
                    }
                )
            )
            need(
                process["returncode"] == 0
                and process["reason"] is None
                and process["exception_type"] is None
            )
            need(process["spawn_attempted"] and not process["killed_owned_child"])
        need(value["pip_checks"] == {"build": True, "runtime": True})
        need(
            type(value["build_environment"]) is dict
            and value["build_environment"]
            == {"pip": "26.3", "setuptools": "84.2.1", "wheel": "0.48.0", "packaging": "26.3"}
        )
        need({item["name"] for item in value["built_wheels"]} == names)
        need({item["name"] for item in value["records"]} == names)
        need(value["child"] is not None and value["child"]["state"] == "INSTALLED_RUNTIME_52_PASS")
        need(value["child"]["installed"]["sql_sha256"] == expected_sql)
    return value


def packet(value, **bindings):
    execution(value, **bindings)
    raw = schema.encode(value)
    return {
        "schema": PACKET,
        "ok": value["state"] == "INSTALLED_VAULT_WORKLOAD_PASS",
        "execution": value,
        "execution_sha256": sha(raw),
        "execution_bytes": len(raw),
        "authority": False,
        "attestation_verified": False,
    }


def accept(value, code, **bindings):
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "ok",
            "execution",
            "execution_sha256",
            "execution_bytes",
            "authority",
            "attestation_verified",
        }
    )
    need(
        value["schema"] == PACKET
        and value["authority"] is False
        and value["attestation_verified"] is False
    )
    need(type(value["ok"]) is bool and type(value["execution_bytes"]) is int)
    checked = packet(value["execution"], **bindings)
    need(value == checked)
    need(type(code) is int and code in (0, 42) and (code == 0) is value["ok"])
    return value
