"""Future S0 entrypoint; no listener/SQL or new host lifecycle implementation."""

import argparse
import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
orchestrate = importlib.import_module("orchestrate")
adapter = importlib.import_module("adapter_v2")
schema = importlib.import_module("schema")
workload = importlib.import_module("workload_schema")
support = importlib.import_module("support")


def failed(bindings, error):
    return {
        "schema": workload.EXECUTION,
        "state": "FAILED",
        "source_sha256": bindings["expected_source"],
        "materials_sha256": bindings["expected_materials"],
        "processes": [],
        "build_environment": None,
        "built_wheels": [],
        "records": [],
        "pip_checks": {"build": False, "runtime": False},
        "child": None,
        "input_sha256": bindings["expected_input"],
        "inputs_unchanged": False,
        "failure": {
            "phase": "preflight",
            "code": "DATA_OR_ENVIRONMENT_REFUSED",
            "exception_type": type(error).__name__
            if type(error) in (ValueError, AssertionError)
            else "Other",
        },
        "secondary_failure": None,
        "authority": False,
        "attestation_verified": False,
    }


def proc(path, cap):
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    support.need(len(raw) <= cap)
    return raw.decode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    for field in ("source", "input", "sql", "materials"):
        parser.add_argument("--expected-" + field, required=True)
    args = parser.parse_args()
    bindings = {
        "expected_" + field: getattr(args, "expected_" + field)
        for field in ("source", "input", "sql", "materials")
    }
    support.need(all(schema.digest(value) for value in bindings.values()))
    try:
        support.load("entrypoint.py").profile(
            proc(Path("/proc/self/status"), 65536), proc(Path("/proc/self/mountinfo"), 262144)
        )
        support.need(bindings["expected_source"] == orchestrate.PAYLOAD_SHA)
        support.need(
            bindings["expected_materials"] == adapter.MATERIALS
            and bindings["expected_sql"] == adapter.SQL_SHA
        )
        payload, _ = orchestrate.source_payloads()
        support.need(
            bindings["expected_input"]
            == support.sha(schema.encode(orchestrate.description(payload)))
        )
        report = orchestrate.run(Path("/materials"))
    except BaseException as error:
        report = failed(bindings, error)
    packet = workload.packet(report, **bindings)
    raw = schema.encode(packet, schema.MAX_PACKET)
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()  # Export before the container/work tmpfs disappears.
    raise SystemExit(0 if packet["ok"] else 42)


if __name__ == "__main__":
    main()
