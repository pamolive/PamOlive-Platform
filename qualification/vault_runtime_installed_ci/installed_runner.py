"""Future installed52 child. No runtime import until policy/origin checks pass."""

import argparse
import importlib
import importlib.machinery
import importlib.metadata
import re
import site
import sys
import sysconfig
import time
import unittest
from pathlib import Path

CONTROLLER = Path(__file__).resolve().parent
sys.path.insert(0, str(CONTROLLER))

adapter_v2 = importlib.import_module("adapter_v2")
schema = importlib.import_module("schema")
guards = importlib.import_module("guards")
support = importlib.import_module("support")
APPLICATIONS, DRIVERS, REFERENCE = guards.APPLICATIONS, guards.DRIVERS, guards.REFERENCE
ForbiddenIO, Policy = guards.ForbiddenIO, guards.Policy
ROOT, load, need, read_regular, sha = (
    support.ROOT,
    support.load,
    support.need,
    support.read_regular,
    support.sha,
)
CAPTURE = load("entrypoint.py").Capture


def environment_probe(expected):
    prefix = Path(sys.prefix).resolve(strict=True)
    need(sys.prefix != sys.base_prefix and not site.ENABLE_USER_SITE)
    need(
        "include-system-site-packages = false"
        in REFERENCE.bounded_read(prefix / "pyvenv.cfg", 4096).decode().lower()
    )
    directories = REFERENCE.metadata_directories()
    items = list(importlib.metadata.distributions(path=directories))
    actual = {re.sub(r"[-_.]+", "-", row.metadata["Name"]).lower(): row.version for row in items}
    need(len(items) == len(actual) and actual == expected)
    need(all(Path(row.locate_file("")).resolve().is_relative_to(prefix) for row in items))
    for name in DRIVERS | APPLICATIONS | {"setuptools", "wheel", "packaging"}:
        need(name not in sys.modules)
        need(importlib.machinery.PathFinder.find_spec(name, list(directories)) is None)
    site_path = prefix / "lib/python3.12/site-packages"
    need(not list(site_path.rglob("*.pth")))
    origins = {}
    for module in schema.MODULES:
        need(module not in sys.modules)
        spec = importlib.machinery.PathFinder.find_spec(module, list(directories))
        wanted = site_path / module / "__init__.py"
        need(spec is not None and spec.origin is not None)
        need(Path(spec.origin) == wanted and wanted.resolve(strict=True) == wanted)
        origins[module] = wanted.relative_to(prefix).as_posix()
    return {"distributions": actual, "origins": origins}


def installed_probe(description):
    prefix = Path(sys.prefix).resolve(strict=True)
    base = prefix / "lib/python3.12/site-packages"
    count = 0
    for module, records in description["module_files"].items():
        directory = base / module
        actual = set()
        for path in directory.rglob("*"):
            need(not path.is_symlink())
            if path.is_file():
                relative = path.relative_to(directory).as_posix()
                actual.add(relative)
                need(relative in records)
                need(sha(REFERENCE.bounded_read(path, 1024**2)) == records[relative])
                count += 1
        need(actual == set(records))
    sql = prefix / "share/pamolive/vault-reservation/schema.sql"
    need(sql.resolve(strict=True) == sql)
    need(sha(REFERENCE.bounded_read(sql, 65536)) == description["sql_sha256"])
    need(not list(base.rglob("*.pth")))
    return {
        "modules": schema.MODULES.copy(),
        "files_matched": count + 1,
        "sql_sha256": description["sql_sha256"],
        "site_PTH": 0,
    }


def suite_tests(stage, *, importer=importlib.import_module):
    tests = stage / "tests"
    need(str(tests) not in sys.path)
    sys.path.insert(0, str(tests))
    try:
        for module in schema.MODULES:
            package = importer(module)
            need(Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()))
        modules = [
            importer(name) for name in ("test_runtime", "test_ro_slot", "test_r2_boundaries")
        ]
        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(module) for module in modules
        )
        # Test traceback text is bounded/discarded, never a public report field.
        capture = CAPTURE(8192, False)
        result = unittest.TextTestRunner(stream=capture, verbosity=0).run(suite)
        return {
            "run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skips": len(result.skipped),
        }
    finally:
        sys.path.remove(str(tests))


def execute(description, descriptor_sha256, stage, report_path):
    """Callable child workload only; parent build/install/launch is not implemented."""
    need(sys.platform == "linux" and sys.implementation.name == "cpython")
    need(sys.version_info[:3] == (3, 12, 16) and sys.base_prefix == "/usr/local")
    adapter_v2.descriptor(description)
    adapter_v2.validate_stage(stage, description["stage_files"])
    prefix = Path(sys.prefix).resolve(strict=True)
    need(prefix == Path("/work/vault-installed/runtime"))
    need(report_path == prefix.parent / "runtime-child-report.json" and not report_path.exists())
    policy = Policy(
        prefix=prefix,
        stdlib=sysconfig.get_path("stdlib"),
        stage=stage,
        controller=ROOT,
        report=report_path,
    )
    report = {
        "schema": schema.CHILD,
        "state": "FAILED",
        "authority": False,
        "venv": None,
        "installed": None,
        "tests": None,
        "attempts": {},
        "probes": {},
        "input_sha256": descriptor_sha256,
        "elapsed_seconds": 0,
        "failure_code": "ENVIRONMENT",
        "exception_type": None,
    }
    started = time.monotonic()
    # Hook/counters remain active through the one exclusive report write.
    with policy.install():
        try:
            policy.probe()
            need(dict(policy.guard.probes) == dict.fromkeys(schema.PROBES, 1))
            report["failure_code"] = "ORIGIN"
            report["venv"] = environment_probe(description["distributions"])
            report["failure_code"] = "FILES"
            report["installed"] = installed_probe(description)
            report["failure_code"] = "TESTS"
            report["tests"] = suite_tests(stage)
            need(report["tests"] == {"run": 52, "failures": 0, "errors": 0, "skips": 0})
            policy.guard.require_clean()
            report.update(state="INSTALLED_RUNTIME_52_PASS", failure_code="NONE")
        except BaseException as error:
            kind = type(error).__name__
            report["exception_type"] = (
                kind if kind in {"ForbiddenIO", "ValueError", "AssertionError"} else "Other"
            )
            if isinstance(error, ForbiddenIO) or policy.guard.attempts:
                report["failure_code"] = "GUARD"
        finally:
            report.update(
                attempts=dict(policy.guard.attempts),
                probes=dict(policy.guard.probes),
                elapsed_seconds=time.monotonic() - started,
            )
            schema.child(report, description["distributions"])
            raw = schema.encode(report)
            policy.report_enabled = True
            try:
                with report_path.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(raw.decode("utf-8"))
            finally:
                policy.report_enabled = False
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--descriptor-sha256", required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    need(sys.flags.isolated and sys.flags.dont_write_bytecode)
    raw = read_regular(args.descriptor, 65536)
    need(sha(raw) == args.descriptor_sha256)
    description = adapter_v2.descriptor(schema.parse(raw, 65536))
    result = execute(description, args.descriptor_sha256, args.stage, args.report)
    print(schema.encode({"state": result["state"], "authority": False}).decode(), end="")
    raise SystemExit(0 if result["state"] == "INSTALLED_RUNTIME_52_PASS" else 1)


if __name__ == "__main__":
    main()
