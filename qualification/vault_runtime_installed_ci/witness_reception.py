"""Run the W1 tests against their installed packages, without IO."""

import importlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path("/witness")
sys.path.insert(0, str(ROOT))
from witness_wheel import (  # noqa: E402
    MODULE,
    PREFIX,
    SITE,
    need,
    pins,
    read_regular,
    sha,
    verify_install,
)

FIXTURES = ROOT / "fixtures"
TESTS = FIXTURES / "tests"
TEST_MODULES = (
    "test_pure",
    "test_r2",
    "test_http_client",
    "test_history",
    "test_cold_history",
    "test_audit_archive",
    "test_archive_reader",
    "test_anchor_capture",
    "test_anchor_store",
    "test_recovery_cli",
    "test_recovery_manifest",
    "test_recovery_store",
    "test_signed_anchor",
)
TEST_COUNT = 143
attempts = []


def audit(event, _arguments):
    if event.startswith(("socket.", "subprocess.", "sqlite3.")) or event in {
        "os.system",
        "os.posix_spawn",
    }:
        attempts.append(event)
        raise AssertionError("I/O refused in installed witness tests")


def origin(name):
    module = importlib.import_module(name)
    need(Path(module.__file__).resolve(strict=True).is_relative_to(SITE))


def execute(report):
    need(sys.flags.isolated and sys.dont_write_bytecode and Path(sys.prefix) == PREFIX)
    for name, expected in pins(ROOT).items():
        if name.startswith(("tests/", "integration/")) or name == "sql/mirror.sql":
            need(sha(read_regular(FIXTURES / name, 65536)) == expected)
    report["phase"] = "installed_before_tests"
    before = verify_install()
    for name in (
        MODULE,
        "pamolive_vault_runtime",
        "pamolive_pam_trust_verifier",
        "pamolive_vault_contracts",
    ):
        origin(name)
    sys.path.insert(0, str(TESTS))
    sys.addaudithook(audit)
    import psycopg

    report["phase"] = "pure_tests"
    with (
        patch.object(psycopg, "connect", side_effect=AssertionError("SQL refused")),
        patch.object(psycopg.Connection, "connect", side_effect=AssertionError("SQL refused")),
    ):
        modules = [importlib.import_module(name) for name in TEST_MODULES]
        need(all(Path(m.__file__) == TESTS / (m.__name__ + ".py") for m in modules))
        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(m) for m in modules
        )
        need(suite.countTestCases() == TEST_COUNT)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    report.update(
        {
            "tests": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skips": len(result.skipped),
            "external_attempts": len(attempts),
        }
    )
    need(
        result.wasSuccessful()
        and result.testsRun == TEST_COUNT
        and not result.skipped
        and not attempts
    )
    report["phase"] = "installed_after_tests"
    need(verify_install() == before)
    report.update(before)
    report["source_index_sha256"] = sha(read_regular(ROOT / "witness-source.sha256", 16384))
    report["vault_input_sha256"] = sha(read_regular(Path("/inputs/descriptor.json"), 65536))
    report["phase"] = "complete"
    report["ok"] = True


if __name__ == "__main__":
    report = {
        "schema": "pamolive.witness-installed-pure/1",
        "phase": "inputs",
        "ok": False,
        "authority": False,
    }
    try:
        execute(report)
    except Exception:
        pass
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["ok"] else 42)
