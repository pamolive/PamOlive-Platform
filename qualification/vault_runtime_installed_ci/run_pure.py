"""Only mocked seam/schema/guard tests. Prints summary; never rewrites a gel."""

import importlib
import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
attempts = {}
support = importlib.import_module("support")
IDS_SHA = "46b13c9fdfbbccbd2d1e235bdc2c8e14a98fc702496fb3867b8597191a81e7e4"
PRODUCTION = {
    "pamolive_vault_runtime",
    "pamolive_vault_contracts",
    "pamolive_pam_trust_verifier",
    "django",
    "config",
    "platform_core",
    "platform_modules",
    "pamolive_vault_envelope",
}


def expected_ids():
    raw = support.read_regular(ROOT / "test-ids.json", 32768)
    support.need(support.sha(raw) == IDS_SHA)
    value = json.loads(raw)
    support.need(
        set(value) == {"schema", "ids"}
        and value["schema"] == "pamolive.vault-installed-pure-test-ids/1"
    )
    names = value["ids"]
    support.need(type(names) is list and len(names) == len(set(names)) == 65)
    support.need(all(type(name) is str and 0 < len(name) <= 256 for name in names))
    return set(names)


def suite_ids(suite):
    if isinstance(suite, unittest.TestSuite):
        return [name for item in suite for name in suite_ids(item)]
    support.need(isinstance(suite, unittest.TestCase))
    name = suite.id()
    support.need(type(name) is str and 0 < len(name) <= 256)
    return [name]


def production_imports():
    return sorted(
        name
        for name in PRODUCTION
        if any(module == name or module.startswith(name + ".") for module in sys.modules)
    )


def audit(event, _values):
    if event.startswith(("socket.", "sqlite3.")) or event in {
        "subprocess.Popen",
        "os.system",
        "os.posix_spawn",
        "os.exec",
        "os.spawn",
    }:
        attempts[event] = attempts.get(event, 0) + 1
        raise AssertionError("pure_external_IO_refused")


def main():
    sys.addaudithook(audit)
    started = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(ROOT), pattern="test_*.py")
    names = suite_ids(suite)
    support.need(len(names) == 65 and len(set(names)) == 65 and set(names) == expected_ids())
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {
        "run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "seconds": time.monotonic() - started,
        "external_attempts": attempts,
        "runtime_package_imported": "pamolive_vault_runtime" in sys.modules,
        "production_packages_imported": production_imports(),
        "expected_test_ids_matched": True,
    }
    print(json.dumps(summary))
    raise SystemExit(
        not result.wasSuccessful()
        or result.testsRun != 65
        or bool(result.skipped)
        or bool(attempts)
        or bool(summary["production_packages_imported"])
    )


if __name__ == "__main__":
    main()
