"""Closed39 pure suite; stdout only, never rewrites a frozen result."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
ATTEMPTS = []


def audit(event, _args):
    if event.startswith(("socket.", "subprocess.", "sqlite3.", "ctypes.")) or event in {
        "os.system",
        "os.posix_spawn",
    }:
        ATTEMPTS.append(event)
        raise AssertionError("Operational IO forbidden")


def main():
    sys.addaudithook(audit)
    binding = json.loads((HERE / "bindings.json").read_bytes())
    for name, row in binding["files"].items():
        raw = (HERE / name).read_bytes()
        assert len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"]
    import test_deadline_rounding
    import test_owner
    import test_probe
    import test_r4

    suite = unittest.TestSuite(
        (
            unittest.defaultTestLoader.loadTestsFromTestCase(test_probe.ProbeTests),
            unittest.defaultTestLoader.loadTestsFromTestCase(test_owner.OwnerTests),
            unittest.defaultTestLoader.loadTestsFromTestCase(test_r4.R4Tests),
            unittest.defaultTestLoader.loadTestsFromTestCase(
                test_deadline_rounding.DeadlineRoundingTests
            ),
        )
    )
    assert suite.countTestCases() == 39
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            {
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skips": len(result.skipped),
                "external_attempts": ATTEMPTS,
                "real_probe_executed": False,
            }
        )
    )
    return (
        0
        if result.wasSuccessful() and result.testsRun == 39 and not result.skipped and not ATTEMPTS
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
