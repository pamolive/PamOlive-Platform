"""Closed eight fake-runner tests. No collector main or real Docker invocation."""

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
ATTEMPTS = []


def audit(event, _args):
    if event.startswith(("socket.", "subprocess.", "sqlite3.")) or event in {
        "os.system",
        "os.posix_spawn",
    }:
        ATTEMPTS.append(event)
        raise AssertionError("Operational IO forbidden in pure tests")


def main():
    sys.addaudithook(audit)
    import test_collector

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_collector.CollectorTests)
    assert suite.countTestCases() == 8
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            {
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skips": len(result.skipped),
                "external_attempts": ATTEMPTS,
                "Docker_executed": False,
            }
        )
    )
    return (
        0
        if result.wasSuccessful() and result.testsRun == 8 and not result.skipped and not ATTEMPTS
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
