"""Run KMS adapter tests with only the two explicit component source roots."""

import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
COMPONENT = TESTS.parent
sys.path[:0] = [str(COMPONENT / "src"), str(COMPONENT.parent / "vault/src")]

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(TESTS))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.testsRun and result.wasSuccessful() and not result.skipped else 1)
