"""Portable DATA-only tests; explicit new output path."""

import io
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE.parents[1]))
attempts = []


def audit(event, args):
    if event.startswith(("socket.", "subprocess.", "ctypes.", "sqlite3.")) or event in {
        "os.system",
        "os.fork",
        "os.posix_spawn",
    }:
        attempts.append(event)
        raise RuntimeError("readonly_pure_external_refused")


sys.addaudithook(audit)
from qualification import test_public_fixture_parents  # noqa: E402
from qualification.build_origin import test_preflight  # noqa: E402

log = io.StringIO()
r = unittest.TextTestRunner(stream=log, verbosity=2).run(
    unittest.TestSuite(
        [
            unittest.defaultTestLoader.loadTestsFromModule(test_preflight),
            unittest.defaultTestLoader.loadTestsFromModule(test_public_fixture_parents),
        ]
    )
)
result = dict(
    tests=r.testsRun,
    failures=len(r.failures),
    errors=len(r.errors),
    skips=len(r.skipped),
    audit=attempts,
    log=log.getvalue(),
    native=False,
)
with Path(sys.argv[1]).open("x", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
print(json.dumps({k: v for k, v in result.items() if k != "log"}))
if not r.wasSuccessful():
    print(log.getvalue())
raise SystemExit(0 if r.wasSuccessful() and not attempts and not r.skipped else 42)
