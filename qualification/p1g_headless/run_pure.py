"""Explicitly source contracts only; never confuse these with browser execution."""

import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
attempts = []


def audit(event, args):
    if (
        event.startswith(("socket.", "subprocess.", "ctypes.", "sqlite3."))
        or event in {"os.system", "os.exec", "os.fork", "os.posix_spawn"}
        or (
            event == "import"
            and args[0].split(".")[0]
            in {"django", "playwright", "pyexpat", "_elementtree", "psycopg", "psycopg2", "pyodbc"}
        )
    ):
        attempts.append(event)
        raise RuntimeError("pure_contract_external_attempt")


sys.addaudithook(audit)
from qualification.p1g_headless import test_contracts  # noqa: E402

log = io.StringIO()
result = unittest.TextTestRunner(stream=log, verbosity=2).run(
    unittest.defaultTestLoader.loadTestsFromModule(test_contracts)
)
value = {
    "tests": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skips": len(result.skipped),
    "external_attempts": attempts,
    "browser_or_SQL_executed": False,
    "log": log.getvalue(),
}
print(json.dumps(value))
raise SystemExit(0 if result.wasSuccessful() and not attempts and not result.skipped else 42)
