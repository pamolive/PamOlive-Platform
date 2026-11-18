"""Source tests only; importing Django/browser/SQL/native libraries is forbidden."""

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
        or event == "import"
        and args[0].split(".")[0]
        in {
            "django",
            "playwright",
            "asyncssh",
            "uvicorn",
            "psycopg",
            "sqlite3",
            "pyodbc",
            "xml",
            "pyexpat",
            "_elementtree",
        }
    ):
        attempts.append(event)
        raise RuntimeError("CHROME_PURE_EXTERNAL_FORBIDDEN")


sys.addaudithook(audit)
sys.path.insert(0, str(Path(__file__).resolve().parent / "gpg_fixture"))
suite = unittest.TestSuite()
for name in ("test_chrome_bootstrap", "test_chrome_key_scope", "test_chrome_bundle"):
    module = __import__("qualification.p1g_headless." + name, fromlist=[name])
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
sys.path.insert(0, str(Path(__file__).resolve().parent / "gpg_fixture"))
fixture = __import__("test_fixture")
suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(fixture))
log = io.StringIO()
result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
print(
    json.dumps(
        {
            "tests": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skips": len(result.skipped),
            "external_attempts": attempts,
            "log": log.getvalue(),
            "GPG_DEB_Chrome_SQL_executed": False,
        }
    )
)
raise SystemExit(0 if result.wasSuccessful() and not result.skipped and not attempts else 42)
