"""N0 only. Audit installed before candidate imports; result path must be fresh."""

import io
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
if len(sys.argv) != 2 or Path(sys.argv[1]).resolve().is_relative_to(HERE):
    raise SystemExit("usage_NEW_RESULT_JSON_outside_source")
if Path(sys.argv[1]).exists():
    raise SystemExit("result_must_be_fresh")
attempts = []


def audit(event, args):
    if event.startswith(("socket.", "subprocess.", "ctypes.", "sqlite3.")) or event in {
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.fork",
    }:
        attempts.append(event)
        raise RuntimeError("N0_external_execution_refused")
    if event == "import" and args[0].split(".")[0] in {
        "pyexpat",
        "_elementtree",
        "xml",
        "psycopg",
        "psycopg2",
        "pyodbc",
        "playwright",
    }:
        attempts.append("import:" + args[0])
        raise RuntimeError("N0_product_parser_refused")


sys.addaudithook(audit)
import test_upgrade  # noqa: E402 -- audit precedes candidate imports

log = io.StringIO()
suite = unittest.defaultTestLoader.loadTestsFromModule(test_upgrade)
result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
value = {
    "tests": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skips": len(result.skipped),
    "external_attempts": attempts,
    "log": log.getvalue(),
    "native_GPG_compiler_Docker_KDC_executed": False,
    "strict_Linux_SBOM_schema_executed": False,
}
if len(sys.argv) != 2:
    raise SystemExit("usage_NEW_RESULT_JSON")
with Path(sys.argv[1]).open("x", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2)
print(json.dumps({key: value for key, value in value.items() if key != "log"}))
raise SystemExit(0 if result.wasSuccessful() and not result.skipped and not attempts else 42)
