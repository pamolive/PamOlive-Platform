"""Only safe preparation models. No native/crypto/XML or network execution."""

import io
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
attempts = []


def audit(event, args):
    if event == "import" and args[0].split(".")[0] in {
        "pyexpat",
        "_elementtree",
        "xml",
        "sqlite3",
        "psycopg",
        "psycopg2",
        "pyodbc",
    }:
        attempts.append("import:" + args[0])
        raise RuntimeError("pure_native_parser_or_db_refused")
    if event.startswith(("socket.", "subprocess.", "sqlite3.")) or event in {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.fork",
        "socket.connect",
        "socket.getaddrinfo",
        "ctypes.dlopen",
        "sqlite3.connect",
        "sqlite3.connect/handle",
    }:
        attempts.append(event)
        raise RuntimeError("pure_io_refused")


sys.addaudithook(audit)
import test_build_diagnostics  # noqa: E402 -- audit before tested module imports
import test_models  # noqa: E402 -- audit must be installed before importing tests
import test_negative_guard_tests  # noqa: E402 -- fake commands, same strict audit
import test_os_release  # noqa: E402 -- same audit protects the two fake-IO guards
import test_python_pgo  # noqa: E402 -- same audit covers pure optimization-policy models
import test_sanitizer_release  # noqa: E402 -- pinned release DATA and fake build commands
import test_wide_test_port  # noqa: E402 -- test-only ushort port boundaries

if len(sys.argv) == 3:
    test_models.MATERIALS = Path(sys.argv[2]).resolve()
suite = unittest.TestSuite(
    [
        unittest.defaultTestLoader.loadTestsFromModule(test_build_diagnostics),
        unittest.defaultTestLoader.loadTestsFromModule(test_models),
        unittest.defaultTestLoader.loadTestsFromModule(test_negative_guard_tests),
        unittest.defaultTestLoader.loadTestsFromModule(test_os_release),
        unittest.defaultTestLoader.loadTestsFromModule(test_python_pgo),
        unittest.defaultTestLoader.loadTestsFromModule(test_sanitizer_release),
        unittest.defaultTestLoader.loadTestsFromModule(test_wide_test_port),
    ]
)
log = io.StringIO()
result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
value = {
    "tests": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skips": len(result.skipped),
    "external_attempts": attempts,
    "log": log.getvalue(),
    "downloaded_payload_PGP_XML_parser_or_compiler_executed": False,
}
if len(sys.argv) not in (2, 3):
    raise SystemExit("usage NEW_RESULT_JSON [EXISTING_PINNED_MATERIALS_DIR]")
with Path(sys.argv[1]).open("x", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2)
print(json.dumps({k: v for k, v in value.items() if k != "log"}))
raise SystemExit(0 if result.wasSuccessful() and not attempts and not result.skipped else 42)
