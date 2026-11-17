"""Finite source/data tests, never native tools or repository mutations."""

import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
attempts = []


def audit(event, args):
    if (
        event.startswith(("socket.", "subprocess.", "ctypes.", "sqlite3."))
        or event in {"os.system", "os.exec", "os.posix_spawn", "os.fork"}
        or (
            event == "import"
            and args[0].split(".")[0]
            in {"django", "psycopg", "psycopg2", "xml", "pyexpat", "_elementtree"}
        )
    ):
        attempts.append(event)
        raise RuntimeError("C_pure_external_IO_forbidden")


sys.addaudithook(audit)
spec = importlib.util.spec_from_file_location("c_tests", HERE / "tests/test_expat_apt.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
log = io.StringIO()
extra_spec = importlib.util.spec_from_file_location(
    "c_fence_tests", HERE / "tests/test_expat_apt_fence.py"
)
extra = importlib.util.module_from_spec(extra_spec)
sys.modules[extra_spec.name] = extra
extra_spec.loader.exec_module(extra)
suite = unittest.TestSuite(
    [
        unittest.defaultTestLoader.loadTestsFromModule(module),
        unittest.defaultTestLoader.loadTestsFromModule(extra),
    ]
)
result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
value = {
    "tests": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skips": len(result.skipped),
    "audit": attempts,
    "log": log.getvalue(),
    "native_tools_or_payloads_executed": False,
    "crypto_verification_mode": "fake native boundary; real codecs/data only",
}
target = Path(sys.argv[1])
with target.open("x", encoding="utf8") as output:
    json.dump(value, output, indent=2)
print(json.dumps({name: item for name, item in value.items() if name != "log"}))
if not result.wasSuccessful():
    print(log.getvalue())
raise SystemExit(0 if result.wasSuccessful() and not result.skipped and not attempts else 42)
