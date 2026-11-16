"""Run only the small source/graph tests; write solely to a fresh output directory."""

import io
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
attempts = []


def audit(event, args):
    if event in {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.fork",
        "socket.connect",
        "socket.getaddrinfo",
        "ctypes.dlopen",
    }:
        attempts.append(event)
        raise RuntimeError("pure_external_refused")


if len(sys.argv) not in (2, 3):
    raise SystemExit("usage NEW_OUTPUT_DIRECTORY [PINNED_PG_REFERENCE_DIRECTORY]")
output = Path(sys.argv[1])
output.mkdir(mode=0o700)
sys.addaudithook(audit)
import test_source  # noqa: E402 -- install audit before loading tested modules

test_source.WORK = output
if len(sys.argv) == 3:
    test_source.PG_REFERENCE = Path(sys.argv[2])
suite = unittest.defaultTestLoader.loadTestsFromModule(test_source)
log = io.StringIO()
result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
value = {
    "tests": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skips": len(result.skipped),
    "external_attempts": attempts,
    "log": log.getvalue(),
    "Linux_Docker_sudo_ctr_pull_or_PG_executed": False,
}
with (output / "report.json").open("x", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2)
print(json.dumps({k: v for k, v in value.items() if k != "log"}))
raise SystemExit(0 if result.wasSuccessful() and not attempts and not result.skipped else 42)
