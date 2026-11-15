"""Exactly 42 synthetic adapter tests; closed checkout data, no package import."""

import hashlib
import json
import socket
import sqlite3
import subprocess
import sys
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
CODE = ROOT
SOURCE = ROOT.parents[1] / "components/pam-trust-verifier"
SOURCE_MANIFEST = "3628a50534a0bb37c142ffcee201ca3aaa232d926d13db65b552033627d1c340"
attempts = {}


def refuse(*_args, **_kwargs):
    attempts["unplanned_external"] = attempts.get("unplanned_external", 0) + 1
    raise AssertionError("real operational IO forbidden")


def main():
    assert (
        hashlib.sha256((SOURCE / "PAYLOAD-MANIFEST.json").read_bytes()).hexdigest()
        == "3628a50534a0bb37c142ffcee201ca3aaa232d926d13db65b552033627d1c340"
    )
    started = time.monotonic()
    sys.path.insert(0, str(CODE))
    with (
        patch.object(subprocess, "Popen", side_effect=refuse),
        patch.object(subprocess, "run", side_effect=refuse),
        patch.object(socket, "socket", side_effect=refuse),
        patch.object(socket, "getaddrinfo", side_effect=refuse),
        patch.object(sqlite3, "connect", side_effect=refuse),
        patch.object(urllib.request.OpenerDirector, "open", side_effect=refuse),
    ):
        import test_adapter_pure
        import test_child_failure_diagnostic

        # Fixture path only; source_payload still checks its closed 353-entry manifest.
        test_adapter_pure.SOURCE = SOURCE
        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(module)
            for module in (test_adapter_pure, test_child_failure_diagnostic)
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            {
                "type": "INSTALLED_CHILD_DIAGNOSTIC_PURE_ONLY",
                "run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skips": len(result.skipped),
                "external_attempts": attempts,
                "elapsed_seconds": time.monotonic() - started,
                "package_or_qualifier_main_executed": False,
                "source_fixture_manifest": SOURCE_MANIFEST,
            }
        )
    )
    raise SystemExit(
        0
        if result.testsRun == 42 and result.wasSuccessful() and not result.skipped and not attempts
        else 1
    )


if __name__ == "__main__":
    main()
