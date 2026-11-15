"""Run synthetic protocol/lifecycle tests only; all real children/network/SQL refused."""

import json
import socket
import sqlite3
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch


def main():
    attempts = {}

    def refused(*_args, **_kwargs):
        attempts["unplanned_external_mock_call"] = (
            attempts.get("unplanned_external_mock_call", 0) + 1
        )
        raise AssertionError("real external operation forbidden in pure tests")

    def audit(event, _args):
        if event in {
            "subprocess.Popen",
            "socket.connect",
            "socket.bind",
            "socket.getaddrinfo",
            "sqlite3.connect",
        }:
            attempts[event] = attempts.get(event, 0) + 1
            raise AssertionError("external audit event forbidden")

    sys.addaudithook(audit)
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root))
    started = time.monotonic()
    with (
        patch.object(subprocess, "Popen", side_effect=refused),
        patch.object(subprocess, "run", side_effect=refused),
        patch.object(socket, "socket", side_effect=refused),
        patch.object(socket, "getaddrinfo", side_effect=refused),
        patch.object(sqlite3, "connect", side_effect=refused),
    ):
        suite = unittest.defaultTestLoader.discover(str(root), pattern="test_pipeline.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            {
                "type": "P2_RUNNER_PURE_TESTS_ONLY",
                "run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skips": len(result.skipped),
                "external_attempts": attempts,
                "elapsed_seconds": time.monotonic() - started,
                "authority": False,
            }
        )
    )
    raise SystemExit(0 if result.wasSuccessful() and not attempts else 1)


if __name__ == "__main__":
    main()
