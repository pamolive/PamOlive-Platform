"""Exactly 52 synthetic Vault tests; no listener, SQL, process or network reception."""

import importlib
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

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "components/vault/runtime"
LIBRARIES = {
    "pamolive_vault_runtime": RUNTIME,
    "pamolive_vault_contracts": ROOT / "components/vault-registry/src",
    "pamolive_pam_trust_verifier": ROOT / "components/pam-trust-verifier/src",
}
attempts = {}
sys.dont_write_bytecode = True


def refuse(*_args, **_kwargs):
    attempts["unplanned_external"] = attempts.get("unplanned_external", 0) + 1
    raise AssertionError("real operational IO forbidden")


def audit(event, _arguments):
    if event.startswith(("subprocess.", "socket.", "sqlite3.")) or event in {
        "os.system",
        "os.posix_spawn",
        "os.exec",
        "os.spawn",
    }:
        attempts[event] = attempts.get(event, 0) + 1
        raise AssertionError("real operational IO forbidden")


def main():
    started = time.monotonic()
    sys.addaudithook(audit)
    for path in (*LIBRARIES.values(), RUNTIME / "tests"):
        assert path.is_dir(), "required_checkout_source_missing"
        sys.path.insert(0, str(path))
    # Guard maintained driver entry points before importing tests. These are test
    # guards, not an OS sandbox or evidence of real database-role isolation.
    import psycopg

    with (
        patch.object(subprocess, "Popen", side_effect=refuse),
        patch.object(subprocess, "run", side_effect=refuse),
        patch.object(socket, "socket", side_effect=refuse),
        patch.object(socket, "create_connection", side_effect=refuse),
        patch.object(socket, "getaddrinfo", side_effect=refuse),
        patch.object(sqlite3, "connect", side_effect=refuse),
        patch.object(psycopg, "connect", side_effect=refuse),
        patch.object(psycopg.Connection, "connect", side_effect=refuse),
        patch.object(psycopg.AsyncConnection, "connect", side_effect=refuse),
        patch.object(urllib.request.OpenerDirector, "open", side_effect=refuse),
    ):
        modules = [
            importlib.import_module(name)
            for name in ("test_runtime", "test_ro_slot", "test_r2_boundaries")
        ]
        for name, directory in LIBRARIES.items():
            module = importlib.import_module(name)
            assert Path(module.__file__).resolve().is_relative_to(directory.resolve())
        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(module) for module in modules
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            {
                "type": "VAULT_RESERVATION_PURE_ONLY",
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skips": len(result.skipped),
                "external_attempts": attempts,
                "elapsed_seconds": time.monotonic() - started,
                "real_TLS_or_PostgreSQL_received_by_this_run": False,
                "authority": False,
            }
        )
    )
    raise SystemExit(
        0
        if result.testsRun == 52 and result.wasSuccessful() and not result.skipped and not attempts
        else 1
    )


if __name__ == "__main__":
    main()
