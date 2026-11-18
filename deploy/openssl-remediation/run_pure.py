"""Standalone read-only stdlib tests: python -I -B -S deploy/openssl-remediation/run_pure.py."""

import importlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


def main():
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.flags.ignore_environment
    ):
        raise SystemExit("Use python -I -B -S for the SOURCE-only test runner.")
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    attempts = []
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def audit(event, args):
        if event.startswith(("socket.", "subprocess.", "ctypes.", "sqlite3.")) or event in {
            "os.system",
            "os.exec",
            "os.fork",
            "os.posix_spawn",
            "os.remove",
            "os.rename",
            "os.rmdir",
            "os.mkdir",
            "os.chmod",
            "os.chown",
            "os.link",
            "os.symlink",
        }:
            attempts.append(event)
            raise RuntimeError("OPENSSL_PURE_EXTERNAL_OR_MUTATION_FORBIDDEN")
        if event == "open":
            _, mode, flags = args
            if (
                (isinstance(mode, str) and any(c in mode for c in "wax+"))
                or isinstance(flags, int)
                and flags & write_flags
            ):
                attempts.append("file_write")
                raise RuntimeError("OPENSSL_PURE_WRITE_FORBIDDEN")

    sys.addaudithook(audit)
    names = [
        "test_data_contracts",
        "test_hardening_r2",
        "test_fifo_r3",
        "test_independent_contracts",
        "test_publication",
    ]
    modules = [importlib.import_module(name) for name in names]
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromModule(module) for module in modules
    )
    log = io.StringIO()
    # Only source_text actors use this Linux constant: their opens are already mocked.
    # No native syscall or FIFO is exercised; original test semantics are preserved.
    with patch.object(os, "O_NONBLOCK", modules[2].NONBLOCK, create=True):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    report = {
        "schema": "pamolive.openssl-pure-tests/1",
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "skipped_tests": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        "forbidden_attempts": attempts,
        "scope": "SOURCE stdlib actors and UTF8 only; no Linux/GPG/archives/ELF/native/network",
        "build_verified": False,
        "CVE_closed": 0,
        "operational_GO": False,
    }
    print(json.dumps(report, sort_keys=True))
    if not result.wasSuccessful():
        print(log.getvalue(), file=sys.stderr)
    return 0 if result.wasSuccessful() and not result.skipped and not attempts else 42


if __name__ == "__main__":
    raise SystemExit(main())
