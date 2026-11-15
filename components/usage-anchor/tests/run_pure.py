"""Source-only real-crypto unit tests; explicitly no SQL/network/listener/process."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for entry in (
    "components/usage-anchor",
    "components/usage-anchor/tests",
    "components/vault/runtime",
    "components/vault-registry/src",
    "components/pam-trust-verifier/src",
):
    sys.path.insert(0, str(ROOT / entry))
sys.dont_write_bytecode = True
attempts = []


def audit(event, arguments):
    if event.startswith(("socket.", "subprocess.", "sqlite3.")) or event in {
        "os.system",
        "os.posix_spawn",
    }:
        attempts.append(event)
        raise AssertionError("operational IO forbidden in pure tests")


if __name__ == "__main__":
    sys.addaudithook(audit)
    from unittest.mock import patch

    import psycopg

    with (
        patch.object(psycopg, "connect", side_effect=AssertionError("SQL forbidden")),
        patch.object(psycopg.Connection, "connect", side_effect=AssertionError("SQL forbidden")),
    ):
        import test_http_client
        import test_pure
        import test_r2

        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(module)
            for module in (test_pure, test_r2, test_http_client)
        )
        if suite.countTestCases() != 62:
            raise SystemExit("Closed62 methods required, including original59")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            {
                "type": "W1_SOURCE_PURE_REAL_SYNTHETIC_SIGNATURES",
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skips": len(result.skipped),
                "external_attempts": attempts,
                "real_SQL_TLS_or_host_received": False,
            },
            sort_keys=True,
        )
    )
    raise SystemExit(
        0
        if result.wasSuccessful() and result.testsRun == 62 and not result.skipped and not attempts
        else 1
    )
