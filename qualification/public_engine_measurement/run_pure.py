"""Only fake runners/FDs. No operational entry point is called."""

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
ATTEMPTS = []


def audit(event, _args):
    if event.startswith(("socket.", "subprocess.", "sqlite3.", "ctypes.")) or event in {
        "os.system",
        "os.posix_spawn",
    }:
        ATTEMPTS.append(event)
        raise AssertionError("operational IO forbidden")


def main():
    sys.addaudithook(audit)
    import test_cli_identity
    import test_collector
    import test_containerd_public
    import test_env_contract
    import test_runtime_compatibility
    import test_version_format

    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        for cls in (
            test_cli_identity.CliIdentityTests,
            test_collector.CollectorTests,
            test_containerd_public.PublicTests,
            test_containerd_public.ParentTests,
            test_runtime_compatibility.ToolCompatibilityTests,
            test_runtime_compatibility.ParentDiagnosticTests,
            test_env_contract.EnvToolTests,
            test_env_contract.ParentEnvTests,
            test_version_format.VersionFormatTests,
        )
    )
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    row = {
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "external_attempts": ATTEMPTS,
        "all_processes_fake": True,
        "Linux_FDs_fake": True,
        "Docker_sudo_ctr_executed": False,
    }
    print(json.dumps(row))
    return (
        0
        if result.wasSuccessful() and result.testsRun == 65 and not result.skipped and not ATTEMPTS
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
