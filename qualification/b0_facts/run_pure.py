"""Run new and unchanged legacy units with all real child/network creation forbidden."""

import importlib.util
import io
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def main():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT))
    temporary = ROOT / "test-temp"
    temporary.mkdir(exist_ok=True)
    modules = []
    forbidden = AssertionError("real subprocess/network forbidden by pure runner")
    with (
        patch.object(subprocess, "Popen", side_effect=forbidden),
        patch.object(subprocess, "run", side_effect=forbidden),
        patch.object(socket, "socket", side_effect=forbidden),
        patch.object(socket, "create_connection", side_effect=forbidden),
        patch.object(socket, "getaddrinfo", side_effect=forbidden),
        patch.object(tempfile, "tempdir", str(temporary)),
    ):
        for name, path in (
            ("d0_adapter_tests", ROOT / "test_adapter.py"),
            ("d0_diagnostic_tests", ROOT / "test_diagnostic_adapter.py"),
            ("d0_unchanged_stage0_tests", ROOT / "legacy/test_pure.py"),
        ):
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            modules.append(module)
        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(module) for module in modules
        )
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    print(output.getvalue(), end="")
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
