"""Refuse Python startup hooks without importing or executing any hook bytes."""

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
adapter = importlib.import_module("adapter_v2")
ATTEMPTS = {}


def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "sqlite3.")) or event in {
        "os.system",
        "os.exec",
        "os.spawn",
        "os.fork",
    }:
        ATTEMPTS[event] = ATTEMPTS.get(event, 0) + 1
        raise AssertionError("startup_external_operation_refused")


class StartupTests(unittest.TestCase):
    def site(self):
        # TemporaryDirectory removes only this explicitly named fresh subtree.
        directory = tempfile.TemporaryDirectory(prefix="startup-test-", dir=HERE)
        self.addCleanup(directory.cleanup)
        return Path(directory.name).resolve()

    def test_sitecustomize_source_refuses_before_import(self):
        site = self.site()
        (site / "sitecustomize.py").write_bytes(b"raise AssertionError('MUST NOT EXECUTE')\n")
        with self.assertRaises(ValueError):
            adapter.runtime_prelaunch(site)
        self.assertNotIn("sitecustomize", sys.modules)

    def test_reserved_native_extension_names_refuse_without_loading(self):
        site = self.site()
        for name in ("sitecustomize.so", "sitecustomize.cpython-312-x86_64-linux-gnu.so"):
            path = site / name
            path.write_bytes(b"SYNTHETIC NOT A NATIVE LIBRARY")
            with self.subTest(name=name), self.assertRaises(ValueError):
                adapter.runtime_prelaunch(site)
            path.unlink()

    def test_startup_package_refuses_without_reading_init(self):
        site = self.site()
        package = site / "sitecustomize"
        package.mkdir()
        (package / "__init__.py").write_bytes(b"raise AssertionError('MUST NOT EXECUTE')\n")
        with self.assertRaises(ValueError):
            adapter.runtime_prelaunch(site)

    def test_usercustomize_family_is_closed_even_with_isolated_mode(self):
        site = self.site()
        path = site / "usercustomize.py"
        path.write_bytes(b"raise AssertionError('MUST NOT EXECUTE')\n")
        with self.assertRaises(ValueError):
            adapter.runtime_prelaunch(site)
        path.unlink()
        (site / "usercustomize").mkdir()
        with self.assertRaises(ValueError):
            adapter.runtime_prelaunch(site)

    def test_existing_PTH_and_bytecode_refusals_are_preserved(self):
        site = self.site()
        nested = site / "package"
        nested.mkdir()
        for name in ("startup.pth", "__init__.pyc"):
            path = nested / name
            path.write_bytes(b"SYNTHETIC")
            with self.subTest(name=name), self.assertRaises(ValueError):
                adapter.runtime_prelaunch(site)
            path.unlink()

    def test_ordinary_closed_package_does_not_create_startup_authority(self):
        site = self.site()
        package = site / "ordinary_package"
        package.mkdir()
        (package / "__init__.py").write_bytes(b"raise AssertionError('MUST NOT IMPORT')\n")
        self.assertTrue(adapter.runtime_prelaunch(site))
        self.assertNotIn("ordinary_package", sys.modules)


if __name__ == "__main__":
    sys.addaudithook(audit)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StartupTests)
    if suite.countTestCases() != 6:
        raise SystemExit("Closed six startup tests required")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "external_attempts": ATTEMPTS,
        "hooks_are_inert_data_only": True,
        "actual_startup_hook_or_product_or_native_execution": False,
    }
    print(json.dumps(summary))
    raise SystemExit(
        0
        if result.wasSuccessful() and result.testsRun == 6 and not result.skipped and not ATTEMPTS
        else 1
    )
