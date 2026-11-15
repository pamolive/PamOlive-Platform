"""Filesystem and installed-runner helpers with synthetic data/fake metadata."""

import copy
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import adapter_v2
import installed_runner
from guards import ForbiddenIO, Policy
from support import ROOT, sha
from test_contracts import descriptor


class RunnerTests(unittest.TestCase):
    def test_suite_imports_under_active_guards_from_venv_and_preserves_masked_attempt(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            prefix = Path(directory) / "runtime"
            prefix.mkdir()
            stage = Path(directory) / "stage/components/vault/runtime"
            stage.mkdir(parents=True)
            modules = {}
            # Fifty-two empty synthetic tests exercise runner plumbing only.
            # They are not the actual52runtime tests or any installed receipt.
            for module_name, count in (
                ("test_runtime", 30),
                ("test_ro_slot", 11),
                ("test_r2_boundaries", 11),
            ):
                module = ModuleType(module_name)
                methods = {f"test_{index:02d}": lambda self: None for index in range(count)}
                module.Synthetic = type("Synthetic", (unittest.TestCase,), methods)
                modules[module_name] = module
            current = Policy(
                prefix=prefix,
                stdlib=Path(installed_runner.sys.base_prefix) / "Lib",
                stage=stage,
                controller=ROOT,
                report=Path(directory) / "report.json",
            )
            seen = []

            def importer(name):
                self.assertTrue(current.active)
                seen.append(name)
                if name in installed_runner.schema.MODULES:
                    # A swallowed driver refusal must survive the successful fake suite.
                    try:
                        current.imported("psycopg")
                    except ForbiddenIO:
                        pass
                    return SimpleNamespace(__file__=str(prefix / name / "__init__.py"))
                return modules[name]

            with patch.object(installed_runner.sys, "prefix", str(prefix)), current.install():
                result, diagnostics = installed_runner.suite_tests(stage, importer=importer)
                self.assertEqual(result, {"run": 52, "failures": 0, "errors": 0, "skips": 0})
                self.assertEqual(diagnostics, [])
                with self.assertRaises(ForbiddenIO):
                    current.guard.require_clean()
            self.assertEqual(len(seen), 6)
            self.assertNotIn(str(stage / "tests"), installed_runner.sys.path)

    def test_parent_prelaunch_refuses_PTH_and_PYC_before_child_can_start(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            site = Path(directory)
            self.assertTrue(adapter_v2.runtime_prelaunch(site))
            for name in ("evil.pth", "compiled.pyc"):
                path = site / name
                path.write_bytes(b"PUBLIC SYNTHETIC ONLY")
                with self.assertRaises(ValueError):
                    adapter_v2.runtime_prelaunch(site)
                path.unlink()

    def test_stage_requires_seven_exact_files_no_source_fallback_or_softskip(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            stage = Path(directory) / "stage/components/vault/runtime"
            expected = {}
            for name in adapter_v2.STAGE:
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = ("PUBLIC " + name).encode()
                path.write_bytes(raw)
                expected[name] = sha(raw)
            adapter_v2.validate_stage(stage, expected)
            with self.assertRaises(ValueError):
                adapter_v2.validate_stage(stage, {**expected, "integration/extra.py": "1" * 64})
            extra = stage / "src/hidden.py"
            extra.parent.mkdir()
            extra.write_bytes(b"PUBLIC EXTRA")
            with self.assertRaises(ValueError):
                adapter_v2.validate_stage(stage, expected)
            extra.unlink()
            missing = stage / "tests/history/r1/transport.py"
            missing.unlink()
            with self.assertRaises(ValueError):
                adapter_v2.validate_stage(stage, expected)

    def test_installed_files_closed8_3_6_and_SQL_data_no_code_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            prefix = Path(directory)
            value = descriptor()
            for module, names in adapter_v2.CODE.items():
                location = prefix / "lib/python3.12/site-packages" / module
                location.mkdir(parents=True)
                for name in names:
                    raw = ("PUBLIC SYNTHETIC " + module + "/" + name).encode()
                    (location / name).write_bytes(raw)
                    value["module_files"][module][name] = sha(raw)
            sql = prefix / "share/pamolive/vault-reservation/schema.sql"
            sql.parent.mkdir(parents=True)
            sql.write_bytes(b"PUBLIC SQL DATA NOT EXECUTED")
            value["sql_sha256"] = sha(sql.read_bytes())
            with patch.object(installed_runner.sys, "prefix", str(prefix)):
                found = installed_runner.installed_probe(value)
                self.assertEqual(found["files_matched"], 18)
                self.assertEqual(
                    found["modules"],
                    {
                        "pamolive_vault_runtime": 8,
                        "pamolive_vault_contracts": 3,
                        "pamolive_pam_trust_verifier": 6,
                    },
                )
                extra = prefix / "lib/python3.12/site-packages/pamolive_vault_runtime/extra.py"
                extra.write_bytes(b"EXTRA")
                with self.assertRaises(ValueError):
                    installed_runner.installed_probe(value)

    def test_environment_all_directories_duplicate_global_extra_driver_and_origins(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            prefix = Path(directory)
            site = prefix / "lib/python3.12/site-packages"
            site.mkdir(parents=True)
            (prefix / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
            for module in installed_runner.schema.MODULES:
                path = site / module / "__init__.py"
                path.parent.mkdir()
                path.write_bytes(b"PUBLIC SYNTHETIC DATA")
            expected = adapter_v2.distributions()
            items = [
                SimpleNamespace(
                    metadata={"Name": name}, version=version, locate_file=lambda _name: site
                )
                for name, version in expected.items()
            ]
            directories = (str(site),)

            def find(name, paths):
                self.assertEqual(paths, list(directories))
                return (
                    SimpleNamespace(origin=str(site / name / "__init__.py"))
                    if name in installed_runner.schema.MODULES
                    else None
                )

            with (
                patch.object(installed_runner.sys, "prefix", str(prefix)),
                patch.object(installed_runner.sys, "base_prefix", "base-other"),
                patch.object(installed_runner.site, "ENABLE_USER_SITE", False),
                patch.object(
                    installed_runner.REFERENCE, "metadata_directories", return_value=directories
                ),
                patch.object(
                    installed_runner.importlib.metadata, "distributions", return_value=items
                ) as enumeration,
                patch.object(
                    installed_runner.importlib.machinery.PathFinder, "find_spec", side_effect=find
                ),
            ):
                self.assertEqual(
                    installed_runner.environment_probe(expected)["distributions"], expected
                )
                enumeration.assert_called_with(path=directories)
                for wrong in (
                    items + [items[0]],
                    items + [SimpleNamespace(metadata={"Name": "django"}, version="6.0")],
                ):
                    enumeration.return_value = wrong
                    with self.assertRaises(ValueError):
                        installed_runner.environment_probe(expected)
                enumeration.return_value = items
                global_items = copy.copy(items)
                global_items[0] = SimpleNamespace(
                    metadata=items[0].metadata,
                    version=items[0].version,
                    locate_file=lambda _name: ROOT,
                )
                enumeration.return_value = global_items
                with self.assertRaises(ValueError):
                    installed_runner.environment_probe(expected)
