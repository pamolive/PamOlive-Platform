"""Real public helper/stdlib validation under guards; never a server or DB."""

import builtins
import importlib.abc
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
SOURCE = REPO / "components/vault/runtime/integration/serve_lab.py"
ATTEMPTS = {}
DRIVER_REFUSALS = 0
DRIVERS = {"psycopg", "psycopg2", "asyncpg", "pg8000"}
EXPECTED = {
    "test_import_real_helper_never_changes_path_or_imports_driver",
    "test_lab_inputs_uses_real_validation_without_driver",
    "test_connector_is_lazy_and_guard_refuses_driver_before_connection",
    "test_bad_connector_target_refuses_before_driver_import",
    "test_capture_closes_36_public_inputs_and_seven_fixtures",
    "test_original_helper_regression_is_driver_refusal_not_driver_stub",
}


class DriverDenied(RuntimeError):
    pass


def driver(name):
    global DRIVER_REFUSALS
    if name.split(".", 1)[0].lower() in DRIVERS:
        DRIVER_REFUSALS += 1
        raise DriverDenied("pure_driver_import_refused")


def audit(event, _values):
    if event.startswith(("socket.", "sqlite3.")) or event in {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
        "os.fork",
    }:
        ATTEMPTS[event] = ATTEMPTS.get(event, 0) + 1
        raise AssertionError("lab_helper_external_operation_refused")


def helper(path=SOURCE):
    before = list(sys.path)
    spec = importlib.util.spec_from_file_location("_public_lab_helper_test", path)
    value = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(value)
        if sys.path != before:
            raise AssertionError("helper_import_changed_sys_path")
        return value
    finally:
        sys.path[:] = before


class HelperTests(unittest.TestCase):
    def test_import_real_helper_never_changes_path_or_imports_driver(self):
        before = DRIVER_REFUSALS
        lab = helper()
        self.assertTrue(callable(lab.lab_inputs))
        self.assertEqual(before, DRIVER_REFUSALS)
        self.assertFalse(DRIVERS & set(sys.modules))

    def test_lab_inputs_uses_real_validation_without_driver(self):
        lab = helper()
        path = str(SOURCE)
        names = {
            "slot_path",
            "runtime_database_file",
            "owner_database_file",
            "web_database_file",
            "worker_database_file",
            "server_certificate",
            "server_key",
            "client_ca",
            "server_ca",
            "client_a_certificate",
            "client_a_key",
            "client_b_certificate",
            "client_b_key",
            "client_a_der",
            "client_b_der",
            "request_file",
        }
        value = dict.fromkeys(names, path)
        value.update(
            schema="pamolive.vault.synthetic-lab-inputs/1",
            slot_sha256="1" * 64,
            port=9443,
            bind_host="127.0.0.1",
            server_host="vault-n0.test",
            bad_tls_clients=[
                {"case": name, "certificate": path, "private_key": path}
                for name in ("unknown_ca", "expired", "future")
            ],
        )
        for host in ("127.0.0.1", "10.253.249.3"):
            with patch.object(
                lab, "local_bytes", return_value=json.dumps({**value, "bind_host": host}).encode()
            ):
                self.assertEqual(lab.lab_inputs(SOURCE)["bind_host"], host)
        for changed in (
            {**value, "bind_host": "0.0.0.0"},
            {**value, "extra": False},
            {**value, "server_host": "foreign.test"},
        ):
            with patch.object(lab, "local_bytes", return_value=json.dumps(changed).encode()):
                with self.assertRaises(lab.need.__globals__["Refusal"]):
                    lab.lab_inputs(SOURCE)
        self.assertFalse(DRIVERS & set(sys.modules))

    def connection_value(self):
        return {
            "host": "vault-n0-db.test",
            "port": 5432,
            "dbname": "vault_n0_lab_fixture",
            "user": "vault_n0_runtime",
            "password": "synthetic",
            "sslrootcert": str(SOURCE),
        }

    def test_connector_is_lazy_and_guard_refuses_driver_before_connection(self):
        lab = helper()
        before = DRIVER_REFUSALS
        with patch.object(
            lab, "local_bytes", return_value=json.dumps(self.connection_value()).encode()
        ):
            connect = lab.connector(SOURCE, role="vault_n0_runtime")
        self.assertEqual(before, DRIVER_REFUSALS)
        with self.assertRaises(DriverDenied):
            connect()
        self.assertEqual(DRIVER_REFUSALS, before + 1)
        self.assertFalse(DRIVERS & set(sys.modules))

    def test_bad_connector_target_refuses_before_driver_import(self):
        lab = helper()
        before = DRIVER_REFUSALS
        for key, value in (
            ("host", "foreign.test"),
            ("dbname", "existing_database"),
            ("user", "owner"),
        ):
            changed = {**self.connection_value(), key: value}
            with patch.object(lab, "local_bytes", return_value=json.dumps(changed).encode()):
                with self.assertRaises(lab.need.__globals__["Refusal"]):
                    lab.connector(SOURCE, role="vault_n0_runtime")
        self.assertEqual(before, DRIVER_REFUSALS)

    def test_capture_closes_36_public_inputs_and_seven_fixtures(self):
        import adapter_v2
        import capture_inputs

        payload = json.loads((ROOT / "payloads.json").read_bytes())
        with tempfile.TemporaryDirectory(prefix="public-stage-", dir=ROOT) as directory:
            target = Path(directory) / "capture"
            receipt = capture_inputs.capture(REPO, target, payload)
            self.assertEqual(receipt["captured_files"], 36)
            stage = target / "runtime-tests"
            expected = {name: row["sha256"] for name, row in payload["runtime_tests"].items()}
            self.assertEqual(len(expected), 7)
            adapter_v2.validate_stage(stage, expected)
            staged = stage / "integration/serve_lab.py"
            self.assertEqual(staged.read_bytes(), SOURCE.read_bytes())
            helper(staged)
            staged.unlink()
            with self.assertRaises(ValueError):
                adapter_v2.validate_stage(stage, expected)

    def test_original_helper_regression_is_driver_refusal_not_driver_stub(self):
        source = SOURCE.read_text(encoding="utf-8")
        source = source.replace(
            'if __name__ == "__main__":\n    sys.path.insert', "sys.path.insert", 1
        )
        source = source.replace(
            "    def connect():\n        import psycopg\n\n", "    def connect():\n", 1
        )
        source = source.replace("    from pamolive_vault_runtime.slot import _read_ro\n\n", "", 1)
        source = source.replace(
            "\n    import uvicorn\n"
            "    from pamolive_vault_runtime.assembly import application\n"
            "    from pamolive_vault_runtime.transport import configuration, tls_context\n",
            "",
            1,
        )
        source = source.replace(
            "from pamolive_vault_runtime.bounded import closed, digest, json_object, need",
            "import psycopg\nimport uvicorn\n"
            "from pamolive_vault_runtime.assembly import application\n"
            "from pamolive_vault_runtime.bounded import closed, digest, json_object, need\n"
            "from pamolive_vault_runtime.slot import _read_ro\n"
            "from pamolive_vault_runtime.transport import configuration, tls_context",
            1,
        )
        before, previous = list(sys.path), DRIVER_REFUSALS
        try:
            with self.assertRaises(DriverDenied):
                exec(
                    compile(source, str(SOURCE), "exec"),
                    {"__name__": "_old_helper", "__file__": str(SOURCE)},
                )
            self.assertNotEqual(before, sys.path)
            self.assertEqual(DRIVER_REFUSALS, previous + 1)
            self.assertFalse(DRIVERS & set(sys.modules))
        finally:
            sys.path[:] = before


def main():
    sys.addaudithook(audit)
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        driver(name)
        return original(name, *args, **kwargs)

    class Finder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            driver(fullname)
            return None

    finder = Finder()
    before = list(sys.path)
    sys.path[:0] = [
        str(ROOT),
        str(REPO / "components/vault/runtime"),
        str(REPO / "components/vault-registry/src"),
        str(REPO / "components/pam-trust-verifier/src"),
    ]
    sys.meta_path.insert(0, finder)
    try:
        with patch.object(builtins, "__import__", guarded):
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(HelperTests)
            names = [test._testMethodName for test in suite]
            if len(names) != 6 or set(names) != EXPECTED:
                raise SystemExit("closed_six_helper_tests_required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        sys.path[:] = before
        sys.meta_path.remove(finder)
    summary = {
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "external_attempts": ATTEMPTS,
        "expected_driver_refusals": DRIVER_REFUSALS,
        "actual_driver_imported": bool(DRIVERS & set(sys.modules)),
        "source_fixture_stdlib_validators_imported": True,
        "third_party_dependencies_required": False,
        "installed_reception": False,
        "actual_build_install_SQL_listener": False,
    }
    print(json.dumps(summary))
    raise SystemExit(
        not result.wasSuccessful()
        or result.testsRun != 6
        or bool(result.skipped)
        or bool(ATTEMPTS)
        or DRIVER_REFUSALS != 2
        or bool(DRIVERS & set(sys.modules))
    )


if __name__ == "__main__":
    main()
