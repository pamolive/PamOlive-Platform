"""Explicit synthetic TEST CLIENT; no service, packaging or provisioning authority.

Reuses the installed52 /2 input, adapter and installed-file probe unchanged.
The commissioning parent verifies existing controller checksums BEFORE Python,
checks startup hooks BEFORE launching this child and provides two fixture files.
This launcher is not a network/OS sandbox. Production invocation performs real
SQL/mTLS only after explicit arguments; preparation tests inject inert doubles.
"""

import argparse
import ast
import contextlib
import importlib
import importlib.machinery
import importlib.util
import io
import json
import sys
import types
import unittest
from pathlib import Path

RESULT = "pamolive.vault-installed-ten-result/1"
METHODS = {
    "PostgreSQLReception": (
        "test_real_concurrent_writers_same_key_same_durable_row_and_nonce",
        "test_actual_runtime_cannot_ddl_change_context_delete_or_update_reservation",
        "test_actual_cert_rotation_same_key_conflicts",
        "test_real_quota_and_owner_seeded_expired_retry_never_renew",
        "test_real_commit_followed_by_simulated_lost_response_retries_same_row",
        "test_actual_declared_closed_or_changed_incarnation_refuses_before_insert",
    ),
    "TLSReception": (
        "test_real_tls_no_client_certificate_refused",
        "test_real_tls_unknown_ca_expired_future_client_refused",
        "test_real_two_connections_der_never_crosses_and_keepalive_revalidates_mapping",
        "test_real_keepalive_original_retry_and_header_does_not_supply_identity",
    ),
}
IDS = frozenset(f"{cls}.{method}" for cls, methods in METHODS.items() for method in methods)
FIXTURES = frozenset({"test_lab.py", "serve_lab.py"})


def need(value):
    if not value:
        raise ValueError("installed_ten_refused")


class Discard(io.TextIOBase):
    def write(self, value):
        return len(value)

    def flush(self):
        return None


class QuietResult(unittest.TestResult):
    """No traceback formatting, test prints, manifest or exception text exported."""

    def __init__(self):
        super().__init__()
        self.seen = []

    def startTest(self, test):
        identifier = ".".join(test.id().split(".")[-2:])
        need(identifier in IDS and identifier not in self.seen)
        self.seen.append(identifier)
        super().startTest(test)

    def addError(self, test, error):
        self.errors.append((test, ""))

    def addFailure(self, test, error):
        self.failures.append((test, ""))

    def addSubTest(self, test, subtest, error):
        if error is not None:
            bucket = self.failures if issubclass(error[0], test.failureException) else self.errors
            bucket.append((test, ""))

    def addSkip(self, test, reason):
        self.skipped.append((test, ""))

    def addExpectedFailure(self, test, error):
        self.expectedFailures.append((test, ""))

    def addUnexpectedSuccess(self, test):
        self.unexpectedSuccesses.append(test)


def source_inventory(raw):
    """Inspect the pinned original file without rewriting any method/body."""
    found = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.ClassDef):
            names = [
                m.name
                for m in node.body
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                and m.name.startswith("test")
            ]
            if names:
                need(node.name not in found and len(names) == len(set(names)))
                found[node.name] = set(names)
    need(found == {name: set(methods) for name, methods in METHODS.items()})


def fixture_bytes(directory, description, test_sha, controller):
    directory = Path(directory)
    need(directory.is_absolute() and directory == directory.resolve(strict=True))
    need({p.name for p in directory.iterdir()} == FIXTURES)
    # test_lab prepends its parent; this stage may contain no source packages.
    need({p.name for p in directory.parent.iterdir()} == {directory.name})
    pins = {
        "test_lab.py": test_sha,
        "serve_lab.py": description["stage_files"]["integration/serve_lab.py"],
    }
    need(controller.schema.digest(test_sha))
    raw = {name: controller.support.read_regular(directory / name, 65536) for name in FIXTURES}
    need(all(controller.support.sha(value) == pins[name] for name, value in raw.items()))
    source_inventory(raw["test_lab.py"])
    return raw


def installed_check(description, controller):
    """Reuse the existing exact 8+3+6 module/SQL probe; no driver prohibition copied."""
    need(sys.platform == "linux" and sys.version_info[:2] == (3, 12))
    need(sys.flags.isolated and sys.dont_write_bytecode and sys.prefix != sys.base_prefix)
    prefix = Path(sys.prefix).resolve(strict=True)
    base = prefix / "lib/python3.12/site-packages"
    need(
        "include-system-site-packages = false"
        in controller.support.read_regular(prefix / "pyvenv.cfg", 4096).decode().lower()
    )
    controller.adapter_v2.runtime_prelaunch(base)
    controller.installed_runner.installed_probe(description)
    rows = list(controller.installed_runner.importlib.metadata.distributions(path=[str(base)]))
    for name, module in (
        ("pamolive-vault-reservation-runtime", "pamolive_vault_runtime"),
        ("pamolive-vault-contracts", "pamolive_vault_contracts"),
        ("pamolive-pam-trust-verifier", "pamolive_pam_trust_verifier"),
    ):
        matched = [row for row in rows if row.metadata["Name"].lower().replace("_", "-") == name]
        need(len(matched) == 1 and matched[0].version == description["distributions"][name])
        need(Path(matched[0].locate_file("")).resolve(strict=True) == base)
        spec = importlib.machinery.PathFinder.find_spec(module, [str(base)])
        wanted = base / module / "__init__.py"
        need(spec is not None and spec.origin == str(wanted))
        effective = importlib.util.find_spec(module)
        need(effective is not None and effective.origin == str(wanted))
        need(list(effective.submodule_search_locations or ()) == [str(wanted.parent)])
        need(wanted == wanted.resolve(strict=True))
        need(list(spec.submodule_search_locations or ()) == [str(wanted.parent)])
    loaded_origins(base, controller.schema.MODULES)
    return base


def loaded_origins(base, roots):
    for name, module in list(sys.modules.items()):
        if any(name == root or name.startswith(root + ".") for root in roots):
            origin = getattr(module, "__file__", None)
            need(origin is not None and Path(origin) == Path(origin).resolve(strict=True))
            need(Path(origin).is_relative_to(base))


class CapturedFixtureLoader(importlib.machinery.SourceFileLoader):
    """Retain each verified buffer/origin independently of the caller's loop."""

    def __init__(self, name, path, body):
        super().__init__(name, path)
        self.body = body

    def get_code(self, fullname):
        return compile(self.body, self.path, "exec", dont_inherit=True)


def load_fixture(directory, raw):
    # Both modules execute the buffers already checked; no second pathname import.
    need("serve_lab" not in sys.modules and "_pamolive_vault_installed_ten" not in sys.modules)
    loaded = {}
    for name, filename in (
        ("serve_lab", "serve_lab.py"),
        ("_pamolive_vault_installed_ten", "test_lab.py"),
    ):
        path = str(directory / filename)

        loader = CapturedFixtureLoader(name, path, raw[filename])
        spec = importlib.util.spec_from_loader(name, loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        loaded[name] = module
    return loaded["_pamolive_vault_installed_ten"]


def run_methods(module):
    need(module.VALUES is not None)
    classes = {
        name: value
        for name, value in vars(module).items()
        if isinstance(value, type)
        and issubclass(value, unittest.TestCase)
        and value is not unittest.TestCase
    }
    need(set(classes) == set(METHODS))
    cases = []
    for name, methods in METHODS.items():
        need(set(unittest.defaultTestLoader.getTestCaseNames(classes[name])) == set(methods))
        cases.extend(classes[name](method) for method in methods)
    result = QuietResult()
    unittest.TestSuite(cases).run(result)
    counts = {
        "run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    good = {
        "run": 10,
        "failures": 0,
        "errors": 0,
        "skips": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    return counts == good and set(result.seen) == IDS, counts


def execute(args, controller, *, probe=installed_check, loader=load_fixture):
    report = {
        "schema": RESULT,
        "ok": False,
        "phase": "installed_input",
        "tests": None,
        "authorized": False,
        "provisioned": False,
        "service_started": False,
    }
    try:
        need(args.execute_new_synthetic_lab)
        raw_input = controller.support.read_regular(args.installed_input, 65536)
        need(controller.schema.digest(args.installed_input_sha256))
        need(controller.support.sha(raw_input) == args.installed_input_sha256)
        description = controller.adapter_v2.descriptor(controller.schema.parse(raw_input, 65536))
        report["installed_input_sha256"] = args.installed_input_sha256
        report["phase"] = "fixtures"
        raw = fixture_bytes(args.integration_dir, description, args.test_lab_sha256, controller)
        report["test_lab_sha256"] = args.test_lab_sha256
        report["phase"] = "manifest_presence"
        need(args.manifest.is_absolute())
        controller.support.read_regular(args.manifest, 32768)
        report["phase"] = "installed_origins"
        base = probe(description, controller)
        report["phase"] = "load_pinned_tests"
        with contextlib.redirect_stdout(Discard()), contextlib.redirect_stderr(Discard()):
            module = loader(args.integration_dir, raw)
            module.VALUES = module.lab_inputs(args.manifest)
            loaded_origins(base, controller.schema.MODULES)
            report["phase"] = "ten_methods"
            ok, counts = run_methods(module)
            report["tests"] = counts
        report["phase"] = "postcheck"
        need(
            fixture_bytes(args.integration_dir, description, args.test_lab_sha256, controller)
            == raw
        )
        need(probe(description, controller) == base)
        loaded_origins(base, controller.schema.MODULES)
        need(controller.support.read_regular(args.installed_input, 65536) == raw_input)
        report["fixtures_unchanged"] = True
        report["installed_files_rechecked"] = True
        report["ok"] = ok
        report["phase"] = "complete" if ok else "tests_refused"
    except BaseException:
        # No exception text/type, path, credentials, nonce, body or traceback.
        report["ok"] = False
    return report


def controller_modules(directory):
    """Parent MUST verify the existing source-checksums before child invocation."""
    need(directory.is_absolute() and directory == directory.resolve(strict=True))
    sys.path.insert(0, str(directory))
    modules = {}
    for name in ("support", "schema", "adapter_v2", "installed_runner"):
        need(name not in sys.modules)
        module = importlib.import_module(name)
        need(Path(module.__file__) == directory / (name + ".py"))
        modules[name] = module
    return types.SimpleNamespace(**modules)


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--execute-new-synthetic-lab", action="store_true", required=True)
    parser.add_argument("--controller-dir", type=Path, required=True)
    parser.add_argument("--installed-input", type=Path, required=True)
    parser.add_argument("--installed-input-sha256", required=True)
    parser.add_argument("--integration-dir", type=Path, required=True)
    parser.add_argument("--test-lab-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    try:
        with contextlib.redirect_stderr(Discard()):
            args = parser.parse_args(argv)
        need(args.report.is_absolute() and not args.report.exists())
        need(args.report.parent == args.report.parent.resolve(strict=True))
        with contextlib.redirect_stdout(Discard()), contextlib.redirect_stderr(Discard()):
            controller = controller_modules(args.controller_dir)
            report = execute(args, controller)
        with args.report.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, sort_keys=True)
            stream.write("\n")
        print(json.dumps(report, sort_keys=True))
        return 0 if report["ok"] else 1
    except BaseException:
        print(json.dumps({"schema": RESULT, "ok": False, "phase": "arguments_or_report"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
