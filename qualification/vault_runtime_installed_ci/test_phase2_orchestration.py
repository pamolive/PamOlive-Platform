"""Real orchestration/gates with a fake command boundary, never a build/install."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import adapter_v2
import orchestrate
import phase2_fixtures as fixture
import schema
import wheel_gate
import workload_schema
from support import ROOT, load, sha
from test_seam import Result

ORDER = [
    "venv-build",
    "no-pip-build",
    "bootstrap-build",
    "venv-runtime",
    "no-pip-runtime",
    "bootstrap-runtime",
    "install-build",
    "pipcheck-build",
    "probe-build",
    "wheel-verifier",
    "wheel-contracts",
    "wheel-runtime",
    "install-public",
    "install-internal",
    "pipcheck-runtime",
    "child52",
]


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.work = self.directory / "work"
        self.materials = self.directory / "materials"
        self.materials.mkdir()
        self.plan = copy.deepcopy(adapter_v2.materials())
        for name, row in self.plan["selected_materials"].items():
            raw = ("PUBLIC SYNTHETIC MATERIAL " + name).encode()
            row["size"], row["sha256"] = len(raw), sha(raw)
            (self.materials / row["filename"]).write_bytes(raw)
        (self.materials / "acquisition.json").write_bytes(b"{}")
        q = load("qualify_installed.py")
        actual_zip = q.zip_inventory

        def inventory(raw, *, name, version, **options):
            if name in {entry[0] for entry in wheel_gate.PACKAGES.values()}:
                return actual_zip(raw, name=name, version=version, **options)
            return {"RECORD_checked": True}

        for boundary in (
            patch.object(adapter_v2, "materials", return_value=self.plan),
            patch.object(orchestrate, "target", return_value=None),
            patch.object(q, "zip_inventory", side_effect=inventory),
        ):
            boundary.start()
            self.addCleanup(boundary.stop)
        self.calls, self.wheels, self.buffers = [], {}, {}

    def invoke(self, command, **limits):
        phase = ORDER[len(self.calls)]
        self.calls.append((phase, command, limits))
        self.assertEqual(command[1:3], ["-I", "-B"])
        self.assertEqual(
            set(limits["env"]), {"PATH", "HOME", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE"}
        )
        self.assertTrue(0 < limits["timeout"] <= 300)
        self.assertEqual(limits["stdout_cap"], 8192)
        self.assertEqual(limits["stderr_cap"], 8192)
        if phase.startswith("venv-"):
            prefix = Path(command[-1])
            (prefix / "lib/python3.12/site-packages").mkdir(parents=True)
            (prefix / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
        if phase == "probe-build":
            expected = {
                name: self.plan["selected_materials"][name]["version"]
                for name in self.plan["build_and_bootstrap_names"]
            }
            value = {
                "schema": "pamolive.public-pam-verifier-installed-child/1",
                "operation": "probe",
                "state": "INSTALLED_ONLY_PROBE_PASS",
                "authority": False,
                "venv": {
                    "distributions": expected,
                    "origins_within_venv": {"pip": "lib/python3.12/site-packages/pip/__init__.py"},
                    "global_site_fallback": False,
                    "application_or_SDK_importable": False,
                },
                "forbidden_attempts": {},
                "intentional_guard_probes": dict.fromkeys(
                    (
                        "socket.constructor",
                        "DNS",
                        "sqlite3.connect",
                        "subprocess.Popen",
                        "import.django",
                        "file.read_outside_roots",
                    ),
                    1,
                ),
                "elapsed_seconds": 1,
                "installed_wheel_only": True,
                "OS_network_sandbox_claimed": False,
                "full_P0_acceptance": False,
                "build_attestation": False,
            }
            (self.work / "build-probe.json").write_bytes(schema.encode(value))
        if phase.startswith("wheel-"):
            kind = phase.removeprefix("wheel-")
            raw, files, _ = fixture.fixture(kind)
            stem = wheel_gate.PACKAGES[kind][0].replace("-", "_")
            wheel = self.work / "built" / kind / (stem + "-0.1.0a1-py3-none-any.whl")
            wheel.write_bytes(raw)
            self.wheels[kind], self.buffers[kind] = wheel, files
        if phase == "install-internal":
            for kind, wheel in self.wheels.items():
                inventory = wheel_gate.validate(
                    wheel.read_bytes(),
                    ROOT / "inputs" / kind,
                    kind,
                    repository=self.work / "source-skeleton",
                )
                fixture.install_data(self.work / "runtime", inventory, wheel, self.buffers[kind])
        if phase == "child52":
            # Closed fake child is a test boundary, never the actual52 methods.
            description = json.loads((self.work / "input.json").read_bytes())
            child = {
                "schema": schema.CHILD,
                "state": "INSTALLED_RUNTIME_52_PASS",
                "authority": False,
                "venv": {
                    "distributions": description["distributions"],
                    "origins": {
                        module: "lib/python3.12/site-packages/" + module + "/__init__.py"
                        for module in schema.MODULES
                    },
                },
                "installed": {
                    "modules": schema.MODULES.copy(),
                    "files_matched": 18,
                    "sql_sha256": adapter_v2.SQL_SHA,
                    "site_PTH": 0,
                },
                "tests": {"run": 52, "failures": 0, "errors": 0, "skips": 0},
                "attempts": {},
                "probes": dict.fromkeys(schema.PROBES, 1),
                "input_sha256": sha((self.work / "input.json").read_bytes()),
                "elapsed_seconds": 1,
                "failure_code": "NONE",
                "exception_type": None,
            }
            (self.work / "runtime-child-report.json").write_bytes(schema.encode(child))
        result = Result()
        result.stdout = result.stderr = b""
        return result

    def run_workload(self, invoke=None, clock=lambda: 0):
        return orchestrate.run(
            self.materials,
            self.work,
            sources=ROOT / "inputs",
            invoke=invoke or self.invoke,
            clock=clock,
        )

    def bindings(self, report):
        return {
            "expected_source": orchestrate.PAYLOAD_SHA,
            "expected_input": report["input_sha256"],
            "expected_sql": adapter_v2.SQL_SHA,
            "expected_materials": adapter_v2.MATERIALS,
        }

    def test_real_flow_build_gates_RECORDs_prelaunch_and_child_order_with_fake_commands(self):
        report = self.run_workload()
        self.assertEqual(report["state"], "INSTALLED_VAULT_WORKLOAD_PASS")
        self.assertEqual([phase for phase, *_ in self.calls], ORDER)
        workload_schema.execution(report, **self.bindings(report))
        internal = (self.work / "internal.lock").read_text()
        self.assertEqual(internal.count("file:///"), 3)
        self.assertEqual(internal.count("--hash=sha256:"), 3)
        self.assertNotIn("https:", internal)
        for phase, command, _ in self.calls:
            if phase.startswith(("wheel-", "install-")):
                self.assertIn("--no-index", command)
                self.assertIn("--no-deps", command)
            if phase.startswith("install-"):
                self.assertIn("--no-compile", command)
                self.assertIn("--require-hashes", command)

    def test_partial_wheel_failure_has_no_invented_child_and_preserves_phase(self):
        actual = self.invoke

        def fail(command, **limits):
            if ORDER[len(self.calls)] == "wheel-contracts":
                self.calls.append(("wheel-contracts", command, limits))
                result = Result(1)
                result.stdout = result.stderr = b""
                return result
            return actual(command, **limits)

        report = self.run_workload(fail)
        self.assertEqual(report["state"], "FAILED")
        self.assertIsNone(report["child"])
        self.assertEqual(report["failure"]["phase"], "wheel-contracts")
        self.assertEqual(len(report["built_wheels"]), 1)
        packet = workload_schema.packet(report, **self.bindings(report))
        self.assertFalse(workload_schema.accept(packet, 42, **self.bindings(report))["ok"])

    def test_shared900deadline_refuses_before_first_command(self):
        times = iter((0, 901))
        report = self.run_workload(clock=times.__next__)
        self.assertFalse(self.calls)
        self.assertEqual(report["state"], "FAILED")
        self.assertIsNone(report["child"])

    def test_PARENT_prelaunch_refuses_PTH_before_runtime_pipcheck(self):
        actual = self.invoke

        def inject(command, **limits):
            phase = ORDER[len(self.calls)]
            result = actual(command, **limits)
            if phase == "install-internal":
                (self.work / "runtime/lib/python3.12/site-packages/evil.pth").write_bytes(
                    b"PUBLIC NOEXEC FIXTURE"
                )
            return result

        report = self.run_workload(inject)
        self.assertEqual(report["state"], "FAILED")
        self.assertNotIn("pipcheck-runtime", [phase for phase, *_ in self.calls])
        self.assertIsNone(report["child"])

    def test_new_envelope_rejects_missing_RECORDs_skip_false_bindings_and_old_packet(self):
        report = self.run_workload()
        bindings = self.bindings(report)
        for mutate in (
            lambda value: value.update(records=[]),
            lambda value: value["pip_checks"].update(runtime=False),
            lambda value: value["child"]["tests"].update(skips=1),
            lambda value: value["child"].update(input_sha256="a" * 64),
        ):
            changed = copy.deepcopy(report)
            mutate(changed)
            with self.assertRaises(ValueError):
                workload_schema.packet(changed, **bindings)
        with self.assertRaises(ValueError):
            workload_schema.accept({"schema": schema.PACKET}, 0, **bindings)

    def test_report_persistence_failure_retains_real_observed_history_not_fake_preflight(self):
        actual = orchestrate.write

        def fail_report(path, raw):
            if path.name == "execution.json":
                raise OSError("PUBLIC_PERSISTENCE_ERROR")
            return actual(path, raw)

        with patch.object(orchestrate, "write", side_effect=fail_report):
            report = self.run_workload()
        self.assertEqual(report["state"], "FAILED")
        self.assertEqual(report["secondary_failure"], "REPORT_PERSISTENCE_FAILED")
        self.assertEqual(len(report["processes"]), 16)
        self.assertIsNotNone(report["child"])
        self.assertFalse(workload_schema.packet(report, **self.bindings(report))["ok"])
