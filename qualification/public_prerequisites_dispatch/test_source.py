"""Pure tests of real functions/AST; all process and privileged seams are doubles."""

import ast
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
WORK = HERE.parent
PG_REFERENCE = HERE.parent / "public_pg_identity_probe"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


c = module("_quick_test_collector", HERE / "engine/collector.py")
q = module("_quick_test_driver", HERE / "quick.py")


class Result:
    def __init__(self, data=None, **changes):
        self.stdout = json.dumps(data).encode() if data is not None else b"public"
        self.stderr = b""
        self.ok = True
        self.row = {
            "spawn_attempted": True,
            "pid": 123,
            "returncode": 0,
            "reason": None,
            "exception_type": None,
            "killed_owned_child": False,
            "owned_child_reaped": True,
            "drains_complete": True,
            "cleanup_exception_type": None,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": 0,
        } | changes

    def facts(self):
        return dict(self.row)


def fixtures(name):
    if name == "version":
        return {
            "client_version": "29.4.2",
            "client_api": "1.54",
            "client_os": "linux",
            "client_arch": "amd64",
            "server_version": "29.4.2",
            "server_api_min": "1.40",
            "server_api_max": "1.54",
            "server_git_commit": "d329809",
            "server_os": "linux",
            "server_arch": "amd64",
            "containerd": [{"version": "v2.2.3", "revision": "a" * 40}],
        }
    if name == "info":
        return {
            "driver": "overlayfs",
            "driver_status": [["driver-type", "io.containerd.snapshotter.v1"]],
            "root": "/var/lib/docker",
            "containerd": {
                "Address": "/run/containerd/containerd.sock",
                "Namespaces": {"Containers": "moby", "Plugins": "plugins.moby"},
            },
        }
    return {
        "Id": "sha256:" + "a" * 64,
        "Os": "linux",
        "Architecture": "amd64",
        "RootFS": {"Type": "layers", "Layers": ["sha256:" + "b" * 64]},
        "RepoDigests": None,
        **{key: {"present": False, "value": None} for key in c.CONFIG_FIELDS},
    }


class Queries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=WORK, prefix="quick-pure-")
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name) / "work"

    def runner(self, calls, bad=False):
        def run(argv, **options):
            calls.append(argv)
            self.assertEqual(set(options["env"]), {"PATH", "HOME", "LANG", "LC_ALL"})
            self.assertEqual(
                (options["timeout"], options["stdout_cap"], options["stderr_cap"]),
                (15, 32768, 4096),
            )
            return Result(fixtures(argv[5]), **({"owned_child_reaped": False} if bad else {}))

        return run

    def test_two_and_four_real_request_counts(self):
        calls = []
        report = c.collect_two(self.work, self.runner(calls), {"sha256": "x"})
        self.assertEqual([args[5] for args in calls], ["version", "info"])
        self.assertEqual(set(report["queries"]), {"version", "info"})
        self.assertTrue(report["two_queries_projected"])
        self.assertNotIn("four_queries_projected", report)
        self.assertEqual(c.finalize_two(self.work, report, report["tool"]), 42)
        calls.clear()
        full = c.collect(self.work.with_name("four"), self.runner(calls), {"sha256": "x"})
        self.assertEqual([args[5] for args in calls], ["version", "info", "image", "image"])
        self.assertTrue(full["four_queries_projected"])
        self.assertNotIn("two_queries_projected", full)

    def test_unknown_stops_second_read_and_blocks_root(self):
        calls = []
        report = c.collect_two(self.work, self.runner(calls, bad=True), {"sha256": "x"})
        self.assertEqual(len(calls), 1)
        self.assertFalse(report["all_clients_reaped_drained"])
        with mock.patch.object(c, "_collect_prerequisites") as private:
            c.collect_two_prerequisites(self.work, report, None, b"")
            self.assertFalse(private.call_args.kwargs["ready"])
        forged = report | {
            "schema": "W-A1-public-Engine-DATA/1",
            "four_queries_projected": True,
            "all_clients_reaped_drained": True,
        }
        with mock.patch.object(c, "_collect_prerequisites") as private:
            c.collect_prerequisites(self.work, forged, None, b"")
            self.assertFalse(private.call_args.kwargs["ready"])

    def test_pull_exact_once_closed_env_and_unknown_gate(self):
        self.work.mkdir()
        verified, calls = [], []
        owner = SimpleNamespace(
            CLI_FACTS={
                "sha256": "3e898b1e7498b1bf98ec29a3d2ce77f9f09dd357e0b8dbf6ca69b463a871de88"
            },
            verify_cli=lambda: verified.append(True),
        )
        public = c.public_module()

        def run(argv, **opts):
            self.assertEqual(len(verified), 1)
            calls.append(argv)
            self.assertEqual(
                argv[-5:], ["pull", "--platform", "linux/amd64", "--quiet", q.PG_MANIFEST]
            )
            self.assertEqual(
                set(opts["env"]), {"PATH", "HOME", "LANG", "LC_ALL", "DOCKER_API_VERSION"}
            )
            self.assertEqual(
                (opts["timeout"], opts["stdout_cap"], opts["stderr_cap"]), (55, 4096, 4096)
            )
            opts["on_spawn"](987)
            result = Result(owned_child_reaped=False)
            result.stdout = b"PRIVATE_FAKE_SENTINEL_NEVER_PUBLISHED"
            return result

        value = q.pull_public(self.work, owner, SimpleNamespace(run_capped=run), public)
        self.assertEqual(len(calls), 1)
        self.assertFalse(value["complete"])
        self.assertTrue((self.work / "pull-process.json").exists())
        for path in self.work.glob("*.json"):
            self.assertNotIn(b"PRIVATE_FAKE_SENTINEL", path.read_bytes())


class Graph(unittest.TestCase):
    def test_event_ref_repo_scope_closed(self):
        valid = {
            "GITHUB_REPOSITORY": "pamolive/PamOlive-Platform",
            "GITHUB_JOB": "public_prerequisites",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": q.PUSH_REF,
        }
        q.event_guard(valid)
        q.event_guard(valid | {"GITHUB_EVENT_NAME": "workflow_dispatch"})
        for delta in (
            {"GITHUB_REPOSITORY": "fork/PamOlive-Platform"},
            {"GITHUB_JOB": "Platform"},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_EVENT_NAME": "schedule"},
            {"GITHUB_REF": "refs/heads/main"},
            {"GITHUB_REF": q.PUSH_REF + "-suffix"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main"},
            {"GITHUB_REF": "refs/tags/agent/ci-public-observer-diagnostics-ecfe"},
        ):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                q.event_guard(valid | delta)

    def test_235_horizon_exact_pull_pg_boundaries_and_preparation(self):
        for before_pull, before_pg, finished, expected_count, expected_state in (
            (45, 105, 235, 3, "DATA_COMPLETE"),
            (45.001, 105, 235, 1, "FAILED_OR_UNKNOWN"),
            (45, 105.001, 235, 2, "FAILED_OR_UNKNOWN"),
            (45, 105, 235.001, 3, "FAILED_OR_UNKNOWN"),
        ):
            calls = []
            clock = iter((0, 0, before_pull, before_pg, finished))

            def action():
                calls.append(True)
                return {"complete": True}

            report = q.campaign(
                action, action, action, lambda *args: None, clock=lambda: next(clock)
            )
            self.assertEqual(len(calls), expected_count)
            self.assertEqual(report["state"], expected_state)
        calls = []
        report = q.campaign(
            lambda: calls.append(True),
            lambda: calls.append(True),
            lambda: calls.append(True),
            lambda *args: None,
            clock=lambda: 160,
            started=0,
        )
        self.assertEqual(calls, [])
        self.assertEqual(report["state"], "FAILED_OR_UNKNOWN")

    def test_no_pull_or_pg_after_root_unknown(self):
        calls = []

        def observed():
            calls.append("observe")
            return {"complete": False}

        def forbidden():
            self.fail("operation after unknown observation")

        report = q.campaign(observed, forbidden, forbidden, lambda *args: None, clock=lambda: 0)
        self.assertEqual(calls, ["observe"])
        self.assertEqual(report["state"], "FAILED_OR_UNKNOWN")

    def test_no_retry_no_pg_after_unknown_pull(self):
        calls, saved = [], {}

        def action(name, ok):
            def invoke():
                calls.append(name)
                return {"complete": ok}

            return invoke

        report = q.campaign(
            action("observe", True),
            action("pull", False),
            action("pg", True),
            lambda name, value: saved.update({name: copy.deepcopy(value)}),
            clock=lambda: 0,
        )
        self.assertEqual(calls, ["observe", "pull"])
        self.assertEqual(report["state"], "FAILED_OR_UNKNOWN")
        self.assertFalse(report["authority"])
        self.assertIn("intent", saved)

    def test_deadline_refuses_before_owner_cleanup_window(self):
        seen = []
        clock = iter((0, 0, 0, 170))

        def ok():
            seen.append(True)
            return {"complete": True}

        report = q.campaign(ok, ok, ok, lambda *args: None, clock=lambda: next(clock))
        self.assertEqual(len(seen), 2)
        self.assertEqual(report["state"], "FAILED_OR_UNKNOWN")

    def test_complete_requires_three_actual_complete_packets(self):
        report = q.campaign(
            *([lambda: {"complete": True}] * 3), lambda *args: None, clock=lambda: 0
        )
        self.assertEqual(report["state"], "DATA_COMPLETE")
        self.assertEqual(set(report["phases"]), {"observation", "pull", "pg"})
        self.assertFalse(report["profile_accepted"])


def read_workflow(base=HERE):
    if base.name == "public_prerequisites_dispatch" and base.parent.name == "qualification":
        path = base.parent.parent / ".github/workflows/public-prerequisites.yml"
    else:
        # Explicit preparation layout only; never a fallback after a missing real workflow.
        q.need(
            base.parent.name == "output"
            and base.name == "public-prerequisites-dispatch-source-20261116-r3",
            "EXPLICIT_OUT_LAYOUT_ONLY",
        )
        path = base / "workflow.proposed.yml"
    return q.regular(path, 65536).decode("utf-8").replace("\r\n", "\n")


class SourceContracts(unittest.TestCase):
    def test_repo_layout_requires_actual_workflow_no_DATA_fallback(self):
        with tempfile.TemporaryDirectory(dir=WORK, prefix="workflow-layout-") as directory:
            root = Path(directory)
            deployed = root / "qualification/public_prerequisites_dispatch"
            deployed.mkdir(parents=True)
            (deployed / "workflow.proposed.yml").write_text("wrong DATA fallback\n")
            with self.assertRaises(FileNotFoundError):
                read_workflow(deployed)
            actual = root / ".github/workflows/public-prerequisites.yml"
            actual.parent.mkdir(parents=True)
            actual.write_text("actual deployed workflow\n")
            self.assertEqual(read_workflow(deployed), "actual deployed workflow\n")
            with self.assertRaises(ValueError):
                read_workflow(root / "unrecognized-layout")

    def test_private_bodies_inverse_ast_equal_parent(self):
        old = ast.parse((HERE / "collector.before.DATA.py").read_text())
        new = ast.parse((HERE / "engine/collector.py").read_text())

        def functions(tree):
            return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

        original, changed = functions(old), functions(new)
        generic = copy.deepcopy(changed["_collect"])
        generic.name = "collect"
        generic.args = original["collect"].args

        class Restore(ast.NodeTransformer):
            def visit_Name(self, node):
                if node.id == "commands":
                    node.id = "COMMANDS"
                return node

            def visit_Dict(self, node):
                self.generic_visit(node)
                if any(
                    isinstance(k, ast.Constant) and k.value == "queries_projected"
                    for k in node.keys
                ):
                    node.keys.insert(0, ast.Constant("schema"))
                    node.values.insert(0, ast.Constant("W-A1-public-Engine-DATA/1"))
                    for key in node.keys:
                        if isinstance(key, ast.Constant) and key.value == "queries_projected":
                            key.value = "four_queries_projected"
                return node

        self.assertEqual(ast.dump(Restore().visit(generic)), ast.dump(original["collect"]))
        generic = copy.deepcopy(changed["_collect_prerequisites"])
        generic.name = "collect_prerequisites"
        generic.args = original["collect_prerequisites"].args
        next(n for n in generic.body if isinstance(n, ast.If)).test = next(
            n for n in original["collect_prerequisites"].body if isinstance(n, ast.If)
        ).test
        self.assertEqual(ast.dump(generic), ast.dump(original["collect_prerequisites"]))

    def test_payload_gate_closed_set(self):
        payload = (HERE / "payload.json").read_bytes()
        fixed_mapping = q.source_path
        with mock.patch.object(
            q,
            "source_path",
            lambda name: PG_REFERENCE / name.removeprefix("pg/")
            if name.startswith("pg/")
            else fixed_mapping(name),
        ):
            buffers = q.capture(q.sha(payload))
        self.assertEqual(set(buffers), q.FILES)
        self.assertEqual(len(buffers), 15)
        self.assertEqual(
            q.sha(buffers["engine/containerd_public.py"]),
            "556c24b9265b291a155ea15212f74853727f768795b6ffffc99f5a07e23e1e21",
        )
        with self.assertRaises(ValueError):
            q.capture("0" * 64)

    def test_manual_workflow_scope_pins_no_product_or_private(self):
        workflow = read_workflow()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn(
            "on:\n  push:\n    branches: [agent/ci-public-observer-diagnostics-ecfe]\n"
            "  workflow_dispatch:",
            workflow,
        )
        self.assertIn("github.ref == '" + q.PUSH_REF + "'", workflow)
        self.assertIn(
            "github.event_name == 'push' || github.event_name == 'workflow_dispatch'", workflow
        )
        self.assertIn("GITHUB_REF='${{ github.ref }}'", workflow)
        self.assertIn("GITHUB_EVENT_NAME='${{ github.event_name }}'", workflow)
        self.assertIn("GITHUB_REPOSITORY='${{ github.repository }}'", workflow)
        self.assertIn("timeout-minutes: 5", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn(
            "--query-mode prerequisites-only --github-hosted-disposable-public-read", workflow
        )
        for forbidden in (
            "continue-on-error",
            "pull_request:",
            "workflow_call:",
            "schedule:",
            "services:",
            "secrets.",
            "docker build",
            "docker run",
            "docker compose",
        ):
            self.assertNotIn(forbidden, workflow)
        for name in ("quick.py", "run_pure.py", "test_source.py", "payload.json"):
            self.assertIn(q.sha((HERE / name).read_bytes()), workflow)
