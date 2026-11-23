"""Preparation-only contracts. These do not execute a browser, Django or SQL."""

import ast
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from qualification.p1g_headless import lab_support as lab


def environment():
    return {
        "GITHUB_ACTIONS": "true",
        "PAMOLIVE_P1G_DISPOSABLE": "1",
        "GITHUB_REPOSITORY": "pamolive/PamOlive-Platform",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/heads/agent/p1-g-headless",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "DATABASE_URL": "postgresql://p1g:synthetic-only@127.0.0.1:15432/pamolive_p1g",
        "PAMOLIVE_TEST_DATABASE_NAME": "test_pamolive_p1g_browser",
    }


def sandbox_rows():
    return [
        ["Layer 1 Sandbox", "Namespace"],
        ["PID namespaces", "Yes"],
        ["Network namespaces", "Yes"],
        ["Seccomp-BPF sandbox", "Yes"],
        ["Seccomp-BPF sandbox supports TSYNC", "Yes"],
    ]


def kernel_status(pid, uid, depth, filters, *, no_new_privs=1, seccomp=2, caps=0):
    pids = str(pid) + " 7" * (depth - 1)
    return (
        f"Pid:\t{pid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nNSpid:\t{pids}\n"
        f"NoNewPrivs:\t{no_new_privs}\nSeccomp:\t{seccomp}\nSeccomp_filters:\t{filters}\n"
        f"CapEff:\t{caps:016x}\n"
    ).encode("ascii")


class Contracts(unittest.TestCase):
    def test_sandbox_diagnostic_refuses_absent_missing_or_duplicate_rows(self):
        good = "You are adequately sandboxed."
        lab.sandbox_diagnostic(sandbox_rows(), good)
        suid_rows = sandbox_rows()
        suid_rows[0][1] = "SUID"
        lab.sandbox_diagnostic(suid_rows, good)
        for index, value in enumerate(("None", "No", "No", "No")):
            rows = sandbox_rows()
            rows[index][1] = value
            with self.assertRaisesRegex(ValueError, "chromium_sandbox_not_active"):
                lab.sandbox_diagnostic(rows, good)
        with self.assertRaisesRegex(ValueError, "sandbox_diagnostic_shape"):
            lab.sandbox_diagnostic(sandbox_rows() + [sandbox_rows()[0]], good)
        with self.assertRaisesRegex(ValueError, "sandbox_diagnostic_rows"):
            lab.sandbox_diagnostic(sandbox_rows()[:-1], good)

    def test_kernel_renderer_requires_its_own_namespace_and_filter(self):
        host = lab.process_sandbox_status(kernel_status(100, 1001, 1, 1), 100, 1001)
        good = lab.process_sandbox_status(kernel_status(200, 1001, 2, 2), 200, 1001)
        self.assertTrue(lab.renderer_sandboxed(good, host))
        for changed in ({"pid_depth": 1}, {"filters": 1}, {"restricted": False}):
            self.assertFalse(lab.renderer_sandboxed({**good, **changed}, host))
        for flags in ({"no_new_privs": 0}, {"seccomp": 0}, {"caps": 8}):
            observed = lab.process_sandbox_status(
                kernel_status(200, 1001, 2, 2, **flags),
                200,
                1001,
            )
            self.assertFalse(lab.renderer_sandboxed(observed, host))
        with self.assertRaisesRegex(ValueError, "sandbox_status_identity"):
            lab.process_sandbox_status(kernel_status(200, 1001, 2, 2), 200, 1002)

    def test_sandbox_receipt_keeps_apparmor_mode_separate(self):
        self.assertEqual(lab.apparmor_mode(b"synthetic (enforce)\n"), "enforce")
        self.assertEqual(lab.apparmor_mode(b"unconfined\n"), "unconfined")
        self.assertEqual(lab.apparmor_mode(b"synthetic (complain)\n"), "complain")
        with self.assertRaisesRegex(ValueError, "sandbox_apparmor_unknown"):
            lab.apparmor_mode(b"synthetic (unknown)\n")
        receipt = {
            "schema": "pamolive.p1g-active-sandbox/1",
            "browser_apparmor": "unconfined",
            "renderer_apparmor": ["unconfined"],
            "renderers_checked": 1,
        }
        self.assertTrue(lab.sandbox_receipt(receipt))
        self.assertFalse(lab.sandbox_receipt({**receipt, "renderers_checked": True}))
        self.assertFalse(lab.sandbox_receipt({**receipt, "renderer_apparmor": [[]]}))
        self.assertFalse(lab.sandbox_receipt({**receipt, "apparmor_enforced": True}))

    def test_active_browser_probe_uses_inert_pages_and_closes_them_on_failure(self):
        for remove_renderer in (False, True):
            with self.subTest(remove_renderer=remove_renderer):
                browser = mock.Mock()
                context = browser.new_context.return_value
                diagnostic, inert = mock.Mock(), mock.Mock()
                context.new_page.side_effect = [diagnostic, inert]
                diagnostic.url = lab.SANDBOX_URL
                diagnostic.locator.side_effect = [
                    mock.Mock(evaluate_all=mock.Mock(return_value=sandbox_rows())),
                    mock.Mock(text_content=mock.Mock(return_value="You are adequately sandboxed.")),
                ]
                session = browser.new_browser_cdp_session.return_value
                root_process = {"id": 100, "type": "browser"}
                renderer = {"id": 200, "type": "renderer"}
                all_processes = [root_process, renderer]
                session.send.side_effect = [
                    {"processInfo": all_processes},
                    {"processInfo": [root_process] if remove_renderer else all_processes},
                ]
                facts = [
                    {"pid_depth": 1, "filters": 1, "restricted": False, "apparmor": "unconfined"},
                    {"pid_depth": 2, "filters": 2, "restricted": True, "apparmor": "enforce"},
                ]
                path = Path("/synthetic-review/chrome")
                with (
                    mock.patch.object(lab.os, "getuid", return_value=1001, create=True),
                    mock.patch.object(lab, "observe_process", side_effect=facts) as observe,
                ):
                    if remove_renderer:
                        with self.assertRaisesRegex(ValueError, "sandbox_renderer_missing"):
                            lab.observe_browser_sandbox(browser, path)
                    else:
                        receipt = lab.observe_browser_sandbox(browser, path)
                        self.assertTrue(lab.sandbox_receipt(receipt))
                        self.assertEqual(receipt["renderer_apparmor"], ["enforce"])
                    observe.assert_has_calls(
                        [mock.call(100, 1001, executable=path), mock.call(200, 1001)]
                    )
                diagnostic.goto.assert_called_once_with(
                    lab.SANDBOX_URL,
                    wait_until="load",
                    timeout=10000,
                )
                inert.set_content.assert_called_once()
                session.detach.assert_called_once()
                context.close.assert_called_once()

    def test_chrome_refusal_codes_are_exact_closed_and_phase_exclusive(self):
        class PrivateValueError(ValueError):
            def __str__(self):
                raise AssertionError("no_exception_stringification")

        codes = {
            "tool_alias_refused",
            "tool_type_owner_mode",
            "tool_parent_writable_or_alias",
            "tool_fd_identity",
            "tool_byte_budget",
            "tool_changed_or_not_ELF",
        }
        with mock.patch.object(Path, "lstat", side_effect=OSError) as read:
            for code in codes:
                packet = lab.chrome_tool_diagnostic(ValueError(code), phase="chrome_tool_preflight")
                self.assertEqual(packet["code"], code)
                self.assertEqual(packet["leaf"]["state"], "unknown")
            for error in (
                ValueError("tool_alias_refused\n::error::SYNTHETIC_PRIVATE"),
                ValueError("SYNTHETIC_PRIVATE"),
                ValueError(True),
                ValueError({"secret": "SYNTHETIC_PRIVATE"}),
                ValueError("tool_alias_refused", "SYNTHETIC_PRIVATE"),
                RuntimeError("tool_alias_refused"),
                PrivateValueError("tool_alias_refused"),
            ):
                packet = lab.chrome_tool_diagnostic(error, phase="chrome_tool_preflight")
                self.assertEqual(packet["code"], "unknown")
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(packet))
            read.reset_mock()
            for phase in ("source_binding", "resource_preflight", "TLS_setup", "browser_increment"):
                self.assertIsNone(
                    lab.chrome_tool_diagnostic(ValueError(next(iter(codes))), phase=phase)
                )
            read.assert_not_called()

    def test_chrome_leaf_projection_has_fixed_path_closed_types_and_no_target(self):
        row = SimpleNamespace(st_mode=0o100755, st_uid=0, st_gid=1, st_nlink=2, st_size=1234)
        fixed = Path("/opt/google/chrome/chrome")
        with (
            mock.patch.object(Path, "lstat", return_value=row) as read,
            mock.patch.object(Path, "resolve", return_value=Path("/synthetic/target")),
            mock.patch.object(Path, "open", side_effect=AssertionError("no_content_read")),
        ):
            packet = lab.chrome_tool_diagnostic(
                ValueError("tool_type_owner_mode"), phase="chrome_tool_preflight"
            )
        read.assert_called_once_with()
        self.assertEqual(
            packet["leaf"],
            {
                "state": "observed",
                "type": "regular",
                "uid": 0,
                "gid": 1,
                "mode": 0o755,
                "nlink": 2,
                "size_bytes": 1234,
                "alias": True,
            },
        )
        self.assertNotIn("/synthetic/target", json.dumps(packet))
        for mode, kind in ((0o120777, "symlink"), (0o40755, "directory"), (0o10600, "other")):
            row.st_mode = mode
            with (
                mock.patch.object(Path, "lstat", return_value=row),
                mock.patch.object(Path, "resolve", return_value=fixed),
            ):
                leaf = lab.chrome_tool_diagnostic(ValueError(), phase="chrome_tool_preflight")[
                    "leaf"
                ]
                self.assertEqual(leaf["type"], kind)
                self.assertIs(leaf["alias"], False)
        # The metadata path is a source literal, never an exception argument.
        body = (Path(__file__).parent / "lab_support.py").read_text(encoding="utf-8")
        tree = ast.parse(body)
        function = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "chrome_tool_diagnostic"
        )
        paths = [
            n
            for n in ast.walk(function)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "Path"
        ]
        self.assertEqual(
            [ast.literal_eval(n.args[0]) for n in paths], [str(fixed).replace("\\", "/")]
        )

    def test_chrome_leaf_absent_or_bad_numeric_metadata_remains_unknown(self):
        original = dict(st_mode=0o100755, st_uid=0, st_gid=0, st_nlink=1, st_size=8)
        for key, bad in (
            ("st_mode", True),
            ("st_mode", 0o200000),
            ("st_uid", "0"),
            ("st_gid", -1),
            ("st_uid", 2**32),
            ("st_nlink", 2**32),
            ("st_nlink", False),
            ("st_size", 2**63),
            ("st_size", -1),
        ):
            with (
                self.subTest(key=key, bad=bad),
                mock.patch.object(
                    Path, "lstat", return_value=SimpleNamespace(**(original | {key: bad}))
                ),
                mock.patch.object(Path, "resolve", side_effect=AssertionError("not_validated")),
            ):
                packet = lab.chrome_tool_diagnostic(ValueError(), phase="chrome_tool_preflight")
                self.assertEqual(packet["leaf"]["state"], "unknown")
                self.assertTrue(
                    all(
                        packet["leaf"][k] is None
                        for k in ("uid", "gid", "mode", "nlink", "size_bytes", "alias")
                    )
                )
        for error, state in ((FileNotFoundError(), "absent"), (PermissionError(), "unknown")):
            with mock.patch.object(Path, "lstat", side_effect=error):
                self.assertEqual(
                    lab.chrome_tool_diagnostic(ValueError(), phase="chrome_tool_preflight")["leaf"][
                        "state"
                    ],
                    state,
                )
        with (
            mock.patch.object(Path, "lstat", return_value=SimpleNamespace(**original)),
            mock.patch.object(Path, "resolve", side_effect=OSError),
        ):
            leaf = lab.chrome_tool_diagnostic(ValueError(), phase="chrome_tool_preflight")["leaf"]
            self.assertEqual(leaf["state"], "observed")
            self.assertIsNone(leaf["alias"])

    def test_actual_worker_only_chrome_phase_publishes_the_enum(self):
        from qualification.p1g_headless import run_lab as controller

        for fail_at in ("source_binding", "resources", "tool_pin"):
            with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as tmp:
                private = Path(tmp)
                written = {}
                info = SimpleNamespace(st_mode=0o40700, st_uid=1001)

                def lstat(path):
                    if path == private:
                        return info
                    raise PermissionError

                with (
                    mock.patch.object(Path, "lstat", lstat),
                    mock.patch.object(Path, "resolve", lambda path, strict=False: path),
                    mock.patch.object(os, "getuid", return_value=1001, create=True),
                    mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp, "GITHUB_SHA": "a" * 40}),
                    mock.patch.object(lab, "source_binding", return_value={}),
                    mock.patch.object(lab, "resources", return_value={}),
                    mock.patch.object(lab, "tool_pin", return_value={}),
                    mock.patch.object(lab, fail_at, side_effect=ValueError("tool_alias_refused")),
                    mock.patch.object(
                        lab, "prepare_tls", side_effect=AssertionError("not_reached")
                    ),
                    mock.patch.object(
                        lab,
                        "fresh_write",
                        side_effect=lambda path, raw: written.update({path.name: json.loads(raw)}),
                    ),
                ):
                    self.assertEqual(controller.worker(private), 42)
                packet = written["worker-report.json"]
                self.assertEqual(packet["state"], "FAILED_OR_UNKNOWN")
                self.assertEqual(packet["tests"], 0)
                self.assertFalse(packet["full_P1G_qualified"])
                if fail_at == "tool_pin":
                    self.assertEqual(packet["phase"], "chrome_tool_preflight")
                    self.assertEqual(packet["chrome_tool_diagnostic"]["code"], "tool_alias_refused")
                else:
                    self.assertNotIn("chrome_tool_diagnostic", packet)

    def source_fixture(self, root):
        pins, files = {}, {}
        for index in range(24):
            name = f"template-{index:02d}.txt"
            (root / name).write_bytes(b"synthetic UI source")
            pins[name] = files[name] = hashlib.sha256(b"synthetic UI source").hexdigest()
        name = "qualification/p1g_headless/ui-input-pins.json"
        manifest = root / name
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps(pins), encoding="utf-8")
        files[name] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        receipt = root / "context.json"
        receipt.write_text(
            json.dumps(
                {
                    "schema": "pamolive.committed-build-context.v1",
                    "revision": "a" * 40,
                    "files": files,
                }
            ),
            encoding="utf-8",
        )
        return pins, manifest, receipt

    def test_pin_manifest_cannot_hide_mutated_or_omitted_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins, manifest, receipt = self.source_fixture(root)
            reader = SimpleNamespace(read_regular=lambda path, cap: path.read_bytes())
            with mock.patch.object(lab, "bounded", return_value=reader):
                self.assertEqual(
                    len(lab.source_binding(root, receipt, "a" * 40)["reviewed_UI_inputs"]), 24
                )
                (root / "template-01.txt").write_bytes(b"mutated source")
                del pins["template-01.txt"]
                manifest.write_text(json.dumps(pins), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "UI_pin_manifest_drift"):
                    lab.source_binding(root, receipt, "a" * 40)

    def test_reviewed_input_count_cannot_shrink_with_a_matching_manifest_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins, manifest, receipt = self.source_fixture(root)
            pins.pop("template-01.txt")
            manifest.write_text(json.dumps(pins), encoding="utf-8")
            value = json.loads(receipt.read_text(encoding="utf-8"))
            value["files"]["qualification/p1g_headless/ui-input-pins.json"] = hashlib.sha256(
                manifest.read_bytes()
            ).hexdigest()
            receipt.write_text(json.dumps(value), encoding="utf-8")
            with mock.patch.object(
                lab,
                "bounded",
                return_value=SimpleNamespace(read_regular=lambda p, cap: p.read_bytes()),
            ):
                with self.assertRaisesRegex(ValueError, "UI_input_pin_budget"):
                    lab.source_binding(root, receipt, "a" * 40)

    def test_exact_disposable_push_and_same_repository_PR(self):
        env = environment()
        lab.guard(env, platform="linux", uid=1001)
        env.update(
            GITHUB_EVENT_NAME="pull_request",
            GITHUB_HEAD_REF="agent/p1-g-headless",
            P1G_HEAD_REPOSITORY="pamolive/PamOlive-Platform",
        )
        lab.guard(env, platform="linux", uid=1001)
        env["P1G_HEAD_REPOSITORY"] = "foreign/fork"
        with self.assertRaises(ValueError):
            lab.guard(env, platform="linux", uid=1001)

    def test_PC_root_unknown_event_repo_branch_refused(self):
        for platform, uid in (("win32", 1001), ("linux", 0)):
            with self.subTest(platform=platform, uid=uid), self.assertRaises(ValueError):
                lab.guard(environment(), platform=platform, uid=uid)
        for key, value in (
            ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_REPOSITORY", "foreign/repo"),
            ("PAMOLIVE_P1G_DISPOSABLE", "0"),
            ("GITHUB_SHA", "not_a_commit"),
        ):
            env = environment()
            env[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                lab.guard(env, platform="linux", uid=1001)

    def test_no_existing_database_or_external_host_profile(self):
        for url in (
            "postgresql://p1g:p@nas.example:5432/pamolive_p1g",
            "postgresql://root:p@127.0.0.1:5432/pamolive_p1g",
            "postgresql://p1g:p@127.0.0.1:5432/existing",
            "postgresql://p1g:p@127.0.0.1:5432/pamolive_p1g?sslmode=disable",
        ):
            env = environment()
            env["DATABASE_URL"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                lab.guard(env, platform="linux", uid=1001)

    def test_application_origin_has_no_suffix_scheme_or_credentials_escape(self):
        origin = "https://pam.example.test:12345"
        self.assertTrue(lab.same_origin(origin + "/static/app.js", origin))
        for url in (
            "http://pam.example.test:12345/",
            "https://pam.example.test:1/",
            "https://pam.example.test.evil:12345/",
            "https://u:p@pam.example.test:12345/",
        ):
            with self.subTest(url=url):
                self.assertFalse(lab.same_origin(url, origin))

    def test_atime_change_does_not_invalidate_unchanged_data_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "ELF-DATA-only"
            path.write_bytes(b"\x7fELF" + b"x" * 32)
            real = path.stat()
            names = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_atime_ns",
            )
            attrs = {key: getattr(real, key) for key in names}
            attrs["st_mode"] &= ~0o6022
            before = SimpleNamespace(**attrs)
            attrs["st_atime_ns"] += 1
            after = SimpleNamespace(**attrs)
            with (
                mock.patch.object(Path, "lstat", side_effect=[before, after]),
                mock.patch.object(os, "fstat", return_value=before),
                mock.patch.object(os, "getuid", return_value=before.st_uid, create=True),
            ):
                pin = lab.tool_pin(path, root_owner=False)
            self.assertEqual(pin["bytes"], 36)

    def test_actual_NSS_supervisor_incomplete_child_retains_UNKNOWN(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = SimpleNamespace(
                ok=True,
                spawn_attempted=True,
                pid=123,
                returncode=0,
                reason=None,
                owned_child_reaped=False,
                drains_complete=True,
                killed_owned_child=False,
                exception_type=None,
                cleanup_exception_type=None,
                stdout=b"",
                stderr=b"",
                facts=lambda: {"owned_child_reaped": False},
            )

            def run(*args, **kwargs):
                self.assertEqual(
                    json.loads((root / "command/intent.json").read_bytes())["state"], "PENDING"
                )
                self.assertEqual(set(kwargs["env"]), {"PATH", "HOME", "LANG", "LC_ALL"})
                self.assertEqual(kwargs["timeout"], 15)
                self.assertEqual(kwargs["work_timeout"], 10)
                kwargs["on_spawn"](123)
                return result

            io = SimpleNamespace(run_capped=run)
            with mock.patch.object(lab, "tool_pin", return_value={"sha256": "a" * 64}):
                with self.assertRaisesRegex(ValueError, "failed_or_unknown"):
                    lab.public_command(io, ["/usr/bin/certutil", "-N"], root, root / "command")
            self.assertEqual(
                json.loads((root / "command/UNKNOWN.json").read_bytes())["state"], "UNKNOWN"
            )

    def test_source_has_real_WebAuthn_JS_no_login_or_TLS_shortcut(self):
        root = Path(__file__).resolve().parent
        body = (root / "browser_case.py").read_text(encoding="utf-8")
        tree = ast.parse(body)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        launch = [
            node
            for node in calls
            if isinstance(node.func, ast.Attribute) and node.func.attr == "launch"
        ]
        self.assertEqual(len(launch), 1)
        options = {item.arg: item.value for item in launch[0].keywords}
        self.assertTrue(ast.literal_eval(options["chromium_sandbox"]))
        sandbox = next(
            node
            for node in calls
            if isinstance(node.func, ast.Attribute) and node.func.attr == "observe_browser_sandbox"
        )
        method = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "test_synthetic_JS_increment"
        )
        first_login = min(
            node.lineno
            for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "login"
        )
        self.assertLess(launch[0].lineno, sandbox.lineno)
        self.assertLess(sandbox.lineno, first_login)
        self.assertNotIn("--no-sandbox", body)
        self.assertNotIn("ignore_https_errors=True", body)
        self.assertNotIn("force_login", body)
        self.assertNotIn("storage_state=", body)
        self.assertNotIn('session["mfa_verified_at"]', body)
        self.assertIn("WebAuthn.addVirtualAuthenticator", body)
        self.assertIn("self.trust.update", body)
        self.assertIn("verify_authorization_evidence", body)
        self.assertIn('reverse("grant-review"', body)
        self.assertIn('name="Retirer le droit"', body)
        self.assertNotIn("review_grant(", body)
        constants = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertIn('#pam-trust-form button[type="submit"]', constants)

    def test_controller_capture_precedes_failure_gate_and_full_P1G_stays_open(self):
        body = (Path(__file__).resolve().parent / "run_lab.py").read_text(encoding="utf-8")
        tree = ast.parse(body)
        failure_capture, success_capture = sorted(
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and node.value == "worker-data.json"
        )
        failure_branch = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "packet['state'] == 'FAILED_OR_UNKNOWN'"
        )
        self.assertLess(failure_branch.lineno, failure_capture)
        self.assertEqual(failure_branch.end_lineno, failure_capture)
        refusal_line = next(
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "need"
            and any(
                isinstance(child, ast.Attribute) and child.attr == "ok" for child in ast.walk(node)
            )
        )
        packet_gate = next(
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "need"
            and any(
                isinstance(child, ast.Constant) and child.value == "worker_packet_refused"
                for child in ast.walk(node)
            )
        )
        self.assertLess(failure_capture, refusal_line)
        self.assertLess(packet_gate, success_capture)
        self.assertIn("test_pamolive_p1g_browser", body)
        self.assertIn("before[2] is None", body)
        self.assertIn('"VM_teardown_is_not_cleanup_evidence": True', body)
        self.assertIn('"full_P1G_qualified": False', body)
        self.assertIn('sandbox_receipt(value["browser_sandbox"])', body)
        self.assertIn('sandbox_receipt(report.get("browser_sandbox"))', body)
