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


class Contracts(unittest.TestCase):
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
        capture_line = next(
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and node.value == "worker-data.json"
        )
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
        self.assertLess(capture_line, refusal_line)
        self.assertIn("test_pamolive_p1g_browser", body)
        self.assertIn("before[2] is None", body)
        self.assertIn('"VM_teardown_is_not_cleanup_evidence": True', body)
        self.assertIn('"full_P1G_qualified": False', body)
