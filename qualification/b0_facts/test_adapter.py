"""Pure adapter tests: original lifecycle, fake daemon, fresh synthetic files only."""

import ast
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import adapter as A

ROOT = Path(__file__).resolve().parent
MANIFEST_SHA = A.digest((ROOT / "facts-assets.json").read_bytes())


def success():
    return {
        "schema": "pamolive.b0-d0-public-facts/1",
        "phase": A.PHASE,
        "code": "B0_FACTS_PUBLIC_INVENTORY_READY",
        "ok": True,
        "os": [],
        "repositories": [{}],
        "keyring": {
            "primary_fingerprints": None,
            "subkey_fingerprints": None,
            "certificate_bindings_verified": False,
        },
        "global_trust_inventory": [],
        "packages": [],
        "architecture_file_names": None,
        "nss_package_records": {},
        "files": [],
        "hashed_bytes": 0,
        "truncation": False,
        "stage0_passed": False,
        "certutil_functional": None,
        "nss_empty": None,
        "Release_signatures_verified": False,
        "archives_verified": False,
        "dynamic_library_selection_verified": False,
        "TLS_observed": False,
        "sandbox_observed": False,
        "CDP_observed": False,
        "authority": False,
        "build_verified": False,
        "attestation_verified": False,
        "release_qualified": False,
        "nodeVersion": "v26.13.0",
    }


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.module, self.pins, self.buffers = A.context(ROOT, MANIFEST_SHA)
        self.temp = tempfile.TemporaryDirectory(prefix="b0-d0-public-")
        self.root = Path(self.temp.name)
        self.assertTrue(self.root.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)

    def test_all_four_original_stage0_assets_remain_byte_exact(self):
        for name, expected in A.LEGACY_HASHES.items():
            self.assertEqual(A.digest((ROOT / "legacy" / name).read_bytes()), expected)
        old = ast.parse((ROOT / "legacy/controller.py").read_bytes())
        parser = next(
            n
            for n in ast.walk(old)
            if isinstance(n, ast.Call)
            and any(
                k.arg == "choices" and isinstance(k.value, ast.Tuple) and len(k.value.elts) == 4
                for k in n.keywords
            )
        )
        self.assertEqual(
            ast.literal_eval(next(k.value for k in parser.keywords if k.arg == "choices")),
            ("prepare", "pull", "stage0", "cleanup"),
        )
        self.assertEqual(self.module.ASSETS, {"stage0.cjs": 16384, "pins-stage0.json": 8192})
        for name, expected in {
            "test_pure.py": ("c6d04fd94df725da91b9103bd5febb65638a06edb87658629fdf33235486d4a3"),
            "review-sources.sha256": (
                "ee1c0ffd8907da498b5e7c43ebd860dce20f7dd5fce15dc499751c6bff6bd99c"
            ),
        }.items():
            self.assertEqual(A.digest((ROOT / "legacy" / name).read_bytes()), expected)

    def test_probe_has_no_child_network_gpg_or_private_environment_dependency(self):
        source = (ROOT / "facts.cjs").read_text(encoding="utf-8")
        self.assertEqual(
            set(re.findall(r"require\('([^']+)'\)", source)),
            {"node:fs", "node:crypto", "node:path", "node:util"},
        )
        self.assertEqual(re.findall(r"process\.env\.([A-Z0-9_]+)", source), ["B0_PINS_SHA256"])
        self.assertNotRegex(source, r"\b(?:spawn|spawnSync|exec|execSync|fetch|eval)\s*\(")
        self.assertNotIn("readFileSync", source)

    def test_manifest_and_input_pins_checked_before_use(self):
        with self.assertRaisesRegex(RuntimeError, "B0_FACTS_MANIFEST_CHANGED"):
            A.context(ROOT, "0" * 64)
        candidate = self.root / "candidate"
        (candidate / "legacy").mkdir(parents=True)
        for name in A.LEGACY_HASHES:
            (candidate / "legacy" / name).write_bytes((ROOT / "legacy" / name).read_bytes())
        for name in (*A.ASSETS, "facts-assets.json"):
            (candidate / name).write_bytes((ROOT / name).read_bytes())
        (candidate / "facts.cjs").write_bytes(b"NOT THE REVIEWED PROBE")
        with self.assertRaisesRegex(RuntimeError, "B0_FACTS_ASSET_CHANGED"):
            A.context(candidate, MANIFEST_SHA)

    def test_new_spool_is_exact_two_readonly_files_not_source_or_git(self):
        A.spool(self.module, self.root, self.buffers)
        self.assertEqual({p.name for p in (self.root / "inputs").iterdir()}, set(A.ASSETS))
        (self.root / "inputs/.git").mkdir()
        with self.assertRaisesRegex(self.module.Refusal, "SPOOL_NOT_CLOSED"):
            A.check_spool(self.module, self.root, self.buffers)

    def test_container_profile_prefix_exact_only_no_shell_entrypoint_tail_differs(self):
        state = {
            "user": "1000:1000",
            "pins_sha256": A.digest(self.buffers["facts-pins.json"]),
        }
        old = self.module.create_arguments(self.root, self.pins, state)
        new = A.create_arguments(self.module, self.root, self.pins, state)
        at = old.index("--entrypoint")
        self.assertEqual(old[:at], new[:at])
        self.assertEqual(
            new[at:],
            ["--entrypoint", "/usr/bin/node", self.pins["image"], "/inputs/facts.cjs"],
        )
        self.assertIn("--init", new)
        for forbidden in (
            "/bin/sh",
            "-c",
            "stage0.cjs",
            "--privileged",
            "SYS_ADMIN",
            "host",
        ):
            self.assertNotIn(forbidden, new)

    def test_success_is_inventory_only_not_stage0_NSS_TLScert_or_PGP_authority(self):
        self.assertTrue(A.validate_evidence(self.module, success())["ok"])
        for key in (
            "stage0_passed",
            "authority",
            "Release_signatures_verified",
            "archives_verified",
            "dynamic_library_selection_verified",
            "TLS_observed",
            "sandbox_observed",
            "CDP_observed",
            "build_verified",
            "attestation_verified",
            "release_qualified",
            "certutil_functional",
            "nss_empty",
        ):
            row = success()
            row[key] = True
            with self.subTest(key=key), self.assertRaises(self.module.Refusal):
                A.validate_evidence(self.module, row)
        for key in (
            "primary_fingerprints",
            "subkey_fingerprints",
            "certificate_bindings_verified",
        ):
            row = success()
            row["keyring"][key] = True
            with self.subTest(key=key), self.assertRaises(self.module.Refusal):
                A.validate_evidence(self.module, row)

    def test_failure_values_preserved_but_cannot_be_positive_stage0(self):
        row = {
            "schema": "pamolive.b0-d0-public-facts/1",
            "phase": A.PHASE,
            "code": "B0_FACTS_REFUSED",
            "ok": False,
            "stage0_passed": False,
            "primary_fingerprints": None,
            "subkey_fingerprints": None,
            "authority": False,
            "release_qualified": False,
        }
        self.assertFalse(A.validate_evidence(self.module, row)["ok"])
        row["schema"] = "pamolive.b0-stage0-report/2"
        with self.assertRaises(self.module.Refusal):
            A.validate_evidence(self.module, row)

    def test_output_exact_limit_plus_one_and_shared_expansion_bounded(self):
        row = {"value": "abc"}
        raw = A.bounded_json(row)
        self.assertEqual(A.bounded_json(row, len(raw)), raw)
        with self.assertRaises(ValueError):
            A.bounded_json({"value": "abcd"}, len(raw))
        shared = "x" * 8192
        with self.assertRaises(ValueError):
            A.bounded_json([shared] * 2048, 16384)
        A.write_public(self.root, row)
        self.assertEqual((self.root / "public-facts-report.json").read_bytes(), raw)

    def test_prepare_main_with_fully_fake_daemon_retains_false_inventory(self):
        work = self.root / "work"

        def storage(_client, _minimum, observe):
            observe.update(driver="mock", filesystems=[])

        with (
            patch.object(A, "context", return_value=(self.module, self.pins, self.buffers)),
            patch.object(A, "ci_guard"),
            patch.object(self.module, "memory_guard", return_value=4 * 1024**3),
            patch.object(self.module, "storage_observation", side_effect=storage),
            patch.object(self.module, "LocalDocker", return_value=SimpleNamespace()),
            patch.object(A.os, "getuid", return_value=1000, create=True),
            patch.object(A.os, "getgid", return_value=1000, create=True),
            patch.object(
                sys,
                "argv",
                [
                    "adapter.py",
                    "prepare",
                    "--work-dir",
                    str(work),
                    "--manifest-sha256",
                    MANIFEST_SHA,
                ],
            ),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                A.main()
        self.assertEqual(result.exception.code, 0)
        public = json.loads((work / "public-facts-report.json").read_bytes())
        self.assertEqual(public["phase"], A.PHASE)
        self.assertFalse(public["inventory_completed"])
        self.assertFalse(public["stage0_passed"])
        self.assertIsNone(public["certutil_functional"])
        self.assertTrue(public["resources_released"])
        self.assertNotIn("stage0", public)

    def test_public_output_overflow_is_failure_after_owned_cleanup(self):
        work = self.root / "overflow-work"
        original = A.write_public
        writes = []

        def write_once_then_fail_once(directory, report):
            writes.append(report["code"])
            if len(writes) == 1:
                raise ValueError("synthetic serialized budget")
            original(directory, report)

        with (
            patch.object(A, "context", return_value=(self.module, self.pins, self.buffers)),
            patch.object(A, "ci_guard"),
            patch.object(self.module, "memory_guard", return_value=4 * 1024**3),
            patch.object(
                self.module,
                "storage_observation",
                side_effect=lambda _c, _m, out: out.update(driver="mock"),
            ),
            patch.object(self.module, "LocalDocker", return_value=SimpleNamespace()),
            patch.object(A.os, "getuid", return_value=1000, create=True),
            patch.object(A.os, "getgid", return_value=1000, create=True),
            patch.object(A, "write_public", side_effect=write_once_then_fail_once),
            patch.object(
                sys,
                "argv",
                [
                    "adapter.py",
                    "prepare",
                    "--work-dir",
                    str(work),
                    "--manifest-sha256",
                    MANIFEST_SHA,
                ],
            ),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                A.main()
        self.assertEqual(result.exception.code, 42)
        public = json.loads((work / "public-facts-report.json").read_bytes())
        self.assertEqual(public["code"], "B0_FACTS_PUBLIC_OUTPUT_BUDGET")
        self.assertFalse(public["ok"])
        self.assertFalse(public["inventory_completed"])
        self.assertTrue(public["resources_released"])

    def test_legacy_state_cannot_be_used_as_facts_state(self):
        with (
            patch.object(A.os, "getuid", return_value=1000, create=True),
            patch.object(A.os, "getgid", return_value=1000, create=True),
            self.assertRaises(self.module.Refusal),
        ):
            A.state_check(
                self.module,
                {"run": "pamolive-b0-pre-" + "a" * 32},
                self.pins,
                self.buffers,
                MANIFEST_SHA,
            )

    def test_additional_proxy_auth_guard_refuses_presence_without_echo_or_request(self):
        for key in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "DOCKER_AUTH_CONFIG",
        ):
            with (
                patch.object(self.module, "ci_guard"),
                patch.dict(A.os.environ, {key: "synthetic-never-used"}, clear=True),
                self.subTest(key=key),
                self.assertRaisesRegex(
                    self.module.Refusal, "B0_FACTS_AMBIENT_PROXY_OR_AUTH_REFUSED"
                ),
            ):
                A.ci_guard(self.module, self.root)

    def test_adapter_has_no_second_cleanup_or_real_Popen_implementation(self):
        source = ast.parse((ROOT / "adapter.py").read_bytes())
        names = {n.name for n in source.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        self.assertFalse(
            names
            & {
                "LocalDocker",
                "reserve_create",
                "reconcile",
                "owns",
                "storage_observation",
                "validate_profile",
            }
        )
        calls = {ast.unparse(n.func) for n in ast.walk(source) if isinstance(n, ast.Call)}
        self.assertTrue(
            {
                "module.reserve_create",
                "module.reconcile",
                "module.validate_profile",
                "module.storage_observation",
            }
            <= calls
        )
        self.assertFalse(calls & {"subprocess.run", "subprocess.Popen", "os.system"})


if __name__ == "__main__":
    unittest.main()
