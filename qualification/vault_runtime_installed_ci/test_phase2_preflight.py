"""Source assets, fixed S0 and early-entry failure without actual execution."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import adapter_v2
import orchestrate
import schema
import workload_entry
import workload_host
import workload_prepare
import workload_schema
from support import ROOT, load, sha


class PreflightTests(unittest.TestCase):
    def test_s0_identity_has_one_exact_profile_no_tag_or_unknown_fields(self):
        pins = json.loads((ROOT / "s0-pins.json").read_bytes())
        self.assertEqual(workload_prepare.s0_pins(pins), pins)
        for change in (
            {**pins, "image": "python:3.12"},
            {**pins, "image_config": "sha256:" + "0" * 64},
            {**pins, "diff_ids": []},
            {**pins, "extra": False},
        ):
            with self.assertRaises(ValueError):
                workload_prepare.s0_pins(change)

    def test_closed29_controller_assets_rehash_and_reject_extra_or_changed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            destination = Path(directory)
            rows = {}
            for name in workload_prepare.CONTROLLER_FILES:
                raw = (ROOT / name).read_bytes()
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                rows[name] = {"bytes": len(raw), "sha256": sha(raw)}
            manifest = {
                "schema": "pamolive.vault-installed-source-assets/2",
                "controller_files": rows,
                "payloads_sha256": orchestrate.PAYLOAD_SHA,
            }
            path = destination / "source-assets.json"
            raw = schema.encode(manifest)
            path.write_bytes(raw)
            self.assertEqual(
                len(workload_prepare.assets(destination, sha(raw))["controller_files"]), 29
            )
            (destination / "schema.py").write_bytes(b"PUBLIC_CHANGED")
            with self.assertRaises(ValueError):
                workload_prepare.assets(destination, sha(raw))
            rows["EXTRA"] = {"bytes": 0, "sha256": "0" * 64}
            raw = schema.encode(manifest)
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                workload_prepare.assets(destination, sha(raw))

    def test_entry_early_kernel_failure_exports_no_fake_child_and_no_raw_error(self):
        payload, _ = orchestrate.source_payloads(ROOT / "inputs")
        bindings = {
            "expected_source": orchestrate.PAYLOAD_SHA,
            "expected_input": sha(schema.encode(orchestrate.description(payload))),
            "expected_sql": adapter_v2.SQL_SHA,
            "expected_materials": adapter_v2.MATERIALS,
        }
        args = ["entry"]
        for name, value in bindings.items():
            args.extend(["--" + name.replace("_", "-"), value])
        output = io.BytesIO()
        reference = load("entrypoint.py")
        with (
            patch.object(workload_entry.sys, "argv", args),
            patch.object(workload_entry.sys, "stdout", SimpleNamespace(buffer=output)),
            patch.object(workload_entry, "proc", return_value="PUBLIC_FIXTURE"),
            patch.object(reference, "profile", side_effect=ValueError("PUBLIC_ERROR_NOT_EXPORTED")),
            patch.object(orchestrate, "run") as run,
        ):
            with self.assertRaises(SystemExit) as caught:
                workload_entry.main()
        self.assertEqual(caught.exception.code, 42)
        run.assert_not_called()
        raw = output.getvalue()
        self.assertNotIn(b"PUBLIC_ERROR_NOT_EXPORTED", raw)
        value = workload_schema.accept(schema.parse(raw, schema.MAX_PACKET), 42, **bindings)
        self.assertFalse(value["ok"])
        self.assertIsNone(value["execution"]["child"])
        self.assertEqual(value["execution"]["processes"], [])

    def test_bootstrap_fixed_path_bounded_same_buffer_and_no_runpy_reopen(self):
        bindings = dict.fromkeys(
            ("expected_source", "expected_input", "expected_sql", "expected_materials"), "a" * 64
        )
        raw = workload_host.bootstrap("b" * 64, bindings)
        self.assertIn(b"r=s.read(262145)", raw)
        self.assertIn(b"exec(compile(r,p,'exec')", raw)
        self.assertIn(b"/controller/workload_entry.py", raw)
        self.assertNotIn(b"runpy", raw)
        self.assertNotIn(b"subprocess", raw)
        compile(raw, "<bootstrap-data-only>", "exec")
        with self.assertRaises(ValueError):
            workload_host.bootstrap("BAD", bindings)
