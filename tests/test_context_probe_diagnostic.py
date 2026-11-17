"""Pure probe CLI diagnostics: memory filesystem/process doubles only."""

import io
import json
import stat
import sys
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import build_context as gate
from tests import test_sealed_build_context as memory


class ContextProbeDiagnosticTests(TestCase):
    def setUp(self):
        self.model = memory.SealedContextTests("runTest")
        self.model.setUp()
        self.fs = self.model.fs
        self.argv = [
            "build_context",
            "--probe",
            "--revision",
            "a" * 40,
            "--sealed-archive",
            "/sealed/context.tar",
            "--sealed-receipt",
            "/sealed/receipt.json",
            "--source-manifest",
            "/sealed/manifest.json",
            "--probe-receipt",
            "/sealed/probe.json",
        ]

    @contextmanager
    def cli(self, run=None):
        with self.fs.install():
            self.model.seal(parity=False)
            output = io.StringIO()
            with (
                patch.object(gate.argparse, "_", lambda message: message),
                patch.object(sys, "argv", self.argv),
                patch.object(gate.subprocess, "run", run or self.model.probe_run),
                redirect_stdout(output),
            ):
                yield output

    def diagnostic(self):
        value = json.loads(self.fs.nodes["/sealed/diagnostic.json"]["data"])
        self.assertEqual(value["schema"], "pamolive.context-probe-diagnostic/1")
        self.assertLessEqual(len(self.fs.nodes["/sealed/diagnostic.json"]["data"]), 2048)
        self.assertFalse(value["parity_probe"])
        self.assertFalse(value["authority"])
        self.assertFalse(value["global_cleanup_qualified"])
        self.assertFalse(value["H1_qualified"])
        self.assertNotIn("/sealed/probe.json", self.fs.nodes)
        return value

    def failed_probe(self, exception, phase="export_check"):
        def fail(*args, diagnostic):
            diagnostic["phase"] = phase
            raise exception

        return fail

    def test_known_code_is_closed_and_original_refusal_stays_last(self):
        with (
            self.cli() as out,
            patch.object(gate, "probe", self.failed_probe(ValueError("context_unknown_entry"))),
        ):
            self.assertEqual(gate.main(), 1)
        value = self.diagnostic()
        self.assertEqual(value["code"], "context_unknown_entry")
        self.assertEqual(value["phase"], "export_check")
        self.assertEqual(
            json.loads(out.getvalue().splitlines()[-1]),
            {
                "parity_probe": False,
                "error": "context_parity_refused",
                "global_cleanup_qualified": False,
            },
        )

    def test_unknown_secret_exception_has_no_free_text_or_path(self):
        secret = "PRIVATE_CANARY_/home/person/credentials/never_publish"
        with (
            self.cli() as out,
            patch.object(gate, "probe", self.failed_probe(OSError(13, secret, secret))),
        ):
            self.assertEqual(gate.main(), 1)
        value = self.diagnostic()
        self.assertEqual(value["code"], "UNKNOWN")
        self.assertNotIn(secret, out.getvalue())
        self.assertNotIn(secret.encode(), self.fs.nodes["/sealed/diagnostic.json"]["data"])

    def test_valueerror_prefix_is_not_an_allowlist(self):
        with (
            self.cli() as out,
            patch.object(
                gate, "probe", self.failed_probe(ValueError("context_unknown_entry PRIVATE_CANARY"))
            ),
        ):
            self.assertEqual(gate.main(), 1)
        self.assertEqual(self.diagnostic()["code"], "UNKNOWN")
        self.assertNotIn("PRIVATE_CANARY", out.getvalue())

    def test_exception_subclass_str_is_never_called(self):
        class SecretException(ValueError):
            def __str__(self):
                raise AssertionError("exception_string_must_not_be_called")

        with (
            self.cli(),
            patch.object(
                gate, "probe", self.failed_probe(SecretException("context_root_metadata"))
            ),
        ):
            self.assertEqual(gate.main(), 1)
        self.assertEqual(self.diagnostic()["code"], "UNKNOWN")

    def test_unknown_phase_is_not_exported(self):
        with (
            self.cli() as out,
            patch.object(
                gate,
                "probe",
                self.failed_probe(ValueError("context_root_metadata"), "PRIVATE_CANARY"),
            ),
        ):
            self.assertEqual(gate.main(), 1)
        self.assertEqual(self.diagnostic()["phase"], "UNKNOWN")
        self.assertNotIn("PRIVATE_CANARY", out.getvalue())

    def test_real_probe_extra_export_directory_refuses_before_unknown_content(self):
        unknown = "/sealed/probe-export/proof/config/unexpected-empty"

        def run(argv, **kwargs):
            result = self.model.probe_run(argv, **kwargs)
            self.fs.add(unknown, None, 0o755)
            return result

        with self.cli(run):
            self.assertEqual(gate.main(), 1)
        value = self.diagnostic()
        self.assertEqual((value["phase"], value["code"]), ("export_check", "context_unknown_entry"))
        self.assertNotIn(unknown, self.fs.reads)

    def test_real_export_root_metadata_still_refuses_without_opening_files(self):
        def run(argv, **kwargs):
            result = self.model.probe_run(argv, **kwargs)
            self.fs.nodes["/sealed/probe-export"]["mode"] = stat.S_IFDIR | 0o777
            return result

        with self.cli(run):
            self.assertEqual(gate.main(), 1)
        value = self.diagnostic()
        self.assertEqual((value["phase"], value["code"]), ("export_check", "context_root_metadata"))
        self.assertFalse(any(p.startswith("/sealed/probe-export/") for p in self.fs.reads))
        self.assertEqual(self.fs.nodes["/sealed/probe-export"]["mode"], stat.S_IFDIR | 0o777)

    def test_diagnostic_collision_does_not_read_or_overwrite(self):
        with self.cli() as out:
            self.fs.add("/sealed/diagnostic.json", b"PRIVATE_CANARY", 0o600)
            with patch.object(
                gate, "probe", self.failed_probe(ValueError("context_unknown_entry"))
            ):
                self.assertEqual(gate.main(), 1)
        self.assertEqual(self.fs.nodes["/sealed/diagnostic.json"]["data"], b"PRIVATE_CANARY")
        self.assertNotIn("/sealed/diagnostic.json", self.fs.reads)
        self.assertNotIn("PRIVATE_CANARY", out.getvalue())
        self.assertIn('"diagnostic_export_refused"', out.getvalue())
        self.assertNotIn("/sealed/probe.json", self.fs.nodes)

    def test_noncanonical_protocol_parent_leaf_does_not_write(self):
        with self.fs.install(), redirect_stdout(io.StringIO()):
            gate.publish_probe_diagnostic(
                ValueError("context_root_metadata"),
                "export_check",
                memory.MemoryPath("/sealed/other.json"),
            )
        self.assertNotIn("/sealed/diagnostic.json", self.fs.nodes)

    def test_diagnostic_export_error_keeps_primary_refusal(self):
        with (
            self.cli() as out,
            patch.object(gate, "probe", self.failed_probe(ValueError("context_unknown_entry"))),
            patch.object(gate, "exclusive", side_effect=OSError("PRIVATE_CANARY")),
        ):
            self.assertEqual(gate.main(), 1)
        self.assertNotIn("PRIVATE_CANARY", out.getvalue())
        self.assertEqual(
            json.loads(out.getvalue().splitlines()[0])["code"], "context_unknown_entry"
        )
        self.assertEqual(
            json.loads(out.getvalue().splitlines()[-1])["error"], "context_parity_refused"
        )
        self.assertNotIn("/sealed/probe.json", self.fs.nodes)

    def test_success_has_pass_receipt_and_no_failure_diagnostic(self):
        with self.cli():
            self.assertEqual(gate.main(), 0)
        self.assertEqual(json.loads(self.fs.nodes["/sealed/probe.json"]["data"])["status"], "PASS")
        self.assertNotIn("/sealed/diagnostic.json", self.fs.nodes)

    def workflow(self):
        return (
            Path(__file__).resolve().parents[1] / ".github/workflows/adr021-context-probe.yml"
        ).read_text(encoding="utf8")

    def test_workflow_is_closed_to_main_with_read_only_permissions(self):
        text = self.workflow()
        self.assertIn("branches: [main]", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("github.repository == 'pamolive/PamOlive-Platform'", text)
        self.assertIn(
            "github.event_name == 'push' || github.event_name == 'workflow_dispatch'", text
        )
        self.assertEqual(
            text.split("permissions:\n", 1)[1].split("\njobs:", 1)[0],
            "  contents: read\n  actions: read\n",
        )
        self.assertIn("persist-credentials: false", text)
        self.assertNotIn("id-token", text)
        self.assertNotIn("pull_request_target", text)

    def test_workflow_retains_only_four_json_leaves_without_tar_or_image(self):
        text = self.workflow()
        upload = text.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual(
            upload.splitlines(),
            [
                "            ${{ runner.temp }}/pamolive-committed-context.json",
                "            ${{ runner.temp }}/pamolive-context-input/receipt.json",
                "            ${{ runner.temp }}/pamolive-context-input/probe.json",
                "            ${{ runner.temp }}/pamolive-context-input/diagnostic.json",
            ],
        )
        self.assertNotIn(".tar", upload)
        self.assertNotIn(".log", upload)
        self.assertNotIn("--build-target", text)
        self.assertNotIn("apt-get", text)
        self.assertNotIn("services:", text)

    def test_workflow_keeps_probe_timer_and_same_context_arguments(self):
        text = self.workflow()
        self.assertIn("timeout-minutes: 5", text)
        self.assertEqual(
            text.count("timeout --signal=TERM --kill-after=15s 75s bash -euo pipefail"), 2
        )
        self.assertEqual(
            text.count("timeout --signal=TERM --kill-after=15s 60s python -m deploy.build_context"),
            1,
        )
        for arg in [
            "--destination",
            "--output",
            "--sealed-archive",
            "--sealed-receipt",
            "--source-manifest",
            "--probe-receipt",
        ]:
            self.assertIn(arg, text)
        self.assertEqual(text.count("sha256sum --check --status"), 3)
