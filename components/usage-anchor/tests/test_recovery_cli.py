import io
import json
import stat
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pamolive_usage_anchor import codec, recovery_cli, recovery_manifest, signed_anchor
from test_audit_archive import audit_rows, checkpoint, event, uid


class RecoveryCLITests(unittest.TestCase):
    def setUp(self):
        self.point = checkpoint(audit_rows([event("activation_challenge", uid(10))]))
        self.scope = recovery_manifest.RecoveryScope.from_checkpoint(self.point)
        self.authority = "1" * 64
        self.manifest, self.document = b"synthetic manifest", b"synthetic checkpoint"
        self.proposed = codec.sha(self.manifest)
        self.selected = codec.sha(self.document)
        self.flags = [
            "--directory",
            "/custody/store",
            "--governance-key",
            self.authority,
            "--organization",
            self.scope.organization_id,
            "--installation",
            self.scope.installation_id,
            "--context",
            self.scope.context_id,
            "--slot-sha256",
            self.scope.slot_sha256,
        ]
        self.proposal = [
            "--manifest",
            "/incoming/proposal",
            "--proposal-sha256",
            self.proposed,
            "--checkpoint",
            "/incoming/object",
        ]
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.enterContext(redirect_stdout(self.stdout))
        self.enterContext(redirect_stderr(self.stderr))
        self.enterContext(patch.object(recovery_cli.sys, "platform", "linux"))
        self.enterContext(patch.object(recovery_cli.os, "geteuid", return_value=1000, create=True))
        self.output = self.enterContext(
            patch.object(
                recovery_cli.os,
                "write",
                side_effect=lambda fd, data: self.stdout.write(data.decode()),
            )
        )
        self.new_store = self.enterContext(
            patch.object(recovery_cli.recovery_store, "RecoveryStore")
        )
        self.store = self.new_store.return_value
        self.store.commission.return_value = self.proposed
        self.store.advance.return_value = self.proposed
        self.store.restore.return_value = self.point

    def main(self, *args):
        return recovery_cli.main([*self.flags, *args])

    def test_commission_passes_the_exact_bytes_from_one_bounded_read(self):
        with patch.object(
            recovery_cli, "_read", side_effect=[self.manifest, self.document]
        ) as read:
            self.assertEqual(self.main("commission", *self.proposal), 0)
        self.assertEqual(read.call_count, 2)
        self.new_store.assert_called_once_with(
            Path("/custody/store"),
            owner_uid=1000,
            governance_key=bytes.fromhex(self.authority),
            scope=self.scope,
        )
        self.store.commission.assert_called_once_with(
            self.manifest, checkpoints={self.selected: self.document}
        )
        self.assertEqual(
            json.loads(self.stdout.getvalue()),
            {
                "schema": recovery_cli.SCHEMA,
                "operation": "commission",
                "manifest_sha256": self.proposed,
            },
        )
        self.assertEqual(self.stderr.getvalue(), "")

    def test_proposal_pin_mismatch_refuses_before_reading_objects_or_writing(self):
        with patch.object(recovery_cli, "_read", return_value=b"different proposal") as read:
            self.assertEqual(self.main("commission", *self.proposal), 1)
        read.assert_called_once_with(Path("/incoming/proposal"), recovery_manifest.MAX_BYTES)
        self.store.commission.assert_not_called()
        self.assertEqual(self.stdout.getvalue(), "")
        self.assertEqual(self.stderr.getvalue(), "anchor_refused\n")

    def test_advance_requires_predecessor_and_refuses_repeated_objects(self):
        predecessor = "3" * 64
        with patch.object(
            recovery_cli, "_read", side_effect=[self.manifest, self.document, self.document]
        ):
            self.assertEqual(
                self.main(
                    "advance",
                    "--current-sha256",
                    predecessor,
                    *self.proposal,
                    "--checkpoint",
                    "/incoming/duplicate",
                ),
                1,
            )
        self.store.advance.assert_not_called()
        self.assertEqual(self.stderr.getvalue(), "invalid_request\n")
        self.stderr.truncate(0)
        self.stderr.seek(0)
        with patch.object(recovery_cli, "_read", side_effect=[self.manifest, self.document]):
            self.assertEqual(
                self.main("advance", "--current-sha256", predecessor, *self.proposal), 0
            )
        self.store.advance.assert_called_once_with(
            self.manifest, expected=predecessor, checkpoints={self.selected: self.document}
        )

    def test_restore_uses_both_explicit_pins_and_returns_closed_point(self):
        self.assertEqual(
            self.main(
                "restore", "--current-sha256", self.proposed, "--checkpoint-sha256", self.selected
            ),
            0,
        )
        self.store.restore.assert_called_once_with(
            expected=self.proposed, checkpoint_sha256=self.selected
        )
        self.assertEqual(
            json.loads(self.stdout.getvalue()),
            {
                "schema": recovery_cli.SCHEMA,
                "operation": "restore",
                "manifest_sha256": self.proposed,
                "checkpoint_sha256": self.selected,
                "checkpoint": asdict(self.point),
            },
        )

    def test_io_error_keeps_paths_and_exception_details_out_of_output(self):
        with patch.object(recovery_cli, "_read", side_effect=OSError("private path")):
            self.assertEqual(self.main("commission", *self.proposal), 1)
        self.store.commission.assert_not_called()
        self.assertEqual(self.stderr.getvalue(), "unavailable\n")
        self.assertEqual(self.stdout.getvalue(), "")

    def test_closed_stdout_reports_uncertain_completion_after_the_store_returns(self):
        self.output.side_effect = BrokenPipeError
        with (
            patch.object(recovery_cli, "_read", side_effect=[self.manifest, self.document]),
            patch.object(recovery_cli.sys, "stdout", None),
        ):
            status = self.main("advance", "--current-sha256", "3" * 64, *self.proposal)
        self.assertEqual(status, 1)
        self.store.advance.assert_called_once()
        self.assertEqual(self.stdout.getvalue(), "")
        self.assertEqual(self.stderr.getvalue(), "unavailable\n")

    def test_input_reader_refuses_nonregular_and_oversized_inputs_before_read(self):
        path = Path("/incoming/document")
        maximum = signed_anchor.MAX_ANCHOR_BYTES
        stream = Mock()
        filesystem = SimpleNamespace(
            O_RDONLY=0,
            O_NOFOLLOW=1,
            O_NONBLOCK=2,
            O_CLOEXEC=4,
            O_NOCTTY=8,
            open=Mock(return_value=4),
            fstat=Mock(),
            fdopen=Mock(),
        )
        manager = filesystem.fdopen.return_value
        manager.__enter__ = Mock(return_value=stream)
        manager.__exit__ = Mock(return_value=False)
        for mode, size in ((stat.S_IFIFO, 3), (stat.S_IFREG, maximum + 1)):
            filesystem.fstat.return_value = SimpleNamespace(st_mode=mode, st_size=size)
            with patch.object(recovery_cli, "os", filesystem), self.assertRaises(codec.Error):
                recovery_cli._read(path, maximum)
        stream.read.assert_not_called()
        filesystem.open.assert_called_with(path, 15)
