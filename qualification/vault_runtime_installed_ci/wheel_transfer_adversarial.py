"""Test the transfer using the existing offline orchestration doubles."""

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import orchestrate  # noqa: E402
import schema  # noqa: E402
import test_phase2_orchestration as fixture  # noqa: E402
import wheel_transfer  # noqa: E402
import workload_cli  # noqa: E402
import workload_entry  # noqa: E402
import workload_host  # noqa: E402
import workload_schema  # noqa: E402
from support import load, sha  # noqa: E402


class WheelTransferTests(unittest.TestCase):
    def setUp(self):
        flow = fixture.OrchestrationTests()
        flow.setUp()
        self.addCleanup(flow.doCleanups)
        self.report = flow.run_workload()
        self.bindings = flow.bindings(self.report)
        self.packet = workload_schema.packet(self.report, **self.bindings)
        self.work = flow.work
        self.raw = wheel_transfer.from_work(self.work, self.packet, bindings=self.bindings)

    def test_roundtrip_transfers_only_the_three_wheels_and_the_bound_descriptor(self):
        packet, descriptor, files = wheel_transfer.decode(self.raw, bindings=self.bindings)
        self.assertEqual(packet, self.packet)
        self.assertEqual(descriptor, (self.work / "input.json").read_bytes())
        self.assertEqual(
            files,
            {
                name: (self.work / "built" / kind / name).read_bytes()
                for kind, name in wheel_transfer.wheel_names().items()
            },
        )

    def test_capture_refuses_changed_post_check_wheel(self):
        name = wheel_transfer.wheel_names()["runtime"]
        path = self.work / "built" / "runtime" / name
        value = path.read_bytes()
        path.write_bytes(value[:-1] + bytes([value[-1] ^ 1]))
        with self.assertRaises(ValueError):
            wheel_transfer.from_work(self.work, self.packet, bindings=self.bindings)

    def test_receiver_refuses_wrong_contents_truncation_and_surplus(self):
        header_end = len(wheel_transfer.MAGIC) + wheel_transfer.HEADER.size
        overflow = wheel_transfer.MAGIC + b"\xff" * wheel_transfer.HEADER.size
        for raw in (
            self.raw[:-1],
            self.raw + b"x",
            self.raw[:-1] + bytes([self.raw[-1] ^ 1]),
            b"X" + self.raw[1:],
            overflow + self.raw[header_end:],
            b"\x00" * (wheel_transfer.MAX_FRAME + 1),
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                wheel_transfer.decode(raw, bindings=self.bindings)

    def test_receiver_refuses_wrong_descriptor_binding(self):
        bindings = {**self.bindings, "expected_input": "0" * 64}
        with self.assertRaises(ValueError):
            wheel_transfer.decode(self.raw, bindings=bindings)

    def test_wire_protocol_is_only_selected_when_requested(self):
        with patch.object(orchestrate, "WORK", self.work):
            ordinary, code = workload_entry.encode_result(self.report, self.bindings, False)
            transfer, transfer_code = workload_entry.encode_result(self.report, self.bindings, True)
        self.assertEqual(ordinary, schema.encode(self.packet, schema.MAX_PACKET))
        self.assertEqual(transfer, self.raw)
        self.assertEqual((code, transfer_code), (0, 0))
        entry = workload_host.bootstrap("b" * 64, self.bindings)
        alternate = workload_host.bootstrap("b" * 64, self.bindings, transfer_verified_wheels=True)
        self.assertNotIn(b"--transfer-verified-wheels", entry)
        self.assertIn(b"--transfer-verified-wheels", alternate)

    def test_failed_transfer_uses_normal_failed_packet_and_preserves_processes(self):
        with patch.object(wheel_transfer, "from_work", side_effect=OSError("PRIVATE DETAIL")):
            raw, code = workload_entry.encode_result(self.report, self.bindings, True)
        self.assertEqual(code, 42)
        packet = workload_schema.accept(schema.parse(raw, schema.MAX_PACKET), code, **self.bindings)
        self.assertFalse(packet["ok"])
        self.assertEqual(packet["execution"]["processes"], self.report["processes"])
        self.assertNotIn(b"PRIVATE DETAIL", raw)

    def test_receipt_is_written_once_without_overwriting_a_prior_file(self):
        target = self.work / wheel_transfer.FILENAME
        wheel_transfer.keep_private(self.work, self.raw)
        self.assertEqual(target.read_bytes(), self.raw)
        if sys.platform != "win32":
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            wheel_transfer.keep_private(self.work, b"different")
        self.assertEqual(target.read_bytes(), self.raw)

    def test_independent_cleanup_uses_the_prepared_entry_variant(self):
        assets_sha = "a" * 64
        entry_sha = "b" * 64
        assets = {"controller_files": {"workload_entry.py": {"sha256": entry_sha}}}
        state = {
            "assets_sha256": assets_sha,
            "bindings": self.bindings,
            "transfer_verified_wheels": True,
        }
        args = [
            "workload_cli.py",
            "cleanup",
            "--assets-sha256",
            assets_sha,
            "--work",
            str(self.work),
        ]
        control = load("controller.py")
        with (
            patch.object(sys, "argv", args),
            patch.object(sys, "stdout", io.StringIO()),
            patch.object(workload_cli.prepare, "assets", return_value=assets),
            patch.object(control, "regular", return_value=schema.encode(state)),
            patch.object(control, "atomic"),
            patch.object(
                workload_host, "cleanup_owned", return_value={"resources_released": True}
            ) as cleanup,
            self.assertRaises(SystemExit) as result,
        ):
            workload_cli.main()
        self.assertEqual(result.exception.code, 0)
        entry = workload_host.bootstrap(entry_sha, self.bindings, transfer_verified_wheels=True)
        self.assertEqual(cleanup.call_args.args[2:], (state, entry, sha(entry)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
