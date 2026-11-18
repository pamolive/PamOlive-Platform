"""Test the transfer using the existing offline orchestration doubles."""

import io
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consumer_inputs  # noqa: E402
import orchestrate  # noqa: E402
import schema  # noqa: E402
import support  # noqa: E402
import test_phase2_orchestration as fixture  # noqa: E402
import verify_offline  # noqa: E402
import wheel_gate  # noqa: E402
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

    def received(self):
        cleanup = {
            "container_released": True,
            "clients_released": True,
            "resources_released": True,
            "failure": None,
            "authority": False,
        }
        public = {
            **cleanup,
            "schema": "pamolive.vault-installed-host-reception/2",
            "ok": True,
            "container_exit_code": 0,
            "container_OOMKilled": False,
            "packet": self.packet,
        }
        return public, cleanup

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

    def test_consumer_stage_binds_the_three_lock_lines_to_the_received_archives(self):
        public, cleanup = self.received()
        desc, wheels = consumer_inputs.verify_reception(
            self.raw, public, cleanup, bindings=self.bindings
        )
        inventories, lock = consumer_inputs.installation_inputs(
            consumer_inputs.ROOT.parents[1], consumer_inputs.ROOT / "inputs", wheels
        )
        self.assertEqual(desc, (self.work / "input.json").read_bytes())
        self.assertEqual(len(lock.splitlines()), 3)
        public_checks = SimpleNamespace(
            support=support, wheel_gate=wheel_gate, qualifier=load("qualify_installed.py")
        )
        for kind, name in wheel_transfer.wheel_names().items():
            line = (
                f"{inventories[kind]['name']} @ file:///inputs/wheels/{name}"
                f" --hash=sha256:{sha(wheels[name])}"
            ).encode("ascii")
            self.assertIn(line, lock.splitlines())
            self.assertTrue(
                verify_offline.check_internal_members(
                    public_checks, wheels[name], inventories[kind]
                )
            )

    def test_consumer_refuses_unconfirmed_cleanup_and_unrelated_public_packet(self):
        public, cleanup = self.received()
        foreign = deepcopy(self.packet)
        foreign["execution_sha256"] = "0" * 64
        for report, cleanup_result in (
            (public, {**cleanup, "resources_released": False}),
            ({**public, "container_exit_code": False}, cleanup),
            ({**public, "container_OOMKilled": True}, cleanup),
            ({**public, "packet": foreign}, cleanup),
        ):
            with self.assertRaises(ValueError):
                consumer_inputs.verify_reception(
                    self.raw, report, cleanup_result, bindings=self.bindings
                )

    def test_consumer_refuses_changed_native_verification_helper(self):
        deploy = consumer_inputs.ROOT.parents[1] / "deploy"
        utils = consumer_inputs.pinned_utils(deploy)
        self.assertEqual(set(utils), {"check_database_driver.py", "native_inventory.py"})
        utils["native_inventory.py"] += b"\n# changed\n"
        with patch.object(consumer_inputs, "read_regular", side_effect=lambda p, _: utils[p.name]):
            with self.assertRaises(ValueError):
                consumer_inputs.pinned_utils(deploy)


if __name__ == "__main__":
    unittest.main(verbosity=2)
