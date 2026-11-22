"""Test the W01 orchestration gates without Docker, SQL or an installed runtime."""

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_witness_lab as runner  # noqa: E402
from lab import witness_driver  # noqa: E402

RUN = "0123456789abcdef"
ROLES = {name: (name, None) for name in ("preparer", "w-postgres", "v-postgres")}


class OrchestrationTests(unittest.TestCase):
    def exercise(self, fail_at=None):
        ledger = []
        report = {"empty_clusters_verified": 0, "clusters_provisioned": 0}

        def stage(_lab, _prepare, _run, phase, marker, **options):
            ledger.append(phase)
            if phase == "provision":
                self.assertEqual(
                    options["data"], f"W01_{RUN}_wpg_EMPTY\nW01_{RUN}_vpg_EMPTY\n".encode()
                )
            if phase == "provision-vault":
                self.assertEqual(options["data"], f"W01_{RUN}_wpg_PROVISIONED\n".encode())
            return marker

        def read_role(_lab, _prepare, name, _cap):
            return Path(name).stem.encode()

        def run_pg(_lab, role, _spec, sql):
            db, phase = sql.decode().split("-")
            self.assertEqual(role, runner.PG_ROLES[db])
            name = f"{db}-{phase}"
            ledger.append(name)
            receipt = "EMPTY" if phase == "preflight" else "PROVISIONED"
            raw = f"W01_{RUN}_{db}_{receipt}\n".encode()
            denied = name == fail_at
            return SimpleNamespace(
                returncode=0, stdout=raw if not denied else raw + b"x", stderr=b""
            )

        lab = SimpleNamespace(start=lambda *_: None)
        with (
            patch.object(runner, "stage", stage),
            patch.object(runner, "wait"),
            patch.object(runner, "read_role", read_role),
            patch.object(runner, "run_pg", run_pg),
        ):
            if fail_at:
                with self.assertRaises(ValueError):
                    runner.bootstrap(lab, ROLES, RUN, report)
            else:
                runner.bootstrap(lab, ROLES, RUN, report)
        return ledger, report

    def test_requires_both_read_only_receipts_before_emitting_w_provision(self):
        attempts, report = self.exercise("vpg-preflight")
        self.assertEqual(attempts, ["base", "wpg-preflight", "vpg-preflight"])
        self.assertEqual(report["clusters_provisioned"], 0)

    def test_never_requests_v_sql_when_w_provision_receipt_is_invalid(self):
        attempts, report = self.exercise("wpg-provision")
        self.assertEqual(
            attempts, ["base", "wpg-preflight", "vpg-preflight", "provision", "wpg-provision"]
        )
        self.assertEqual(report["empty_clusters_verified"], 2)
        self.assertEqual(report["clusters_provisioned"], 0)

    def test_binds_two_real_receipts_in_order_before_starting_driver(self):
        attempts, report = self.exercise()
        self.assertEqual(
            attempts,
            [
                "base",
                "wpg-preflight",
                "vpg-preflight",
                "provision",
                "wpg-provision",
                "provision-vault",
                "vpg-provision",
            ],
        )
        self.assertEqual(report["clusters_provisioned"], 2)

    def test_native_receipt_rejects_private_or_incomplete_content(self):
        source = "a" * 64
        for value in (
            {"schema": "W01-results/2", "source_sha256": source},
            {"schema": "W01-results/2", "source_sha256": source, "private": "never_publish"},
        ):
            with self.assertRaises(ValueError):
                runner.collect_native(json.dumps(value).encode(), source)

    def exercise_restore(self, marker, storage):
        lab = MagicMock()
        recovery, driver, wpg = [(object(), object()) for _ in range(3)]
        report = {"restoration_storage": None, "storage_failure": None}
        with (
            patch.object(runner, "wait_driver") as wait,
            patch.object(runner, "read_role", return_value=marker),
            patch.object(runner, "restore_witness_storage", return_value=storage) as restore,
            patch.object(runner, "start_history_listener") as start,
            patch.object(runner, "mark") as mark,
        ):
            ledger = MagicMock()
            for name, action in (
                ("restore", restore),
                ("retire", lab.retire_recovery),
                ("start", start),
                ("mark", mark),
            ):
                ledger.attach_mock(action, name)
            args = (lab, recovery, driver, wpg, "consumer", RUN, "a" * 64, report)
            exact = storage.keys() == set(runner.STORAGE_CASES) and all(
                value is True for value in storage.values()
            )
            if marker != b"W01_RESTORE_READY\n" or not exact:
                with self.assertRaises(ValueError):
                    runner.restore_closed_witness(*args)
                lab.retire_recovery.assert_not_called()
                start.assert_not_called()
                mark.assert_not_called()
            else:
                runner.restore_closed_witness(*args)
                self.assertEqual(
                    [call[0] for call in ledger.mock_calls], ["restore", "retire", "start", "mark"]
                )
                restore.assert_called_once_with(lab, *wpg, RUN)
                lab.retire_recovery.assert_called_once_with(*recovery)
                start.assert_called_once_with(lab, "consumer", "witness-restored", RUN, "a" * 64)
                mark.assert_called_once_with(lab, driver, "restored")
            wait.assert_called_once_with(lab, driver, "restore-ready", 50, report)
        return report

    def test_restore_replaces_listener_only_after_exact_storage_receipt(self):
        facts = dict.fromkeys(runner.STORAGE_CASES, True)
        report = self.exercise_restore(b"W01_RESTORE_READY\n", facts)
        self.assertEqual(report["restoration_storage"], facts)
        self.assertEqual(report["phase"], "restoration_startup")

    def test_restore_rejects_wrong_marker_and_noncanonical_storage_facts(self):
        facts = dict.fromkeys(runner.STORAGE_CASES, True)
        for marker, storage in (
            (b"W01_RESTORE_READY\nextra", facts),
            (b"W01_RESTORE_READY\n", {**facts, "extra": True}),
            (b"W01_RESTORE_READY\n", {**facts, "archive_verified": False}),
            (b"W01_RESTORE_READY\n", {**facts, "archive_verified": 1}),
        ):
            with self.subTest(marker=marker, storage=storage):
                self.assertIsNone(self.exercise_restore(marker, storage)["restoration_storage"])

    def test_diagnostic_publishes_only_an_enumerated_phase(self):
        driver = ({"identity": "a" * 64}, None)
        state = SimpleNamespace(returncode=42, stdout=b"", stderr=b"")
        lab = SimpleNamespace(
            exec=lambda *_args, **_options: state,
            engine=SimpleNamespace(
                deadline=float("inf"), checked=lambda *_args, **_options: b"42\n"
            ),
        )
        for payload, expected in ((b"database_roles\n", "database_roles"), (b"private\n", None)):
            with self.subTest(expected=expected):
                report = {"driver_failure": None}
                with (
                    patch.object(runner, "read_role", return_value=payload),
                    patch.object(runner, "mark") as mark,
                    self.assertRaises(ValueError),
                ):
                    runner.wait_driver(lab, driver, "initialized", 5, report)
                self.assertEqual(report["driver_failure"], expected)
                self.assertEqual(mark.call_count, 1 if expected else 0)

    def test_libpq_connection_errors_expose_only_fixed_categories(self):
        self.assertEqual(
            witness_driver.connection_failure(ValueError("certificate verify failed: private")),
            "database_peer",
        )
        self.assertEqual(
            witness_driver.connection_failure(ValueError("unknown private diagnostic")),
            "database_other_connection",
        )
        self.assertEqual(
            witness_driver.connection_failure(ValueError("could not find digest for NID UNDEF")),
            "database_channel_binding",
        )

    def test_tls_probe_accepts_abort_only_after_tcp_connect_and_before_tls(self):
        markers = []
        client = MagicMock()
        transport = MagicMock()
        args = (b"public-der", None, set(), "tls_no_client", markers.append)
        with (
            patch.object(witness_driver, "verify_server") as valid_control,
            patch.object(witness_driver, "context", return_value=client),
            patch.object(witness_driver.socket, "create_connection") as connect,
        ):
            connect.side_effect = ConnectionResetError
            with self.assertRaises(ConnectionResetError):
                witness_driver.denied_tls(*args)
            client.wrap_socket.assert_not_called()
            markers.clear()
            valid_control.reset_mock()
            connect.side_effect = None
            connect.return_value = transport
            client.wrap_socket.side_effect = ConnectionResetError
            witness_driver.denied_tls(*args)
            self.assertEqual(valid_control.call_count, 2)
            self.assertEqual(
                markers,
                [
                    "tls_no_client_control_before",
                    "tls_no_client_handshake",
                    "tls_no_client_control_after",
                ],
            )


if __name__ == "__main__":
    unittest.main()
