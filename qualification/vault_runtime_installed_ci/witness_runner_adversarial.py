"""Test the W01 orchestration gates without Docker, SQL or an installed runtime."""

import errno
import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_witness_lab as runner  # noqa: E402
import witness_anchor_handoff as handoff  # noqa: E402
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

    def test_restore_ready_is_a_checked_driver_marker(self):
        state = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        lab = MagicMock()
        lab.engine.deadline = float("inf")
        lab.exec.return_value = state
        driver = (object(), object())
        runner.wait_driver(lab, driver, "restore-ready", 5, {})
        command = lab.exec.call_args.args
        self.assertEqual(command[:2], driver)
        self.assertIn("test -f /work/restore-ready", command[-1])

    def test_cluster_restore_orders_shutdown_preflight_and_new_service(self):
        lab = MagicMock()
        ledger = MagicMock()
        for name in ("retire_recovery", "retire_source", "start"):
            ledger.attach_mock(getattr(lab, name), name)
        recovery, driver, source, target = [(object(), object()) for _ in range(4)]
        facts = dict.fromkeys(runner.CLUSTER_STORAGE_CASES, True)
        report = {"empty_clusters_verified": 2, "clusters_provisioned": 2}

        def storage(*args, switch_clusters):
            self.assertEqual(args, (lab, *source, *target, RUN))
            switch_clusters()
            return facts

        with (
            patch.object(runner, "wait_driver"),
            patch.object(runner, "read_role", return_value=b"W01_RESTORE_READY\n"),
            patch.object(runner, "restore_witness_cluster", side_effect=storage) as restore,
            patch.object(runner, "wait"),
            patch.object(runner, "run_pg") as pg,
            patch.object(runner, "start_history_listener") as listen,
            patch.object(runner, "mark"),
        ):
            pg.side_effect = [
                SimpleNamespace(
                    returncode=0, stdout=f"W01_{RUN}_wpr_{phase}\n".encode(), stderr=b""
                )
                for phase in ("EMPTY", "PROVISIONED")
            ]
            ledger.attach_mock(restore, "storage")
            ledger.attach_mock(pg, "pg")
            ledger.attach_mock(listen, "listener")
            runner.restore_closed_witness(
                lab, recovery, driver, source, "image", RUN, "a" * 64, report,
                recovery_pg=(target, b"preflight", b"provision"),
            )
            self.assertEqual(
                [call[0] for call in ledger.mock_calls],
                ["storage", "retire_recovery", "retire_source", "start", "pg", "pg", "listener"],
            )
            self.assertEqual([call.args for call in pg.call_args_list], [
                (lab, *target, b"preflight"), (lab, *target, b"provision"),
            ])
        self.assertEqual(report["empty_clusters_verified"], 3)
        self.assertEqual(report["clusters_provisioned"], 3)

    def test_pitr_never_admits_observer_before_verified_archive_copy_and_replay(self):
        recovery, driver, source, target, copy = [(object(), object()) for _ in range(5)]
        base = object()
        for complete in (True, False):
            with self.subTest(complete=complete):
                lab = MagicMock()
                ledger = MagicMock()
                for name in ("retire_recovery", "retire_source", "start"):
                    ledger.attach_mock(getattr(lab, name), name)
                lab.start.side_effect = [
                    SimpleNamespace(returncode=0, stdout=runner.COPY_READY, stderr=b""), None,
                ]
                report = {"empty_clusters_verified": 2, "clusters_provisioned": 2}

                def storage(*args, base, switch_clusters, role_sql):
                    self.assertEqual(args, (lab, *source, *target, RUN))
                    self.assertIs(base, proof[3])
                    self.assertEqual(role_sql, b"role_sql")
                    switch_clusters()
                    return dict.fromkeys(runner.PITR_STORAGE_CASES, complete)

                proof = (copy, target, b"role_sql", base)
                with (
                    patch.object(runner, "wait_driver"),
                    patch.object(runner, "read_role", return_value=b"W01_RESTORE_READY\n"),
                    patch.object(runner, "finish_witness_pitr", side_effect=storage) as finish,
                    patch.object(runner, "wait"),
                    patch.object(runner, "run_pg") as pg,
                    patch.object(runner, "start_history_listener") as listen,
                    patch.object(runner, "mark"),
                ):
                    ledger.attach_mock(finish, "finish")
                    ledger.attach_mock(listen, "listener")
                    args = (lab, recovery, driver, source, "image", RUN, "b" * 64, report)
                    if complete:
                        runner.restore_closed_witness(*args, pitr=proof)
                        listen.assert_called_once()
                        expected = ["listener"]
                    else:
                        with self.assertRaises(ValueError):
                            runner.restore_closed_witness(*args, pitr=proof)
                        listen.assert_not_called()
                        expected = []
                    self.assertEqual(
                        [call[0] for call in ledger.mock_calls],
                        ["finish", "retire_recovery", "retire_source", "start", "start", *expected],
                    )
                    self.assertEqual(lab.start.call_args_list[0].args, copy)
                    self.assertEqual(lab.start.call_args_list[1].args, target)
                    pg.assert_not_called()
                self.assertEqual(report["empty_clusters_verified"], 2)
                self.assertEqual(report["clusters_provisioned"], 3 if complete else 2)

    def database_rows(self):
        rows = {}
        for database, users in witness_driver.ROLES.items():
            host, address = witness_driver.HOSTS[database]
            rows[database] = {
                "host": host,
                "hostaddr": address,
                "port": 5432,
                "dbname": f"w01_{RUN}_{database}",
                "credentials": {user: "fixture-" * 4 + user for user in users},
            }
        return rows

    def test_restored_database_factory_binds_only_observer_and_exact_copy(self):
        rows = self.database_rows()
        raw = witness_driver.encode({"run": RUN, "databases": rows})

        def read_regular(path, _cap):
            return raw if path.name == "driver.json" else path.name.encode("ascii")

        row = rows["wpg"]
        dbname = row["dbname"] + "_restored"
        observer = "usage_anchor_observer"
        connection = SimpleNamespace(
            autocommit=False,
            info=SimpleNamespace(
                user=observer,
                dbname=dbname,
                host=row["host"],
                hostaddr=row["hostaddr"],
                port=5432,
                server_version=witness_driver.TLS_EXPECTED,
            ),
        )
        connect = MagicMock(return_value=connection)
        with patch.dict(sys.modules, {
            "psycopg": SimpleNamespace(connect=connect),
            "witness_wheel": SimpleNamespace(read_regular=read_regular),
        }):
            plain = witness_driver.database_connectors(RUN, lambda _: None)
            phases = []
            factories = witness_driver.database_connectors(
                RUN, phases.append, restore_witness=True
            )
            self.assertEqual(factories.keys() - plain.keys(), {"restored_observer"})
            self.assertEqual(phases[-1], "database_restore_configuration")
            connect.assert_not_called()
            self.assertIs(factories["restored_observer"](), connection)
        settings = connect.call_args.kwargs
        self.assertEqual(settings["dbname"], dbname)
        self.assertEqual(settings["user"], observer)
        self.assertEqual(settings["password"], row["credentials"][observer])
        self.assertEqual(settings["sslmode"], "verify-full")
        self.assertEqual(settings["channel_binding"], "require")
        self.assertIn("default_transaction_read_only=on", settings["options"])

    def test_cluster_restore_requires_a_distinct_sql_identity(self):
        rows = self.database_rows()
        source = rows["wpg"]
        observer = "usage_anchor_observer"
        host, address = witness_driver.RESTORE_HOST
        target = {
            **source,
            "host": host,
            "hostaddr": address,
            "dbname": source["dbname"] + "_restored",
            "credentials": {observer: "restore-" * 4 + observer},
        }
        for field, change, same_ca in (
            (None, None, False),
            ("hostaddr", source["hostaddr"], False),
            ("credentials", {observer: source["credentials"][observer]}, False),
            (None, None, True),
        ):
            with self.subTest(field=field, same_ca=same_ca):
                candidate = target if field is None else {**target, field: change}
                raw = witness_driver.encode(
                    {"run": RUN, "databases": rows, "database_restored": candidate}
                )

                def read_regular(path, _cap):
                    if path.name == "driver.json":
                        return raw
                    if same_ca and path.name == "wpr-ca.crt":
                        return b"wpg-ca.crt"
                    return path.name.encode("ascii")

                connect = MagicMock(return_value=SimpleNamespace(
                    autocommit=False,
                    info=SimpleNamespace(user=observer, host=host, hostaddr=address, port=5432,
                                         dbname=target["dbname"], server_version=170012),
                ))
                with patch.dict(sys.modules, {
                    "psycopg": SimpleNamespace(connect=connect),
                    "witness_wheel": SimpleNamespace(read_regular=read_regular),
                }):
                    if field or same_ca:
                        with self.assertRaises(ValueError):
                            witness_driver.database_connectors(
                                RUN, lambda _: None, restore_cluster=True
                            )
                        connect.assert_not_called()
                        continue
                    factories = witness_driver.database_connectors(
                        RUN, lambda _: None, restore_cluster=True
                    )
                    factories["restored_observer"]()
                    settings = connect.call_args.kwargs
                    self.assertEqual(settings["hostaddr"], address)
                    self.assertEqual(settings["user"], observer)
                    self.assertTrue(settings["sslrootcert"].endswith("wpr-ca.crt"))

    def test_source_outage_requires_transport_failure_at_exact_endpoint(self):
        with patch.object(witness_driver.socket, "create_connection") as connect:
            connect.side_effect = ConnectionRefusedError(errno.ECONNREFUSED, "fixture")
            witness_driver.require_original_database_unavailable()
            connect.assert_called_once_with((witness_driver.HOSTS["wpg"][1], 5432), timeout=3)
            connect.side_effect = OSError(errno.EACCES, "fixture")
            with self.assertRaises(ValueError):
                witness_driver.require_original_database_unavailable()
            connect.side_effect = None
            with self.assertRaises(ValueError):
                witness_driver.require_original_database_unavailable()

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


class AnchorHandoffTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(self.enterContext(TemporaryDirectory(prefix="w01-handoff-"))).resolve()
        self.outputs = self.work / "outputs"
        self.enterContext(patch.dict(os.environ, {"GITHUB_OUTPUT": str(self.outputs)}))
        self.boot = self.enterContext(
            patch.object(handoff, "boot_fingerprint", return_value="a" * 64)
        )
        self.raw = b"synthetic handoff fixture"
        self.pin = handoff.sha(self.raw)
        self.public = "b" * 64
        self.report = {
            "schema": "pamolive.witness-installed-pitr-anchor-store/2",
            "ok": True,
            "cleaned_up": True,
            "authority": False,
            "native": {"anchor_store": {
                "restore_copy_exact": True, "checkpoint_key_rotation_verified": True,
            }},
        }
        self.report_path = self.work / "witness-lab-public.json"
        self.report_path.write_bytes(json.dumps(self.report).encode("ascii"))
        (self.work / handoff.NAME).write_bytes(self.raw)
        (self.work / "anchor-reference").write_bytes(f"{self.public}\n{self.pin}\n".encode("ascii"))

    def test_handoff_exposes_only_fixed_references_and_the_boot_fingerprint(self):
        handoff.publish(self.work)
        self.assertEqual(
            self.outputs.read_text(encoding="ascii"),
            f"anchor_sha={self.pin}\npublic_hex={self.public}\nboot_sha={'a' * 64}\n",
        )

    def test_handoff_refuses_an_unfinished_or_unclean_producer(self):
        for field in ("ok", "cleaned_up"):
            with self.subTest(field=field):
                self.report_path.write_bytes(json.dumps({**self.report, field: False}).encode())
                with self.assertRaises(ValueError):
                    handoff.publish(self.work)
                self.assertFalse(self.outputs.exists())
        self.boot.assert_not_called()

    def test_handoff_refuses_modified_bytes_or_extra_reference_lines(self):
        (self.work / handoff.NAME).write_bytes(self.raw + b"modified")
        with self.assertRaises(ValueError):
            handoff.publish(self.work)
        (self.work / handoff.NAME).write_bytes(self.raw)
        (self.work / "anchor-reference").write_bytes(f"{self.public}\n{self.pin}\n\n".encode())
        with self.assertRaises(ValueError):
            handoff.publish(self.work)
        self.assertFalse(self.outputs.exists())
        self.boot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
