"""Storage restoration control flow on inert lab and PostgreSQL output doubles."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from helpers.bounded_io import Result  # noqa: E402
from lab import witness_restore_storage as storage  # noqa: E402

RUN = "0123456789abcdef"
RESERVATION = "pv-" + RUN * 2
SOURCE = f"w01_{RUN}_wpg"
CLONE = f"{SOURCE}_restored"
ARCHIVE = b"PGDMP_inert_test_archive"
TOC = b"\n".join(
    f"{n}; 0 100 TABLE DATA pam_usage_anchor {table} usage_anchor_owner".encode()
    for n, table in enumerate(storage.TABLES, 1)
) + b"\n"
SNAP = b"W01_STATE_SEALED\n" + (b"a" * 64 + b"\n") * (len(storage.TABLES) + 1)
STEPS = (
    b"W01_TARGET_ABSENT\n", SNAP, ARCHIVE, TOC, b"W01_TARGET_FRESH\n", b"", SNAP,
    SNAP, b"W01_TARGET_READ_ONLY\n",
)
SOURCE_ID = b"7051354136572160041\n"
TARGET_ID = b"7051354136572160042\n"
CLUSTER_SOURCE_STEPS = (b"W01_TARGET_ABSENT\n", SNAP, SOURCE_ID, ARCHIVE, TOC, SNAP)
CLUSTER_TARGET_STEPS = (
    TARGET_ID, b"W01_TARGET_FRESH\n", b"", SNAP, b"W01_TARGET_READ_ONLY\n", TARGET_ID,
)

ATTEMPTS = []


def fence(event, args):
    if event.startswith(("socket.", "subprocess.", "ctypes.", "sqlite3.")):
        ATTEMPTS.append(event)
        raise AssertionError("only lab output doubles allowed")
    if event == "open" and len(args) > 2 and type(args[2]) is int:
        if args[2] & (1 | 2 | 64 | 512 | 1024):
            ATTEMPTS.append("file_write")
            raise AssertionError("only read-only file I/O allowed")


sys.addaudithook(fence)


def result(stdout, **override):
    values = {
        "spawn_attempted": True,
        "pid": 9,
        "returncode": 0,
        "owned_child_reaped": True,
        "drains_complete": True,
        "stdout": stdout,
        "stdout_bytes": len(stdout),
    }
    return Result(**{**values, **override})


class Lab:
    def __init__(self):
        self.reservation = RESERVATION
        self.item = {"name": self.reservation + "-w-postgres", "identity": "b" * 64}
        self.spec = SimpleNamespace(
            role="w-postgres", user="999:999",
            command=("postgres", "-c", "config_file=/lab/postgresql.conf"),
        )
        self.replies = [result(value) for value in STEPS]
        self.calls = []

    def exec(self, item, spec, *argv, **options):
        if item is not self.item or spec is not self.spec:
            raise AssertionError("unexpected allocation")
        self.calls.append((argv, options))
        return self.replies[len(self.calls) - 1]

    def run(self, run_id=RUN):
        return storage.restore_witness_storage(self, self.item, self.spec, run_id)


class RestoreTests(unittest.TestCase):
    def assert_refused(self, lab, phase, calls, *, run_id=RUN):
        with self.assertRaises(storage.WitnessStorageRefused) as trapped:
            lab.run(run_id)
        self.assertEqual(trapped.exception.phase, phase)
        self.assertEqual(str(trapped.exception), "witness_storage_refused")
        self.assertIsNone(trapped.exception.__cause__)
        self.assertEqual(len(lab.calls), calls)

    def test_success_owns_every_step_and_preserves_read_only_clone(self):
        lab = Lab()
        self.assertEqual(lab.run(), {
            "archive_verified": True,
            "distinct_database_created": True,
            "history_and_state_preserved": True,
            "read_only_grants_verified": True,
        })
        self.assertEqual(len(lab.calls), len(STEPS))
        for argv, kwargs in lab.calls:
            self.assertEqual(argv[:len(storage.LOCAL)], storage.LOCAL)
            self.assertEqual(kwargs["stdin_cap"], storage.MAX_ARCHIVE)
            self.assertLessEqual(kwargs["stdout_cap"], storage.MAX_ARCHIVE)
            self.assertLessEqual(kwargs["timeout"], 9)
        dump = lab.calls[2][0]
        self.assertIn(SOURCE, dump)
        self.assertIn("--schema=pam_usage_anchor", dump)
        self.assertIn("--format=custom", dump)
        self.assertIn("/var/run/postgresql", dump)
        self.assertNotIn(CLONE, dump)
        self.assertEqual(lab.calls[3][1]["data"], ARCHIVE)
        create = lab.calls[4][1]["data"]
        self.assertNotIn(b"DROP", create)
        self.assertIn(f"CREATE DATABASE \"{CLONE}\"".encode(), create)
        self.assertLess(create.index(b"ALLOW_CONNECTIONS false"), create.index(b"FROM PUBLIC"))
        self.assertLess(
            create.index(b"TO usage_anchor_observer"), create.index(b"ALLOW_CONNECTIONS true")
        )
        restore, options = lab.calls[5]
        self.assertIn(f"--dbname={CLONE}", restore)
        self.assertIn("--role=usage_anchor_owner", restore)
        self.assertIn("--exit-on-error", restore)
        self.assertIn("--single-transaction", restore)
        self.assertNotIn("--clean", restore)
        self.assertNotIn("--no-acl", restore)
        self.assertNotIn("--create", restore)
        self.assertEqual(options["data"], ARCHIVE)
        for step in (0, 1, 6, 7, 8):
            self.assertIn(b"REPEATABLE READ READ ONLY", lab.calls[step][1]["data"])
        self.assertIn(CLONE, lab.calls[6][0])
        self.assertIn(SOURCE, lab.calls[7][0])

    def test_unowned_target_refused_without_io(self):
        for alternate in ("f" * 16, "0123';", "not-a-database"):
            with self.subTest(alternate=alternate):
                self.assert_refused(Lab(), "inputs", 0, run_id=alternate)
        lab = Lab()
        lab.spec.role = "v-postgres"
        self.assert_refused(lab, "inputs", 0)
        lab = Lab()
        lab.item["identity"] = "w-postgres"
        self.assert_refused(lab, "inputs", 0)
        lab = Lab()
        lab.item["removed"] = True
        self.assert_refused(lab, "inputs", 0)

    def test_target_already_exists_or_source_open(self):
        lab = Lab()
        lab.replies[0] = result(b"")
        self.assert_refused(lab, "source", 1)
        lab = Lab()
        lab.replies[1] = result(SNAP.replace(b"W01_STATE_SEALED\n", b""))
        self.assert_refused(lab, "source", 2)

    def test_unverified_archive_stops_before_create(self):
        cases = (
            (2, b"ARCH_ordinary_bytes"),
            (2, b"PGDMP" + b"x" * storage.MAX_ARCHIVE),
            (3, b""),
            (3, TOC.replace(b"usage_anchor_owner", b"postgres", 1)),
            (3, TOC + TOC[:TOC.index(b"\n") + 1]),
        )
        for step, stdout in cases:
            with self.subTest(step=step, size=len(stdout)):
                lab = Lab()
                lab.replies[step] = result(stdout)
                self.assert_refused(lab, "archive", step + 1)

    def test_invalid_process_receipts_stay_private(self):
        for override in (
            {"stdout_bytes": 0}, {"pid": 0}, {"owned_child_reaped": False},
            {"drains_complete": False}, {"stderr": b"synthetic_failure", "stderr_bytes": 17},
            {"returncode": 1, "reason": "nonzero_exit"},
        ):
            with self.subTest(override=tuple(override)):
                lab = Lab()
                lab.replies[2] = result(ARCHIVE, **override)
                self.assert_refused(lab, "archive", 3)

    def test_create_and_restore_fail_closed(self):
        lab = Lab()
        lab.replies[4] = result(b"")
        self.assert_refused(lab, "create", 5)
        lab = Lab()
        lab.replies[5] = result(b"unexpected pg_restore stdout")
        self.assert_refused(lab, "restore", 6)

    def test_no_success_if_either_database_or_grants_differ(self):
        for step, stdout in (
            (6, SNAP.replace(b"a" * 64, b"b" * 64, 1)),
            (7, SNAP.replace(b"a" * 64, b"b" * 64, 1)),
            (8, b""),
        ):
            with self.subTest(step=step):
                lab = Lab()
                lab.replies[step] = result(stdout)
                self.assert_refused(lab, "verify", step + 1)
        self.assertEqual(ATTEMPTS, [])


class ClusterLab(Lab):
    def __init__(self):
        super().__init__()
        self.target_item = {
            "name": self.reservation + "-w-postgres-restore", "identity": "c" * 64,
        }
        self.target_spec = SimpleNamespace(
            role="w-postgres-restore", user=self.spec.user, command=self.spec.command,
        )
        self.states = {"w-postgres": "running", "w-postgres-restore": "created"}
        self.exit_code = 0
        self.replies = {
            self.spec.role: [result(stdout) for stdout in CLUSTER_SOURCE_STEPS],
            self.target_spec.role: [result(stdout) for stdout in CLUSTER_TARGET_STEPS],
        }
        self.cutoffs = 0

    def bind(self, item, spec):
        if item is self.item and spec is self.spec:
            return self.spec.role
        if item is self.target_item and spec is self.target_spec:
            return self.target_spec.role
        raise AssertionError("unexpected allocation")

    def exec(self, item, spec, *argv, **options):
        role = self.bind(item, spec)
        if self.states[role] != "running":
            raise AssertionError("exec in stopped or unstarted PostgreSQL")
        self.calls.append((role, argv, options))
        return self.replies[role].pop(0)

    def container_profile(self, item, spec):
        status = self.states[self.bind(item, spec)]
        return {
            "State": {
                "Status": status,
                "Running": status == "running",
                "OOMKilled": False,
                "ExitCode": self.exit_code,
            },
        }

    def switch_clusters(self):
        self.cutoffs += 1
        self.states.update({"w-postgres": "exited", "w-postgres-restore": "running"})

    def run(self, run_id=RUN):
        return storage.restore_witness_cluster(
            self, self.item, self.spec, self.target_item, self.target_spec, run_id,
            switch_clusters=self.switch_clusters,
        )


class ClusterRestoreTests(unittest.TestCase):
    def assert_refused(self, lab, phase, source_calls, target_calls, cutoffs):
        with self.assertRaises(storage.WitnessStorageRefused) as trapped:
            lab.run()
        self.assertEqual(trapped.exception.phase, phase)
        self.assertEqual(str(trapped.exception), "witness_storage_refused")
        self.assertIsNone(trapped.exception.__cause__)
        self.assertEqual(
            [role for role, _, _ in lab.calls],
            [lab.spec.role] * source_calls + [lab.target_spec.role] * target_calls,
        )
        self.assertEqual(lab.cutoffs, cutoffs)

    def test_cross_cluster_uses_archive_only_after_source_is_unavailable(self):
        lab = ClusterLab()
        self.assertEqual(lab.run(), {
            "archive_verified": True,
            "distinct_database_created": True,
            "history_and_state_preserved": True,
            "read_only_grants_verified": True,
            "original_cluster_unavailable": True,
            "distinct_cluster_verified": True,
        })
        self.assertEqual(
            [role for role, _, _ in lab.calls],
            [lab.spec.role] * len(CLUSTER_SOURCE_STEPS)
            + [lab.target_spec.role] * len(CLUSTER_TARGET_STEPS),
        )
        self.assertEqual(lab.cutoffs, 1)
        self.assertEqual(lab.states[lab.spec.role], "exited")
        self.assertIn(SOURCE, lab.calls[3][1])
        self.assertIn(b"pg_control_system()", lab.calls[2][2]["data"])
        target_identity = lab.calls[6][2]["data"]
        self.assertIn(b"pg_control_system()", target_identity)
        self.assertIn(b"pg_database", target_identity)
        self.assertIn(b"pg_auth_members", target_identity)
        self.assertIn(b"ARRAY['postgres','usage_anchor_observer']", target_identity)
        for role in storage.NONLOGIN_ROLES:
            self.assertIn(role.encode(), target_identity)
        creation = lab.calls[7][2]["data"]
        self.assertIn(b"pg_database", creation)
        self.assertIn(b"NOT rolcanlogin", creation)
        self.assertNotIn(b"DROP", creation)
        self.assertIn(f"--dbname={CLONE}", lab.calls[8][1])
        self.assertEqual(lab.calls[8][2]["data"], ARCHIVE)
        self.assertEqual(ATTEMPTS, [])

    def test_prestarted_or_aliased_target_is_refused_before_reading_source(self):
        lab = ClusterLab()
        lab.states[lab.target_spec.role] = "running"
        self.assert_refused(lab, "inputs", 0, 0, 0)
        lab = ClusterLab()
        lab.target_item["identity"] = lab.item["identity"]
        self.assert_refused(lab, "inputs", 0, 0, 0)

    def test_source_disagreement_before_cutoff_refuses_without_stopping_either(self):
        lab = ClusterLab()
        lab.replies[lab.spec.role][5] = result(SNAP.replace(b"a" * 64, b"c" * 64, 1))
        self.assert_refused(lab, "cutoff", 6, 0, 0)
        self.assertEqual(lab.states[lab.spec.role], "running")

    def test_source_still_running_or_abnormally_exited_after_cutoff_is_refused(self):
        lab = ClusterLab()
        original_switch = lab.switch_clusters

        def keep_source_running():
            original_switch()
            lab.states[lab.spec.role] = "running"

        lab.switch_clusters = keep_source_running
        self.assert_refused(lab, "cutoff", 6, 0, 1)
        lab = ClusterLab()
        lab.exit_code = 137
        self.assert_refused(lab, "cutoff", 6, 0, 1)

    def test_target_reused_system_identifier_or_unverified_freshness_is_refused(self):
        for output in (SOURCE_ID, b"", b"98706\n98706\n"):
            with self.subTest(output=output):
                lab = ClusterLab()
                lab.replies[lab.target_spec.role][0] = result(output)
                self.assert_refused(lab, "target", 6, 1, 1)

    def test_wrong_restored_snapshot_grants_or_postrestore_identity_fail(self):
        for step, output in (
            (3, SNAP.replace(b"a" * 64, b"d" * 64, 1)),
            (4, b""),
            (5, b"7051354136572160043\n"),
        ):
            with self.subTest(step=step):
                lab = ClusterLab()
                lab.replies[lab.target_spec.role][step] = result(output)
                self.assert_refused(lab, "verify", 6, step + 1, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
