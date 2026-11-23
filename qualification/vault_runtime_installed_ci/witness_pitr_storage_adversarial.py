"""Exercise the PITR acceptance gates with inert PostgreSQL responses."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lab import witness_pitr_storage as pitr  # noqa: E402
from witness_restore_storage_adversarial import (  # noqa: E402
    ATTEMPTS,
    CLONE,
    RUN,
    SNAP,
    SOURCE,
    SOURCE_ID,
    TARGET_ID,
    ClusterLab,
    result,
)

ROLE_SQL = b"SELECT 'synthetic_role_stage';\n"
WAL1 = b"000000010000000000000007"
WAL2 = b"000000010000000000000008"
POINT = b"0/7FFFFE0|0/8000120|" + WAL1 + b"|" + WAL2 + b"\n"
BASE_STEPS = (
    b"W01_TARGET_ABSENT\n", SOURCE_ID, b"1\n", b"W01_PITR_CONTROL_READY\n", b"", b"", b"",
)
SEALED_STEPS = (SOURCE_ID, b"1\n", SNAP, POINT, pitr.ARCHIVE_READY, SNAP)
TARGET_STEPS = (
    b"W01_PITR_REPLAYED\n",
    SOURCE_ID,
    b"2\n",
    f"W01_{RUN}_wpr_PITR_RESTRICTED\n".encode("ascii"),
    b"W01_PITR_MARKERS_EXACT\n",
    SNAP,
    b"W01_TARGET_ABSENT\n",
    b"W01_TARGET_READ_ONLY\n",
    b"W01_PITR_LOGIN_RESTRICTED\n",
)


class PitrLab(ClusterLab):
    def __init__(self):
        super().__init__()
        self.replies = {
            self.spec.role: [result(stdout) for stdout in BASE_STEPS + SEALED_STEPS],
            self.target_spec.role: [result(stdout) for stdout in TARGET_STEPS],
        }

    def take(self, run_id=RUN):
        return pitr.take_pitr_base(self, self.item, self.spec, run_id)

    def finish(self, base, *, role_sql=ROLE_SQL):
        return pitr.finish_witness_pitr(
            self, self.item, self.spec, self.target_item, self.target_spec, RUN,
            base=base, role_sql=role_sql, switch_clusters=self.switch_clusters,
        )


class PitrTests(unittest.TestCase):
    def assert_refused(self, phase, action, *args, **kwargs):
        with self.assertRaises(pitr.PitrRefused) as trapped:
            action(*args, **kwargs)
        self.assertEqual(trapped.exception.phase, phase)
        self.assertEqual(str(trapped.exception), "witness_pitr_refused")
        self.assertIsNone(trapped.exception.__cause__)

    def test_named_point_and_acl_validation_on_exact_owned_roles(self):
        lab = PitrLab()
        base = lab.take()
        self.assertNotIn(SOURCE_ID.decode("ascii").strip(), repr(base))
        self.assertEqual(lab.finish(base), {
            "base_backup_verified": True,
            "wal_archived": True,
            "named_point_recovered": True,
            "post_target_write_excluded": True,
            "physical_identity_preserved": True,
            "timeline_advanced": True,
            "source_cluster_unavailable": True,
            "history_and_state_preserved": True,
            "read_only_grants_verified": True,
        })
        self.assertEqual(lab.cutoffs, 1)
        self.assertEqual(
            [role for role, _, _ in lab.calls],
            [lab.spec.role] * (len(BASE_STEPS) + len(SEALED_STEPS))
            + [lab.target_spec.role] * len(TARGET_STEPS),
        )
        for _, argv, options in lab.calls:
            self.assertEqual(argv[:len(pitr.LOCAL)], pitr.LOCAL)
            self.assertLessEqual(options["stdout_cap"], 8192)
        backup = lab.calls[5][1]
        self.assertIn(pitr.PG_BIN + "pg_basebackup", backup)
        self.assertIn("--host=/var/run/postgresql", backup)
        self.assertIn("--wal-method=stream", backup)
        self.assertIn("--manifest-checksums=SHA256", backup)
        verify = lab.calls[6][1]
        self.assertIn(pitr.PG_BIN + "pg_verifybackup", verify)
        self.assertNotIn("--skip-checksums", verify)
        self.assertNotIn("--no-parse-wal", verify)
        point = lab.calls[len(BASE_STEPS) + 3][2]["data"]
        self.assertLess(point.index(b"VALUES('included')"), point.index(b"pg_create_restore_point"))
        self.assertLess(point.index(b"pg_create_restore_point"), point.index(b"VALUES('excluded')"))
        self.assertLess(point.index(b"VALUES('excluded')"), point.index(b"pg_switch_wal"))
        archive = lab.calls[len(BASE_STEPS) + 4][1]
        self.assertEqual(archive[-2:], (WAL1.decode("ascii"), WAL2.decode("ascii")))
        self.assertIn('cmp -s -- "$original" "$archived"', pitr.ARCHIVE_CHECK)
        start = len(BASE_STEPS) + len(SEALED_STEPS)
        replay = lab.calls[start][2]["data"]
        self.assertIn(b"pg_last_wal_replay_lsn()='0/7FFFFE0'::pg_lsn", replay)
        self.assertIn(b"CHECKPOINT", replay)
        self.assertEqual(lab.calls[start + 3][2]["data"], ROLE_SQL)
        self.assertIn(CLONE, lab.calls[start + 4][1])
        self.assertIn(b"ARRAY['included']", lab.calls[start + 4][2]["data"])
        self.assertNotIn(SOURCE, lab.calls[start + 4][1])
        self.assertEqual(ATTEMPTS, [])

    def test_invalid_allocation_or_private_role_sql_refused_before_io(self):
        lab = PitrLab()
        self.assert_refused("inputs", lab.take, "f" * 16)
        self.assertEqual(lab.calls, [])
        base = lab.take()
        self.assert_refused("inputs", lab.finish, base, role_sql=b"")
        self.assert_refused("inputs", lab.finish, base, role_sql=b"x" * 131073)
        self.assert_refused("inputs", lab.finish, base, role_sql=b"\xff")
        other = PitrLab()
        other.item["identity"] = "f" * 64
        self.assert_refused("inputs", other.finish, base)
        self.assertEqual(other.calls, [])
        self.assertEqual(len(lab.calls), len(BASE_STEPS))

    def test_unsealed_or_already_seeded_source_cannot_produce_receipt(self):
        for index, phase in ((0, "base_control"), (3, "base_control"),
                             (5, "base_backup"), (6, "base_verify")):
            with self.subTest(index=index):
                lab = PitrLab()
                lab.replies[lab.spec.role][index] = result(b"invalid")
                self.assert_refused(phase, lab.take)
                self.assertEqual(len(lab.calls), index + 1)
        lab = PitrLab()
        base = lab.take()
        lab.replies[lab.spec.role][2] = result(b"W01_STATE_OPEN\n")
        self.assert_refused("source", lab.finish, base)
        self.assertEqual(lab.cutoffs, 0)

    def test_nonforward_lsn_or_wrong_timeline_refused_before_cutoff(self):
        for row in (POINT.replace(b"0/8000120", b"0/7AAAAAA"), POINT.replace(WAL2, b"0" * 24)):
            with self.subTest(row=row):
                lab = PitrLab()
                base = lab.take()
                lab.replies[lab.spec.role][3] = result(row)
                self.assert_refused("restore_point", lab.finish, base)
                self.assertEqual(lab.cutoffs, 0)

    def test_wal_wait_is_bounded_and_changes_prevent_cutoff(self):
        lab = PitrLab()
        base = lab.take()
        lab.replies[lab.spec.role][4] = result(pitr.ARCHIVE_WAIT)
        with patch.object(pitr.time, "monotonic", side_effect=(1, 1, 37)):
            with patch.object(pitr.time, "sleep"):
                self.assert_refused("wal_archive", lab.finish, base)
        self.assertEqual(lab.cutoffs, 0)
        lab = PitrLab()
        base = lab.take()
        lab.replies[lab.spec.role][-1] = result(SNAP.replace(b"a" * 64, b"e" * 64, 1))
        self.assert_refused("wal_archive", lab.finish, base)
        self.assertEqual(lab.cutoffs, 0)

    def test_target_cannot_replay_early_start_or_expose_unrestricted_roles(self):
        for index, stdout, phase in (
            (0, b"", "replay"),
            (1, TARGET_ID, "replay"),
            (2, b"1\n", "replay"),
            (3, b"unexpected role setup", "restrict"),
            (4, b"", "verify"),
            (5, SNAP.replace(b"a" * 64, b"f" * 64, 1), "verify"),
            (8, b"", "verify"),
        ):
            with self.subTest(index=index):
                lab = PitrLab()
                base = lab.take()
                lab.replies[lab.target_spec.role][index] = result(stdout)
                self.assert_refused(phase, lab.finish, base)
                self.assertEqual(lab.cutoffs, 1)
        lab = PitrLab()
        base = lab.take()
        lab.states[lab.target_spec.role] = "running"
        self.assert_refused("inputs", lab.finish, base)
        self.assertEqual(lab.cutoffs, 0)

    def test_copy_uses_fresh_destination_and_verifies_before_any_write(self):
        command = pitr.COPY_COMMAND
        self.assertIn('test -z "$(find "$data" -mindepth 1 -maxdepth 1 -print -quit)"', command)
        self.assertIn('test -z "$(find "$base" -xdev ! -type d ! -type f -print -quit)"', command)
        self.assertLess(command.index("pg_verifybackup"), command.index("cp -a"))
        self.assertLess(command.index("cp -a"), command.index('> "$data/recovery.signal"'))
        self.assertIn('sync -f "$data"', command)
        self.assertNotIn("--no-parse-wal", command)
        self.assertNotIn("--skip-checksums", command)
        self.assertEqual(pitr.COPY_READY, b"W01_PITR_COPY_READY\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
