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


if __name__ == "__main__":
    unittest.main(verbosity=2)
