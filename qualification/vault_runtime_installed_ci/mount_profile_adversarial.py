"""Closed pure mount-table composition tests; orchestration is always a fake."""

import importlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
ATTEMPTS = {}
STATUS = "\n".join(
    [
        "Uid:\t1000 1000 1000 1000",
        "Gid:\t1000 1000 1000 1000",
        "Groups:\t1000",
        "NoNewPrivs:\t1",
        *[
            key + ":\t0000000000000000"
            for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")
        ],
    ]
)
MOUNTS = "\n".join(
    [
        "overlay / overlay ro,relatime 0 0",
        *[
            "fixture " + target + " ext4 ro,relatime 0 0"
            for target in ("/controller", "/source", "/materials")
        ],
        "tmpfs /work tmpfs rw,nosuid,nodev,relatime 0 0",
        "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0",
    ]
)
MOUNTINFO = "\n".join(
    "10 9 0:1 / " + line.split()[1] + " " + line.split()[3] + " - tmpfs tmpfs rw"
    for line in MOUNTS.splitlines()
)
EXPECTED = {
    "test_real_profile_rejects_mountinfo",
    "test_main_mounts_reaches_only_fake_orchestration",
    "test_main_mountinfo_stops_before_orchestration",
    "test_each_readonly_mount_remains_required",
    "test_capabilities_and_nnp_remain_required",
    "test_tmpfs_type_and_options_remain_required",
    "test_tmpfs_exec_policy_remains_required",
    "test_uid_gid_and_groups_remain_required",
}


def audit(event, _values):
    if event.startswith(("subprocess.", "socket.", "sqlite3.")) or event in {
        "os.system",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
        "os.fork",
    }:
        ATTEMPTS[event] = ATTEMPTS.get(event, 0) + 1
        raise AssertionError("mount_pure_external_operation_refused")


class MountProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = importlib.import_module("workload_entry")
        cls.profile_module = cls.entry.support.load("entrypoint.py")
        cls.payload = json.loads((ROOT / "payloads.json").read_bytes())
        cls.bindings = {
            "expected_source": cls.entry.orchestrate.PAYLOAD_SHA,
            "expected_input": cls.entry.support.sha(
                cls.entry.schema.encode(cls.entry.orchestrate.description(cls.payload))
            ),
            "expected_sql": cls.entry.adapter.SQL_SHA,
            "expected_materials": cls.entry.adapter.MATERIALS,
        }

    def invoke(self, status=STATUS, mounts=MOUNTS):
        entry = self.entry
        reads, reports = [], []
        fake_report = {"synthetic_orchestration_not_executed": True}
        run = Mock(return_value=fake_report)

        def proc(path, cap):
            reads.append((path.as_posix(), cap))
            if path.as_posix() == "/proc/self/status":
                return status
            if path.as_posix() == "/proc/mounts":
                return mounts
            if path.as_posix() == "/proc/self/mountinfo":
                return MOUNTINFO
            raise AssertionError("unexpected_proc_path")

        def packet(report, **bindings):
            self.assertEqual(bindings, self.bindings)
            reports.append(report)
            # This seam never claims an installed result, even on its positive path.
            return {"ok": False}

        argv = ["workload_entry.py"]
        for name, value in self.bindings.items():
            argv += ["--" + name.replace("_", "-"), value]
        stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with (
            patch.object(sys, "argv", argv),
            patch.object(sys, "stdout", stdout),
            patch.object(entry, "proc", side_effect=proc),
            patch.object(entry.orchestrate, "source_payloads", return_value=(self.payload, {})),
            patch.object(entry.orchestrate, "run", run),
            patch.object(entry.workload, "packet", side_effect=packet),
        ):
            with self.assertRaises(SystemExit) as raised:
                entry.main()
        self.assertEqual(raised.exception.code, 42)
        self.assertEqual(len(reports), 1)
        return run, reports[0], reads, fake_report

    def refused(self, status=STATUS, mounts=MOUNTS):
        run, report, _, _ = self.invoke(status, mounts)
        run.assert_not_called()
        self.assertEqual(report["state"], "FAILED")
        self.assertEqual(report["failure"]["phase"], "preflight")
        self.assertIsNone(report["child"])
        self.assertEqual(report["processes"], [])

    def test_real_profile_rejects_mountinfo(self):
        with self.assertRaises(KeyError) as raised:
            self.profile_module.profile(STATUS, MOUNTINFO)
        self.assertEqual(raised.exception.args, ("/",))

    def test_main_mounts_reaches_only_fake_orchestration(self):
        run, report, reads, fake_report = self.invoke()
        run.assert_called_once_with(Path("/materials"))
        self.assertIs(report, fake_report)
        self.assertEqual(reads, [("/proc/self/status", 65536), ("/proc/mounts", 262144)])

    def test_main_mountinfo_stops_before_orchestration(self):
        self.refused(mounts=MOUNTINFO)

    def test_each_readonly_mount_remains_required(self):
        for target in ("/", "/controller", "/source", "/materials"):
            changed = [
                line.replace(" ro,", " rw,") if line.split()[1] == target else line
                for line in MOUNTS.splitlines()
            ]
            with self.subTest(target=target):
                self.refused(mounts="\n".join(changed))

    def test_capabilities_and_nnp_remain_required(self):
        for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"):
            with self.subTest(field=key):
                self.refused(status=STATUS.replace(key + ":\t0000000000000000", key + ":\t1"))
        self.refused(status=STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"))

    def test_tmpfs_type_and_options_remain_required(self):
        for target in ("/work", "/tmp"):
            for remove in ("tmpfs", "rw", "nosuid", "nodev"):
                changed = []
                for line in MOUNTS.splitlines():
                    row = line.split()
                    if row[1] == target:
                        if remove == "tmpfs":
                            row[2] = "ext4"
                        else:
                            row[3] = ",".join(
                                value for value in row[3].split(",") if value != remove
                            )
                    changed.append(" ".join(row))
                with self.subTest(target=target, remove=remove):
                    self.refused(mounts="\n".join(changed))

    def test_tmpfs_exec_policy_remains_required(self):
        self.refused(mounts=MOUNTS.replace("/work tmpfs rw,", "/work tmpfs rw,noexec,"))
        self.refused(mounts=MOUNTS.replace("nodev,noexec,", "nodev,"))

    def test_uid_gid_and_groups_remain_required(self):
        for key in ("Uid", "Gid"):
            with self.subTest(field=key):
                self.refused(
                    status=STATUS.replace(key + ":\t1000 1000 1000 1000", key + ":\t0 0 0 0")
                )
        self.refused(status=STATUS.replace("Groups:\t1000", "Groups:\t1000 0"))


def main():
    sys.addaudithook(audit)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MountProfileTests)
    names = [test._testMethodName for test in suite]
    if len(names) != len(EXPECTED) or set(names) != EXPECTED:
        raise SystemExit("closed_eight_mount_tests_required")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    production = {
        "pamolive_vault_runtime",
        "pamolive_vault_contracts",
        "pamolive_pam_trust_verifier",
        "django",
        "config",
        "platform_core",
        "platform_modules",
    }
    imported = sorted(name for name in production if name in sys.modules)
    summary = {
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": len(result.skipped),
        "external_attempts": ATTEMPTS,
        "production_packages_imported": imported,
        "actual_build_install_or_container": False,
        "real_inherited_profile": True,
        "orchestration_always_fake": True,
    }
    print(json.dumps(summary))
    raise SystemExit(
        not result.wasSuccessful()
        or result.testsRun != 8
        or bool(result.skipped)
        or bool(ATTEMPTS)
        or bool(imported)
    )


if __name__ == "__main__":
    main()
