"""Actual Python guard mechanisms and synthetic audit events, no syscalls."""

import importlib
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from guards import DRIVERS, REFERENCE, ForbiddenIO, Policy


def policy():
    base = Path(__file__).resolve().parent
    flags = SimpleNamespace(
        **{name: getattr(os, name) for name in dir(os) if name.startswith("O_")}
    )
    flags.O_ACCMODE = 3  # Explicit POSIX fixture; production uses actual Linux os.
    return Policy(
        prefix=base / "runtime",
        stdlib=Path(sys.base_prefix) / "Lib",
        stage=base / "stage",
        controller=base,
        report=base / "report.json",
        constants=flags,
    )


class GuardTests(unittest.TestCase):
    def test_driver_imports_all_block_before_resolution_and_masked_error_latches(self):
        current = policy()
        with current.install():
            current.probe()
            self.assertEqual(sum(current.guard.probes.values()), 6)
            for name in DRIVERS:
                for importing in (__import__, importlib.import_module):
                    try:
                        importing(name)
                    except ForbiddenIO:
                        pass
                    else:
                        self.fail("driver imported")
            with self.assertRaises(ForbiddenIO):
                current.guard.require_clean()
        self.assertEqual(current.guard.attempts["import.driver"], len(DRIVERS) * 2)

    def test_import_application_or_decrypt_SDK_denied_without_import(self):
        current = policy()
        for name in ("django", "platform_core.services", "pamolive_vault_envelope", "boto3"):
            with self.assertRaises(ForbiddenIO):
                current.imported(name)
        current.imported("pamolive_vault_contracts")
        self.assertEqual(current.guard.attempts["import.application_or_SDK"], 4)

    def test_all_reference_fs_mutations_count_and_cannot_be_masked(self):
        current = policy()
        current.active = True
        for event in REFERENCE.FILESYSTEM_MUTATIONS:
            with self.assertRaises(ForbiddenIO):
                current.audit(event, ("unused",))
        self.assertEqual(
            current.guard.attempts["file.mutation"], len(REFERENCE.FILESYSTEM_MUTATIONS)
        )
        with self.assertRaises(ForbiddenIO):
            current.guard.require_clean()

    def test_open_mutation_flags_and_report_exclusive_window_only(self):
        for flags in (
            os.O_RDONLY | os.O_TRUNC,
            os.O_RDONLY | os.O_CREAT,
            os.O_APPEND,
            os.O_EXCL,
            os.O_WRONLY,
            os.O_RDWR,
        ):
            current = policy()
            current.active = True
            with self.assertRaises(ForbiddenIO):
                current.audit("open", (str(current.roots[0] / "file"), None, flags))
        current = policy()
        current.active = True
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        with self.assertRaises(ForbiddenIO):
            current.audit("open", (str(current.report), "x", flags))
        current.report_enabled = True
        current.audit("open", (str(current.report), "x", flags))
        with self.assertRaises(ForbiddenIO):
            current.audit("open", (str(current.report), "x", flags))

    def test_read_fd_outside_roots_and_global_site_refuse(self):
        current = policy()
        current.active = True
        for event in ("open", "os.listdir", "os.scandir"):
            values = ("/outside/read", "r", os.O_RDONLY) if event == "open" else ("/outside/read",)
            with self.assertRaises(ForbiddenIO):
                current.audit(event, values)
        with self.assertRaises(ForbiddenIO):
            current.audit("open", (100, "r", os.O_RDONLY))
        with self.assertRaises(ForbiddenIO):
            current.audit("open", (str(current.base_site / "foreign.py"), "r", os.O_RDONLY))

    def test_composite_TMPFILE_and_directory_flag_preserve_reference_semantics(self):
        constants = type(
            "Flags",
            (),
            {
                "O_TMPFILE": 0x410000,
                "O_DIRECTORY": 0x10000,
                "O_CREAT": 0x40,
                "O_TRUNC": 0x200,
                "O_APPEND": 0x400,
                "O_EXCL": 0x80,
                "O_ACCMODE": 3,
                "O_RDONLY": 0,
            },
        )
        self.assertFalse(REFERENCE.open_mutates(None, constants.O_DIRECTORY, constants))
        self.assertTrue(REFERENCE.open_mutates(None, constants.O_TMPFILE, constants))
