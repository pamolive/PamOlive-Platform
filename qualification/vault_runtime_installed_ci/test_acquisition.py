"""Acquisition glue with synthetic plan/buffers and fake transport, no cache IO."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import adapter_v2
from support import ROOT, sha


class AcquisitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = copy.deepcopy(adapter_v2.materials())
        cls.rows = cls.plan["selected_materials"]
        cls.buffers = {name: ("PUBLIC SYNTHETIC BUFFER " + name).encode() for name in cls.rows}
        for name, row in cls.rows.items():
            row["size"], row["sha256"] = len(cls.buffers[name]), sha(cls.buffers[name])

    def setUp(self):
        boundary = patch.object(adapter_v2, "materials", return_value=copy.deepcopy(self.plan))
        boundary.start()
        self.addCleanup(boundary.stop)

    def fake(self, **changes):
        calls = []
        gate = SimpleNamespace(
            load_manifest=lambda _path: (
                {"materials": list(copy.deepcopy(self.rows).values())},
                adapter_v2.MANIFEST,
            ),
            check_locks=lambda *_: calls.append("locks"),
            https_opener=lambda: object(),
            download=lambda row, _dest, _opener, *, deadline: calls.append((row["name"], deadline)),
            verify_file=lambda _path, row: self.buffers[row["name"]],
        )
        gate.__dict__.update(changes)
        return gate, calls

    def test_exact16_and_deadline_without_network_or_material_writes(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            destination = Path(directory) / "fresh"
            gate, calls = self.fake()
            receipt = adapter_v2.acquire(
                repository,
                destination,
                gate=gate,
                inventory=lambda *_args, **_kwargs: {"RECORD_checked": True},
                clock=lambda: 10,
            )
            self.assertEqual(len(receipt["files"]), 16)
            self.assertEqual(receipt["state"], "SIXTEEN_PUBLIC_WHEELS_CHECKED")
            self.assertEqual(len(calls), 17)
            self.assertTrue(all(call[1] == 1810 for call in calls[1:]))
            self.assertEqual({path.name for path in destination.iterdir()}, {"acquisition.json"})

    def test_foreign_material_row_refused_before_destination_or_transport(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as directory:
            repository = Path(directory)
            wrong = copy.deepcopy(self.rows)
            wrong["h11"]["url"] = "https://unapproved.invalid/h11.whl"
            gate, calls = self.fake(
                load_manifest=lambda _: ({"materials": list(wrong.values())}, adapter_v2.MANIFEST)
            )
            target = repository.parent / (repository.name + "-not-created")
            with self.assertRaises(ValueError):
                adapter_v2.acquire(repository, target, gate=gate)
            self.assertFalse(target.exists())
            self.assertEqual(calls, ["locks"])

    def test_deadline_or_integrity_refusal_remains_failed(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            for name, gate, clock in (
                ("deadline", self.fake()[0], iter([0, 1801]).__next__),
                ("integrity", self.fake(verify_file=lambda *_: b"WRONG")[0], lambda: 0),
            ):
                destination = Path(directory) / name
                with self.assertRaises(ValueError):
                    adapter_v2.acquire(repository, destination, gate=gate, clock=clock)
                self.assertEqual(
                    json.loads((destination / "acquisition.json").read_bytes())["state"], "FAILED"
                )

    def test_original_transport_error_survives_receipt_failure(self):
        original = ValueError("SYNTHETIC_ORIGINAL")

        def fail(*_args, **_kwargs):
            raise original

        with tempfile.TemporaryDirectory(dir=ROOT.parent) as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            gate, _ = self.fake(download=fail)
            with patch.object(Path, "open", side_effect=OSError("SYNTHETIC_REPORT_IO")):
                with self.assertRaises(ValueError) as caught:
                    adapter_v2.acquire(
                        repository, Path(directory) / "fresh", gate=gate, clock=lambda: 0
                    )
            self.assertIs(caught.exception, original)
