"""Scanner workspace bounds, using synthetic archives without Docker or network."""

import gzip
import hashlib
import io
import json
import tarfile
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import check_scan_scratch as gate
from deploy.qualified_image import QualificationError


class ScanScratchTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pamolive-scratch-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @staticmethod
    def tar(entries):
        result = io.BytesIO()
        with tarfile.open(fileobj=result, mode="w") as archive:
            for name, data, kind in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        return result.getvalue()

    def archive(self, layers=None, names=None, kind=b"0", duplicate=False):
        layers = layers if layers is not None else [self.tar([("fact", b"synthetic", b"0")])]
        names = names if names is not None else ["blobs/sha256/" + hashlib.sha256(x).hexdigest()
                                                for x in layers]
        entries = [("manifest.json", json.dumps([{"Layers": names}]).encode(), b"0")]
        entries += [(name, data, kind) for name, data in zip(names, layers)]
        if duplicate:
            entries.append(entries[-1])
        path = self.root / "image.tar"
        path.write_bytes(self.tar(entries))
        return path

    def test_raw_and_gzip_layers_measured_from_actual_expansion(self):
        raw = self.tar([("fact", b"synthetic", b"0")])
        path = self.archive([raw, gzip.compress(raw)])
        result = gate.measure(path)
        self.assertEqual(result["expanded_layer_bytes"], 2 * len(raw))
        self.assertEqual(result["required_bytes"],
                         path.stat().st_size + 4 * len(raw) + gate.MARGIN_BYTES)
        self.assertEqual(result["archive_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_compression_bomb_hits_budget_without_extraction(self):
        path = self.archive([gzip.compress(b"x" * 2_000_000)])
        with patch.object(gate, "SCRATCH_BYTES", 100_000), patch.object(gate, "MARGIN_BYTES", 1000):
            with self.assertRaisesRegex(QualificationError, "scratch_budget"):
                gate.measure(path)

    def test_duplicate_layer_entry_refused(self):
        with self.assertRaisesRegex(QualificationError, "scratch_layer_type"):
            gate.measure(self.archive(duplicate=True))

    def test_repeated_manifest_layer_refused(self):
        name = "blobs/sha256/" + "a" * 64
        with self.assertRaisesRegex(QualificationError, "scratch_layers"):
            gate.measure(self.archive([b"a", b"b"], [name, name]))

    def test_layer_symlink_refused(self):
        with self.assertRaisesRegex(QualificationError, "scratch_layer_type"):
            gate.measure(self.archive(kind=b"2"))

    def test_traversal_and_arbitrary_layer_paths_refused(self):
        for name in ("../layer.tar", "/layer.tar", "blobs/sha256/invalid"):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(QualificationError, "scratch_layers"),
            ):
                gate.measure(self.archive(names=[name]))

    def test_unknown_compression_and_truncated_gzip_refused(self):
        for data in (b"\x28\xb5\x2f\xfd" + b"x" * 1000, gzip.compress(b"x" * 100)[:-5]):
            with (
                self.subTest(data=data[:4]),
                self.assertRaises((ValueError, OSError, EOFError, tarfile.TarError)),
            ):
                gate.measure(self.archive([data]))

    def test_output_exclusive_and_failure_evidence(self):
        path = self.archive()
        output = self.root / "report.json"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(["--archive", str(path), "--output", str(output)]), 0)
            original = output.read_bytes()
            self.assertEqual(gate.main(["--archive", str(path), "--output", str(output)]), 1)
        self.assertEqual(output.read_bytes(), original)
        failed = self.root / "failed.json"
        path.write_bytes(b"invalid")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(["--archive", str(path), "--output", str(failed)]), 1)
        self.assertFalse(json.loads(failed.read_bytes())["passed"])
