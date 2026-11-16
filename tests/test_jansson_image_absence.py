"""Pure migration checks over synthetic Docker-save DATA, never ELF execution."""

import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path
from unittest import TestCase

from deploy import jansson_image_absence as migration
from deploy import qualify_image_scan as gate
from tests.test_native_inventory import elf


class JanssonAbsenceTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="jansson-data-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.archive = Path(self.tmp.name) / "image.tar"
        self.status = b"Package: libjansson4\nStatus: install ok installed\nVersion: 2.14-2+b3\n"
        self.sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": "libjansson4",
                    "version": "2.14-2+b3",
                    "purl": "pkg:deb/debian/libjansson4@2.14-2%2Bb3",
                }
            ],
        }

    def make(self, rows):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as tar:
            for name, data in rows:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        raw = layer.getvalue()
        config = json.dumps(
            {
                "os": "linux",
                "architecture": "amd64",
                "rootfs": {
                    "type": "layers",
                    "diff_ids": ["sha256:" + hashlib.sha256(raw).hexdigest()],
                },
            }
        ).encode()
        with tarfile.open(self.archive, "w") as tar:
            for name, data in (
                ("manifest.json", b'[{"Config":"config.json","Layers":["layer.tar"]}]'),
                ("config.json", config),
                ("layer.tar", raw),
            ):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))

    def check(self, extra=()):
        self.make(
            [("usr/lib/libsynthetic.so", elf()), ("var/lib/dpkg/status", self.status), *extra]
        )
        return migration.examine(self.archive, self.sbom)

    def test_clean_data_bound_to_archive_config_and_full_elf_set(self):
        result = self.check([("app/documentation.txt", b"cJSON_Compare is an old advisory")])
        self.assertTrue(result["physical_checks_passed"])
        self.assertEqual(
            result["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest()
        )
        self.assertEqual(result["elf_set"]["elf_count"], 1)
        self.assertEqual(len(result["layer_diff_ids"]), 1)

    def test_cjson_core_utils_sources_and_alias_names_fail(self):
        for name in (
            "usr/lib/libcjson.so.1",
            "usr/lib/libcjson_utils.so.1",
            "source/cJSON_Utils.c",
        ):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(gate.ScanPolicyError, "cjson_physical_file"),
            ):
                self.check([(name, b"synthetic-non-elf")])

    def test_renamed_static_and_cross_chunk_symbols_fail(self):
        for marker in (b"cJSON_Compare", b"cJSONUtils_ApplyPatches"):
            for prefix in (elf(), elf() + b"x" * (64 + 1024 * 1024 - len(elf()) - 3)):
                with (
                    self.subTest(marker=marker, size=len(prefix)),
                    self.assertRaisesRegex(gate.ScanPolicyError, "cjson_elf_symbol"),
                ):
                    self.check([("usr/lib/renamed.so", prefix + marker)])

    def test_dpkg_and_nested_sbom_cjson_are_refused(self):
        original = self.status
        self.status += b"\nPackage: libcjson1\nStatus: install ok installed\n"
        with self.assertRaisesRegex(gate.ScanPolicyError, "cjson_dpkg_package"):
            self.check()
        self.status = original
        self.sbom["components"].append(
            {
                "name": "parent",
                "components": [{"name": "renamed", "purl": "pkg:generic/cjson@1.7.19"}],
            }
        )
        with self.assertRaisesRegex(gate.ScanPolicyError, "cjson_sbom_package"):
            self.check()

    def test_jansson_missing_or_wrong_version_refuses(self):
        for value in (
            b"Package: other\nStatus: install ok installed\n",
            self.status.replace(b"2.14-2+b3", b"0.19+ds-1"),
        ):
            self.status = value
            with self.assertRaisesRegex(gate.ScanPolicyError, "jansson_dpkg_version"):
                self.check()
        self.status = b"Package: libjansson4\nStatus: install ok installed\nVersion: 2.14-2+b3\n"
        self.sbom["components"][0]["version"] = "0.19+ds-1"
        with self.assertRaisesRegex(gate.ScanPolicyError, "jansson_sbom_version"):
            self.check()
