"""Exact-archive and SBOM contracts for the reviewed ACL consumers."""

import copy
import hashlib
import struct
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from deploy import acl_consumer_runtime as runtime
from deploy import acl_runtime_inventory as acl
from deploy import qualify_image_scan as gate
from tests import test_expat_product, test_image_scan_policy, test_native_sbom

ROOT = Path(__file__).resolve().parents[1]
IMAGE = {"revision": "a" * 40, "image_id": "sha256:" + "d" * 64, "archive_sha256": "b" * 64}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class AclConsumerRuntimeTests(TestCase):
    def setUp(self):
        raw = (ROOT / runtime.QUALIFICATION).read_bytes()
        self.qualification = gate.json_bytes(raw)
        packages = self.qualification["packages"]
        captured = {path: ("synthetic:" + path).encode() for path in runtime.MANAGED}
        self.symbols = {path: ["perm_copy_fd@ACL_1.1"] for path in runtime.FD_ONLY}
        for package in packages.values():
            for path, binary in package["binaries"].items():
                binary["sha256"] = digest(captured[path])
                self.symbols[path] = binary["descriptor_imports"]
        self.raw = (gate.canonical(self.qualification) + "\n").encode()
        captured[runtime.INSTALLED_QUALIFICATION] = self.raw
        installed = [
            (name, row["version"], "") for name, row in packages.items()
        ] + [("libacl1", acl.VERSION, "Source: acl\n")]
        captured[acl.STATUS] = "".join(
            f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n{source}"
            "Status: install ok installed\n\n" for name, version, source in installed
        ).encode()
        entries = {
            path: {"path": path, "class": 64, "machine": 62, "type": "elf",
                   "sha256": digest(captured[path])}
            for path in runtime.MANAGED
        }
        entries[runtime.LIBRARY_ALIAS] = {
            "path": runtime.LIBRARY_ALIAS, "type": "symlink",
            "target": PurePosixPath(acl.LIBRARY).name,
        }
        attrs = {
            path: {"uid": 0, "gid": 0, "mode": 0o755, "has_capability": False}
            for path in runtime.MANAGED
        }
        attrs[acl.LIBRARY]["mode"] = 0o644
        attrs[runtime.INSTALLED_QUALIFICATION] = {**attrs[acl.LIBRARY], "mode": 0o444}
        linkage = {
            entries[path]["sha256"]: {"status": "observed", "needed": [acl.SONAME]}
            for path in runtime.ALL_CONSUMERS
        }
        linkage[entries[acl.LIBRARY]["sha256"]] = {"status": "observed", "needed": []}
        self.facts = gate.ArchiveFacts(
            set(captured) | set(entries), entries, entries=entries, captured=captured,
            contents={path: {} for path in captured}, attributes=attrs, elf_linkage=linkage,
        )

    def mock_readelf(self, data, target):
        path = data.decode().removeprefix("synthetic:")
        if path == acl.LIBRARY:
            symbols = sorted({name for names in self.symbols.values() for name in names})
            return f"Library soname: [{acl.SONAME}]\n" + "".join(
                f"1: 0000 0 FUNC GLOBAL DEFAULT 12 {symbol}\n" for symbol in symbols
            )
        return "".join(
            f"1: 0000 0 FUNC GLOBAL DEFAULT UND {symbol}\n" for symbol in self.symbols[path]
        )

    def measure(self):
        with (patch.object(acl, "readelf", side_effect=self.mock_readelf),
              patch.object(acl, "ELF_SHA256", digest(self.facts.captured[acl.LIBRARY]))):
            return runtime.measure(self.facts, self.raw, IMAGE, Path("unused.elf"))

    def test_package_install_ledger_matches_reviewed_materials(self):
        source = ROOT / runtime.QUALIFICATION
        packages = runtime.validate_qualification(gate.json_bytes(source.read_bytes()))
        ledger = (source.parent / "consumers" / "package.sha256").read_text(encoding="ascii")
        self.assertEqual(set(ledger.splitlines()), {
            f"{row['deb_sha256']}  {name}_{row['version']}_amd64.deb"
            for name, row in packages.items()
        })

    def test_measures_direct_consumers_and_their_bound_package_identity(self):
        report = self.measure()
        self.assertEqual(set(report["consumers"]), runtime.ALL_CONSUMERS)
        self.assertEqual(report["qualification_sha256"], digest(self.raw))
        self.assertEqual(report["image_config_id"], IMAGE["image_id"])
        self.assertEqual(report["archive_sha256"], IMAGE["archive_sha256"])

    def test_pinned_python_relocatable_has_no_runtime_program_headers(self):
        path = runtime.PYTHON_OBJECT
        ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
        data = struct.pack("<16sHHIQQQIHHHHHH", ident, 1, 62, 1, 0, 0, 64, 0,
                           64, 0, 0, 64, 0, 0)
        identity = digest(data)
        self.facts.captured[path] = data
        self.facts.entries[path] = {
            "path": path, "type": "elf", "class": 64, "machine": 62, "sha256": identity,
        }
        self.facts.elf_linkage[identity] = {"status": "unsupported"}
        with patch.object(runtime, "PYTHON_OBJECT_SHA256", identity):
            self.assertEqual(self.measure()["relocatable_objects"], {path: identity})
            self.facts.entries["/usr/local/bin/other.o"] = {
                **self.facts.entries[path], "type": "hardlink", "target": path,
            }
            with self.assertRaisesRegex(acl.InventoryError, "acl_consumer_relocatable_identity"):
                self.measure()
            self.facts.entries.pop("/usr/local/bin/other.o")
            self.facts.elf_linkage["f" * 64] = {"status": "budget_exceeded"}
            with self.assertRaisesRegex(acl.InventoryError, "acl_consumer_linkage_incomplete"):
                self.measure()
        with self.assertRaisesRegex(acl.InventoryError, "acl_consumer_linkage_incomplete"):
            self.measure()

    def test_relocatable_header_check_rejects_program_headers_and_executables(self):
        path = runtime.PYTHON_OBJECT
        ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
        for kind, program_offset, program_size, program_count in (
            (1, 64, 56, 1), (2, 0, 0, 0),
        ):
            with self.subTest(kind=kind, program_count=program_count):
                data = struct.pack("<16sHHIQQQIHHHHHH", ident, kind, 62, 1, 0, program_offset,
                                   64, 0, 64, program_size, program_count, 64, 0, 0)
                identity = digest(data)
                self.facts.captured[path] = data
                self.facts.entries[path] = {"path": path, "type": "elf", "sha256": identity}
                linkage = self.facts.elf_linkage
                with (patch.dict(linkage, {identity: {"status": "unsupported"}}),
                      patch.object(runtime, "PYTHON_OBJECT_SHA256", identity),
                      self.assertRaisesRegex(acl.InventoryError,
                                             "acl_consumer_relocatable_header")):
                    self.measure()

    def test_layer_facts_require_the_exact_configuration_and_archive(self):
        data, config_id = test_expat_product.fixture()
        metadata = {"image_id": config_id, "archive_sha256": digest(data)}
        with TemporaryDirectory() as directory:
            archive = Path(directory) / "fixture.tar"
            archive.write_bytes(data)
            config, facts = gate.bound_archive_facts(archive, metadata, [])
            self.assertEqual("sha256:" + digest(config), config_id)
            self.assertTrue(facts.layer_digests)
            with self.assertRaisesRegex(gate.ScanPolicyError, "archive_config_identity"):
                gate.bound_archive_facts(archive, {**metadata, "image_id": IMAGE["image_id"]}, [])
            with self.assertRaisesRegex(gate.ScanPolicyError, "archive_checksum"):
                gate.bound_archive_facts(archive, {**metadata, "archive_sha256": "f" * 64}, [])

    def test_scan_requires_archive_marker_and_acl_sbom_together(self):
        fixtures = test_image_scan_policy.ImageScanPolicyTests()
        fixtures.setUp()
        self.addCleanup(fixtures.doCleanups)
        self.assertTrue(fixtures.evaluate()["passed"])
        with self.assertRaisesRegex(gate.ScanPolicyError, "acl_product_image_binding"):
            fixtures.evaluate(self.facts, revision=IMAGE["revision"],
                              archive_sha256=IMAGE["archive_sha256"])
        fixtures.sbom["metadata"]["properties"].append({
            "name": "pamolive:sbom:acl-input-sha256", "value": "a" * 64,
        })
        with self.assertRaisesRegex(gate.ScanPolicyError, "acl_product_image_binding"):
            fixtures.evaluate(revision=IMAGE["revision"], archive_sha256=IMAGE["archive_sha256"])

    def test_refuses_legacy_import_and_unreviewed_hardlink_consumer(self):
        path = "/usr/bin/cp"
        self.symbols[path].append("acl_set_file@ACL_1.0")
        with self.assertRaisesRegex(acl.InventoryError, "acl_consumer_legacy_import"):
            self.measure()
        self.symbols[path].pop()
        self.facts.entries["/usr/bin/alias"] = {
            **self.facts.entries[path], "type": "hardlink", "target": path,
        }
        with self.assertRaisesRegex(acl.InventoryError, "acl_consumer_dependency_scope"):
            self.measure()

    def test_refuses_archive_version_modes_and_receipt_changes(self):
        def try_change(mapping, key, value, reason):
            original = mapping[key]
            mapping[key] = value
            try:
                with self.assertRaisesRegex(acl.InventoryError, reason):
                    self.measure()
            finally:
                mapping[key] = original

        try_change(self.facts.captured, acl.STATUS,
                   self.facts.captured[acl.STATUS].replace(b"+pamolive1", b"+unexpected"),
                   "acl_consumer_installed_identity")
        try_change(self.facts.attributes["/usr/bin/sed"], "mode", 0o4755,
                   "acl_consumer_elf_attributes")
        try_change(self.facts.captured, runtime.INSTALLED_QUALIFICATION, b"{}",
                   "acl_consumer_installed_qualification")
        try_change(self.facts.captured, "/usr/bin/sed", b"synthetic:/usr/bin/tar",
                   "acl_consumer_elf_identity")

    def test_sbom_binding_rejects_changed_package_hash_and_disconnected_root(self):
        fixtures = test_native_sbom.NativeSbomTests()
        fixtures.setUp()
        report = self.measure()
        fixtures.hashes["acl"] = digest((gate.canonical(report) + "\n").encode("ascii"))
        sbom = fixtures.merge(image_digest_kind="image_config", acl_report=report)
        props = {item["name"]: item["value"] for item in sbom["metadata"]["properties"]}
        gate.verify_acl_sbom(sbom, report, IMAGE["image_id"], props)
        forged = copy.deepcopy(sbom)
        package = next(row for row in forged["components"]
                       if row.get("purl", "").startswith("pkg:deb/debian/sed@"))
        package["hashes"][0]["content"] = "0" * 64
        with self.assertRaisesRegex(gate.ScanPolicyError, "acl_sbom_components"):
            gate.verify_acl_sbom(forged, report, IMAGE["image_id"], props)
        image_ref = next(row for row in sbom["components"] if row["type"] == "container")["bom-ref"]
        edge = next(row for row in sbom["dependencies"] if row["ref"] == image_ref)
        edge["dependsOn"].remove(package["bom-ref"])
        with self.assertRaisesRegex(gate.ScanPolicyError, "acl_sbom_components"):
            gate.verify_acl_sbom(sbom, report, IMAGE["image_id"], props)
