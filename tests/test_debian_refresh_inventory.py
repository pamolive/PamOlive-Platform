"""Exercise the official package inventory using synthetic files and image archives."""

import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from deploy import debian_refresh_inventory as inventory
from deploy import qualified_image
from qualification.debian_138_refresh import verify_refresh as refresh

REVISION = "a" * 40


def native_files():
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:20] = b"\x03\x00\x3e\x00"
    return {path: bytes(header) + path.encode("ascii") for path in sorted(inventory.ELF_PATHS)}


def installed_status(names):
    rows = []
    for package in sorted(names):
        source, version, _, _ = refresh.PACKAGES[package]
        rows.append(
            f"Package: {package}\nStatus: install ok installed\n"
            f"Architecture: amd64\nSource: {source} ({version})\nVersion: {version}\n"
        )
    return "\n".join(rows).encode("ascii")


def make_receipt(files):
    packages = []
    for name in sorted(refresh.PACKAGES):
        source, version, suite, _ = refresh.PACKAGES[name]
        packages.append({
            "package": name,
            "source": source,
            "version": version,
            "suite": suite,
            "archive_sha256": refresh.sha(name.encode("ascii")),
            "archive_bytes": 42,
        })
    instance = {
        "schema": "pamolive.debian-138-refresh/1",
        "architecture": "amd64",
        "selection": {"releases": dict.fromkeys(refresh.RELEASES, "b" * 64), "packages": packages},
        "installed_elf_sha256": {path: refresh.sha(data) for path, data in files.items()},
        "checks": dict.fromkeys(refresh.CHECKS, True),
    }
    return json.dumps(instance, sort_keys=True).encode("ascii")


def write_tar(files, *, aliases=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        for path, data in files.items():
            info = tarfile.TarInfo(path.lstrip("/"))
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for path, target in (aliases or {}).items():
            info = tarfile.TarInfo(path.lstrip("/"))
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return stream.getvalue()


class DebianRuntimeInventoryTests(TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.files = native_files()
        self.receipt = make_receipt(self.files)
        receipt = json.loads(self.receipt)
        expected = {"installed_elf_sha256": receipt["installed_elf_sha256"],
                    "packages": receipt["selection"]["packages"]}
        raw = (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        pin = patch.object(refresh, "REVIEWED_MATERIALS_SHA256", refresh.sha(raw))
        pin.start()
        self.addCleanup(pin.stop)
        self.aliases = {path: PurePosixPath(target).name
                        for path, target in inventory.KRB5_ALIASES.items()}
        self.payload = {
            **self.files,
            inventory.RECEIPT: self.receipt,
            inventory.DPKG_STATUS: installed_status(inventory.RUNTIME_PACKAGES),
        }

    def filesystem(self, payload):
        for name, data in payload.items():
            path = self.root / name.lstrip("/")
            if path.exists():
                path.chmod(0o644)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            # Synthesized files are made read-only for consistent POSIX and NT checks.
            path.chmod(0o444)

    def inspect_fixture_root(self, *, sdk=False, aliases=None):
        lstat = Path.lstat
        links = {self.root.resolve() / name.lstrip("/"): target
                 for name, target in (self.aliases if aliases is None else aliases).items()}
        readlink = os.readlink

        def fixture_owner(path):
            value = lstat(path)
            if path.is_relative_to(self.root) and stat.S_ISREG(value.st_mode):
                return os.stat_result((*value[:4], 0, 0, *value[6:]))
            return value

        def fixture_readlink(path, *args, **kwargs):
            return links[path] if path in links else readlink(path, *args, **kwargs)

        with patch.object(Path, "lstat", fixture_owner), patch.object(
            inventory.os, "readlink", fixture_readlink
        ):
            return inventory.inspect_root(self.root, sdk=sdk)

    def bundle(self, payload, *, declared_image=None, aliases=None):
        layer = write_tar(payload, aliases=self.aliases if aliases is None else aliases)
        config = json.dumps({
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + refresh.sha(layer)]},
            "config": {"Labels": {
                "org.opencontainers.image.source": qualified_image.SOURCE,
                "org.opencontainers.image.revision": REVISION,
                "io.pamolive.source.license": "AGPL-3.0-or-later",
            }},
        }).encode("ascii")
        config_path = refresh.sha(config) + ".json"
        manifest = json.dumps([{
            "Config": config_path, "Layers": ["root.tar"], "RepoTags": [qualified_image.TAG],
        }]).encode("ascii")
        archive = write_tar({
            "manifest.json": manifest, "root.tar": layer, config_path: config,
        })
        (self.root / qualified_image.ARCHIVE).write_bytes(archive)
        metadata = {
            "schema": qualified_image.FORMAT, "source": qualified_image.SOURCE,
            "revision": REVISION, "platform": "linux/amd64",
            "image_id": declared_image or "sha256:" + refresh.sha(config),
            "archive_sha256": refresh.sha(archive),
        }
        (self.root / qualified_image.METADATA).write_text(json.dumps(metadata), encoding="ascii")
        return metadata

    def test_installed_runtime_evidence_contains_only_the_six_runtime_packages(self):
        self.filesystem(self.payload)
        report = self.inspect_fixture_root()
        self.assertEqual(inventory.validate_report(report), report)
        self.assertEqual(report["receipt_sha256"], refresh.sha(self.receipt))
        self.assertEqual(
            [item["package"] for item in report["packages"]], sorted(inventory.RUNTIME_PACKAGES)
        )
        self.assertEqual(set(report["installed_elf_sha256"]), inventory.ELF_PATHS)

    def test_root_entry_point_imports_in_the_two_file_builder_context(self):
        for module, target in (
            (inventory, "deploy/debian_refresh_inventory.py"),
            (refresh, "qualification/debian_138_refresh/verify_refresh.py"),
        ):
            path = self.root / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(Path(module.__file__).read_bytes())
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from deploy.debian_refresh_inventory import main; main(['--help'])"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", code, str(self.root)],
            cwd=self.root, capture_output=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("ascii", errors="replace"))
        self.assertIn(b"--root", result.stdout)

    def test_installed_elf_must_match_the_prequalified_bytes(self):
        path = next(iter(self.files))
        self.filesystem({**self.payload, path: self.files[path] + b"altered"})
        with self.assertRaisesRegex(inventory.InventoryError, "installed_elf_changed"):
            self.inspect_fixture_root()

    def test_kerberos_soname_aliases_must_target_the_qualified_elf(self):
        self.filesystem(self.payload)
        alias = next(iter(self.aliases))
        aliases = {**self.aliases, alias: "../alternate/libkrb5.so.3.3"}
        with self.assertRaisesRegex(inventory.InventoryError, "kerberos_alias"):
            self.inspect_fixture_root(aliases=aliases)

    def test_archive_rejects_changed_and_missing_kerberos_aliases(self):
        alias = next(iter(self.aliases))
        aliases = dict(self.aliases)
        aliases.pop(alias)
        for value in (aliases, {**aliases, alias: "/tmp/other.so"}):
            with self.subTest(aliases=value):
                self.bundle(self.payload, aliases=value)
                with self.assertRaisesRegex(inventory.InventoryError, "kerberos_alias"):
                    inventory.inspect_bundle(self.root, REVISION)

    def test_status_rejects_missing_altered_and_duplicate_package_rows(self):
        good = installed_status(inventory.RUNTIME_PACKAGES)
        package = sorted(inventory.RUNTIME_PACKAGES)[0]
        cases = [
            installed_status(inventory.RUNTIME_PACKAGES - {package}),
            good.replace(b"install ok installed", b"install ok unpacked", 1),
            good.replace(b"Architecture: amd64", b"Architecture: arm64", 1),
            good.replace(b"Source: glibc", b"Source: alternate", 1),
            good.replace(b"Version: 2.41", b"Version: 2.42", 1),
            good + b"\n" + installed_status({package}),
        ]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(inventory.InventoryError):
                inventory.verify_status(data)

    def test_runtime_rejects_sdk_and_legacy_local_inventory(self):
        sdk = installed_status(refresh.PACKAGES)
        self.filesystem({**self.payload, inventory.DPKG_STATUS: sdk})
        with self.assertRaisesRegex(inventory.InventoryError, "status_package_overlap"):
            self.inspect_fixture_root()
        evidence = self.inspect_fixture_root(sdk=True)
        self.assertEqual(len(evidence["packages"]), len(refresh.PACKAGES))
        self.filesystem({**self.payload, inventory.LEGACY_PREFIX + "/inventory.json": b"{}"})
        with self.assertRaisesRegex(inventory.InventoryError, "legacy_backport"):
            self.inspect_fixture_root()

    def test_archive_receipt_is_bound_to_revision_config_and_archive(self):
        metadata = self.bundle(self.payload)
        report = inventory.inspect_bundle(self.root, REVISION)
        self.assertEqual(inventory.validate_report(report, archive=True), report)
        self.assertEqual(report["image_config_id"], metadata["image_id"])
        self.assertEqual(report["archive_sha256"], metadata["archive_sha256"])
        self.assertEqual(report["revision"], REVISION)
        with self.assertRaisesRegex(qualified_image.QualificationError, "metadata"):
            inventory.inspect_bundle(self.root, "c" * 40)

    def test_archive_rejects_unrelated_config_and_changed_elf(self):
        self.bundle(self.payload, declared_image="sha256:" + "d" * 64)
        with self.assertRaisesRegex(qualified_image.QualificationError, "configuration"):
            inventory.inspect_bundle(self.root, REVISION)
        path = next(iter(self.files))
        self.bundle({**self.payload, path: self.files[path] + b"changed"})
        with self.assertRaisesRegex(inventory.InventoryError, "installed_elf_changed"):
            inventory.inspect_bundle(self.root, REVISION)

    def test_image_rejects_agreeing_fabricated_receipt_and_elf(self):
        path = next(iter(self.files))
        changed = {**self.files, path: self.files[path] + b"replacement"}
        payload = {**self.payload, **changed, inventory.RECEIPT: make_receipt(changed)}
        self.bundle(payload)
        with self.assertRaisesRegex(inventory.InventoryError, "unreviewed_debian_materials"):
            inventory.inspect_bundle(self.root, REVISION)

    def test_image_rejects_repacked_deb_and_allows_new_signed_index_digest(self):
        receipt = json.loads(self.receipt)
        receipt["selection"]["releases"]["trixie"] = "c" * 64
        self.bundle({**self.payload, inventory.RECEIPT: json.dumps(receipt).encode("ascii")})
        self.assertEqual(inventory.inspect_bundle(self.root, REVISION)["revision"], REVISION)
        receipt["selection"]["packages"][0]["archive_sha256"] = "e" * 64
        self.bundle({**self.payload, inventory.RECEIPT: json.dumps(receipt).encode("ascii")})
        with self.assertRaisesRegex(inventory.InventoryError, "unreviewed_debian_materials"):
            inventory.inspect_bundle(self.root, REVISION)
