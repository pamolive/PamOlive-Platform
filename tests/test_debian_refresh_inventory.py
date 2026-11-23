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

from deploy import (
    build_context,
    glibc_trixie_materials,
    krb5_trixie_materials,
    native_sbom,
    openssl_trixie_materials,
    qualified_image,
    util_linux_trixie_materials,
)
from deploy import debian_refresh_inventory as inventory
from deploy import qualify_image_scan as scan
from qualification.debian_138_refresh import verify_refresh as refresh

REVISION = "a" * 40


def native_files(paths=inventory.ELF_PATHS):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:20] = b"\x03\x00\x3e\x00"
    return {path: bytes(header) + path.encode("ascii") for path in sorted(paths)}


def installed_status(names, *, kerberos_version=None, openssl_version=None, util_linux=False,
                     glibc_version=None):
    rows = []
    for package in sorted(names):
        if package in refresh.PACKAGES:
            source, version, _, _ = refresh.PACKAGES[package]
            if source == "krb5" and kerberos_version is not None:
                version = kerberos_version
            if source == "glibc" and glibc_version is not None:
                version = glibc_version
        elif util_linux and package in util_linux_trixie_materials.PACKAGE_VERSIONS:
            source, version = "util-linux", util_linux_trixie_materials.PACKAGE_VERSIONS[package]
        else:
            source, version = "openssl", openssl_version
        source_version = util_linux_trixie_materials.VERSION if source == "util-linux" else version
        source_field = "" if package == source else f"Source: {source} ({source_version})\n"
        rows.append(
            f"Package: {package}\nStatus: install ok installed\n"
            f"Architecture: amd64\n{source_field}Version: {version}\n"
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


def write_tar(files, *, aliases=None, attributes=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        for path, data in files.items():
            info = tarfile.TarInfo(path.lstrip("/"))
            info.size = len(data)
            for field, value in (attributes or {}).get(path, {}).items():
                setattr(info, field, value)
            tar.addfile(info, io.BytesIO(data))
        for path, target in (aliases or {}).items():
            info = tarfile.TarInfo(path.lstrip("/"))
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return stream.getvalue()


class KerberosPackageMaterialsTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name).resolve()
        self.packages = {}
        self.receipt = {"packages": {}}
        for name in (*krb5_trixie_materials.RUNTIME_PACKAGES, *krb5_trixie_materials.SDK_PACKAGES):
            payload = name.encode("ascii")
            path = self.directory / f"{name}_{krb5_trixie_materials.VERSION}_amd64.deb"
            path.write_bytes(payload)
            self.packages[name] = path
            self.receipt["packages"][name] = {"bytes": len(payload), "sha256": refresh.sha(payload)}
        pin = patch.object(krb5_trixie_materials, "load_reviewed", return_value=self.receipt)
        pin.start()
        self.addCleanup(pin.stop)

    def test_runtime_and_sdk_verify_only_their_qualified_archives(self):
        krb5_trixie_materials.verify_packages(self.directory, sdk=True)
        self.packages["libkrb5-dev"].unlink()
        krb5_trixie_materials.verify_packages(self.directory)
        with self.assertRaises(FileNotFoundError):
            krb5_trixie_materials.verify_packages(self.directory, sdk=True)

    def test_same_size_replacement_is_refused_before_installation(self):
        path = self.packages["libkrb5-3"]
        path.write_bytes(b"!" * path.stat().st_size)
        with self.assertRaisesRegex(ValueError, "kerberos_package_digest"):
            krb5_trixie_materials.verify_packages(self.directory)


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

    def inspect_fixture_root(self, *, sdk=False, aliases=None, kerberos_backport=False,
                             openssl_backport=False):
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
            return inventory.inspect_root(
                self.root, sdk=sdk, kerberos_backport=kerberos_backport,
                openssl_backport=openssl_backport,
            )

    def bundle(self, payload, *, declared_image=None, aliases=None, attributes=None):
        layer = write_tar(payload, aliases=self.aliases if aliases is None else aliases,
                          attributes=attributes)
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

    def test_committed_context_pins_match_the_debian_qualification_sources(self):
        root = Path(__file__).resolve().parents[1]
        actual = {name: refresh.sha((root / name).read_bytes())
                  for name in build_context.DEBIAN_REFRESH_INPUTS}
        self.assertEqual(actual, build_context.DEBIAN_REFRESH_INPUTS)

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

    def pin_backport_fixture(self, materials, receipt, files):
        receipt["installed_elf_sha256"] = {path: refresh.sha(data) for path, data in files.items()}
        raw = json.dumps(receipt, sort_keys=True).encode("ascii")
        for attribute, value in (("SHA256", refresh.sha(raw)), ("load_reviewed", lambda: receipt)):
            replacement = patch.object(materials, attribute, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        return raw

    def backport_fixture(self):
        materials = krb5_trixie_materials
        kerberos = materials.load_reviewed()
        files = {path: self.files[path] + b"local" for path in kerberos["installed_elf_sha256"]}
        raw = self.pin_backport_fixture(materials, kerberos, files)
        payload = {
            **self.payload,
            **files,
            str(materials.PATH): raw,
            inventory.DPKG_STATUS: installed_status(
                inventory.RUNTIME_PACKAGES, kerberos_version=materials.VERSION,
            ),
        }
        return materials, payload, kerberos

    def test_backport_live_and_archive_report_the_same_reviewed_facts(self):
        materials, payload, kerberos = self.backport_fixture()
        metadata = self.bundle(payload)
        archive = inventory.inspect_bundle(self.root, REVISION, kerberos_backport=True)
        self.assertEqual(archive["image_config_id"], metadata["image_id"])
        self.assertEqual(archive["archive_sha256"], metadata["archive_sha256"])
        self.assertEqual(archive["revision"], REVISION)
        self.assertEqual(inventory.validate_report(archive, archive=True), archive)
        with TemporaryDirectory() as output_folder:
            report_path = Path(output_folder) / "report.json"
            self.assertEqual(inventory.main([
                "--bundle", str(self.root), "--revision", REVISION,
                "--kerberos-backport", "--output", str(report_path),
            ]), 0)
            self.assertEqual(json.loads(report_path.read_bytes()), archive)

        self.filesystem(payload)
        live = self.inspect_fixture_root(kerberos_backport=True)
        self.assertEqual(live, {key: value for key, value in archive.items()
                                if key not in inventory.IMAGE_FIELDS})
        self.assertEqual(live["schema"], inventory.SCHEMA_V2)
        self.assertEqual(live["receipt_sha256"], refresh.sha(self.receipt))
        self.assertEqual(live["kerberos_receipt_sha256"], materials.SHA256)
        library = next(row for row in live["packages"] if row["package"] == "libkrb5-3")
        package = kerberos["packages"]["libkrb5-3"]
        self.assertEqual(library, {
            "package": "libkrb5-3", "source": "krb5", "version": materials.VERSION,
            "suite": inventory.KERBEROS_SUITE, "archive_sha256": package["sha256"],
            "archive_bytes": package["bytes"],
        })
        with self.assertRaisesRegex(inventory.InventoryError, "status_identity"):
            self.inspect_fixture_root()

    def test_backport_requires_reviewed_receipt_installed_elf_and_official_materials(self):
        materials, payload, kerberos = self.backport_fixture()
        path = next(iter(kerberos["installed_elf_sha256"]))
        official = json.loads(self.receipt)
        official["installed_elf_sha256"][path] = "e" * 64
        receipt_path = str(materials.PATH)
        for changes, expected in (
            ({receipt_path: payload[receipt_path] + b"\n"}, "kerberos_receipt_hash"),
            ({path: payload[path] + b"changed"}, "installed_elf_changed"),
            ({inventory.RECEIPT: json.dumps(official).encode()}, "unreviewed_debian_materials"),
            ({inventory.DPKG_STATUS: self.payload[inventory.DPKG_STATUS]}, "status_identity"),
        ):
            with self.subTest(expected=expected):
                self.bundle({**payload, **changes})
                with self.assertRaisesRegex(inventory.InventoryError, expected):
                    inventory.inspect_bundle(self.root, REVISION, kerberos_backport=True)
        self.bundle({name: data for name, data in payload.items() if name != receipt_path})
        with self.assertRaisesRegex(inventory.InventoryError, "archive_evidence"):
            inventory.inspect_bundle(self.root, REVISION, kerberos_backport=True)

    def test_backport_sdk_requires_all_and_only_the_selected_sdk_packages(self):
        materials, payload, _ = self.backport_fixture()
        self.filesystem(payload)
        with self.assertRaisesRegex(inventory.InventoryError, "status_missing"):
            self.inspect_fixture_root(sdk=True, kerberos_backport=True)
        payload[inventory.DPKG_STATUS] = installed_status(
            refresh.PACKAGES, kerberos_version=materials.VERSION,
        )
        self.filesystem(payload)
        with self.assertRaisesRegex(inventory.InventoryError, "status_package_overlap"):
            self.inspect_fixture_root(kerberos_backport=True)
        report = self.inspect_fixture_root(sdk=True, kerberos_backport=True)
        self.assertEqual(inventory.validate_report(report, sdk=True), report)
        versions = {row["package"]: row["version"] for row in report["packages"]}
        self.assertEqual(set(versions), set(refresh.PACKAGES))
        self.assertEqual(versions["krb5-multidev"], materials.VERSION)

    def openssl_fixture(self):
        kerberos, payload, _ = self.backport_fixture()
        openssl = openssl_trixie_materials
        reviewed = openssl.load_reviewed()
        files = native_files(reviewed["installed_elf_sha256"])
        raw = self.pin_backport_fixture(openssl, reviewed, files)
        names = {*inventory.RUNTIME_PACKAGES, *openssl.RUNTIME_PACKAGES}
        return {
            **payload,
            **files,
            openssl.PATH: raw,
            inventory.DPKG_STATUS: installed_status(
                names, kerberos_version=kerberos.VERSION, openssl_version=openssl.VERSION,
            ),
        }, reviewed

    def test_openssl_mode_requires_explicit_kerberos_mode(self):
        with self.assertRaisesRegex(inventory.InventoryError, "openssl_requires_kerberos"):
            inventory.inspect_root(self.root, openssl_backport=True)
        with self.assertRaisesRegex(inventory.InventoryError, "openssl_requires_kerberos"):
            inventory.inspect_bundle(self.root, REVISION, openssl_backport=True)
        with patch.object(sys, "stderr", new=io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as rejected:
                inventory.main([
                    "--root", str(self.root), "--openssl-backport", "--output", "unused.json",
                ])
        self.assertEqual(rejected.exception.code, 2)
        self.assertIn("--openssl-backport requires --kerberos-backport", stderr.getvalue())

    def util_linux_fixture(self):
        payload, _ = self.openssl_fixture()
        material = util_linux_trixie_materials
        reviewed = material.load_reviewed()
        files = native_files(reviewed["installed_elf_sha256"])
        raw = self.pin_backport_fixture(material, reviewed, files)
        names = {*inventory.RUNTIME_PACKAGES, *openssl_trixie_materials.RUNTIME_PACKAGES,
                 *material.RUNTIME_PACKAGES}
        self.aliases.update({alias: PurePosixPath(path).name
                             for alias, path in material.ALIASES.items()})
        payload.update({
            **native_files(material.SPECIAL_MODE_PATHS),
            **files,
            material.PATH: raw,
            inventory.DPKG_STATUS: installed_status(
                names, kerberos_version=krb5_trixie_materials.VERSION,
                openssl_version=openssl_trixie_materials.VERSION, util_linux=True,
            ),
        })
        attributes = {path: {"mode": 0o4755} for path in material.SPECIAL_MODE_PATHS}
        return payload, attributes

    def test_util_linux_report_binds_epoch_versions_elfs_and_sbom(self):
        payload, attributes = self.util_linux_fixture()
        material = util_linux_trixie_materials
        self.bundle(payload, attributes=attributes)
        mode = {"kerberos_backport": True, "openssl_backport": True}
        stock = inventory.inspect_bundle(self.root, REVISION, **mode)
        report = inventory.inspect_bundle(self.root, REVISION, util_linux_backport=True, **mode)
        self.assertEqual(report["schema"], inventory.SCHEMA_V4)
        self.assertEqual(report["util_linux_receipt_sha256"], material.SHA256)
        self.assertEqual(report["image_config_id"], stock["image_config_id"])
        self.assertEqual(report["archive_sha256"], stock["archive_sha256"])
        self.assertEqual({row["package"]: row["version"] for row in report["packages"]
                          if row["source"] == "util-linux"}, material.PACKAGE_VERSIONS)
        components, dependencies, _ = native_sbom.debian_components(
            report, report["image_config_id"], "image_config",
        )
        login = next(row for row in components if row["name"] == "login")
        self.assertIn("login@1%3A4.16.0-2%2Breally", login["purl"])
        self.assertIn("upstream=util-linux", login["purl"])
        scan.verify_trixie_sbom(
            {"components": components, "dependencies": dependencies}, stock,
            report["image_config_id"], {
                "pamolive:sbom:debian-archive-sha256": report["archive_sha256"],
                "pamolive:sbom:openssl-receipt-sha256": report["openssl_receipt_sha256"],
            },
        )
        with self.assertRaisesRegex(inventory.InventoryError, "util_linux_runtime_only"):
            inventory.validate_report(report, sdk=True)

    def test_util_linux_archive_refuses_wrong_privilege_or_library_alias(self):
        payload, attributes = self.util_linux_fixture()
        mode = {"kerberos_backport": True, "openssl_backport": True, "util_linux_backport": True}
        material = util_linux_trixie_materials
        target = "/usr/bin/newgrp"
        for change in ({"mode": 0o755}, {"uid": 1},
                       {"pax_headers": {"SCHILY.xattr.security.capability": "synthetic"}}):
            with self.subTest(change=change):
                tampered = {**attributes, target: {**attributes[target], **change}}
                self.bundle(payload, attributes=tampered)
                with self.assertRaisesRegex(inventory.InventoryError, "archive_util_linux_special"):
                    inventory.inspect_bundle(self.root, REVISION, **mode)
        alias = next(iter(material.ALIASES))
        self.bundle(payload, attributes=attributes,
                    aliases={**self.aliases, alias: "unreviewed.so"})
        with self.assertRaisesRegex(inventory.InventoryError, "util_linux_alias"):
            inventory.inspect_bundle(self.root, REVISION, **mode)

    def test_util_linux_checks_both_source_and_binary_versions(self):
        payload, attributes = self.util_linux_fixture()
        mode = {"kerberos_backport": True, "openssl_backport": True, "util_linux_backport": True}
        status = payload[inventory.DPKG_STATUS]
        version = util_linux_trixie_materials.PACKAGE_VERSIONS["bsdutils"].encode("ascii")
        for before, after in ((b"Version: " + version, b"Version: " + version[2:]),
                              (b"Source: util-linux (", b"Source: unexpected (")):
            self.bundle({**payload, inventory.DPKG_STATUS: status.replace(before, after, 1)},
                        attributes=attributes)
            with self.assertRaisesRegex(inventory.InventoryError, "status_identity"):
                inventory.inspect_bundle(self.root, REVISION, **mode)

    def test_util_linux_archive_refuses_an_extra_libmount_copy(self):
        payload, attributes = self.util_linux_fixture()
        mode = {"kerberos_backport": True, "openssl_backport": True, "util_linux_backport": True}
        material = util_linux_trixie_materials
        library, = material.ELF_BY_PACKAGE["libmount1"]
        self.bundle({**payload, "/usr/local/lib/libmount.so.1": payload[library]},
                    attributes=attributes)
        with self.assertRaisesRegex(inventory.InventoryError, "archive_util_linux_libmount_copies"):
            inventory.inspect_bundle(self.root, REVISION, **mode)

    def glibc_fixture(self):
        payload, attributes = self.util_linux_fixture()
        material = glibc_trixie_materials
        reviewed = material.load_reviewed()
        files = native_files(reviewed["installed_elf_sha256"])
        files[material.LIBC] += b"candidate"
        raw = self.pin_backport_fixture(material, reviewed, files)
        names = {*inventory.RUNTIME_PACKAGES, *openssl_trixie_materials.RUNTIME_PACKAGES,
                 *util_linux_trixie_materials.RUNTIME_PACKAGES}
        self.aliases.update(material.ALIASES)
        self.aliases["/lib64"] = "usr/lib64"
        return {**payload, **files,
                material.PATH: raw, inventory.DPKG_STATUS: installed_status(
                    names, kerberos_version=krb5_trixie_materials.VERSION,
                    openssl_version=openssl_trixie_materials.VERSION, util_linux=True,
                    glibc_version=material.VERSION,
                )}, attributes

    def test_glibc_archive_and_sbom_bind_the_new_library_and_package_versions(self):
        payload, attributes = self.glibc_fixture()
        self.bundle(payload, attributes=attributes)
        report = inventory.inspect_bundle(
            self.root, REVISION, kerberos_backport=True, openssl_backport=True,
            util_linux_backport=True, glibc_backport=True,
        )
        material = glibc_trixie_materials
        self.assertEqual(report["schema"], inventory.SCHEMA_V5)
        self.assertEqual(report["glibc_receipt_sha256"], material.SHA256)
        self.assertEqual(report["installed_elf_sha256"][material.LIBC],
                         refresh.sha(payload[material.LIBC]))
        components, deps, _ = native_sbom.debian_components(
            report, report["image_config_id"], "image_config",
        )
        libc = next(row for row in components if row["name"] == "libc6")
        self.assertEqual(libc["version"], material.VERSION)
        self.assertIn("14841015571", libc["externalReferences"][0]["url"])
        properties = {
            "pamolive:sbom:debian-archive-sha256": report["archive_sha256"],
            "pamolive:sbom:openssl-receipt-sha256": report["openssl_receipt_sha256"],
            "pamolive:sbom:util-linux-receipt-sha256": report["util_linux_receipt_sha256"],
            "pamolive:sbom:glibc-receipt-sha256": report["glibc_receipt_sha256"],
        }
        sbom = {"components": components, "dependencies": deps}
        scan.verify_trixie_sbom(sbom, report, report["image_config_id"], properties)
        del properties["pamolive:sbom:glibc-receipt-sha256"]
        with self.assertRaisesRegex(scan.ScanPolicyError, "trixie_glibc_sbom_binding"):
            scan.verify_trixie_sbom(sbom, report, report["image_config_id"], properties)

    def test_glibc_archive_refuses_an_unexpected_library_or_loader_link(self):
        payload, attributes = self.glibc_fixture()
        material = glibc_trixie_materials
        modes = dict(kerberos_backport=True, openssl_backport=True,
                     util_linux_backport=True, glibc_backport=True)
        self.bundle({**payload, "/usr/local/lib/libc.so.6": payload[material.LIBC]},
                    attributes=attributes)
        with self.assertRaisesRegex(inventory.InventoryError, "archive_glibc_provider_paths"):
            inventory.inspect_bundle(self.root, REVISION, **modes)
        alias = next(iter(material.ALIASES))
        self.bundle(payload, attributes=attributes,
                    aliases={**self.aliases, alias: "ld-linux-x86-64.so.2"})
        with self.assertRaisesRegex(inventory.InventoryError, "glibc_loader_alias"):
            inventory.inspect_bundle(self.root, REVISION, **modes)
        self.bundle(payload, attributes=attributes, aliases={**self.aliases, "/lib64": "usr/bin"})
        with self.assertRaisesRegex(inventory.InventoryError, "glibc_interpreter_alias"):
            inventory.inspect_bundle(self.root, REVISION, **modes)

    def test_cli_reports_permission_failure_without_disclosing_path(self):
        with (
            patch.object(inventory, "inspect_root", side_effect=PermissionError("/private/input")),
            patch.object(sys, "stderr", new=io.StringIO()) as stderr,
        ):
            result = inventory.main([
                "--root", str(self.root), "--output", str(self.root / "report.json"),
            ])
        self.assertEqual(result, 1)
        self.assertIn("[filesystem_permission]", stderr.getvalue())
        self.assertNotIn("/private/input", stderr.getvalue())

    def test_openssl_v3_binds_live_and_archive_without_changing_kerberos_facts(self):
        payload, reviewed = self.openssl_fixture()
        mode = {"kerberos_backport": True, "openssl_backport": True}
        metadata = self.bundle(payload)
        archive = inventory.inspect_bundle(self.root, REVISION, **mode)
        kerberos = inventory.inspect_bundle(self.root, REVISION, kerberos_backport=True)
        self.assertEqual(archive["schema"], inventory.SCHEMA_V3)
        self.assertEqual(archive["openssl_receipt_sha256"], openssl_trixie_materials.SHA256)
        self.assertEqual(archive["image_config_id"], metadata["image_id"])
        self.assertEqual(archive["archive_sha256"], metadata["archive_sha256"])
        self.assertEqual(archive["revision"], REVISION)
        expected_packages = list(kerberos["packages"])
        for name in openssl_trixie_materials.RUNTIME_PACKAGES:
            package = reviewed["packages"][name]
            expected_packages.append({
                "package": name, "source": "openssl", "version": openssl_trixie_materials.VERSION,
                "suite": inventory.BACKPORT_SUITE, "archive_sha256": package["sha256"],
                "archive_bytes": package["bytes"],
            })
        self.assertEqual(
            archive["packages"], sorted(expected_packages, key=lambda row: row["package"]),
        )
        self.assertEqual(archive["installed_elf_sha256"], {
            **kerberos["installed_elf_sha256"], **reviewed["installed_elf_sha256"],
        })
        with TemporaryDirectory() as output_folder:
            report_path = Path(output_folder) / "report.json"
            self.assertEqual(inventory.main([
                "--bundle", str(self.root), "--revision", REVISION, "--kerberos-backport",
                "--openssl-backport", "--output", str(report_path),
            ]), 0)
            self.assertEqual(json.loads(report_path.read_bytes()), archive)
        self.filesystem(payload)
        self.assertEqual(self.inspect_fixture_root(**mode), {
            key: value for key, value in archive.items() if key not in inventory.IMAGE_FIELDS
        })

    def test_openssl_requires_pinned_receipt_all_elfs_and_exact_dpkg_source_and_version(self):
        payload, reviewed = self.openssl_fixture()
        openssl = openssl_trixie_materials
        mode = {"kerberos_backport": True, "openssl_backport": True}
        path = next(iter(reviewed["installed_elf_sha256"]))
        status = payload[inventory.DPKG_STATUS]
        source_row = f"Source: openssl ({openssl.VERSION})\n".encode("ascii")
        wrong_version = status.replace(openssl.VERSION.encode(), b"3.5.9-1~deb13u1")
        wrong_source = status.replace(b"Package: openssl\n", b"Package: openssl\nSource: other\n")
        for changes, expected in (
            ({openssl.PATH: payload[openssl.PATH] + b"\n"}, "openssl_receipt_hash"),
            ({path: payload[path] + b"changed"}, "installed_elf_changed"),
            ({inventory.DPKG_STATUS: status.replace(source_row, b"", 1)}, "status_identity"),
            ({inventory.DPKG_STATUS: wrong_source}, "status_identity"),
            ({inventory.DPKG_STATUS: wrong_version}, "status_identity"),
        ):
            with self.subTest(expected=expected):
                self.bundle({**payload, **changes})
                with self.assertRaisesRegex(inventory.InventoryError, expected):
                    inventory.inspect_bundle(self.root, REVISION, **mode)
        for missing, expected in (
            (openssl.PATH, "archive_evidence"), (path, "archive_elf_identity"),
        ):
            self.bundle({name: data for name, data in payload.items() if name != missing})
            with self.assertRaisesRegex(inventory.InventoryError, expected):
                inventory.inspect_bundle(self.root, REVISION, **mode)

    def test_openssl_sdk_package_is_required_in_sdk_and_rejected_in_runtime(self):
        payload, _ = self.openssl_fixture()
        openssl = openssl_trixie_materials
        mode = {"kerberos_backport": True, "openssl_backport": True}
        names = {*refresh.PACKAGES, *openssl.RUNTIME_PACKAGES, *openssl.SDK_PACKAGES}
        status = installed_status(
            names - set(openssl.SDK_PACKAGES), kerberos_version=krb5_trixie_materials.VERSION,
            openssl_version=openssl.VERSION,
        )
        self.filesystem({**payload, inventory.DPKG_STATUS: status})
        with self.assertRaisesRegex(inventory.InventoryError, "status_missing"):
            self.inspect_fixture_root(sdk=True, **mode)
        runtime_with_ssl_dev = {
            *inventory.RUNTIME_PACKAGES, *openssl.RUNTIME_PACKAGES, *openssl.SDK_PACKAGES,
        }
        status = installed_status(
            runtime_with_ssl_dev, kerberos_version=krb5_trixie_materials.VERSION,
            openssl_version=openssl.VERSION,
        )
        self.filesystem({**payload, inventory.DPKG_STATUS: status})
        with self.assertRaisesRegex(inventory.InventoryError, "status_package_overlap"):
            self.inspect_fixture_root(**mode)
        status = installed_status(
            names, kerberos_version=krb5_trixie_materials.VERSION, openssl_version=openssl.VERSION,
        )
        self.filesystem({**payload, inventory.DPKG_STATUS: status})
        report = self.inspect_fixture_root(sdk=True, **mode)
        self.assertEqual(inventory.validate_report(report, sdk=True), report)
        self.assertEqual({row["package"] for row in report["packages"]}, names)
