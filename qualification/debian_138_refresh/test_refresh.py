"""Qualification input and receipt tests. All tool and archive inputs are synthetic."""

import copy
import io
import sys
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verify_refresh as refresh  # noqa: E402


def raw_record(name="libkrb5-3", **changes):
    source, version, _, pool = refresh.PACKAGES[name]
    row = {
        "Package": name, "Source": source, "Version": version, "Architecture": "amd64",
        "Filename": pool + refresh.archive_name(name), "Size": "1234", "SHA256": "1" * 64,
    }
    row.update(changes)
    return ("".join(f"{key}: {value}\n" for key, value in row.items()) + "\n").encode()


def receipt():
    return {
        "schema": "pamolive.debian-138-refresh/1",
        "architecture": "amd64",
        "selection": {
            "releases": {suite: "8" * 64 for suite in refresh.RELEASES},
            "packages": [refresh.apt_record(name, raw_record(name))
                         for name in sorted(refresh.PACKAGES)],
        },
        "installed_elf_sha256": {
            path: "6" * 64 for names in refresh.NATIVE_FILES.values() for path in names
        },
        "checks": dict.fromkeys(refresh.CHECKS, True),
    }


def tar_data(path, data, *, mode=0o755, duplicate=False, member_type=tarfile.REGTYPE):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for _ in range(2 if duplicate else 1):
            info = tarfile.TarInfo("." + path)
            info.type = member_type
            info.mode = mode
            if info.isreg():
                info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class RefreshTests(unittest.TestCase):
    def test_requires_exact_stable_family_and_ignores_installed_only_stanza(self):
        raw = raw_record() + b"Package: libkrb5-3\nStatus: install ok installed\n\n"
        item = refresh.apt_record("libkrb5-3", raw)
        self.assertEqual(item["source"], "krb5")
        self.assertEqual(item["version"], "1.21.3-5+deb13u2")
        self.assertEqual(item["suite"], "trixie-security")
        self.assertEqual(item["archive_bytes"], 1234)

    def test_rejects_missing_duplicate_and_foreign_records(self):
        raw = raw_record()
        with self.assertRaisesRegex(refresh.Refused, "apt_record_ambiguous"):
            refresh.apt_record("libkrb5-3", raw + raw)
        with self.assertRaisesRegex(refresh.Refused, "apt_record_ambiguous"):
            refresh.apt_record("libkrb5-3", b"Package: libkrb5-3\n")
        for change in (
            dict(Architecture="arm64"), dict(Source="foreign"),
            dict(Version="1.21.3-5+deb13u1"), dict(Filename="pool/main/k/krb5/a.deb"),
        ):
            with self.subTest(change=change):
                with self.assertRaisesRegex(refresh.Refused, "apt_record_identity"):
                    refresh.apt_record("libkrb5-3", raw_record(**change))

    def test_rejects_unbounded_archive_and_invalid_index_digest(self):
        with self.assertRaisesRegex(refresh.Refused, "apt_archive_cap"):
            refresh.apt_record("libkrb5-3", raw_record(Size="80000000"))
        with self.assertRaisesRegex(refresh.Refused, "apt_record_digest"):
            refresh.apt_record("libkrb5-3", raw_record(SHA256="incorrect"))
        with self.assertRaisesRegex(refresh.Refused, "apt_record_framing"):
            refresh.apt_record("libkrb5-3", b"Package: value\nPackage: duplicate\n")

    def test_selected_archive_payload_must_be_unique_regular_root_owned_and_amd64(self):
        path = refresh.NATIVE_FILES["libkrb5-3"][0]
        elf = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00" + b"fixture"
        archive_path = Path("/sample.deb")
        with patch.object(refresh, "command", return_value=tar_data(path, elf)):
            self.assertEqual(refresh.archive_bytes_by_file(archive_path, (path,)),
                             {path: refresh.sha(elf)})
        for raw in (
            tar_data(path, elf, duplicate=True), tar_data(path, elf, mode=0o777),
            tar_data(path, elf, member_type=tarfile.SYMTYPE),
            tar_data(path, elf.replace(b"\x3e\x00", b"\xb7\x00")), tar_data("/other", elf),
        ):
            with patch.object(refresh, "command", return_value=raw):
                with self.assertRaises(refresh.Refused):
                    refresh.archive_bytes_by_file(archive_path, (path,))

    def test_receipt_is_closed_over_facts_and_package_set(self):
        good = receipt()
        self.assertIs(refresh.validate_receipt(good), good)
        edits = (
            lambda row: row.update(private_payload="unexpected"),
            lambda row: row["checks"].update(native_smoke=1),
            lambda row: row["selection"]["packages"][0].update(archive_bytes=True),
            lambda row: row["selection"]["packages"][0].update(version="other"),
            lambda row: row["selection"]["packages"].pop(),
            lambda row: row["installed_elf_sha256"].pop(next(iter(row["installed_elf_sha256"]))),
        )
        for edit in edits:
            row = copy.deepcopy(good)
            edit(row)
            with self.assertRaises(refresh.Refused):
                refresh.validate_receipt(row)

    def test_same_exact_transaction_is_used_for_acquisition_and_offline_install(self):
        download = refresh.apt_install("--download-only")
        install = refresh.apt_install("--no-download")
        self.assertEqual(download[:5], install[:5])
        self.assertEqual(download[6:], install[6:])
        self.assertEqual(install[6:],
                         ["install", *refresh.package_refs(), "gcc"])
        self.assertIn("RUN --network=none", (HERE / "Dockerfile").read_text())
        self.assertEqual(len((HERE / "debian.list").read_text().splitlines()), 2)
        self.assertIn('APT::Update::Error-Mode "any";', (HERE / "apt.conf").read_text())

    def test_unreviewed_bytes_are_refused_before_apt_install(self):
        value = receipt()
        with (
            patch.object(refresh, "load_json", return_value=value["selection"]),
            patch.object(refresh, "verify_archive", return_value=Path("/sample.deb")),
            patch.object(
                refresh, "archive_bytes_by_file",
                side_effect=lambda _, names: {name: "6" * 64 for name in names},
            ),
            patch.object(refresh, "command") as command,
            self.assertRaisesRegex(refresh.Refused, "unreviewed_debian_materials"),
        ):
            refresh.qualify()
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
