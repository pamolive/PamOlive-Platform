import hashlib
import io
import tarfile
from pathlib import Path, PurePosixPath
from unittest import TestCase
from unittest.mock import patch

from deploy import acl_runtime_inventory as acl

LIBRARY = b"\x7fELF synthetic library"
CONSUMER = b"\x7fELF synthetic consumer libacl.so.1\0acl_get_file"
STATUS = (
    "Package: libacl1\nStatus: install ok installed\nArchitecture: amd64\n"
    f"Source: acl\nVersion: {acl.VERSION}\n\n"
).encode()


def snapshot(*, alias="libacl.so.1.2.2400", library=LIBRARY, extra=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        files = [
            (acl.LIBRARY, library),
            (acl.STATUS, STATUS),
            ("/usr/bin/cp", CONSUMER),
            *extra,
        ]
        for name, data in files:
            entry = tarfile.TarInfo(name.lstrip("/"))
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        link = tarfile.TarInfo(str(PurePosixPath(acl.LIBRARY).with_name(acl.SONAME)).lstrip("/"))
        link.type = tarfile.SYMTYPE
        link.linkname = alias
        archive.addfile(link)
    buffer.seek(0)
    return buffer


class AclRuntimeInventoryTests(TestCase):
    def inspect(self, archive, symbol="acl_get_file@ACL_1.0"):
        def readelf(data, _):
            if data == LIBRARY:
                return (
                    "Library soname: [libacl.so.1]\n"
                    "1: 0000 0 FUNC GLOBAL DEFAULT 12 acl_get_file@@ACL_1.0\n"
                )
            return (
                "Shared library: [libacl.so.1]\n"
                f"1: 0000 0 FUNC GLOBAL DEFAULT UND {symbol}\n"
            )

        with (
            patch.object(acl, "readelf", side_effect=readelf),
            patch.object(acl, "ELF_SHA256", hashlib.sha256(LIBRARY).hexdigest()),
        ):
            return acl.inventory(archive, Path.cwd() / "unused.elf")

    def test_legacy_consumer_remains_visible_with_fixed_package(self):
        report = self.inspect(snapshot())
        cp = report["consumers"]["/usr/bin/cp"]
        self.assertEqual(cp["legacy_path_imports"], ["acl_get_file@ACL_1.0"])
        self.assertTrue(cp["direct_dependency"])
        self.assertIs(report["legacy_api_migrated"], False)

    def test_missing_symbol_version_rejects_the_candidate(self):
        with self.assertRaisesRegex(ValueError, "acl_missing_abi"):
            self.inspect(snapshot(), symbol="acl_get_file@ACL_1.2")

    def test_wrong_library_alias_or_utility_is_refused(self):
        with self.assertRaisesRegex(ValueError, "acl_soname_link"):
            self.inspect(snapshot(alias="libacl.so.1.1.2302"))
        with self.assertRaisesRegex(ValueError, "acl_runtime_tool"):
            self.inspect(snapshot(extra=(("/usr/bin/setfacl", b"data"),)))

    def test_sdk_is_refused(self):
        with self.assertRaisesRegex(ValueError, "acl_runtime_sdk"):
            self.inspect(snapshot(extra=(("/usr/include/sys/acl.h", b"data"),)))
