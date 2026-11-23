import hashlib
import io
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from deploy import cairo_runtime_inventory as cairo

ELF_HEADER = b"\x7fELF\x02\x01" + b"\0" * 12 + b">\0"
LIBRARY = ELF_HEADER + b" synthetic Cairo"
CONSUMER = ELF_HEADER + b" libcairo.so.2\0"
LIBRARY_SHA = hashlib.sha256(LIBRARY).hexdigest()
CONFIG_ID = "sha256:" + "a" * 64
STATUS = (
    "Package: libcairo2\nStatus: install ok installed\nArchitecture: amd64\n"
    f"Source: cairo\nVersion: {cairo.VERSION}\n\n"
).encode()


def snapshot(*, status=STATUS, alias=cairo.LIBRARY.name, extra=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in (
            (cairo.LIBRARY, LIBRARY),
            (cairo.STATUS, status),
            ("/opt/pamolive-guac/lib/synthetic.so", CONSUMER),
            *extra,
        ):
            member = tarfile.TarInfo(str(name).lstrip("/"))
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        link = tarfile.TarInfo(str(cairo.ALIAS).lstrip("/"))
        link.type, link.linkname = tarfile.SYMTYPE, alias
        archive.addfile(link)
    buffer.seek(0)
    return buffer


class CairoRuntimeInventoryTests(TestCase):
    def inspect(self, archive, *, dependency="", symbol=""):
        def readelf(data, _target, _timeout):
            if data == LIBRARY:
                return "0 (SONAME) Library soname: [libcairo.so.2]\n"
            return f"0 (NEEDED) Shared library: [libcairo.so.2]\n{dependency}{symbol}"

        with patch.object(cairo, "readelf", side_effect=readelf):
            return cairo.inventory(archive, Path.cwd() / "unused.elf", LIBRARY_SHA)

    def test_verified_export_is_bound_to_the_image_config(self):
        source = snapshot().getvalue()
        with TemporaryDirectory(prefix="cairo-inventory-test-") as folder:
            archive = Path(folder) / "root.tar"
            archive.write_bytes(source)
            with patch.object(
                cairo,
                "readelf",
                side_effect=(
                    "0 (SONAME) Library soname: [libcairo.so.2]\n",
                    "0 (NEEDED) Shared library: [libcairo.so.2]\n",
                ),
            ):
                report = cairo.verify(archive, CONFIG_ID, LIBRARY_SHA)
        self.assertEqual(report["image_config_id"], CONFIG_ID)
        self.assertEqual(report["export_sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(report["elf_sha256"], LIBRARY_SHA)
        self.assertEqual(set(report["consumers"]), {"/opt/pamolive-guac/lib/synthetic.so"})
        self.assertIs(report["x_runtime_absent"], True)

    def test_x_dependency_is_refused_even_without_an_x_library_file(self):
        with self.assertRaisesRegex(ValueError, "cairo_x_elf_dependency"):
            self.inspect(snapshot(), dependency="0 (NEEDED) Shared library: [libXrender.so.1]\n")

    def test_disabled_import_is_refused_even_without_an_x_dependency(self):
        with self.assertRaisesRegex(ValueError, "cairo_x_elf_import"):
            self.inspect(
                snapshot(), symbol="4: 0000 0 FUNC GLOBAL DEFAULT UND cairo_xcb_surface_create\n",
            )

    def test_an_elf_with_an_x_soname_is_refused_under_another_filename(self):
        with self.assertRaisesRegex(ValueError, "cairo_x_elf_provider"):
            self.inspect(snapshot(), dependency="0 (SONAME) Library soname: [libXau.so.6]\n")

    def test_x_files_and_sdk_are_refused(self):
        with self.assertRaisesRegex(ValueError, "cairo_x_runtime_file"):
            self.inspect(snapshot(extra=(("/opt/extensions/libX11.so.6", b"fixture"),)))
        with self.assertRaisesRegex(ValueError, "cairo_sdk_file"):
            self.inspect(snapshot(extra=(("/usr/include/cairo/cairo.h", b"fixture"),)))

    def test_installed_x_data_package_is_refused(self):
        package = b"Package: libx11-data\nStatus: install ok installed\nVersion: 2:1.8.12-1\n"
        with self.assertRaisesRegex(ValueError, "cairo_excluded_package"):
            self.inspect(snapshot(status=STATUS + package))

    def test_wrong_soname_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, "cairo_soname_link"):
            self.inspect(snapshot(alias="libcairo.so.2.11802.4"))

    def test_runtime_requires_at_least_one_cairo_consumer(self):
        with patch.object(
            cairo,
            "readelf",
            side_effect=(
                "0 (SONAME) Library soname: [libcairo.so.2]\n",
                "0 (NEEDED) Shared library: [libc.so.6]\n",
            ),
        ), self.assertRaisesRegex(ValueError, "cairo_consumers_missing"):
            cairo.inventory(snapshot(), Path.cwd() / "unused.elf", LIBRARY_SHA)
