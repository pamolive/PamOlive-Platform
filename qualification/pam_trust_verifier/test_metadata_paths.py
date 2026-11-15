"""Real stdlib metadata discovery with synthetic bounded IO and path fixtures only."""

import contextlib
import importlib.metadata
import stat
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

import test_adapter_pure as original

CHILD = original.CHILD
ZIP = "/usr/local/lib/python312.zip"
VENV = "/work/venv"
SITE = VENV + "/lib/python3.12/site-packages"
STDLIB = "/usr/local/lib/python3.12"
OBSERVATIONS = []


def normalized(value):
    return str(value).replace("\\", "/")


class VirtualPath(PurePosixPath):
    def __new__(cls, *parts):
        return super().__new__(cls, *(normalized(value) for value in parts))

    def resolve(self, *args, **kwargs):
        return self


class Files:
    """Finite data-only filesystem; unexpected metadata reads never reach the host."""

    def __init__(self, guard=None):
        self.directories = {
            "/",
            "/usr",
            "/usr/local",
            "/usr/local/lib",
            STDLIB,
            STDLIB + "/lib-dynload",
            "/work",
            VENV,
            VENV + "/lib",
            VENV + "/lib/python3.12",
            SITE,
        }
        self.types = {}
        self.children = {}
        self.contents = {}
        self.guard = guard
        self.forbidden = set()
        self.reads = []

    def lstat(self, path):
        name = normalized(path)
        if name in self.types:
            return SimpleNamespace(st_mode=self.types[name], st_file_attributes=0, st_mtime=1)
        if name in self.directories:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0, st_mtime=1)
        raise FileNotFoundError(name)

    def listdir(self, path):
        name = normalized(path)
        self.reads.append(("listdir", name))
        if name in self.forbidden:
            self.guard.refuse("file.read_outside_roots")
        if name not in self.directories:
            raise FileNotFoundError(name)
        return self.children.get(name, [])

    def open_zip(self, path, *args, **kwargs):
        name = normalized(path)
        self.reads.append(("open", name))
        if name in self.forbidden:
            self.guard.refuse("file.read_outside_roots")
        raise AssertionError("unexpected archive open")

    def read_text(self, path, *args, **kwargs):
        name = normalized(path)
        self.reads.append(("read_text", name))
        if name not in self.contents:
            raise FileNotFoundError(name)
        return self.contents[name]

    def distribution(self, directory, name, version="1.0"):
        entry = name.replace("-", "_") + "-" + version + ".dist-info"
        self.children.setdefault(directory, []).append(entry)
        self.contents[directory + "/" + entry + "/METADATA"] = (
            "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"
        )

    @contextlib.contextmanager
    def paths(self, entries):
        with (
            patch.object(CHILD, "Path", VirtualPath),
            patch.object(CHILD.sys, "path", entries),
            patch.object(CHILD.sys, "platform", "linux"),
            patch.object(CHILD.sys, "version_info", (3, 12, 16)),
            patch.object(CHILD.sys, "base_prefix", "/usr/local"),
            patch.object(CHILD.sys, "base_exec_prefix", "/usr/local"),
            patch.object(CHILD.os, "lstat", self.lstat),
        ):
            yield

    @contextlib.contextmanager
    def metadata(self):
        # These are the maintained metadata/zipfile implementations, not replacements.
        metadata = importlib.metadata
        metadata.MetadataPathFinder.invalidate_caches()
        with (
            patch.object(sys, "meta_path", [metadata.MetadataPathFinder]),
            patch.object(metadata.os, "stat", self.lstat),
            patch.object(metadata.os, "listdir", self.listdir),
            patch.object(metadata.zipfile.io, "open", self.open_zip),
            patch.object(
                Path,
                "read_text",
                lambda path, *args, **kwargs: self.read_text(path, *args, **kwargs),
            ),
        ):
            yield
        metadata.MetadataPathFinder.invalidate_caches()


class MetadataPathTests(unittest.TestCase):
    def probe(self, fs, entries, expected, *, system_site=False):
        with (
            fs.paths(entries),
            fs.metadata(),
            patch.object(CHILD.sys, "prefix", VENV),
            patch.object(CHILD.site, "ENABLE_USER_SITE", False),
            patch.object(
                CHILD,
                "bounded_read",
                return_value=(
                    b"include-system-site-packages = true"
                    if system_site
                    else b"include-system-site-packages = false"
                ),
            ),
            patch.object(
                CHILD.importlib.util,
                "find_spec",
                side_effect=lambda name: SimpleNamespace(origin=SITE + "/pip/__init__.py")
                if name == "pip"
                else None,
            ),
        ):
            return CHILD.distribution_probe(expected, "")

    def test_real_default_metadata_masks_two_absent_zip_refusals(self):
        guard, fs = CHILD.Guards(), Files()
        fs.guard, fs.forbidden = guard, {ZIP}
        with fs.paths([ZIP]), fs.metadata():
            self.assertEqual(list(importlib.metadata.distributions()), [])
        self.assertEqual(dict(guard.attempts), {"file.read_outside_roots": 2})
        with self.assertRaises(CHILD.ForbiddenIO):
            guard.require_clean()
        self.assertEqual(fs.reads, [("listdir", ZIP), ("open", ZIP)])
        OBSERVATIONS.append({"case": "stdlib_default_absent_zip", "masked_attempts": 2})

    def test_explicit_all_directories_omit_only_absent_zip_and_avoid_both_reads(self):
        guard, fs = CHILD.Guards(), Files()
        fs.guard, fs.forbidden = guard, {ZIP}
        fs.distribution(SITE, "pip", "26.3")
        with fs.paths([ZIP, STDLIB, SITE]), fs.metadata():
            directories = CHILD.metadata_directories()
            items = list(importlib.metadata.distributions(path=directories))
            self.assertEqual(
                [(item.metadata["Name"], item.version) for item in items], [("pip", "26.3")]
            )
        self.assertEqual(directories, (STDLIB, SITE))
        self.assertEqual(dict(guard.attempts), {})
        self.assertFalse(any(path == ZIP for _, path in fs.reads))
        OBSERVATIONS.append({"case": "explicit_directories", "masked_attempts": 0})

    def test_all_real_directories_order_and_duplicates_preserved(self):
        fs = Files()
        entries = [STDLIB, SITE, STDLIB + "/lib-dynload", SITE]
        with fs.paths(entries):
            self.assertEqual(CHILD.metadata_directories(), tuple(entries))
            self.assertEqual(CHILD.sys.path, entries)

    def test_missing_only_exact_default_zip_is_tolerated(self):
        fs = Files()
        for missing in (
            ZIP + ".other",
            "/usr/local/lib/python313.zip",
            STDLIB + "/missing",
            "/missing",
        ):
            with self.subTest(path=missing), fs.paths([missing]):
                with self.assertRaisesRegex(ValueError, "distribution_origin"):
                    CHILD.metadata_directories()
        with fs.paths([ZIP]):
            self.assertEqual(CHILD.metadata_directories(), ())

    def test_absent_zip_requires_exact_pinned_S0_runtime_profile(self):
        fs = Files()
        for field, value in (
            ("platform", "win32"),
            ("version_info", (3, 12, 14)),
            ("version_info", (3, 13, 0)),
            ("base_prefix", "/other"),
            ("base_exec_prefix", "/other"),
            ("implementation", SimpleNamespace(name="pypy")),
        ):
            with (
                self.subTest(field=field, value=str(value)),
                fs.paths([ZIP]),
                patch.object(CHILD.sys, field, value),
            ):
                with self.assertRaisesRegex(ValueError, "distribution_origin"):
                    CHILD.metadata_directories()

    def test_existing_zip_archives_files_and_aliases_refuse(self):
        for target, kind in (
            (ZIP, stat.S_IFREG),
            (ZIP, stat.S_IFDIR),
            (ZIP, stat.S_IFLNK),
            (SITE, stat.S_IFLNK),
            (STDLIB, stat.S_IFLNK),
            ("/usr/local", stat.S_IFLNK),
            (SITE + "/active.zip", stat.S_IFREG),
        ):
            fs = Files()
            fs.types[target] = kind | 0o755
            entry = (
                SITE + "/active.zip"
                if target.endswith("active.zip")
                else ZIP
                if target == ZIP
                else STDLIB
                if target in {STDLIB, "/usr/local"}
                else SITE
            )
            with self.subTest(target=target, kind=kind), fs.paths([entry]):
                with self.assertRaisesRegex(ValueError, "distribution_origin"):
                    CHILD.metadata_directories()
            self.assertEqual(fs.reads, [])

    def test_bad_types_relative_alias_forms_and_path_budgets_refuse(self):
        fs = Files()
        for entry in (
            True,
            False,
            0,
            None,
            b"/usr/local",
            "",
            "relative",
            "/x/../y",
            "/x/./y",
            "/x//y",
            "//x",
            "/x/",
            "/x\0y",
            "/" + "x" * 4096,
        ):
            with self.subTest(type=type(entry).__name__), fs.paths([entry]):
                with self.assertRaisesRegex(ValueError, "distribution_origin"):
                    CHILD.metadata_directories()
        for entries in ((SITE,), [SITE] * 33):
            with fs.paths(entries), self.assertRaisesRegex(ValueError, "distribution_origin"):
                CHILD.metadata_directories()

    def test_real_metadata_still_detects_extras_duplicates_and_wrong_origins(self):
        for case in ("extra", "duplicate", "wrong_origin"):
            fs = Files()
            location = STDLIB if case == "wrong_origin" else SITE
            fs.distribution(location, "pip", "26.3")
            if case == "extra":
                fs.distribution(STDLIB, "unexpected-public-fixture", "1.0")
            entries = [ZIP, STDLIB, SITE] + ([SITE] if case == "duplicate" else [])
            with (
                self.subTest(case=case),
                self.assertRaisesRegex(ValueError, "distribution_origin|minimal_distributions"),
            ):
                self.probe(fs, entries, {"pip": "26.3"})
        OBSERVATIONS.append(
            {"case": "real_metadata_extra_duplicate_wrong_origin", "all_refused": True}
        )

    def test_foreign_directory_not_hidden_and_guard_refusal_still_counted(self):
        guard, fs = CHILD.Guards(), Files()
        outside = "/foreign"
        fs.guard, fs.forbidden = guard, {outside}
        fs.directories.add(outside)
        fs.distribution(SITE, "pip", "26.3")
        value = self.probe(fs, [ZIP, SITE, outside], {"pip": "26.3"})
        self.assertEqual(value["distributions"], {"pip": "26.3"})
        self.assertEqual(dict(guard.attempts), {"file.read_outside_roots": 2})
        with self.assertRaises(CHILD.ForbiddenIO):
            guard.require_clean()
        OBSERVATIONS.append({"case": "foreign_directory", "attempts_preserved": 2})

    def test_installed_file_lookup_uses_explicit_paths_not_default_distribution(self):
        with tempfile.TemporaryDirectory(prefix="metadata-lookup-fixture-") as directory:
            prefix = Path(directory).resolve()
            (prefix / "pamolive_pam_trust_verifier").mkdir()
            item = SimpleNamespace(
                metadata={"Name": "pamolive-pam-trust-verifier"}, locate_file=lambda _: prefix
            )
            with (
                patch.object(CHILD.sys, "path", [str(prefix)]),
                patch.object(CHILD.sys, "prefix", str(prefix)),
                patch.object(
                    CHILD.importlib.metadata,
                    "distribution",
                    side_effect=AssertionError("default lookup forbidden"),
                ),
                patch.object(
                    CHILD.importlib.metadata, "distributions", return_value=iter([item])
                ) as discover,
            ):
                self.assertEqual(CHILD.installed_files_probe({})["package_files_closed"], 0)
                discover.assert_called_once_with(path=(str(prefix),))

    def test_complete_path_validation_precedes_first_metadata_read(self):
        fs = Files()
        with fs.paths([SITE, "/unexpected-missing"]), fs.metadata():
            with self.assertRaisesRegex(ValueError, "distribution_origin"):
                list(importlib.metadata.distributions(path=CHILD.metadata_directories()))
        self.assertEqual(fs.reads, [])

    def test_system_site_false_and_exact_expected_distributions_remain_required(self):
        fs = Files()
        fs.distribution(SITE, "pip", "26.3")
        self.assertEqual(
            self.probe(fs, [ZIP, STDLIB, SITE], {"pip": "26.3"})["global_site_fallback"], False
        )
        fs.reads.clear()
        with self.assertRaisesRegex(ValueError, "system_site"):
            self.probe(fs, [ZIP, STDLIB, SITE], {"pip": "26.3"}, system_site=True)
        self.assertEqual(fs.reads, [])
