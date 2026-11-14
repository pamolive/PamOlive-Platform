"""Adversarial committed-context tests; no daemon or real credentials."""

import io
import subprocess
import tarfile
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import build_context as gate


def bundle(extra=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name, kind, content in [
            ("Dockerfile", "file", b"FROM scratch\n"),
            (".dockerignore", "file", b"**\n"),
            *extra,
        ]:
            member = tarfile.TarInfo(name)
            if kind in ("symlink", "hardlink"):
                member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                member.linkname = "/outside"
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
            else:
                member.mode = 0o4755 if kind == "suid" else 0o644
                member.size = len(content)
            archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
    return stream.getvalue()


class BuildContextTests(TestCase):
    def test_real_recipe_from_dirty_checkout_cannot_describe_previous_context(self):
        from deploy import build_recipe
        from tests.test_build_recipe import RecipeFixture

        fixture = RecipeFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        report = {
            "schema": "pamolive.committed-build-context.v1",
            "revision": "a" * 40,
            "files": dict(fixture.recipe["files"]),
        }
        self.assertTrue(gate.bind_recipe(report, fixture.recipe)["recipe_bound"])
        (fixture.repo / "Dockerfile").write_bytes(b"FROM changed-builder.invalid\n")
        changed = build_recipe.capture(
            fixture.repo,
            backport_manifest=fixture.fixture.manifest(),
            elf_entries=fixture.elf_entries,
        )
        self.assertTrue(build_recipe.verify(changed, fixture.repo)["verified"])
        with self.assertRaisesRegex(ValueError, "context_recipe_changed"):
            gate.bind_recipe(report, changed)

    def test_recipe_binding_rejects_dirty_dockerfile_added_missing_and_changed_files(self):
        # Validation of full recipe schema is independently exercised by its suite.
        report = {
            "schema": "pamolive.committed-build-context.v1",
            "revision": "a" * 40,
            "files": {"Dockerfile": "a" * 64, ".secrets.baseline": "b" * 64},
        }
        recipe = {"excluded_exact_paths": [".secrets.baseline"], "files": {"Dockerfile": "a" * 64}}
        with patch("deploy.build_recipe.validate"):
            self.assertTrue(gate.bind_recipe(report, recipe)["recipe_bound"])
            for files in (
                {"Dockerfile": "c" * 64},
                {},
                {"Dockerfile": "a" * 64, "new.py": "d" * 64},
            ):
                with self.subTest(files=files), self.assertRaises(ValueError):
                    gate.bind_recipe(report, {**recipe, "files": files})

    def test_regular_files_accepted_with_exact_content(self):
        rows = gate.checked_members(bundle([("deploy/test.sh", "file", b"exit 0\n")]))
        self.assertEqual(rows[-1], ("deploy/test.sh", b"exit 0\n", 0o644))

    def test_traversal_absolute_alias_and_windows_paths_refused(self):
        for name in (
            "../escape",
            "/absolute",
            "./alias",
            "x//alias",
            "x/../alias",
            "x\\alias",
            "C:/escape",
            "name:stream",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.checked_members(bundle([(name, "file", b"x")]))

    def test_links_devices_and_special_permissions_refused(self):
        for kind in ("symlink", "hardlink", "fifo", "suid"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                gate.checked_members(bundle([("bad", kind, b"x")]))

    def test_windows_device_names_and_normalization_aliases_refused(self):
        for name in (".. /escape", "folder./file", "name ", "AUX", "x/nul.txt", "COM1.py"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.checked_members(bundle([(name, "file", b"x")]))

    def test_duplicate_case_alias_and_file_ancestor_refused(self):
        for extras in (
            [("Dockerfile", "file", b"x")],
            [("dockerfile", "file", b"x")],
            [("a", "file", b"x"), ("a/b", "file", b"y")],
            [("a/b", "file", b"x"), ("a", "file", b"y")],
        ):
            with self.subTest(extras=extras), self.assertRaises(ValueError):
                gate.checked_members(bundle(extras))

    def test_tracked_private_diagnostics_and_git_metadata_refused(self):
        for name in (*gate.FORBIDDEN, ".git/config", "nested/.git/config"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.checked_members(bundle([(name, "file", b"private")]))

    def test_budgets_fail_closed(self):
        for setting, limit in (("MAX_BYTES", 100), ("MAX_FILES", 1), ("MAX_FILE", 1)):
            with self.subTest(setting=setting), patch.object(gate, setting, limit):
                with self.assertRaises(ValueError):
                    gate.checked_members(bundle())

    def test_empty_and_missing_dockerfile_refused(self):
        with self.assertRaises(ValueError):
            gate.checked_members(b"")
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:"):
            pass
        with self.assertRaises(ValueError):
            gate.checked_members(stream.getvalue())

    def test_real_git_tree_excludes_dirty_tracked_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            command = [
                "git",
                "-c",
                "safe.directory=" + root.as_posix(),
                "-c",
                "core.hooksPath=",
                "-C",
                str(root),
            ]

            def git(*args):
                return (
                    subprocess.run([*command, *args], check=True, capture_output=True, timeout=15)
                    .stdout.decode()
                    .strip()
                )

            git("init", "--quiet")
            git("config", "core.autocrlf", "false")
            (root / "Dockerfile").write_bytes(b"FROM scratch\n")
            (root / ".dockerignore").write_bytes(b"**\n")
            git("add", "Dockerfile", ".dockerignore")
            git(
                "-c",
                "user.name=Synthetic fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "synthetic tree",
            )
            revision = git("rev-parse", "HEAD")
            (root / "Dockerfile").write_bytes(b"dirty local content\n")
            (root / "private.env").write_bytes(b"synthetic do not publish\n")
            destination = Path(temporary) / "context"
            report = gate.create(root, destination, revision)
            self.assertEqual((destination / "Dockerfile").read_bytes(), b"FROM scratch\n")
            self.assertFalse((destination / "private.env").exists())
            self.assertEqual(set(report["files"]), {"Dockerfile", ".dockerignore"})
            with self.assertRaises(ValueError):
                gate.create(root, destination, revision)
            with self.assertRaises(ValueError):
                gate.create(root, Path(temporary) / "other", "HEAD")
