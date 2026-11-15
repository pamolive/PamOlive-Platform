"""Mock/data-only controller regressions; never runs qualifier/package/venv/pip."""

import ast
import base64
import csv
import hashlib
import importlib.util
import shutil
import stat
import sys
import tempfile
import time
import unittest
from io import BytesIO, StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parents[1] / "components" / "pam-trust-verifier"
LINUX_FLAGS = SimpleNamespace(
    O_RDONLY=0,
    O_WRONLY=1,
    O_RDWR=2,
    O_ACCMODE=3,
    O_CREAT=64,
    O_EXCL=128,
    O_TRUNC=512,
    O_APPEND=1024,
    O_DIRECTORY=65536,
    O_TMPFILE=4259840,
    O_CLOEXEC=524288,
)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


PARENT = module("installed_adapter_under_pure_test", ROOT / "qualify_installed.py")
CHILD = module("installed_child_under_pure_test", ROOT / "installed_tests.py")
ACQUIRE = module("integrated_acquisition_under_pure_test", ROOT / "acquire_materials.py")


class FakeZip:
    def __init__(self, files, *, entries=None):
        self.files = files
        self.entries = entries or [
            SimpleNamespace(
                filename=name,
                file_size=len(raw),
                external_attr=(stat.S_IFREG | 0o644) << 16,
                flag_bits=0,
                is_dir=lambda: False,
            )
            for name, raw in files.items()
        ]
        self.opened = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def infolist(self):
        return self.entries

    def open(self, entry):
        self.opened.append(entry.filename)
        return BytesIO(self.files[entry.filename])


def synthetic_entries():
    """Mock ZipFile entries, not an actual built wheel or executable package."""
    info = PARENT.PACKAGE + "-" + PARENT.VERSION + ".dist-info"
    files, source = {}, {}
    for name in (
        "__init__.py",
        "_api.py",
        "_codec.py",
        "_context.py",
        "_crypto.py",
        "_v1_rules.py",
    ):
        path = PARENT.PACKAGE + "/" + name
        files[path] = b"# synthetic public bytes, never executed\n"
        source["src/" + path] = {"sha256": PARENT.sha(files[path])}
    for name in ("LICENSE", "LICENSE-DJANGO.txt", "NOTICE.txt"):
        files[info + "/licenses/" + name] = b"public test notice"
        source[name] = {"sha256": PARENT.sha(b"public test notice")}
    files[info + "/METADATA"] = (
        b"Metadata-Version: 2.4\nName: pamolive-pam-trust-verifier\nVersion: 0.1.0a1\n"
        b"Requires-Dist: cryptography==50.0.2\n"
        b"Requires-Dist: webauthn==3.0.1\nRequires-Dist: cbor2==6.2.1\n\n"
    )
    files[info + "/WHEEL"] = b"Root-Is-Purelib: true\nTag: py3-none-any\n"
    files[info + "/top_level.txt"] = b"pamolive_pam_trust_verifier\n"
    return files, source, info


def record(files, info):
    text = StringIO()
    output = csv.writer(text, lineterminator="\n")
    for name, raw in files.items():
        if name != info + "/RECORD":
            hashed = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            output.writerow((name, "sha256=" + hashed, str(len(raw))))
    output.writerow((info + "/RECORD", "", ""))
    files[info + "/RECORD"] = text.getvalue().encode()


class AdapterPureTests(unittest.TestCase):
    def inspect(self, fake, source):
        with patch.object(PARENT.zipfile, "ZipFile", return_value=fake):
            return PARENT.zip_inventory(
                b"synthetic-container-not-a-wheel",
                name=PARENT.DISTRIBUTION,
                version=PARENT.VERSION,
                pure=True,
                source_files=source,
            )

    def test_reference_and_IO_copies_pinned(self):
        self.assertEqual(PARENT.sha(PARENT.bootstrap_read(ROOT / "bounded_io.py")), PARENT.IO_HASH)
        self.assertEqual(
            PARENT.sha(PARENT.bootstrap_read(ROOT / "materials-plan.json")),
            PARENT.MATERIALS_HASH,
        )
        self.assertEqual(
            PARENT.sha(PARENT.bootstrap_read(SOURCE / "PAYLOAD-MANIFEST.json")),
            PARENT.SOURCE_MANIFEST,
        )

    def test_reviewed_IO_loader_uses_hash_checked_buffer_only(self):
        helper = PARENT.load_io()
        self.assertIsNone(helper.Result().pid)
        with patch.object(PARENT, "bootstrap_read", return_value=b"invalid public helper"):
            with self.assertRaisesRegex(ValueError, "reviewed_IO_hash"):
                PARENT.load_io()

    def test_import_refusal_count_survives_swallowing(self):
        guard = CHILD.Guards()
        namespace = {
            "forbidden_imports": {"django", "psycopg"},
            "guard": guard,
            "old_import": Mock(return_value="allowed"),
        }
        importer = self.extracted("installed_tests.py", "main", "guarded_import", namespace)
        try:
            importer("django.conf")
        except CHILD.ForbiddenIO:
            pass
        self.assertEqual(importer("json"), "allowed")
        with self.assertRaises(CHILD.ForbiddenIO):
            guard.require_clean()
        self.assertEqual(dict(guard.attempts), {"import.django": 1})

    def test_exact_thirteen_materials_and_three_hash_locks(self):
        plan, _ = PARENT.document(ROOT / "materials-plan.json", PARENT.MATERIALS_HASH)
        rows = plan["selected_materials"]
        self.assertEqual(set(rows), PARENT.RUNTIME_NAMES | PARENT.BUILD_NAMES | {"pip"})
        self.assertEqual((len(PARENT.RUNTIME_NAMES), len(PARENT.BUILD_NAMES | {"pip"})), (9, 4))
        PARENT.check_locks(rows)

    def test_hash_lock_duplicates_and_unhashed_requirement_rejected(self):
        for raw in (
            b"a==1\n",
            b"a==1 --hash=sha256:" + b"0" * 64 + b"\n" + b"a==1 --hash=sha256:" + b"0" * 64 + b"\n",
        ):
            with self.assertRaises(ValueError):
                PARENT.lock_rows(raw)

    def test_parent_and_child_refuse_oversize_before_open(self):
        row = SimpleNamespace(
            st_mode=stat.S_IFREG, st_nlink=1, st_size=1 << 40, st_file_attributes=0
        )
        for reader in (PARENT.bootstrap_read, CHILD.bounded_read):
            with (
                patch.object(Path, "lstat", return_value=row),
                patch.object(Path, "is_symlink", return_value=False),
                patch.object(Path, "open") as opened,
            ):
                with self.assertRaises(ValueError):
                    reader("never-read", 1024)
                opened.assert_not_called()

    def test_regular_small_read_and_wrong_JSON_hash(self):
        with tempfile.TemporaryDirectory(prefix="installed-adapter-pure-") as directory:
            path = Path(directory) / "public.json"
            path.write_bytes(b'{"public":true}')
            self.assertEqual(CHILD.bounded_json(path), {"public": True})
            with self.assertRaises(ValueError):
                PARENT.document(path, "0" * 64)

    def test_paths_and_aliases_refused(self):
        for path in ("../x", "/x", "C:/x", "a\\b", "a//b"):
            with self.assertRaises(ValueError):
                PARENT.safe_path(path)

    def test_mock_wheel_source_licenses_and_RECORD(self):
        files, source, info = synthetic_entries()
        record(files, info)
        facts = self.inspect(FakeZip(files), source)
        self.assertTrue(facts["RECORD_checked"])
        self.assertEqual((facts["entries"], len(facts["wheel_files_sha256"])), (13, 12))

    def test_valid_RECORD_does_not_mask_altered_source_or_notice(self):
        for path in (
            PARENT.PACKAGE + "/_api.py",
            PARENT.PACKAGE + "-" + PARENT.VERSION + ".dist-info/licenses/NOTICE.txt",
        ):
            files, source, info = synthetic_entries()
            files[path] = b"altered-public-synthetic"
            record(files, info)
            with self.assertRaisesRegex(ValueError, "new_wheel_source_license_bytes"):
                self.inspect(FakeZip(files), source)

    def test_bad_RECORD_hash_rejected(self):
        files, source, info = synthetic_entries()
        record(files, info)
        files[PARENT.PACKAGE + "/_api.py"] += b"changed"
        with self.assertRaisesRegex(ValueError, "wheel_RECORD_identity"):
            self.inspect(FakeZip(files), source)

    def test_oversized_ZIP_entry_before_open(self):
        files, source, info = synthetic_entries()
        record(files, info)
        fake = FakeZip(files)
        fake.entries[0].file_size = 24 * 1024 * 1024 + 1
        with self.assertRaisesRegex(ValueError, "wheel_expansion_budget"):
            self.inspect(fake, source)
        self.assertEqual(fake.opened, [])

    def test_ZIP_symlink_duplicate_traversal_and_PTH(self):
        for mutation in ("link", "duplicate", "traversal", "pth"):
            files, source, info = synthetic_entries()
            record(files, info)
            fake = FakeZip(files)
            if mutation == "link":
                fake.entries[0].external_attr = (stat.S_IFLNK | 0o777) << 16
            elif mutation == "duplicate":
                fake.entries.append(fake.entries[0])
            elif mutation == "traversal":
                fake.entries[0].filename = "../outside"
            else:
                fake.entries[0].filename = "unapproved.pth"
            with self.assertRaises(ValueError):
                self.inspect(fake, source)

    def test_frozen_source_payload_closed_and_layout_has_siblings(self):
        source = SOURCE
        selected, data = PARENT.source_payload(source)
        self.assertEqual(len([name for name in selected if name.startswith("src/")]), 6)
        self.assertEqual(
            {name.split("/", 1)[0] for name in data if name.startswith(("tests/", "fixtures/"))},
            {"tests", "fixtures"},
        )
        self.assertIn("fixtures/reference-p0-child-report.json", data)
        self.assertTrue(
            all(name in selected for name in ("LICENSE", "LICENSE-DJANGO.txt", "NOTICE.txt"))
        )

    def test_integrated_manifest_missing_changed_or_extra_file_refused(self):
        for mutation in ("missing", "modified", "extra", "README"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(prefix="integrated-payload-pure-") as temporary,
            ):
                source = Path(temporary) / "source"
                shutil.copytree(SOURCE, source)
                if mutation == "missing":
                    (source / "PAYLOAD-MANIFEST.json").unlink()
                elif mutation == "modified":
                    with (source / "PAYLOAD-MANIFEST.json").open("ab") as stream:
                        stream.write(b" ")
                elif mutation == "extra":
                    (source / "extra.py").write_bytes(b"# never imported\n")
                else:
                    with (source / "README.md").open("ab") as stream:
                        stream.write(b"unreviewed status\n")
                with self.assertRaises((OSError, ValueError)):
                    PARENT.source_payload(source)

    def test_integrated_README_and_selected_tree_have_no_prototype_dependency(self):
        selected, data = PARENT.source_payload(SOURCE)
        self.assertEqual(len(selected), 353)
        self.assertIn(b"source integration candidate", data["README.md"])
        self.assertNotIn(b"run_tests.py --label", data["README.md"])
        self.assertIn("FIXTURES-NOTICE.md", selected)
        for excluded in (
            "run_tests.py",
            "FREEZE.json",
            "MANIFEST.json",
            "UUID-DELTA.json",
        ):
            self.assertFalse((SOURCE / excluded).exists())
        tree = ast.parse(PARENT.bootstrap_read(ROOT / "qualify_installed.py"))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "source_payload"
        )
        strings = {
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertNotIn("FREEZE.json", strings)
        self.assertNotIn("MANIFEST.json", strings)

    def test_acquisition_selects_exact_existing_thirteen_and_rejects_delta(self):
        expected, _ = PARENT.document(ROOT / "materials-plan.json", PARENT.MATERIALS_HASH)
        rows = list(expected["selected_materials"].values())
        gate = SimpleNamespace(
            load_manifest=Mock(return_value=({"materials": rows}, ACQUIRE.MANIFEST_HASH)),
            check_locks=Mock(),
        )
        selected = ACQUIRE.selected_rows(gate, Path("/checkout"))
        self.assertEqual(len(selected), 13)
        for altered in (
            rows[:-1],
            [
                {**row, "version": "unreviewed"} if index == 0 else row
                for index, row in enumerate(rows)
            ],
        ):
            gate.load_manifest.return_value = (
                {"materials": altered},
                ACQUIRE.MANIFEST_HASH,
            )
            with self.assertRaises(ValueError):
                ACQUIRE.selected_rows(gate, Path("/checkout"))

    def test_acquisition_wrong_gate_refused_before_interpretation(self):
        with (
            patch.object(ACQUIRE.adapter, "bootstrap_read", return_value=b"never interpreted"),
            patch.object(ACQUIRE.importlib.util, "module_from_spec") as create,
        ):
            with self.assertRaisesRegex(ValueError, "existing_gate_hash"):
                ACQUIRE.load_gate(Path("/fake/deploy/python_materials.py"))
            create.assert_not_called()

    def test_acquisition_report_failure_does_not_replace_original_failure(self):
        with tempfile.TemporaryDirectory(prefix="acquisition-failure-mocked-") as temporary:
            repository = Path(temporary) / "repo"
            repository.mkdir()
            gate = SimpleNamespace(https_opener=Mock(side_effect=RuntimeError("original")))
            with (
                patch.object(ACQUIRE, "selected_rows", return_value={}),
                patch.object(ACQUIRE.adapter, "write_new", side_effect=OSError("report")),
            ):
                with self.assertRaisesRegex(RuntimeError, "original"):
                    ACQUIRE.acquire(repository, Path(temporary) / "wheels", gate=gate)

    def test_acquisition_failure_preserves_bounded_static_report_without_retry(self):
        with tempfile.TemporaryDirectory(prefix="acquisition-mocked-") as temporary:
            repository = Path(temporary) / "repo"
            repository.mkdir()
            destination = Path(temporary) / "materials"
            gate = SimpleNamespace(
                https_opener=Mock(return_value=object()),
                download=Mock(side_effect=RuntimeError("synthetic failure")),
            )
            with patch.object(
                ACQUIRE,
                "selected_rows",
                return_value={"public": {"filename": "public.whl"}},
            ):
                with self.assertRaises(RuntimeError):
                    ACQUIRE.acquire(repository, destination, gate=gate)
            gate.download.assert_called_once()
            result = PARENT.document(destination / "acquisition.json")[0]
            self.assertEqual(
                (result["state"], result["exception_type"], result["files"]),
                ("FAILED", "RuntimeError", {}),
            )
            self.assertFalse(result["installed_or_built"])

    def test_work_inside_frozen_source_refused_before_mkdir(self):
        source = Path("/frozen/source")
        work = source / "must-not-create"
        with patch.object(Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(ValueError, "work_outside_frozen_inputs"):
                PARENT.run({}, source, Path("/frozen/materials"), work)
            mkdir.assert_not_called()

    def test_swallowed_IO_error_still_fails_counter(self):
        guard = CHILD.Guards()

        def package_like_wrapper():
            try:
                guard.refuse("socket.connect")
            except Exception:
                return "InvalidMaterials"

        self.assertEqual(package_like_wrapper(), "InvalidMaterials")
        with self.assertRaises(CHILD.ForbiddenIO):
            guard.require_clean()
        self.assertEqual(guard.attempts, {"socket.connect": 1})

    def test_intentional_probes_separate_from_actual_attempts(self):
        guard = CHILD.Guards()
        guard.probing = True
        with self.assertRaises(CHILD.ForbiddenIO):
            guard.refuse("DNS")
        guard.probing = False
        guard.require_clean()
        self.assertEqual((dict(guard.probes), dict(guard.attempts)), ({"DNS": 1}, {}))

    def extracted(self, filename, outer, inner, namespace):
        tree = ast.parse(PARENT.bootstrap_read(ROOT / filename))
        function = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == outer
        )
        selected = next(
            node
            for node in ast.walk(function)
            if isinstance(node, ast.FunctionDef) and node.name == inner
        )
        exec(
            compile(ast.Module(body=[selected], type_ignores=[]), filename, "exec"),
            namespace,
        )
        return namespace[inner]

    def file_audit(self):
        guard = CHILD.Guards()
        namespace = {
            "Path": Path,
            "guard": guard,
            "report_path": Path("/owned/reports/result.json"),
            "base_site": Path("/base/lib/site-packages"),
            "prefix": Path("/owned/venv"),
            "read_roots": (Path("/owned/venv"), Path("/owned/test-stage")),
            "FILESYSTEM_MUTATIONS": CHILD.FILESYSTEM_MUTATIONS,
            "report_admission": {"enabled": False, "used": False},
            "open_mutates": lambda mode, flags: CHILD.open_mutates(mode, flags, LINUX_FLAGS),
            "exclusive_report_open": lambda mode, flags: CHILD.exclusive_report_open(
                mode, flags, LINUX_FLAGS
            ),
        }
        for key in ("report_path", "base_site", "prefix"):
            namespace[key] = namespace[key].resolve()
        namespace["read_roots"] = tuple(path.resolve() for path in namespace["read_roots"])
        audit = self.extracted("installed_tests.py", "main", "audit", namespace)
        return audit, guard, namespace["report_admission"]

    def test_actual_file_audit_blocks_reads_writes_and_bad_descriptors(self):
        audit, guard, admission = self.file_audit()
        for event, values in (
            ("open", ("/outside/context", "r", 0)),
            ("open", ("/owned/test-stage/tests.py", "w", 1)),
            ("open", (3, "r", 0)),
            ("open", ("/base/lib/site-packages/django/x.py", "r", 0)),
        ):
            with self.assertRaises(CHILD.ForbiddenIO):
                audit(event, values)
        admission["enabled"] = True
        audit("open", ("/owned/reports/result.json", "x", 193))
        admission["enabled"] = False
        audit("open", ("/owned/test-stage/fixtures/x.json", "r", 0))
        self.assertEqual(sum(guard.attempts.values()), 4)

    def test_linux_mutation_flags_include_readonly_creation_and_truncation(self):
        for flags in (1, 2, 64, 128, 512, 1024, 4259840, 524288 | 64):
            with self.subTest(flags=flags):
                self.assertTrue(CHILD.open_mutates(None, flags, LINUX_FLAGS))
                audit, guard, _ = self.file_audit()
                try:
                    audit("open", ("/owned/test-stage/public.json", None, flags))
                except CHILD.ForbiddenIO:
                    pass
                with self.assertRaises(CHILD.ForbiddenIO):
                    guard.require_clean()
                self.assertEqual(dict(guard.attempts), {"file.write": 1})
        for flags in (0, 65536, 524288, 65536 | 524288):
            self.assertFalse(CHILD.open_mutates("r", flags, LINUX_FLAGS))
        for flags in (True, -1, None, "512"):
            with self.assertRaises(ValueError):
                CHILD.open_mutates(None, flags, LINUX_FLAGS)

    def test_filesystem_mutations_count_even_if_package_masks_error(self):
        expected = {
            "os.remove",
            "os.rmdir",
            "os.rename",
            "os.mkdir",
            "os.link",
            "os.symlink",
            "os.chmod",
            "os.chown",
            "os.utime",
            "os.truncate",
            "os.chdir",
            "os.chflags",
            "os.setxattr",
            "os.removexattr",
        }
        self.assertEqual(CHILD.FILESYSTEM_MUTATIONS, expected)
        for event in expected:
            with self.subTest(event=event):
                audit, guard, _ = self.file_audit()
                try:
                    audit(event, ("/owned/reports/result.json",))
                except Exception:
                    # Same shape as a package converting ForbiddenIO to InvalidMaterials.
                    pass
                self.assertEqual(dict(guard.attempts), {"file.mutation." + event: 1})
                with self.assertRaises(CHILD.ForbiddenIO):
                    guard.require_clean()

    def test_report_only_single_exclusive_create_inside_final_window(self):
        for mode, flags in (
            ("x", 193),
            (None, 193),
            ("w", 577),
            ("a", 1089),
            ("x", 1),
            ("x", 4259841),
        ):
            for enabled in (False, True):
                with self.subTest(mode=mode, flags=flags, enabled=enabled):
                    audit, guard, admission = self.file_audit()
                    admission["enabled"] = enabled
                    if enabled and mode == "x" and flags == 193:
                        audit("open", ("/owned/reports/result.json", mode, flags))
                        guard.require_clean()
                        self.assertTrue(admission["used"])
                    else:
                        with self.assertRaises(CHILD.ForbiddenIO):
                            audit("open", ("/owned/reports/result.json", mode, flags))
        audit, guard, admission = self.file_audit()
        admission["enabled"] = True
        audit("open", ("/owned/reports/result.json", "x", 193 | 524288))
        with self.assertRaises(CHILD.ForbiddenIO):
            audit("open", ("/owned/reports/result.json", "x", 193))
        with self.assertRaises(CHILD.ForbiddenIO):
            guard.require_clean()

    def test_report_admission_window_is_only_in_finally(self):
        tree = ast.parse(PARENT.bootstrap_read(ROOT / "installed_tests.py"))
        main = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        final = next(node for node in main.body if isinstance(node, ast.Try))
        enables = [
            node
            for node in ast.walk(main)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "report_admission"
                and isinstance(target.slice, ast.Constant)
                and target.slice.value == "enabled"
                for target in node.targets
            )
        ]
        self.assertEqual(len(enables), 2)
        self.assertTrue(
            all(
                node in list(ast.walk(ast.Module(body=final.finalbody, type_ignores=[])))
                for node in enables
            )
        )
        self.assertEqual([node.value.value for node in enables], [True, False])

    def test_actual_parent_call_has_live_caps_and_preserves_failure_facts(self):
        with tempfile.TemporaryDirectory(prefix="installed-adapter-call-") as temporary:
            work = Path(temporary)
            (work / "logs").mkdir()
            facts = {
                "pid": 123,
                "reason": "stdout_overflow",
                "owned_child_reaped": True,
            }
            result = SimpleNamespace(ok=False, facts=lambda: facts)
            capped = Mock(return_value=result)
            report = {"processes": []}
            namespace = {
                "time": time,
                "started": time.monotonic(),
                "work": work,
                "env": {"HOME": "synthetic"},
                "IO": SimpleNamespace(run_capped=capped),
                "Path": Path,
                "report": report,
                "require": PARENT.require,
            }
            call = self.extracted("qualify_installed.py", "run", "call", namespace)
            with self.assertRaisesRegex(ValueError, "owned_process_failed"):
                call("synthetic", ["never-executed"])
            self.assertEqual(
                (
                    capped.call_args.kwargs["stdout_cap"],
                    capped.call_args.kwargs["stderr_cap"],
                ),
                (1048576, 262144),
            )
            self.assertLessEqual(capped.call_args.kwargs["timeout"], 120)
            self.assertEqual(report["processes"], [{"phase": "synthetic", **facts}])

    def test_no_package_Django_or_main_executed_by_pure_suite(self):
        self.assertFalse(
            any(
                name.startswith(
                    (
                        "pamolive_pam_trust_verifier",
                        "django",
                        "platform_core",
                        "platform_modules",
                    )
                )
                for name in sys.modules
            )
        )


if __name__ == "__main__":
    with (
        patch("subprocess.Popen", side_effect=AssertionError("real Popen forbidden")),
        patch("subprocess.run", side_effect=AssertionError("real run forbidden")),
        patch("socket.socket", side_effect=AssertionError("real socket forbidden")),
        patch("socket.getaddrinfo", side_effect=AssertionError("real DNS forbidden")),
        patch(
            "urllib.request.OpenerDirector.open",
            side_effect=AssertionError("real HTTP forbidden"),
        ),
    ):
        unittest.main(verbosity=2)
