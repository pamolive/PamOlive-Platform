"""Typed FILE/DIR selection, pure memory/TAR/FD models; never Docker or extraction."""

import copy
import hashlib
import io
import json
import stat
import tarfile
from pathlib import PurePosixPath
from unittest import TestCase
from unittest.mock import patch

from deploy import build_context as gate
from tests import test_sealed_build_context as memory


class TypedDirectoryContextTests(TestCase):
    def setUp(self):
        self.model = memory.SealedContextTests("runTest")
        self.model.setUp()
        self.addCleanup(self.model.doCleanups)
        self.fs = self.model.fs

    def add_git_file(self, name, data=b"PUBLIC_EXCLUDED=1\n", mode=0o644):
        self.model.files.append((name, data, mode))
        path = PurePosixPath("/ctx") / name
        for parent in reversed(path.parents):
            if str(parent) not in self.fs.nodes:
                self.fs.add(str(parent), None, 0o755)
        node = self.fs.add(str(path), data, mode)
        self.model.written[name] = gate.identity(self.fs.value(node))
        self.model.report["files"][name] = hashlib.sha256(data).hexdigest()

    def tar_data(self, files, directories, *, change=None, extra=()):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:", format=tarfile.PAX_FORMAT) as archive:
            rows = [(n, None, 0o755) for n in sorted(directories)] + list(files)
            for name, data, mode in rows:
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE if data is None else tarfile.REGTYPE
                member.mode = mode
                member.size = 0 if data is None else len(data)
                if change is not None:
                    change(member)
                archive.addfile(member, None if data is None else io.BytesIO(data))
            for member in extra:
                archive.addfile(member)
        return raw.getvalue()

    def assert_headers_refuse_without_member_read(self, raw, files, directories):
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data, _ in files}
        with patch.object(
            tarfile.TarFile, "extractfile", side_effect=AssertionError("member_read")
        ) as read:
            with self.assertRaises(ValueError):
                gate.checked_typed_members(
                    raw,
                    hashes,
                    directories,
                    expected_typed_sha=gate.typed_nodes_digest(files, directories),
                )
        read.assert_not_called()

    def test_known_empty_real_directory_is_in_tar_and_same_three_consumers(self):
        self.add_git_file("config/kept-empty/private.pem")
        with self.fs.install():
            receipt = self.model.seal()
            raw = self.fs.nodes["/sealed/context.tar"]["data"]
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                members = {m.name.rstrip("/"): m for m in archive}
            self.assertTrue(members["config/kept-empty"].isdir())
            self.assertNotIn("config/kept-empty/private.pem", members)
            self.assertIn("/sealed/probe-export/proof/config/kept-empty", self.fs.nodes)
            calls = []

            def run(argv, *, stdin, check):
                self.assertEqual(stdin.read(), raw)
                calls.append((argv, stdin.fileno()))
                return memory.SimpleNamespace(returncode=0)

            with (
                patch.object(gate.subprocess, "run", run),
                patch.dict(gate.os.environ, {"RUNNER_TEMP": "/sealed"}),
            ):
                for target in ["production", "native-test", "json-reference-data"]:
                    self.assertEqual(
                        gate.consume(
                            "/sealed/context.tar",
                            "/sealed/receipt.json",
                            "a" * 40,
                            target,
                            "/sealed/pamolive-jansson-reference-data"
                            if target == "json-reference-data"
                            else None,
                            "/sealed/manifest.json",
                            "/sealed/probe.json",
                        ),
                        0,
                    )
            self.assertEqual(len(calls), 3)
            self.assertEqual(receipt["schema"], "pamolive.sealed-build-context/2")
            proof = json.loads(self.fs.nodes["/sealed/probe.json"]["data"])
            self.assertEqual(
                proof["probe_scope"], "typed-selection-and-public-marker-modes-0644-v2"
            )
            self.assertEqual(proof["marker_file_mode"], 0o644)
            self.assertIs(proof["git_modes_native_observed"], False)

    def test_probe_only_directories_never_enter_real_tar_and_intersections_hold(self):
        with self.fs.install():
            self.model.seal()
            raw = self.fs.nodes["/sealed/context.tar"]["data"]
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                names = {m.name.rstrip("/") for m in archive}
            probe_selected, packet = gate.parity_directories(self.model.report)
            real, selected = gate.directory_selection(
                set(self.model.report["files"]) | set(gate.CANARIES)
            )
            self.assertEqual(probe_selected & real, selected)
            self.assertIn("config/__profile_probe__/n01", probe_selected)
            self.assertNotIn("config/__profile_probe__/n01", names)
            self.assertIn("/sealed/probe-export/proof/config/__profile_probe__/n01", self.fs.nodes)
            self.assertEqual(
                packet["real"],
                gate.directory_summary(set(self.model.report["files"]) | set(gate.CANARIES)),
            )

    def test_directory_exclusions_cover_suffix_type_and_every_ancestor(self):
        names = {
            "Dockerfile",
            ".dockerignore",
            "config/public.py",
            "config/empty/private.pem",
            "config/secret.pem/child/public.py",
            "config/.ssh/child/public.py",
            "config/build/child/public.py",
            "config/building/public.py",
        }
        inputs, selected = gate.directory_selection(names)
        self.assertIn("config/empty", selected)
        self.assertIn("config/building", selected)
        for name in [
            "config/secret.pem",
            "config/secret.pem/child",
            "config/.ssh",
            "config/.ssh/child",
            "config/build",
            "config/build/child",
        ]:
            self.assertIn(name, inputs)
            self.assertNotIn(name, selected)

    def test_controls_are_files_not_directory_whitelist_entries(self):
        for name in [
            "Dockerfile/child",
            ".dockerignore/child",
            "README.md/child",
            ".env.example/child",
        ]:
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "context_directory_role"),
            ):
                gate.directory_selection({"Dockerfile", ".dockerignore", name})

    def test_extra_directory_after_known_file_headers_refuses_before_any_member_read(self):
        files = [("Dockerfile", b"PUBLIC", 0o644)]
        extra = tarfile.TarInfo("unexpected-empty")
        extra.type, extra.mode = tarfile.DIRTYPE, 0o755
        self.assert_headers_refuse_without_member_read(
            self.tar_data(files, set(), extra=[extra]), files, set()
        )

    def test_missing_empty_directory_refuses_before_any_member_read(self):
        files = [("config/public.py", b"PUBLIC", 0o644)]
        self.assert_headers_refuse_without_member_read(
            self.tar_data(files, {"config"}), files, {"config", "config/empty"}
        )

    def test_wrong_directory_type_owner_mode_or_link_refuses_before_member_read(self):
        files = [("config/public.py", b"PUBLIC", 0o644)]
        for field, value in [("type", tarfile.SYMTYPE), ("uid", 1), ("gid", 1), ("mode", 0o777)]:

            def change(member):
                if member.name == "config":
                    setattr(member, field, value)

            self.assert_headers_refuse_without_member_read(
                self.tar_data(files, {"config"}, change=change), files, {"config"}
            )

    def test_directory_alias_duplicate_prefix_or_case_collision_is_not_admitted(self):
        files = [("config/public.py", b"PUBLIC", 0o644)]
        for name in ["config", "CONFIG", "config/../config", "/config", "config/unexpected"]:
            extra = tarfile.TarInfo(name)
            extra.type, extra.mode = tarfile.DIRTYPE, 0o755
            self.assert_headers_refuse_without_member_read(
                self.tar_data(files, {"config"}, extra=[extra]), files, {"config"}
            )
        with self.assertRaises(ValueError):
            gate.expected_nodes(files, explicit_directories={"config", "config/public.py"})

    def test_raw_typed_header_preflight_accepts_exact_empty_dirs_and_no_other(self):
        files = [("config/public.py", b"PUBLIC", 0o755)]
        dirs = {"config", "config/empty"}
        raw = self.tar_data(files, dirs)
        rows = gate.checked_typed_members(
            raw,
            {"config/public.py": hashlib.sha256(b"PUBLIC").hexdigest()},
            dirs,
            expected_typed_sha=gate.typed_nodes_digest(files, dirs),
        )
        self.assertEqual(rows, files)
        self.assertEqual(gate.typed_nodes_digest(rows, dirs), gate.typed_nodes_digest(files, dirs))

    def test_selected_file_mode_digest_is_bound_beyond_v1_content_hash(self):
        with self.fs.install():
            receipt = self.model.seal(parity=False)
            _, dirs = gate.directory_selection(set(self.model.report["files"]) | set(gate.CANARIES))
            files = [
                row
                for row in self.model.files
                if row[0] in gate.CONTROLS or gate.copy_selected(row[0])
            ]
            changed = [(n, b, 0o755 if n == "config/public.py" else mode) for n, b, mode in files]
            raw = self.tar_data(changed, dirs)
            receipt = copy.deepcopy(receipt)
            receipt["archive"]["bytes"] = len(raw)
            receipt["archive"]["sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(ValueError, "context_tar_typed_digest"):
                gate.verified_tar(io.BytesIO(raw), receipt, self.model.report)

    def test_metadata_rejects_bad_known_empty_directory_before_file_reads(self):
        files = [("proof/config/public.py", b"PUBLIC", 0o644)]
        dirs = {"proof", "proof/config", "proof/config/empty"}
        for mode in [stat.S_IFDIR | 0o777, stat.S_IFLNK | 0o777, stat.S_IFREG | 0o644]:
            self.fs.add("/export", None, 0o700)
            for name in sorted(dirs):
                self.fs.add("/export/" + name, None, 0o755)
            self.fs.add("/export/proof/config/public.py", b"PUBLIC", 0o644)
            self.fs.nodes["/export/proof/config/empty"]["mode"] = mode
            with self.fs.install(), self.assertRaises(ValueError):
                gate.exported_probe(memory.MemoryPath("/export"), files, directories=dirs)
            self.assertFalse(any(name.startswith("/export/") for name in self.fs.reads))

    def test_old_sealed_and_parity_versions_are_not_current_fallbacks(self):
        with self.fs.install():
            receipt = self.model.seal()
            old = copy.deepcopy(receipt)
            old["schema"] = "pamolive.sealed-build-context/1"
            old.pop("typed_nodes_sha256")
            self.fs.nodes["/sealed/receipt.json"]["data"] = gate.canonical(old)
            self.fs.changed(self.fs.nodes["/sealed/receipt.json"])
            with self.assertRaises(ValueError):
                gate.checked_seal("/sealed/receipt.json", "/sealed/manifest.json", "a" * 40)
            self.fs.nodes["/sealed/receipt.json"]["data"] = gate.canonical(receipt)
            self.fs.changed(self.fs.nodes["/sealed/receipt.json"])
            proof = json.loads(self.fs.nodes["/sealed/probe.json"]["data"])
            proof["schema"] = "pamolive.context-selection-parity/1"
            self.fs.nodes["/sealed/probe.json"]["data"] = gate.canonical(proof)
            self.fs.changed(self.fs.nodes["/sealed/probe.json"])
            with self.assertRaises(ValueError):
                gate.require_probe("/sealed/probe.json", receipt, self.model.report)

    def test_directory_contract_tamper_is_not_authorized_by_shape_or_rehash(self):
        with self.fs.install():
            receipt = self.model.seal()
            proof = json.loads(self.fs.nodes["/sealed/probe.json"]["data"])
            proof["directory_contract"]["probe"]["selected_directories"] += 1
            self.fs.nodes["/sealed/probe.json"]["data"] = gate.canonical(proof)
            self.fs.changed(self.fs.nodes["/sealed/probe.json"])
            with self.assertRaises(ValueError):
                gate.require_probe("/sealed/probe.json", receipt, self.model.report)

    def test_all_seven_canary_files_remain_in_real_input_metadata_contract(self):
        original = gate.write_tar
        with self.fs.install():

            def change(stream, files, **kwargs):
                count = original(stream, files, **kwargs)
                self.fs.changed(self.fs.nodes["/ctx/" + gate.CANARIES[0]])
                return count

            with patch.object(gate, "write_tar", change), self.assertRaises(ValueError):
                self.model.seal(parity=False)
            self.assertTrue(all("/ctx/" + name in self.fs.nodes for name in gate.CANARIES))
            self.assertNotIn("/sealed/receipt.json", self.fs.nodes)
            self.assertEqual(self.fs.reads, [])

    def test_long_pax_paths_are_exact_and_extra_pax_metadata_refuses_before_content(self):
        long_dir = "config/" + "public-directory-" * 9
        files = [(long_dir + "/public.py", b"PUBLIC", 0o644)]
        directories = {"config", long_dir}
        stream = io.BytesIO()
        gate.write_tar(stream, files, directories=directories)
        rows = gate.checked_typed_members(
            stream.getvalue(),
            {files[0][0]: hashlib.sha256(b"PUBLIC").hexdigest()},
            directories,
            expected_typed_sha=gate.typed_nodes_digest(files, directories),
        )
        self.assertEqual(rows, files)

        def redundant_path(member):
            member.pax_headers = {"path": member.name + "/" if member.isdir() else member.name}

        small_files = [("config/public.py", b"PUBLIC", 0o644)]
        self.assert_headers_refuse_without_member_read(
            self.tar_data(small_files, {"config"}, change=redundant_path), small_files, {"config"}
        )

        def change(member):
            member.pax_headers = {"comment": "PRIVATE_CANARY"}

        self.assert_headers_refuse_without_member_read(
            self.tar_data(files, directories, change=change), files, directories
        )

    def test_unrepresented_git_directory_refuses_sealed_before_write_but_legacy_v1_stays(self):
        _, parents = gate.expected_nodes(self.model.files)
        raw = self.tar_data(self.model.files, parents | {"config/empty-git-tree"})
        self.fs.add("/repo", None, 0o700)

        def git(argv, *, stdout, **kwargs):
            stdout.write(raw)
            return memory.SimpleNamespace(returncode=0)

        with (
            self.fs.install(),
            patch.object(gate, "TemporaryFile", io.BytesIO),
            patch.object(gate.subprocess, "run", git),
        ):
            with self.assertRaisesRegex(ValueError, "context_git_directory_unrepresented"):
                gate.create(
                    "/repo",
                    "/rejected",
                    "a" * 40,
                    sealed_archive="/sealed/context.tar",
                    sealed_receipt="/sealed/receipt.json",
                )
            self.assertNotIn("/rejected", self.fs.nodes)
            report = gate.create("/repo", "/legacy", "a" * 40)
        self.assertEqual(report["schema"], "pamolive.committed-build-context.v1")
        self.assertEqual(report["files"], self.model.report["files"])
        self.assertNotIn("/legacy/config/empty-git-tree", self.fs.nodes)

    def test_R2_valid_but_wrong_file_mode_refuses_before_first_member_read(self):
        with self.fs.install():
            receipt = self.model.seal(parity=False)
            _, directories = gate.directory_selection(
                set(self.model.report["files"]) | set(gate.CANARIES)
            )
            files = [
                row
                for row in self.model.files
                if row[0] in gate.CONTROLS or gate.copy_selected(row[0])
            ]
            changed = [
                (name, body, 0o755 if name == "config/public.py" else mode)
                for name, body, mode in files
            ]
            raw = self.tar_data(changed, directories)
            receipt = copy.deepcopy(receipt)
            receipt["archive"]["bytes"] = len(raw)
            receipt["archive"]["sha256"] = hashlib.sha256(raw).hexdigest()
            with patch.object(
                tarfile.TarFile, "extractfile", side_effect=AssertionError("payload_read")
            ) as read:
                with self.assertRaisesRegex(ValueError, "context_tar_typed_digest"):
                    gate.verified_tar(io.BytesIO(raw), receipt, self.model.report)
            read.assert_not_called()

    def test_R2_header_size_only_change_refuses_before_first_member_read(self):
        with self.fs.install():
            receipt = self.model.seal(parity=False)
            original = self.fs.nodes["/sealed/context.tar"]["data"]
            with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as archive:
                member = next(m for m in archive if m.name == "config/public.py")
            offset, size = member.offset, member.size
            raw = bytearray(original)
            raw[offset + 124 : offset + 136] = f"{size + 1:011o}\0".encode("ascii")
            raw[offset + 148 : offset + 156] = b" " * 8
            checksum = sum(raw[offset : offset + 512])
            raw[offset + 148 : offset + 156] = f"{checksum:06o}\0 ".encode("ascii")
            raw = bytes(raw)
            self.assertEqual(len(raw), len(original))
            self.assertEqual(
                raw[offset + 512 : offset + 512 + size],
                original[offset + 512 : offset + 512 + size],
            )
            receipt = copy.deepcopy(receipt)
            receipt["archive"]["sha256"] = hashlib.sha256(raw).hexdigest()
            with patch.object(
                tarfile.TarFile, "extractfile", side_effect=AssertionError("payload_read")
            ) as read:
                with self.assertRaisesRegex(ValueError, "context_tar_typed_digest"):
                    gate.verified_tar(io.BytesIO(raw), receipt, self.model.report)
            read.assert_not_called()

    def test_R2_expected_typed_digest_is_mandatory_and_never_silently_unbound(self):
        files = [("config/public.py", b"PUBLIC", 0o755)]
        directories = {"config"}
        hashes = {"config/public.py": hashlib.sha256(b"PUBLIC").hexdigest()}
        raw = self.tar_data(files, directories)
        with patch.object(
            tarfile.TarFile, "extractfile", side_effect=AssertionError("payload_read")
        ) as read:
            with self.assertRaises(TypeError):
                gate.checked_typed_members(raw, hashes, directories)
            for expected in [None, True, "short", "0" * 64]:
                with self.subTest(expected=expected), self.assertRaises(ValueError):
                    gate.checked_typed_members(
                        raw, hashes, directories, expected_typed_sha=expected
                    )
        read.assert_not_called()
