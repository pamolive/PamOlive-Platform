"""Pure sealed-context seam tests: memory filesystem and subprocess only."""

import copy
import hashlib
import io
import json
import os
import stat
from contextlib import ExitStack, contextmanager
from pathlib import PurePosixPath
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from deploy import build_context as gate


class MemoryPath(PurePosixPath):
    @classmethod
    def cwd(cls):
        return cls("/repo")

    def absolute(self):
        return self

    def resolve(self, strict=False):
        if strict and str(self) not in self.fs.nodes:
            raise FileNotFoundError(str(self))
        return self

    def exists(self):
        return str(self) in self.fs.nodes

    def is_symlink(self):
        return self.exists() and stat.S_ISLNK(self.fs.nodes[str(self)]["mode"])

    def mkdir(self, mode=0o777, parents=False, exist_ok=False):
        if self.exists():
            if not exist_ok:
                raise FileExistsError(str(self))
            return
        if parents:
            for parent in reversed(self.parents):
                if str(parent) not in self.fs.nodes:
                    self.fs.add(str(parent), None, mode)
        self.fs.add(str(self), None, mode)

    def open(self, mode):
        assert mode == "xb"
        fd = self.fs.open(
            self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=str(self.parent)
        )
        return self.fs.fdopen(fd, "wb", buffering=0)

    def chmod(self, mode):
        node = self.fs.nodes[str(self)]
        node["mode"] = stat.S_IFREG | mode
        self.fs.changed(node)


class MemoryStream(io.BytesIO):
    def __init__(self, fs, fd, node):
        self.fs, self.fd, self.node = fs, fd, node
        super().__init__(node["data"])

    def fileno(self):
        return self.fd

    def write(self, data):
        count = super().write(data)
        self.node["data"] = self.getvalue()
        self.fs.changed(self.node)
        return count

    def read(self, count=-1):
        self.fs.reads.append(self.fs.fds[self.fd][0])
        return super().read(count)


class MemoryFS:
    def __init__(self, files):
        self.nodes, self.fds, self.reads, self.opens = {}, {}, [], []
        self.serial = 10
        self.add("/", None, 0o755)
        self.add("/ctx", None, 0o700)
        self.add("/sealed", None, 0o700)
        for name, data, mode in files:
            path = PurePosixPath("/ctx") / name
            for parent in reversed(path.parents):
                if str(parent) not in self.nodes:
                    self.add(str(parent), None, 0o755)
            self.add(str(path), data, mode)

    def add(self, path, data, mode):
        self.serial += 1
        node = {
            "data": data,
            "dev": 1,
            "ino": self.serial,
            "mode": (stat.S_IFDIR if data is None else stat.S_IFREG) | mode,
            "uid": 1001,
            "gid": 1001,
            "nlink": 1,
            "size": 0 if data is None else len(data),
            "mtime_ns": self.serial,
            "ctime_ns": self.serial,
        }
        self.nodes[path] = node
        parent = str(PurePosixPath(path).parent)
        if parent != path and parent in self.nodes:
            self.nodes[parent].update(mtime_ns=self.serial, ctime_ns=self.serial)
        return node

    def changed(self, node):
        self.serial += 1
        node.update(size=len(node["data"]), mtime_ns=self.serial, ctime_ns=self.serial)

    def value(self, node):
        return SimpleNamespace(**{"st_" + key: node[key] for key in gate.IDENTITY_FIELDS})

    def stat(self, name, *, dir_fd, follow_symlinks):
        assert follow_symlinks is False
        path = str(PurePosixPath(self.parent(dir_fd)) / name)
        if path not in self.nodes:
            raise FileNotFoundError(path)
        return self.value(self.nodes[path])

    def parent(self, descriptor):
        return self.fds[descriptor][0] if isinstance(descriptor, int) else descriptor

    def fstat(self, descriptor):
        return self.value(
            self.fds[descriptor][1] if isinstance(descriptor, int) else self.nodes[descriptor]
        )

    def open(self, name, flags, mode=0o777, *, dir_fd):
        path = str(PurePosixPath(self.parent(dir_fd)) / name)
        self.opens.append(path)
        if flags & os.O_CREAT:
            if path in self.nodes:
                raise FileExistsError(path)
            node = self.add(path, b"", mode)
        else:
            node = self.nodes[path]
        self.serial += 1
        self.fds[self.serial] = (path, node)
        return self.serial

    def fdopen(self, fd, mode, *, buffering):
        assert buffering == 0
        return MemoryStream(self, fd, self.fds[fd][1])

    def mkdir(self, name, mode, *, dir_fd):
        path = str(PurePosixPath(self.parent(dir_fd)) / name)
        if path in self.nodes:
            raise FileExistsError(path)
        self.add(path, None, mode)

    def chmod(self, fd, mode):
        node = self.fds[fd][1]
        node["mode"] = stat.S_IFREG | mode
        self.changed(node)

    @contextmanager
    def scandir(self, fd):
        parent = self.parent(fd)
        names = [
            PurePosixPath(path).name
            for path in self.nodes
            if path != parent and str(PurePosixPath(path).parent) == parent
        ]
        yield iter(SimpleNamespace(name=name) for name in sorted(names))

    @contextmanager
    def directory(self, path):
        name = str(path)
        if not stat.S_ISDIR(self.nodes[name]["mode"]):
            raise ValueError("memory_directory")
        yield name

    @contextmanager
    def install(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(gate, "Path", MemoryPath))
            stack.enter_context(patch.object(MemoryPath, "fs", self, create=True))
            stack.enter_context(patch.object(gate, "directory", self.directory))
            stack.enter_context(patch.object(gate.sys, "platform", "linux"))
            for name in ["stat", "fstat", "open", "fdopen", "mkdir", "scandir"]:
                stack.enter_context(patch.object(gate.os, name, getattr(self, name)))
            stack.enter_context(patch.object(gate.os, "fchmod", self.chmod, create=True))
            stack.enter_context(patch.object(gate.os, "fsync", lambda fd: None))
            stack.enter_context(patch.object(gate.os, "close", lambda fd: None))
            for name in ["geteuid", "getegid"]:
                stack.enter_context(patch.object(gate.os, name, lambda: 1001, create=True))
            for number, name in enumerate(["O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"], 12):
                stack.enter_context(patch.object(gate.os, name, 1 << number, create=True))
            yield


class SealedContextTests(TestCase):
    def setUp(self):
        # Explicit control DATA doubles: these tests also run inside the image,
        # which deliberately contains neither the repository Dockerfile nor .github.
        dockerfile = b"FROM scratch\n"
        dockerignore = b"**\n!config/\n!config/**\n"
        for name, data in (("DOCKERFILE_SHA", dockerfile), ("DOCKERIGNORE_SHA", dockerignore)):
            double = patch.object(gate, name, hashlib.sha256(data).hexdigest())
            double.start()
            self.addCleanup(double.stop)
        self.files = [
            ("Dockerfile", dockerfile, 0o644),
            (".dockerignore", dockerignore, 0o644),
            ("config/public.py", b"PUBLIC=1\n", 0o644),
            ("tests/public.py", b"PASS=1\n", 0o644),
        ]
        self.fs = MemoryFS(self.files)
        self.written = {
            name: gate.identity(self.fs.value(self.fs.nodes["/ctx/" + name]))
            for name, _, _ in self.files
        }
        self.report = {
            "schema": "pamolive.committed-build-context.v1",
            "revision": "a" * 40,
            "archive_sha256": "b" * 64,
            "files": {name: hashlib.sha256(data).hexdigest() for name, data, _ in self.files},
        }

    def consume(self, *args, **kwargs):
        return gate.consume(
            *args, source_path="/sealed/manifest.json", probe_path="/sealed/probe.json", **kwargs
        )

    def probe_run(self, argv, *, check):
        assert not check and argv[:3] == ["docker", "build", "--file"]
        source = argv[-1]
        exported = argv[argv.index("--output") + 1].removeprefix("type=local,dest=")
        self.fs.add(exported, None, 0o700)
        for path, node in list(self.fs.nodes.items()):
            if path.startswith(source + "/") and node["data"] is not None:
                name = path[len(source) + 1 :]
                if gate.copy_selected(name):
                    target = PurePosixPath(exported) / "proof" / name
                    for parent in reversed(target.parents):
                        if str(parent) not in self.fs.nodes:
                            self.fs.add(str(parent), None, 0o755)
                    self.fs.add(str(target), node["data"], 0o644)
        return SimpleNamespace(returncode=0)

    def seal(self, *, parity=True):
        self.fs.add(
            "/sealed/manifest.json", gate.canonical({**self.report, "recipe_bound": False}), 0o644
        )
        gate.seal_context(
            MemoryPath("/ctx"),
            self.files,
            self.written,
            self.report,
            MemoryPath("/sealed/context.tar"),
            MemoryPath("/sealed/receipt.json"),
        )
        if parity:
            with patch.object(gate.subprocess, "run", self.probe_run):
                gate.probe(
                    "/sealed/context.tar",
                    "/sealed/receipt.json",
                    "/sealed/manifest.json",
                    "/sealed/probe.json",
                    "a" * 40,
                )
        return json.loads(self.fs.nodes["/sealed/receipt.json"]["data"])

    def test_real_producer_and_two_consumers_use_one_exact_archive(self):
        with self.fs.install():
            receipt = self.seal()
            archive = self.fs.nodes["/sealed/context.tar"]["data"]
            calls = []

            def run(argv, *, stdin, check):
                self.assertFalse(check)
                self.assertEqual(stdin.tell(), 0)
                self.assertEqual(stdin.read(), archive)
                calls.append((argv, stdin.fileno()))
                return SimpleNamespace(returncode=0)

            with patch.object(gate.subprocess, "run", run):
                for target in ["production", "native-test"]:
                    self.assertEqual(
                        self.consume(
                            "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, target
                        ),
                        0,
                    )
            self.assertEqual(len(calls), 2)
            for argv, _ in calls:
                self.assertEqual(argv[-3:], ["--file", "Dockerfile", "-"])
            self.assertIn("--provenance=false", calls[0][0])
            self.assertNotIn("--provenance=false", calls[1][0])
            self.assertEqual(receipt["synthetic_files"], list(gate.CANARIES))
            self.assertFalse(
                receipt["recipe_bound"] or receipt["authority"] or receipt["build_verified"]
            )
            self.assertEqual(
                receipt["committed_manifest_sha256"],
                hashlib.sha256(gate.canonical({**self.report, "recipe_bound": False})).hexdigest(),
            )
            self.assertTrue(all(path.startswith("/sealed/") for path in self.fs.reads))

    def test_unknown_secret_addition_refuses_before_open_or_read(self):
        self.fs.add("/ctx/config/private.pem", b"PRIVATE-CANARY-NEVER-READ", 0o644)
        with self.fs.install(), self.assertRaisesRegex(ValueError, "context_unknown_entry"):
            self.seal()
        self.assertNotIn("/ctx/config/private.pem", self.fs.opens)
        self.assertTrue(all(self.fs.nodes[path]["data"] is None for path in self.fs.opens))
        self.assertEqual(self.fs.reads, [])

    def test_missing_modified_mode_owner_link_and_alias_refuse_without_content(self):
        for mutation in ["missing", "ctime_ns", "mode", "uid", "gid", "nlink", "ino", "size"]:
            fs = copy.deepcopy(self.fs)
            node = fs.nodes["/ctx/config/public.py"]
            if mutation == "missing":
                del fs.nodes["/ctx/config/public.py"]
            else:
                node[mutation] += 1
            with self.subTest(mutation=mutation), fs.install(), self.assertRaises(ValueError):
                self.seal()
            self.assertEqual(fs.reads, [])

    def test_symlink_directory_and_duplicate_inode_are_not_traversed(self):
        for kind in ["directory_link", "file_link", "hardlink"]:
            fs = copy.deepcopy(self.fs)
            if kind == "directory_link":
                fs.nodes["/ctx/config"]["mode"] = stat.S_IFLNK | 0o755
            elif kind == "file_link":
                fs.nodes["/ctx/config/public.py"]["mode"] = stat.S_IFLNK | 0o644
            else:
                fs.nodes["/ctx/tests/public.py"]["ino"] = fs.nodes["/ctx/config/public.py"]["ino"]
            with self.subTest(kind=kind), fs.install(), self.assertRaises(ValueError):
                self.seal()
            self.assertEqual(fs.reads, [])

    def test_output_collision_keeps_existing_bytes(self):
        self.fs.add("/sealed/context.tar", b"DO-NOT-OVERWRITE", 0o400)
        with self.fs.install(), self.assertRaises(FileExistsError):
            self.seal()
        self.assertEqual(self.fs.nodes["/sealed/context.tar"]["data"], b"DO-NOT-OVERWRITE")
        self.assertNotIn("/sealed/receipt.json", self.fs.nodes)

    def test_actual_tree_contents_never_feed_tar_even_under_forged_metadata(self):
        # No host content read: even a hostile model with preserved metadata cannot leak bytes.
        node = self.fs.nodes["/ctx/config/public.py"]
        node["data"] = b"SECRET!!\n"
        with self.fs.install():
            self.seal()
        raw = self.fs.nodes["/sealed/context.tar"]["data"]
        self.assertNotIn(b"SECRET!!", raw)
        self.assertIn(b"PUBLIC=1\n", raw)
        self.assertTrue(all(path.startswith("/sealed/") for path in self.fs.reads))

    def test_substitution_before_open_prevents_any_build(self):
        with self.fs.install():
            self.seal()
            old = self.fs.nodes["/sealed/context.tar"]
            self.fs.add("/sealed/context.tar", old["data"], 0o400)
            self.fs.opens.clear()
            with patch.object(gate.subprocess, "run") as run, self.assertRaises(ValueError):
                self.consume("/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production")
            run.assert_not_called()
            self.assertNotIn("/sealed/context.tar", self.fs.opens)

    def test_mutation_after_first_build_refuses_without_claiming_rollback(self):
        with self.fs.install():
            self.seal()
            built = []

            def run(argv, *, stdin, check):
                built.append(argv)
                node = self.fs.nodes["/sealed/context.tar"]
                self.fs.changed(node)
                return SimpleNamespace(returncode=0)

            with patch.object(gate.subprocess, "run", run), self.assertRaises(ValueError):
                self.consume("/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production")
            self.assertEqual(len(built), 1)
            with patch.object(gate.subprocess, "run") as second, self.assertRaises(ValueError):
                self.consume("/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "native-test")
            second.assert_not_called()

    def test_path_swap_during_build_is_refused_even_when_fd_bytes_unchanged(self):
        with self.fs.install():
            self.seal()

            def run(argv, *, stdin, check):
                old = self.fs.nodes["/sealed/context.tar"]
                self.fs.add("/sealed/context.tar", old["data"], 0o400)
                return SimpleNamespace(returncode=0)

            with (
                patch.object(gate.subprocess, "run", run),
                self.assertRaisesRegex(ValueError, "context_archive_changed"),
            ):
                self.consume("/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production")

    def test_nonzero_docker_is_retained_and_unknown_never_success(self):
        with self.fs.install():
            self.seal()
            for rc in [2, -9]:
                with patch.object(
                    gate.subprocess, "run", return_value=SimpleNamespace(returncode=rc)
                ):
                    self.assertEqual(
                        self.consume(
                            "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                        ),
                        rc,
                    )
            for result in [SimpleNamespace(returncode=False), OSError("PRIVATE-CANARY")]:
                kwargs = (
                    {"side_effect": result}
                    if isinstance(result, Exception)
                    else {"return_value": result}
                )
                with (
                    patch.object(gate.subprocess, "run", **kwargs),
                    self.assertRaises((ValueError, OSError)),
                ):
                    self.consume(
                        "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                    )

    def test_receipt_contract_wrong_revision_flags_hashes_types_and_fields_refuse(self):
        with self.fs.install():
            receipt = self.seal()
            changes = [
                {"revision": "c" * 40},
                {"authority": True},
                {"source_files": True},
                {"unknown": "PRIVATE-CANARY"},
                {"synthetic_files": []},
                {"tar_policy": "unknown"},
                {"committed_manifest_sha256": "invalid"},
            ]
            for change in changes:
                changed = {**receipt, **change}
                with (
                    self.subTest(change=change),
                    patch.object(gate, "read_receipt", return_value=changed),
                    patch.object(gate.subprocess, "run") as run,
                    self.assertRaises(ValueError),
                ):
                    self.consume(
                        "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                    )
                run.assert_not_called()

    def test_duplicate_receipt_keys_refuse(self):
        with self.fs.install():
            self.seal()
            node = self.fs.nodes["/sealed/receipt.json"]
            node["data"] = b'{"schema":1,"schema":2}'
            self.fs.changed(node)
            with self.assertRaisesRegex(ValueError, "context_receipt_duplicate"):
                gate.read_receipt("/sealed/receipt.json")

    def test_generated_tar_paths_collision_and_all_budgets_are_finite(self):
        for extra in [
            ("Dockerfile", b"x", 0o644),
            ("dockerfile", b"x", 0o644),
            ("config", b"x", 0o644),
            ("../escape", b"x", 0o644),
            ("/absolute", b"x", 0o644),
            ("x:y", b"x", 0o644),
        ]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gate.write_tar(io.BytesIO(), [*self.files, extra])
        for name in ["MAX_FILES", "MAX_FILE", "MAX_BYTES"]:
            with patch.object(gate, name, 1), self.assertRaises(ValueError):
                gate.write_tar(io.BytesIO(), self.files)
        with (
            patch.object(gate, "MAX_BYTES", sum(len(row[1]) for row in self.files) + 512),
            self.assertRaisesRegex(ValueError, "context_sealed_archive_budget"),
        ):
            gate.write_tar(io.BytesIO(), self.files)

    def test_short_archive_write_is_fatal(self):
        stream = SimpleNamespace(write=lambda raw: len(raw) - 1)
        with self.assertRaisesRegex(ValueError, "context_archive_short_write"):
            gate.write_tar(stream, self.files)

    def test_actual_create_legacy_manifest_and_seal_share_verified_Git_buffers(self):
        raw = io.BytesIO()
        gate.write_tar(raw, self.files)
        git_bytes = raw.getvalue()
        self.fs.add("/repo", None, 0o700)

        def git(argv, *, stdout, stderr, timeout, check):
            self.assertEqual(argv[-3:], ["archive", "--format=tar", "a" * 40])
            self.assertEqual(timeout, 30)
            self.assertFalse(check)
            stdout.write(git_bytes)
            return SimpleNamespace(returncode=0)

        with (
            self.fs.install(),
            patch.object(gate, "TemporaryFile", io.BytesIO),
            patch.object(gate.subprocess, "run", git),
        ):
            report = gate.create(
                "/repo",
                "/newctx",
                "a" * 40,
                sealed_archive="/sealed/context.tar",
                sealed_receipt="/sealed/receipt.json",
            )
        self.assertEqual(
            report, {**self.report, "archive_sha256": hashlib.sha256(git_bytes).hexdigest()}
        )
        self.assertTrue(all(path.startswith("/sealed/") for path in self.fs.reads))
        receipt = json.loads(self.fs.nodes["/sealed/receipt.json"]["data"])
        self.assertEqual(
            receipt["committed_manifest_sha256"],
            hashlib.sha256(gate.canonical({**report, "recipe_bound": False})).hexdigest(),
        )

    def test_archive_content_mismatch_refuses_before_build_even_with_preserved_metadata(self):
        with self.fs.install():
            self.seal()
            node = self.fs.nodes["/sealed/context.tar"]
            node["data"] = b"X" + node["data"][1:]
            with (
                patch.object(gate.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "context_archive_hash"),
            ):
                self.consume("/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production")
            run.assert_not_called()

    def test_archive_read_growth_short_identity_and_receipt_budgets_refuse(self):
        with self.assertRaises(ValueError):
            gate.stream_hash(io.BytesIO(b"xx"), 1)
        with self.assertRaises(ValueError):
            gate.stream_hash(io.BytesIO(b""), 1)
        for count in [True, 0, gate.MAX_BYTES + 1]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                gate.stream_hash(io.BytesIO(), count)
        with self.fs.install():
            receipt = self.seal()
            for key, value in [
                ("mode", stat.S_IFLNK | 0o400),
                ("nlink", 2),
                ("size", True),
                ("uid", 0),
            ]:
                expected = {**receipt["archive"]["identity"], key: value}
                with (
                    self.subTest(key=key),
                    self.assertRaises(ValueError),
                    gate.bound_archive("/sealed/context.tar", expected),
                ):
                    self.fail("invalid identity admitted")
            node = self.fs.nodes["/sealed/receipt.json"]
            node["size"] = 16385
            self.fs.opens.clear()
            with self.assertRaisesRegex(ValueError, "context_receipt_file"):
                gate.read_receipt("/sealed/receipt.json")
            self.assertEqual(self.fs.opens, [])

    def test_canary_collision_and_inside_context_outputs_refuse(self):
        for path in ["/ctx/new.tar", "/ctx/config/receipt.json"]:
            with (
                self.subTest(path=path),
                self.fs.install(),
                self.assertRaisesRegex(ValueError, "context_output_inside_input"),
            ):
                gate.seal_context(
                    MemoryPath("/ctx"),
                    self.files,
                    self.written,
                    self.report,
                    MemoryPath(path),
                    MemoryPath("/sealed/receipt.json"),
                )
        self.fs.add("/ctx/.bootstrap-admin", b"UNKNOWN-NEVER-READ", 0o644)
        with self.fs.install(), self.assertRaises(ValueError):
            self.seal()
        self.assertEqual(self.fs.reads, [])

    def test_tar_repeated_serialization_order_and_canonical_metadata(self):
        import tarfile

        first, second = io.BytesIO(), io.BytesIO()
        gate.write_tar(first, self.files)
        gate.write_tar(second, list(reversed(self.files)))
        self.assertEqual(first.getvalue(), second.getvalue())
        with tarfile.open(fileobj=io.BytesIO(first.getvalue()), mode="r:") as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), 6)
            self.assertEqual(len({row.name.casefold() for row in members}), 6)
            for member in members:
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertTrue(member.isfile() or member.isdir())
                self.assertEqual(member.mode, 0o755 if member.isdir() else 0o644)

    def test_third_target_shares_seal_and_preserves_exact_reference_argv(self):
        self.fs.add("/runner", None, 0o700)
        with self.fs.install(), patch.dict(gate.os.environ, {"RUNNER_TEMP": "/runner"}):
            self.seal()
            original = self.fs.nodes["/sealed/context.tar"]
            calls = []

            def run(argv, *, stdin, check):
                self.assertFalse(check)
                self.assertIs(self.fs.fds[stdin.fileno()][1], original)
                self.assertEqual(stdin.read(), original["data"])
                calls.append(argv)
                return SimpleNamespace(returncode=0)

            with patch.object(gate.subprocess, "run", run):
                for target in ["production", "native-test", "json-reference-data"]:
                    output = (
                        "/runner/pamolive-jansson-reference-data"
                        if target == "json-reference-data"
                        else None
                    )
                    self.assertEqual(
                        self.consume(
                            "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, target, output
                        ),
                        0,
                    )
            self.assertEqual(
                calls[2],
                [
                    "docker",
                    "build",
                    "--target",
                    "json-reference-data",
                    "--provenance=false",
                    "--sbom=false",
                    "--output",
                    "type=local,dest=/runner/pamolive-jansson-reference-data",
                    "--file",
                    "Dockerfile",
                    "-",
                ],
            )

    def test_reference_output_never_selects_unexpected_path_or_overwrites_existing(self):
        self.fs.add("/runner", None, 0o700)
        with self.fs.install(), patch.dict(gate.os.environ, {"RUNNER_TEMP": "/runner"}):
            self.seal()
            for target, output in [
                ("json-reference-data", None),
                ("json-reference-data", "/other"),
                ("json-reference-data", "/runner/x/../pamolive-jansson-reference-data"),
                ("production", "/runner/pamolive-jansson-reference-data"),
                ("native-test", "/runner/pamolive-jansson-reference-data"),
                ("unexpected", None),
            ]:
                with (
                    self.subTest(target=target, output=output),
                    patch.object(gate.subprocess, "run") as run,
                    self.assertRaises(ValueError),
                ):
                    self.consume(
                        "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, target, output
                    )
                run.assert_not_called()
            self.fs.add("/runner/pamolive-jansson-reference-data", None, 0o700)
            with (
                patch.object(gate.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "context_reference_output_exists"),
            ):
                self.consume(
                    "/sealed/context.tar",
                    "/sealed/receipt.json",
                    "a" * 40,
                    "json-reference-data",
                    "/runner/pamolive-jansson-reference-data",
                )
            run.assert_not_called()

    def test_consumer_cli_redacts_original_exception_and_never_claims_rollback(self):
        from contextlib import redirect_stdout

        with self.fs.install():
            self.seal()
            argv = [
                "build_context",
                "--revision",
                "a" * 40,
                "--sealed-archive",
                "/sealed/context.tar",
                "--sealed-receipt",
                "/sealed/receipt.json",
                "--build-target",
                "production",
                "--source-manifest",
                "/sealed/manifest.json",
                "--probe-receipt",
                "/sealed/probe.json",
            ]
            output = io.StringIO()
            with (
                patch.object(gate.sys, "argv", argv),
                # argparse locale discovery uses the process-wide os.stat too.
                # Keep the memory filesystem seam independent of host LANG.
                patch.object(gate.argparse, "_", lambda message: message),
                redirect_stdout(output),
                patch.object(gate.subprocess, "run", side_effect=OSError("PRIVATE-NEVER-PUBLISH")),
            ):
                self.assertEqual(gate.main(), 1)
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertEqual(
                json.loads(output.getvalue()),
                {"consumed": False, "error": "sealed_context_refused", "build_may_have_run": True},
            )

    def test_ancestor_fds_are_no_follow_and_all_close_on_failure(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(gate, "Path", MemoryPath))
            stack.enter_context(patch.object(gate.sys, "platform", "linux"))
            for number, name in enumerate(["O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"], 12):
                stack.enter_context(patch.object(gate.os, name, 1 << number, create=True))
            opened = stack.enter_context(patch.object(gate.os, "open", side_effect=[100, 101, 102]))
            closed = stack.enter_context(patch.object(gate.os, "close"))
            with gate.directory("/tmp/owned") as fd:
                self.assertEqual(fd, 102)
            self.assertEqual(
                [call.args[0] for call in opened.call_args_list], ["/", "tmp", "owned"]
            )
            self.assertTrue(
                all(call.args[1] & gate.os.O_NOFOLLOW for call in opened.call_args_list[1:])
            )
            self.assertEqual([call.args[0] for call in closed.call_args_list], [102, 101, 100])
            opened.reset_mock()
            closed.reset_mock()
            opened.side_effect = [200, OSError("alias refused")]
            with self.assertRaises(OSError), gate.directory("/alias/never"):
                self.fail("alias admitted")
            self.assertEqual(opened.call_count, 2)
            closed.assert_called_once_with(200)

    def test_post_write_tree_mutation_keeps_receipt_absent(self):
        original = gate.write_tar
        with self.fs.install():

            def changed(stream, files):
                count = original(stream, files)
                self.fs.changed(self.fs.nodes["/ctx/config/public.py"])
                return count

            with (
                patch.object(gate, "write_tar", changed),
                self.assertRaisesRegex(ValueError, "context_file_changed"),
            ):
                self.seal()
        self.assertIn("/sealed/context.tar", self.fs.nodes)
        self.assertNotIn("/sealed/receipt.json", self.fs.nodes)
        self.assertEqual(self.fs.reads, [])

    def test_output_parent_owner_and_mode_are_required_before_create(self):
        for key, value in [("uid", 0), ("gid", 0), ("mode", stat.S_IFDIR | 0o777)]:
            fs = copy.deepcopy(self.fs)
            fs.nodes["/sealed"][key] = value
            with (
                self.subTest(key=key),
                fs.install(),
                self.assertRaisesRegex(ValueError, "context_private_output_parent"),
            ):
                self.seal()
            self.assertNotIn("/sealed/context.tar", fs.nodes)
            self.assertEqual(fs.reads, [])

    def replace_json(self, path, value):
        node = self.fs.nodes[path]
        node["data"] = gate.canonical(value)
        self.fs.changed(node)

    def test_profile_controls_are_pinned_and_control_is_not_copy_source(self):
        selected, report = gate.selection(self.files)
        self.assertIn(".dockerignore", [name for name, _, _ in selected])
        self.assertFalse(gate.copy_selected(".dockerignore"))
        self.assertTrue(gate.copy_selected("Dockerfile"))
        self.assertEqual(report["synthetic_in_tar"], 0)
        for control in gate.CONTROLS:
            changed = [
                (name, data + b"\n" if name == control else data, mode)
                for name, data, mode in self.files
            ]
            with (
                self.subTest(control=control),
                self.assertRaisesRegex(ValueError, "context_selection_profile"),
            ):
                gate.selection(changed)
        for name, expected in gate.PROBE_COUNTERS:
            self.assertIs(gate.copy_selected(name), expected)

    def test_v1_changed_duplicate_or_nonregular_refuses_before_docker(self):
        for kind in ("raw", "duplicate", "link", "large", "mode", "owner", "nlink"):
            self.setUp()
            with self.fs.install():
                self.seal()
                node = self.fs.nodes["/sealed/manifest.json"]
                if kind == "raw":
                    node["data"] += b" "
                elif kind == "duplicate":
                    node["data"] = b'{"files":{},"files":{}}'
                elif kind == "link":
                    node["mode"] = stat.S_IFLNK | 0o644
                elif kind == "large":
                    node["data"] = b"x" * (2 * 1024**2 + 1)
                elif kind == "mode":
                    node["mode"] = stat.S_IFREG | 0o666
                elif kind == "owner":
                    node["uid"] = 0
                else:
                    node["nlink"] = 2
                self.fs.changed(node)
                with self.subTest(kind=kind), patch.object(gate.subprocess, "run") as run:
                    with self.assertRaises(ValueError):
                        self.consume(
                            "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                        )
                    run.assert_not_called()
                if kind in ("link", "large", "mode", "owner", "nlink"):
                    # Precheck refuses before opening this newly inadmissible object.
                    self.assertNotEqual(self.fs.reads[-1:], ["/sealed/manifest.json"])

    def test_v1_semantic_changes_cannot_be_approved_by_rehashing_only(self):
        for kind in (
            "revision",
            "git_hash",
            "count",
            "missing",
            "case_alias",
            "path_alias",
            "bool_selection",
        ):
            self.setUp()
            with self.fs.install():
                receipt = self.seal()
                manifest = json.loads(self.fs.nodes["/sealed/manifest.json"]["data"])
                if kind == "revision":
                    manifest["revision"] = "c" * 40
                elif kind == "git_hash":
                    manifest["archive_sha256"] = "d" * 64
                elif kind == "count":
                    receipt["source_files"] += 1
                elif kind == "missing":
                    del manifest["files"]["Dockerfile"]
                elif kind == "case_alias":
                    manifest["files"]["Config/public.py"] = "e" * 64
                elif kind == "path_alias":
                    manifest["files"]["config/../unreviewed"] = "e" * 64
                else:
                    receipt["selection"]["synthetic_in_tar"] = False
                raw = gate.canonical(manifest)
                receipt["committed_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
                self.replace_json("/sealed/manifest.json", manifest)
                self.replace_json("/sealed/receipt.json", receipt)
                with self.subTest(kind=kind), patch.object(gate.subprocess, "run") as run:
                    with self.assertRaises(ValueError):
                        self.consume(
                            "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                        )
                    run.assert_not_called()

    def test_tar_contents_must_match_v1_file_map_not_only_shape_and_archive_hash(self):
        with self.fs.install():
            receipt = self.seal()
            manifest = json.loads(self.fs.nodes["/sealed/manifest.json"]["data"])
            manifest["files"]["config/public.py"] = "e" * 64
            receipt["committed_manifest_sha256"] = hashlib.sha256(
                gate.canonical(manifest)
            ).hexdigest()
            self.replace_json("/sealed/manifest.json", manifest)
            self.replace_json("/sealed/receipt.json", receipt)
            parity = json.loads(self.fs.nodes["/sealed/probe.json"]["data"])
            parity["committed_manifest_sha256"] = receipt["committed_manifest_sha256"]
            self.replace_json("/sealed/probe.json", parity)
            with patch.object(gate.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "context_tar_manifest"):
                    self.consume(
                        "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                    )
                run.assert_not_called()

    def test_probe_rejects_extra_missing_mode_alias_and_wrong_marker_bytes(self):
        for kind in ("extra", "missing", "mode", "alias", "bytes"):
            self.setUp()
            with self.fs.install():
                self.seal(parity=False)

                def run(argv, *, check):
                    result = self.probe_run(argv, check=check)
                    prefix = "/sealed/probe-export/proof/"
                    node = self.fs.nodes[prefix + "config/public.py"]
                    if kind == "extra":
                        self.fs.add(prefix + "secret.pem", b"NEVER-READ", 0o644)
                    elif kind == "missing":
                        del self.fs.nodes[prefix + "config/public.py"]
                    elif kind == "mode":
                        node["mode"] = stat.S_IFREG | 0o777
                    elif kind == "alias":
                        node["ino"] = self.fs.nodes[prefix + "tests/public.py"]["ino"]
                    else:
                        node["data"] = b"!" * len(node["data"])
                    return result

                start = len(self.fs.reads)
                with self.subTest(kind=kind), patch.object(gate.subprocess, "run", run):
                    with self.assertRaises(ValueError):
                        gate.probe(
                            "/sealed/context.tar",
                            "/sealed/receipt.json",
                            "/sealed/manifest.json",
                            "/sealed/probe.json",
                            "a" * 40,
                        )
                self.assertNotIn("/sealed/probe.json", self.fs.nodes)
                self.assertNotIn("/sealed/probe-export/proof/secret.pem", self.fs.opens)
                if kind != "bytes":
                    self.assertFalse(
                        any(
                            path.startswith("/sealed/probe-export/")
                            for path in self.fs.reads[start:]
                        )
                    )

    def test_probe_nonzero_signal_timeout_and_collision_never_publish_pass(self):
        for kind in ("nonzero", "signal", "timeout", "collision"):
            self.setUp()
            with self.fs.install():
                self.seal(parity=False)
                if kind == "collision":
                    self.fs.add("/sealed/probe-export", None, 0o700)

                def run(argv, *, check):
                    if kind == "timeout":
                        raise gate.subprocess.TimeoutExpired(argv, 60)
                    return SimpleNamespace(returncode=-15 if kind == "signal" else 1)

                with (
                    self.subTest(kind=kind),
                    patch.object(gate.subprocess, "run", side_effect=run) as call,
                ):
                    with self.assertRaises((ValueError, gate.subprocess.TimeoutExpired)):
                        gate.probe(
                            "/sealed/context.tar",
                            "/sealed/receipt.json",
                            "/sealed/manifest.json",
                            "/sealed/probe.json",
                            "a" * 40,
                        )
                    if kind == "collision":
                        call.assert_not_called()
                self.assertNotIn("/sealed/probe.json", self.fs.nodes)

    def test_probe_receipt_context_counts_and_marker_digest_are_not_shape_only(self):
        for field, value in (
            ("revision", "c" * 40),
            ("archive_sha256", "e" * 64),
            ("exported_files", True),
            ("source_files", 99),
            ("exported_public_markers_sha256", "0" * 64),
            ("authority", True),
            ("H1_qualified", True),
            ("status", "UNKNOWN"),
        ):
            self.setUp()
            with self.fs.install():
                self.seal()
                parity = json.loads(self.fs.nodes["/sealed/probe.json"]["data"])
                parity[field] = value
                self.replace_json("/sealed/probe.json", parity)
                with self.subTest(field=field), patch.object(gate.subprocess, "run") as run:
                    with self.assertRaises(ValueError):
                        self.consume(
                            "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "native-test"
                        )
                    run.assert_not_called()

    def test_probe_or_v1_missing_cannot_be_bypassed_by_any_of_three_consumers(self):
        with self.fs.install():
            self.seal()
            for target in ("production", "native-test", "json-reference-data"):
                with self.subTest(target=target), patch.object(gate.subprocess, "run") as run:
                    for source, parity in (
                        (None, "/sealed/probe.json"),
                        ("/sealed/manifest.json", None),
                    ):
                        with self.assertRaises(ValueError):
                            gate.consume(
                                "/sealed/context.tar",
                                "/sealed/receipt.json",
                                "a" * 40,
                                target,
                                source_path=source,
                                probe_path=parity,
                            )
                    run.assert_not_called()

    def test_archive_size_type_and_v1_stability_refuse_before_consumer(self):
        self.setUp()
        with self.fs.install():
            receipt = self.seal()
            receipt["archive"]["bytes"] = float(receipt["archive"]["bytes"])
            self.replace_json("/sealed/receipt.json", receipt)
            with patch.object(gate.subprocess, "run") as call:
                with self.assertRaises(ValueError):
                    self.consume(
                        "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                    )
                call.assert_not_called()
        self.setUp()
        with self.fs.install():
            self.seal()
            original = self.fs.fdopen

            def fdopen(fd, mode, *, buffering):
                stream = original(fd, mode, buffering=buffering)
                if self.fs.fds[fd][0] == "/sealed/manifest.json":
                    read = stream.read

                    def swap(count=-1):
                        value = read(count)
                        self.fs.add("/sealed/manifest.json", value, 0o644)
                        return value

                    stream.read = swap
                return stream

            with (
                patch.object(gate.os, "fdopen", fdopen),
                patch.object(gate.subprocess, "run") as call,
            ):
                with self.assertRaisesRegex(ValueError, "context_receipt_changed"):
                    self.consume(
                        "/sealed/context.tar", "/sealed/receipt.json", "a" * 40, "production"
                    )
                call.assert_not_called()
