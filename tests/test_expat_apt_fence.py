"""Finite fence preparation tests; all libc/process/exec boundaries are doubles."""

import ast
import copy
import importlib.util
import io
import json
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if "c_tests" in sys.modules:
    old = sys.modules["c_tests"]
else:
    spec = importlib.util.spec_from_file_location(
        "c_fence_fixture", ROOT / "tests/test_expat_apt.py"
    )
    old = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = old
    spec.loader.exec_module(old)
f, t, m = old.fence, old.t, old.m
io_helper = old.module("c_fence_H172_model", "bounded_io.py")


def row(ino=2, mode=stat.S_IFREG | 0o444):
    return SimpleNamespace(
        st_dev=1,
        st_ino=ino,
        st_mode=mode,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
        st_size=123,
        st_mtime_ns=4,
        st_ctime_ns=5,
    )


def config():
    return (
        t.apt_configuration()
        .replace(
            b'Dir::Etc::sourcelist "/dev/null";',
            b'Dir::Etc::sourcelist "/expat-apt-work/solver.sources.list";',
        )
        .replace(
            b'Dir::State::lists "/expat-apt-work/empty-lists";',
            b'Dir::State::lists "/expat-apt-work/solver-lists";',
        )
        .replace(
            b'APT::Get::Download "false";',
            b'APT::Get::Download "true";',
        )
        + b'APT::Color "false";\nAPT::Get::Show-Versions "true";\n'
    )


def packet(pid=123, ordinal=1, helper="h", code="c", py=None, apt=None):
    py = py or ("b" * 64, f.identity(row()))
    apt = apt or ("a" * 64, f.identity(row()))
    return {
        "schema": "pamolive.expat-APT-network-fence-DATA/1",
        "role": f.ROLE,
        "pid": pid,
        "code_pins_sha256": code,
        "helper_sha256": helper,
        "python_sha256": py[0],
        "python_identity": list(py[1]),
        "APT_sha256": apt[0],
        "APT_identity": list(apt[1]),
        "config_sha256": f.SOLVER_CONFIG_SHA,
        "filter_sha256": f.filter_sha(),
        "NNP": 1,
        "seccomp_mode": 2,
        "close_range_UNSHARE": True,
        "stdio": ["DEVNULL", "PIPE", "PIPE"],
        "ordinal": ordinal,
        "build_verified": False,
        "materials_complete": False,
        "operational_GO": False,
    }


class FenceTests(unittest.TestCase):
    def test_62_exact_BPF_denies_all_network_escape_holes_future_and_x32(self):
        for nr in f.NETWORK_DENIED | f.ESCAPE_DENIED:
            self.assertEqual(f.model_filter(f.ARCH_X86_64, nr), f.DENY)
        holes = set(range(max(f.KNOWN_SYSCALLS) + 1)) - set(f.KNOWN_SYSCALLS)
        self.assertTrue(holes)
        for nr in holes | {9999, f.X32_BIT | 39, 0xFFFFFFFF}:
            self.assertEqual(f.model_filter(f.ARCH_X86_64, nr), f.DENY)
        for arch in (0, 0x40000003, 0xC00000B7):
            self.assertEqual(f.model_filter(arch, 39), f.KILL)
        for nr in (0, 1, 3, 39, 57, 59, 60, 231, 322):
            self.assertEqual(f.model_filter(f.ARCH_X86_64, nr), f.ALLOW)
        self.assertLessEqual(len(f.program()), 4096)

    def test_63_configuration_is_exact_solver_only_and_installer_still_offline(self):
        self.assertEqual(f.sha(config()), f.SOLVER_CONFIG_SHA)
        self.assertIn(b'APT::Get::Download "false";', t.apt_configuration())
        self.assertNotIn("--no-download", f.APT_ARGV)
        self.assertEqual(f.APT_ARGV[-14:], old.g.REQUESTS)
        node = ast.parse((ROOT / "deploy/expat_apt/transaction.py").read_text())
        apply = next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == "apply")
        literals = [n.value for n in ast.walk(apply) if isinstance(n, ast.Constant)]
        self.assertIn("--no-download", literals)

    def test_64_launch_is_fixed_Python_helper_hashes_and_role_not_arbitrary_argv(self):
        argv = f.launch_argv(*["a" * 64] * 5, 1)
        self.assertEqual(argv[:5], [f.PYTHON, "-I", "-B", "-S", "-c"])
        self.assertEqual(argv[5], f.LOADER)
        for bad in (True, 0, 17, "1"):
            with self.assertRaisesRegex(ValueError, "fence_launch_role"):
                f.launch_argv(*["a" * 64] * 5, bad)
        for bad in ("PRIVATE\n", False, "a" * 63):
            with self.assertRaises(ValueError):
                f.launch_argv(bad, *["a" * 64] * 4, 1)

    def test_65_public_fence_packet_binds_PID_tools_source_filter_and_false_flags(self):
        positive = packet()
        args = dict(
            pid=123,
            code_sha="c",
            helper_sha="h",
            python_pin=("b" * 64, f.identity(row())),
            apt_pin=("a" * 64, f.identity(row())),
            ordinal=1,
        )
        f.validate_packet(positive, **args)
        for key, value in {
            "pid": True,
            "role": "PRIVATE",
            "NNP": True,
            "seccomp_mode": True,
            "close_range_UNSHARE": False,
            "filter_sha256": "f" * 64,
            "operational_GO": True,
            "code_pins_sha256": "other",
            "python_sha256": "other",
            "APT_sha256": "other",
            "ordinal": True,
            "stdio": ["SOCKET", "PIPE", "PIPE"],
        }.items():
            bad = {**positive, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                f.validate_packet(bad, **args)
        bad = copy.deepcopy(positive)
        bad["APT_identity"][0] = True
        with self.assertRaises(ValueError):
            f.validate_packet(bad, **args)
        with self.assertRaises(ValueError):
            f.validate_packet({**positive, "PRIVATE": "PRIVATE"}, **args)

    def test_66_native_summary_needs_both_real_H1_rows_and_pinned_context(self):
        pins = {"solver_fence.py": "b" * 64, "native_fence_tests.py": "c" * 64}
        value = old.positive_native_summary("a" * 64, pins)
        f.validate_native_summary(value, "a" * 64, pins)
        for key, bad in {
            "state": "REFUSED_OR_UNKNOWN",
            "cases": ["syscalls"],
            "helper_sha256": "f" * 64,
            "operational_GO": True,
        }.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                f.validate_native_summary({**value, key: bad}, "a" * 64, pins)
        for key, bad in {
            "returncode": False,
            "drains_complete": False,
            "owned_child_reaped": False,
            "reason": "timeout",
            "exception_type": "PRIVATE",
            "pid": True,
            "stderr_bytes": 1,
        }.items():
            broken = copy.deepcopy(value)
            broken["H1"][1][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                f.validate_native_summary(broken, "a" * 64, pins)

    def kernel_model(self, *, stdin=None, stdout=None, tasks=1, machine="x86_64"):
        events = []
        api = SimpleNamespace(close_others=lambda: events.append("close_range"))
        inp = stdin or SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_rdev=13)
        out = stdout or SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
        with (
            patch.object(f.sys, "platform", "linux"),
            patch.object(f.os, "uname", return_value=SimpleNamespace(machine=machine), create=True),
            patch.object(f.os, "getuid", return_value=0, create=True),
            patch.object(f.os, "geteuid", return_value=0, create=True),
            patch.object(f.os, "getpid", return_value=55),
            patch.object(f.os, "makedev", return_value=13, create=True),
            patch.object(f.os, "fstat", side_effect=[inp, out, out]),
            patch.object(f.Path, "iterdir", return_value=[SimpleNamespace(name="55")] * tasks),
        ):
            f.prepare_kernel(api)
        return events

    def test_67_kernel_preflight_accepts_only_monothread_root_pipe_DEVNULL(self):
        self.assertEqual(self.kernel_model(), ["close_range"])
        for options in (
            {"tasks": 2},
            {"machine": "aarch64"},
            {"stdin": SimpleNamespace(st_mode=stat.S_IFSOCK, st_rdev=13)},
            {"stdout": SimpleNamespace(st_mode=stat.S_IFSOCK)},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.kernel_model(**options)

    def main_model(self, change=None):
        change = change or {}
        events, written = [], []
        helper = "a" * 64
        raw_pins = json.dumps({"solver_fence.py": helper}).encode()
        py_raw, apt_raw = b"\x7fELF_PY", b"\x7fELF_APT"
        py_row, apt_row = row(3), row(4)
        args = [
            "-c",
            helper,
            f.sha(raw_pins),
            f.sha(apt_raw),
            f.sha(py_raw),
            f.SOLVER_CONFIG_SHA,
            "1",
        ]

        class Executed(BaseException):
            pass

        def execute(fd, argv, env):
            events.append(("execFD", fd, argv, env))
            raise Executed

        def capture(path, cap, **kw):
            path = str(path)
            events.append(("capture", path))
            if path.endswith("code-pins.json"):
                return raw_pins, f.identity(row())
            if path == f.PYTHON:
                return py_raw, f.identity(py_row)
            if path == str(f.CONFIG):
                return change.get("config", config()), f.identity(row())
            self.assertEqual(path, f.APT)
            self.assertTrue(kw["keep"])
            return 3, apt_raw, f.identity(apt_row)

        api = SimpleNamespace(
            install=lambda rows: events.append("filter"),
            execfd=None if change.get("noFD") else execute,
        )
        with (
            patch.object(f.sys, "argv", args),
            patch.object(
                f.sys, "flags", change.get("flags", SimpleNamespace(isolated=1, no_site=1))
            ),
            patch.object(f.sys, "dont_write_bytecode", change.get("dont_write_bytecode", True)),
            patch.dict(vars(f), {"CAPTURED_HELPER_SHA": helper}),
            patch.object(f, "captured_file", side_effect=capture),
            patch.object(f.os, "stat", return_value=py_row),
            patch.object(f, "LinuxAPI", return_value=api),
            patch.object(f, "prepare_kernel", side_effect=lambda api: events.append("close_range")),
            patch.object(f.os, "get_inheritable", return_value=False),
            patch.object(f.os, "fstat", return_value=apt_row),
            patch.object(f.Path, "lstat", return_value=change.get("postrow", apt_row)),
            patch.object(f, "emit", side_effect=lambda path, value: written.append(value)),
            patch.object(f.os, "close", side_effect=lambda fd: events.append(("close", fd))),
            patch.object(f.os, "getpid", return_value=123),
        ):
            try:
                f.main()
            except Executed:
                pass
            except ValueError:
                if not change:
                    raise
        return events, written

    def test_68_main_closes_then_opens_unique_CLOEXEC_FD_then_filter_marker_exec(self):
        events, written = self.main_model()
        self.assertLess(events.index("close_range"), events.index(("capture", f.APT)))
        self.assertLess(events.index(("capture", f.APT)), events.index("filter"))
        called = next(e for e in events if isinstance(e, tuple) and e[0] == "execFD")
        self.assertEqual(called[1:], (3, list(f.APT_ARGV), f.ENV))
        self.assertEqual(len(written), 1)
        self.assertFalse(written[0]["operational_GO"])
        self.assertIn(("close", 3), events)

    def test_69_main_refuses_mutated_config_noFDexec_and_postpath_swap(self):
        for changed in ({"config": b"PRIVATE"}, {"noFD": True}, {"postrow": row(999)}):
            events, written = self.main_model(changed)
            self.assertFalse(any(isinstance(e, tuple) and e[0] == "execFD" for e in events))
            self.assertEqual(written, [])

    def run_solver(
        self,
        *,
        fields=None,
        post_bad=False,
        packet_bad=False,
        sink_bad=False,
        unknown=False,
        role=None,
    ):
        fields = fields or {}
        writes, calls = {}, []
        helper_raw = (ROOT / "deploy/expat_apt/solver_fence.py").read_bytes()
        source_sha = f.sha(helper_raw)
        pins_raw = json.dumps({"solver_fence.py": source_sha}).encode()
        py_raw = b"\x7fELF_PY"
        apt_pin, py_pin = ("a" * 64, f.identity(row())), (f.sha(py_raw), f.identity(row()))
        receipt = packet(helper=source_sha, code=f.sha(pins_raw), py=py_pin, apt=apt_pin)
        if packet_bad:
            receipt["filter_sha256"] = "f" * 64
        result = io_helper.Result(
            spawn_attempted=True,
            pid=123,
            returncode=0,
            owned_child_reaped=True,
            drains_complete=True,
            stdout=b"Inst PUBLIC\n",
            stderr=b"",
            stdout_bytes=12,
            stderr_bytes=0,
        )
        for key, value in fields.items():
            setattr(result, key, value)

        def spawn(argv, **kwargs):
            calls.append((argv, kwargs))
            kwargs["on_spawn"](123)
            return result

        def read(path, cap):
            name = str(path)
            if name.endswith("solver_fence.py"):
                return helper_raw
            if name.endswith("code-pins.json"):
                return pins_raw
            if name == str(f.CONFIG):
                return config()
            self.assertTrue(name.endswith("-fence.json"))
            return json.dumps(receipt).encode()

        def write(path, raw, *args):
            if sink_bad and str(path).endswith(("-apt-diagnostic.json", "-UNKNOWN.json")):
                raise OSError("PRIVATE_MUST_NOT_REPLACE_PRIMARY")
            writes[str(path)] = raw

        runner = t.Runner(SimpleNamespace(run_capped=spawn), m, {}, until=1000)
        runner.solver_fence_module, runner.solver_fence_sha = f, source_sha
        runner.solver_code_sha = f.sha(pins_raw)
        runner.unknown = unknown
        runner.live = lambda name: py_raw
        count = []

        def tool(path):
            count.append(path)
            return ("f" * 64, apt_pin[1]) if post_bad and len(count) > 1 else apt_pin

        runner.tool_pin = tool
        with (
            patch.object(t, "read_regular", side_effect=read),
            patch.object(t, "write_new", side_effect=write),
            patch.object(t.Path, "lstat", return_value=row()),
            patch.object(t.time, "monotonic", return_value=0),
        ):
            error = None
            try:
                runner.simulate(
                    list(f.APT_ARGV) if role is None else role,
                    seconds=90,
                    cap=1024**2,
                    env=dict(f.ENV),
                )
            except ValueError as exc:
                error = exc.args[0]
        return runner, calls, writes, error

    def test_70_real_Runner_frontend_roles_fence_packet_and_success_close(self):
        runner, calls, writes, error = self.run_solver()
        self.assertIsNone(error)
        self.assertFalse(runner.unknown)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][:5], [f.PYTHON, "-I", "-B", "-S", "-c"])
        self.assertEqual(calls[0][1]["work_timeout"], 90)
        self.assertEqual(calls[0][1]["timeout"], 100)
        self.assertEqual(calls[0][1]["stdout_cap"], 1024**2)
        intent = json.loads(next(raw for n, raw in writes.items() if n.endswith("-intent.json")))
        self.assertNotEqual(intent["frontend_python_sha256"], intent["payload_APT_sha256"])
        self.assertEqual(len(runner.records), 1)

    def test_71_posttool_or_forged_fence_refuses_without_plan_or_records(self):
        for options in ({"post_bad": True}, {"packet_bad": True}):
            runner, calls, writes, error = self.run_solver(**options)
            self.assertEqual(error, "client_failed_or_UNKNOWN")
            self.assertTrue(runner.unknown)
            self.assertEqual(runner.records, [])
            self.assertTrue(any(n.endswith("-UNKNOWN.json") for n in writes))

    def test_72_normal_APT100_stays_fatal_with_qualified_message_only(self):
        runner, calls, writes, error = self.run_solver(
            fields={
                "returncode": 100,
                "reason": "nonzero_exit",
                "stderr": t.APT_ARCHIVES_ERROR + b"\n",
            }
        )
        self.assertEqual(error, "client_failed_or_UNKNOWN")
        self.assertTrue(runner.unknown)
        value = json.loads(
            next(raw for name, raw in writes.items() if name.endswith("-apt-diagnostic.json"))
        )
        self.assertEqual(value["state"], "REFUSED")
        self.assertTrue(value["archives_missing_message_observed"])
        self.assertFalse(value["operational_GO"])

    def test_73_uncertain_H1_never_publishes_qualified_fence_APT_message(self):
        for change in (
            {"drains_complete": False},
            {"owned_child_reaped": False},
            {"reason": "timeout"},
            {"pid": True},
            {"killed_owned_child": True},
        ):
            runner, calls, writes, error = self.run_solver(
                fields={
                    "returncode": 100,
                    "reason": "nonzero_exit",
                    "stderr": t.APT_ARCHIVES_ERROR + b"\n",
                    **change,
                }
            )
            self.assertEqual(error, "client_failed_or_UNKNOWN")
            diagnostic = json.loads(
                next(raw for n, raw in writes.items() if n.endswith("-apt-diagnostic.json"))
            )
            self.assertEqual(diagnostic["state"], "UNKNOWN")
            self.assertFalse(diagnostic["archives_missing_message_observed"])

    def test_74_secondary_sinks_cannot_mask_original_refusal_UNKNOWN_sticky(self):
        runner, calls, writes, error = self.run_solver(
            fields={"returncode": 100, "reason": "nonzero_exit"}, sink_bad=True
        )
        self.assertEqual(error, "client_failed_or_UNKNOWN")
        self.assertTrue(runner.unknown)
        self.assertEqual(len(calls), 1)
        runner, calls, writes, error = self.run_solver(unknown=True)
        self.assertEqual(error, "client_budget_or_UNKNOWN")
        self.assertEqual(calls, [])

    def test_75_changed_solver_role_refuses_before_spawn(self):
        for args in (
            [*f.APT_ARGV, "--download-only"],
            list(f.APT_ARGV)[1:],
            [s for s in f.APT_ARGV if s != "--simulate"],
        ):
            runner, calls, writes, error = self.run_solver(role=args)
            self.assertEqual(error, "fenced_solver_role")
            self.assertEqual(calls, [])

    def test_76_close_range_failure_is_closed_and_numbers_are_exact_without_libc(self):
        api = object.__new__(f.LinuxAPI)
        called = []
        api.c = SimpleNamespace(c_long=lambda v: v, c_uint=lambda v: v)
        api.libc = SimpleNamespace(syscall=lambda *args: called.append(args) or -1)
        with self.assertRaisesRegex(ValueError, "fence_close_range"):
            api.close_others()
        self.assertEqual(called, [(436, 3, 0xFFFFFFFF, 2)])

    def test_77_native_recipe_is_network_none_and_keeps_capture_apply_boundaries(self):
        docker = (ROOT / "qualification/expat_apt_C/Dockerfile").read_text()
        self.assertIn("RUN --network=none /usr/bin/timeout", docker)
        self.assertIn('supervisor.py native-fence "${CODE_PINS_SHA}"', docker)
        self.assertIn("COPY --from=capture /c-fence-native/ /fence-native/", docker)
        self.assertIn("RUN --network=none \\\n", docker)
        native = ast.parse((ROOT / "deploy/expat_apt/native_fence_tests.py").read_text())
        constants = {
            n.value
            for n in ast.walk(native)
            if isinstance(n, ast.Constant) and type(n.value) is str
        }
        self.assertIn("inherited", constants)
        self.assertIn("exec", constants)
        self.assertIn("syscalls", constants)
        self.assertNotIn("connect", constants)

    def file_model(self, change=None, keep=False):
        change = change or {}
        original = row()
        raw = b"\x7fELF_PUBLIC_SYNTHETIC"
        original.st_size = len(raw)
        for name, value in change.get("before", {}).items():
            setattr(original, name, value)
        post = copy.copy(original)
        for name, value in change.get("post", {}).items():
            setattr(post, name, value)
        directory = SimpleNamespace(
            parents=(), lstat=lambda: row(mode=stat.S_IFDIR | change.get("parent_mode", 0o755))
        )
        count = []

        def lstat():
            count.append(1)
            return original if len(count) == 1 else post

        path = SimpleNamespace(parent=directory, lstat=lstat)
        contents = io.BytesIO(change.get("raw", raw))
        closed, opened = [], []
        fd_row = copy.copy(original)
        if change.get("fd_swap"):
            fd_row.st_ino += 1
        with (
            patch.object(f.os, "O_NOFOLLOW", 0x20000, create=True),
            patch.object(f.os, "O_NONBLOCK", 0x800, create=True),
            patch.object(f.os, "O_CLOEXEC", 0x80000, create=True),
            patch.object(f, "Path", return_value=path),
            patch.object(f.os, "open", side_effect=lambda *args: opened.append(args) or 3),
            patch.object(f.os, "fstat", return_value=fd_row),
            patch.object(f.os, "read", side_effect=lambda fd, cap: contents.read(cap)),
            patch.object(f.os, "close", side_effect=lambda fd: closed.append(fd)),
        ):
            value, error = None, None
            try:
                value = f.captured_file("PUBLIC_SYNTHETIC", 64, keep=keep, executable=True)
            except ValueError as exc:
                error = exc.args[0]
        return value, error, closed, opened

    def test_78_sameFD_capture_keeps_only_the_CLOEXEC_exec_descriptor(self):
        value, error, closed, opened = self.file_model(keep=True)
        self.assertIsNone(error)
        self.assertEqual(value[0], 3)
        self.assertEqual(closed, [])
        self.assertTrue(opened[0][1] & 0x80000)
        value, error, closed, opened = self.file_model()
        self.assertIsNone(error)
        self.assertEqual(closed, [3])

    def test_79_FD_swap_postpath_mutation_growth_and_truncation_refuse(self):
        for changed in (
            {"fd_swap": True},
            {"post": {"st_ino": 999}},
            {"post": {"st_mtime_ns": 999}},
            {"raw": b"\x7fELF_PUBLIC_SYNTHETICX"},
            {"raw": b"\x7fELF"},
        ):
            value, error, closed, opened = self.file_model(changed)
            self.assertIsNone(value)
            self.assertIsNotNone(error)
            self.assertEqual(closed, [3])

    def test_80_alias_owner_permissions_and_parent_writability_refuse_before_open(self):
        for changed in (
            {"before": {"st_mode": stat.S_IFLNK | 0o777}},
            {"before": {"st_uid": 1000}},
            {"before": {"st_nlink": 2}},
            {"before": {"st_mode": stat.S_IFREG | 0o4666}},
            {"parent_mode": 0o777},
        ):
            value, error, closed, opened = self.file_model(changed)
            self.assertIsNone(value)
            self.assertIsNotNone(error)
            self.assertEqual(opened, [])

    def test_81_direct_execveat_has_AT_EMPTY_PATH_no_proc_or_path_fallback(self):
        class CType:
            def __call__(self, value):
                return value

            def __mul__(self, size):
                return lambda *values: list(values)

        api = object.__new__(f.LinuxAPI)
        api.c = SimpleNamespace(c_char_p=CType(), c_int=lambda v: v, c_long=lambda v: v)
        calls = []
        api.libc = SimpleNamespace(syscall=lambda *args: calls.append(args) or -1)
        with self.assertRaisesRegex(ValueError, "fence_execveat_returned"):
            api.execfd(3, list(f.APT_ARGV), dict(f.ENV))
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(call[:3], (322, 3, b""))
        self.assertEqual(call[-1], 0x1000)
        self.assertIsNone(call[3][-1])
        self.assertIsNone(call[4][-1])
        self.assertNotIn(b"/proc/self/fd/3", call[3])

    def test_82_native_recipe_does_not_import_ctypes_or_invoke_tools_in_pure_mode(self):
        native = old.module("c_native_recipe_model", "native_fence_tests.py")
        self.assertEqual(native.PYTHON, f.PYTHON)
        code = ast.parse((ROOT / "deploy/expat_apt/solver_fence.py").read_text())
        top_imports = [node for node in code.body if isinstance(node, ast.Import)]
        self.assertFalse(
            any(alias.name == "ctypes" for node in top_imports for alias in node.names)
        )
        self.assertIn("CAPTURED_HELPER_SHA", f.LOADER)
        self.assertIn("CAPTURED_NATIVE_SHA", native.LOADER)


class InterpreterFixtureTests(unittest.TestCase):
    def test_explicit_invalid_flags_remain_rejected_by_the_real_entrypoint(self):
        fixture = FenceTests()
        for change in (
            {"flags": SimpleNamespace(isolated=0, no_site=1)},
            {"flags": SimpleNamespace(isolated=1, no_site=0)},
            {"dont_write_bytecode": False},
        ):
            with self.subTest(change=change), patch.object(f, "need", wraps=f.need) as checks:
                events, written = fixture.main_model(change)
            rejected = [args.args for args in checks.call_args_list if args.args[0] is False]
            self.assertEqual(rejected, [(False, "fence_interpreter")])
            self.assertNotIn("filter", events)
            self.assertFalse(
                any(isinstance(event, tuple) and event[0] == "execFD" for event in events)
            )
            self.assertEqual(written, [])

    def test_parent_interpreter_state_is_restored_after_the_positive_fixture(self):
        fixture = FenceTests()
        original_flags = f.sys.flags
        original_bytecode = f.sys.dont_write_bytecode
        parent_flags = SimpleNamespace(isolated=0, no_site=0)
        with (
            patch.object(f.sys, "flags", parent_flags),
            patch.object(f.sys, "dont_write_bytecode", False),
        ):
            events, written = fixture.main_model()
            self.assertTrue(
                any(isinstance(event, tuple) and event[0] == "execFD" for event in events)
            )
            self.assertEqual(len(written), 1)
            self.assertIs(f.sys.flags, parent_flags)
            self.assertIs(f.sys.dont_write_bytecode, False)
        self.assertIs(f.sys.flags, original_flags)
        self.assertEqual(f.sys.dont_write_bytecode, original_bytecode)
