"""Pure TEST contracts and composed owner doubles; no GPG/agent/native execution."""

import ast
import hashlib
import io
import json
import struct
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_exec as bootstrap
import bounded_io as h1
import crypto_guard as g
import fixture_contract as c
import fixture_owner as o
import public_packets as p

HOME = "/tmp/pamolive-fixture-" + "a" * 32 + "/home"
NOW = int(time.time())
CI = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "Linux",
    "RUNNER_ARCH": "X64",
    "ImageOS": "ubuntu24",
    "GITHUB_REPOSITORY": c.REPOSITORY,
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REF": "refs/heads/agent/test-fixture",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_RUN_ID": "123",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_JOB": "test_fixture",
}


def packet(tag, body):
    return bytes([0xC0 + tag, len(body)]) + body


def certs():
    stamp = (NOW - 3600).to_bytes(4, "big")
    primary = b"\x04" + stamp + b"\x01\x00\x01\x01"
    signer = b"\x04" + stamp + b"\x01\x00\x01\x02"

    def sig(kind):
        return packet(2, bytes([4, kind, 1, 8]) + b"\0" * 6)

    before = packet(6, primary) + packet(13, b"TEST") + sig(0x13) + packet(14, signer) + sig(0x18)
    return before, before + sig(0x28), p.fingerprint(primary), p.fingerprint(signer)


BEFORE, AFTER, P, S = certs()


def listing(*, revoked=False, primary=P, signer=S, sub=True):
    def row(kind, validity, key, caps):
        values = [
            kind,
            validity,
            "2048",
            "1",
            key[-16:],
            str(NOW - 3600),
            str(NOW - 3600 + 86400),
            "",
            "",
            "",
            "",
            caps,
        ]
        return ":".join(values) + "\nfpr:::::::::" + key + ":\n"

    raw = row("pub", "u", primary, "cSC")
    if sub:
        raw += row("sub", "r" if revoked else "u", signer, "s")
    return raw.encode()


def valid_status():
    return (
        f"[GNUPG:] GOODSIG {S[-16:]} SYNTHETIC_ONLY\n"
        f"[GNUPG:] VALIDSIG {S} 2026-11-16 {NOW} 0 4 0 1 8 00 {P}\n"
    ).encode()


def result():
    return h1.Result(
        spawn_attempted=True, pid=123, returncode=0, owned_child_reaped=True, drains_complete=True
    )


class Contracts(unittest.TestCase):
    def test_01_roles_and_secret_free_flags(self):
        paths = {
            "message": "/private/message",
            "commands": "/private/commands",
            "signature": "/private/signature",
            "certificate": "/private/certificate",
        }
        for role in (
            "generate",
            "add_signer",
            "list",
            "export",
            "sign",
            "import",
            "verify",
            "revoke",
        ):
            with self.subTest(role=role):
                args = c.argv(role, HOME, P, S, paths)
                self.assertEqual(args[0], "/usr/bin/gpg")
                self.assertIn("--no-autostart", args)
                self.assertNotIn("--yes", args)
                self.assertFalse(
                    any("ignore" in arg or "weak" in arg or "faked" in arg for arg in args)
                )
        self.assertIn(S + "!", c.argv("sign", HOME, P, S, paths))
        self.assertIn("SHA256", c.argv("sign", HOME, P, S, paths))
        self.assertEqual(
            c.argv("sign", HOME, P, S, paths)[-3:], ["-", "--detach-sign", paths["message"]]
        )
        with self.assertRaisesRegex(ValueError, "unknown_role"):
            c.argv("quick_revoke_sig", HOME, P, S, paths)

    def test_02_path_and_purpose_are_closed(self):
        for home in ("/home/user/.gnupg", HOME + "/../x", HOME.replace("a", "A", 1)):
            with self.assertRaises(ValueError):
                c.base(home)
        self.assertNotEqual(c.PURPOSE, p.PURPOSE)
        self.assertNotEqual(P, p.PRIMARY)
        self.assertNotEqual(S, p.SIGNER)

    def test_03_normal_h1_is_strict(self):
        self.assertEqual(c.normal(result())["pid"], 123)
        for key, value in (
            ("returncode", 1),
            ("returncode", -9),
            ("returncode", True),
            ("reason", "timeout"),
            ("reason", "nonzero_exit"),
            ("owned_child_reaped", False),
            ("drains_complete", False),
            ("killed_owned_child", True),
            ("exception_type", "OSError"),
            ("cleanup_exception_type", "TimeoutExpired"),
            ("pid", None),
        ):
            row = result()
            setattr(row, key, value)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                c.normal(row)

    def test_04_h1_byte_counts_not_inferred(self):
        row = result()
        row.stdout = b"X"
        with self.assertRaisesRegex(ValueError, "client_byte_counts"):
            c.normal(row)

    def test_05_tool_versions_are_not_daemon_or_weak_version(self):
        for name in c.TOOLS:
            self.assertEqual(c.version(f"{name} (GnuPG) 2.4.7\nNOTICE\n".encode(), name), "2.4.7")
        for raw in (b"gpg (GnuPG) 2.2.40\n", b"gpg (GnuPG) 2.4.7 extra\n", b"2.4.7\n"):
            with self.assertRaises(ValueError):
                c.version(raw, "gpg")

    def test_06_discover_requires_distinct_single_signer(self):
        self.assertEqual(c.discover(listing(), g, now=NOW), (P, S))
        for raw in (listing(signer=P), listing() + listing(), listing().replace(b":s\n", b":e\n")):
            with self.assertRaises(ValueError):
                c.discover(raw, g, primary=P, signer=S, now=NOW)

    def test_07_real_revoked_guard_required(self):
        c.revoked(listing(revoked=True), P, S, g, NOW)
        for raw in (
            listing(),
            listing(revoked=True, signer="A" * 40),
            listing(revoked=True).replace(b"sub:r:", b"sub:e:"),
        ):
            with self.assertRaises(ValueError):
                c.revoked(raw, P, S, g, NOW)

    def test_08_negative_no_swallow_other_exception_or_accept(self):
        for capability in (lambda *_: None, lambda *_: (_ for _ in ()).throw(ValueError("other"))):
            stub = SimpleNamespace(one_primary=g.one_primary, signing_capability=capability)
            with self.assertRaises(ValueError):
                c.revoked(listing(revoked=True), P, S, stub, NOW)

    def test_09_dialogue_exact_and_bad_never_ignored(self):
        raw = b"".join(f"[GNUPG:] {kind} {name}\n".encode() for kind, name in c.GETS)
        c.transcript(raw, g.BAD)
        for altered in (
            raw[:-40],
            raw + raw,
            raw.replace(b"keyedit.revoke.subkey.okay", b"keyedit.revoke.key.okay"),
            raw + b"[GNUPG:] GET_HIDDEN passphrase\n",
            raw + b"[GNUPG:] ERROR x\n",
        ):
            with self.assertRaises(ValueError):
                c.transcript(altered, g.BAD)

    def test_10_packet_lineage_accepts_exact_one_insert(self):
        self.assertTrue(c.lineage(BEFORE, AFTER, p, P, S))
        rows = p.packets(AFTER)
        inserted = b"".join(r[2] for r in rows[:-2] + rows[-1:] + rows[-2:-1])
        self.assertTrue(c.lineage(BEFORE, inserted, p, P, S))

    def test_11_packet_lineage_refuses_other_changes(self):
        for raw in (
            BEFORE,
            AFTER + p.packets(AFTER)[-1][2],
            AFTER.replace(b"TEST", b"FAIL"),
            AFTER + packet(5, b"PRIVATE_MUST_NOT_PASS"),
            AFTER + packet(7, b"SECRET"),
        ):
            with self.assertRaises(ValueError):
                c.lineage(BEFORE, raw, p, P, S)
        with self.assertRaises(ValueError):
            c.lineage(AFTER, AFTER, p, P, S)

    def test_12_socket_route_not_learned_from_stdout(self):
        self.assertEqual(c.socket_route(HOME, 1001, False), HOME + "/S.gpg-agent")
        path = c.socket_route(HOME, 1001, True)
        self.assertRegex(path, r"^/run/user/1001/gnupg/d\.[a-z1-9]{24}/S.gpg-agent$")
        self.assertNotEqual(path, c.socket_route(HOME.replace("a" * 32, "b" * 32), 1001, True))
        with self.assertRaises(ValueError):
            c.socket_route(HOME, 0, True)

    def test_13_peer_pid_uid_gid_and_alive_all_required(self):
        c.peer_ok((123, 1001, 1001), 123, 1001, 1001, True)
        for peer, alive in (
            ((999, 1001, 1001), True),
            ((123, 0, 1001), True),
            ((123, 1001, 0), True),
            ((123, 1001, 1001), False),
        ):
            with self.assertRaises(ValueError):
                c.peer_ok(peer, 123, 1001, 1001, alive)

    def test_14_export_only_immutable_exact_names_after_cleanup(self):
        buffers = dict(
            zip(
                c.PUBLIC_NAMES,
                (BEFORE, AFTER, c.MESSAGE, b"PUBLIC-SIGNATURE", b"FUTURE", b"EXPIRED"),
                strict=True,
            )
        )
        packet = c.export_facts(buffers, P, S, cleanup=True, unknown=False)
        self.assertFalse(packet["operational_GO"])
        self.assertFalse(packet["adr034_matrix_complete"])
        self.assertEqual(
            packet["files"]["certificate-before.pgp"]["sha256"], hashlib.sha256(BEFORE).hexdigest()
        )
        for cleanup, unknown in ((False, False), (True, True)):
            with self.assertRaises(ValueError):
                c.export_facts(buffers, P, S, cleanup=cleanup, unknown=unknown)
        for bad in (
            {**buffers, "home/private.key": b"PRIVATE"},
            {**buffers, "signature.sig": bytearray(b"MUTABLE")},
        ):
            with self.assertRaises(ValueError):
                c.export_facts(bad, P, S, cleanup=True, unknown=False)

    def test_15_absolute_owner_horizon_not_caller_plus180(self):
        loaded = dict(fixture_contract=c, bounded_io=h1, crypto_guard=g, public_packets=p)
        with (
            patch.object(o.time, "monotonic", return_value=100),
            patch.object(o.os, "getuid", return_value=1001, create=True),
            patch.object(o.os, "getgid", return_value=1001, create=True),
        ):
            owner = o.Owner(
                loaded, {"source-pins.json": b"TEST"}, Path("unused"), until=230, context=CI
            )
            self.assertEqual((owner.end, owner.work_end), (230, 200))
            owner = o.Owner(
                loaded, {"source-pins.json": b"TEST"}, Path("unused"), until=999, context=CI
            )
            self.assertEqual((owner.end, owner.work_end), (280, 250))
            with self.assertRaises(ValueError):
                o.Owner(
                    loaded, {"source-pins.json": b"TEST"}, Path("unused"), until=130, context=CI
                )

    def test_16_callback_does_no_client_work_and_bootstrap_no_fork(self):
        tree = ast.parse(Path(o.__file__).read_text())
        callback = next(
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "spawned"
        )
        calls = [ast.unparse(n.func) for n in ast.walk(callback) if isinstance(n, ast.Call)]
        self.assertEqual(calls, ["need", "time.monotonic", "self.h1_journal", "self.spawned.set"])
        child = ast.parse(Path(bootstrap.__file__).read_text())
        self.assertFalse(
            any(
                isinstance(n, ast.Call)
                and ast.unparse(n.func) in {"os.fork", "os.system", "subprocess.Popen"}
                for n in ast.walk(child)
            )
        )

    def test_17_bootstrap_fd3_inheritable_even_when_already3(self):
        for source_fd, listen_fd in ((3, 3), (3, 8), (9, 3), (9, 8)):
            with self.subTest(source=source_fd, fd=listen_fd), ExitStack() as stack:
                row = SimpleNamespace(
                    st_dev=1,
                    st_ino=2,
                    st_mode=0o100755,
                    st_uid=0,
                    st_gid=0,
                    st_nlink=1,
                    st_size=7,
                    st_mtime_ns=1,
                    st_ctime_ns=1,
                )
                directory = SimpleNamespace(st_mode=0o40700, st_uid=1001)
                root_directory = SimpleNamespace(st_mode=0o40755, st_uid=0)
                order = []
                listener = SimpleNamespace(
                    bind=lambda _: order.append("bind"),
                    listen=lambda _: None,
                    fileno=lambda: listen_fd,
                )
                stack.enter_context(patch.object(bootstrap.os, "name", "posix"))
                stack.enter_context(
                    patch.object(bootstrap.os, "getuid", return_value=1001, create=True)
                )
                stack.enter_context(patch.object(bootstrap.os, "getpid", return_value=123))
                stack.enter_context(
                    patch.object(
                        bootstrap.os,
                        "lstat",
                        side_effect=lambda path: (
                            row
                            if path == "/usr/bin/gpg-agent"
                            else root_directory
                            if path in {"/", "/usr", "/usr/bin"}
                            else directory
                        ),
                    )
                )
                stack.enter_context(patch.object(bootstrap.os, "fstat", return_value=row))
                stack.enter_context(patch.object(bootstrap.os.path, "lexists", return_value=False))
                stack.enter_context(patch.object(bootstrap.os.path, "islink", return_value=False))
                stack.enter_context(patch.object(bootstrap.os, "open", return_value=7))
                stack.enter_context(
                    patch.object(bootstrap.os, "read", side_effect=[b"\x7fELFABC", b""])
                )
                stack.enter_context(
                    patch.object(
                        bootstrap.os, "close", side_effect=lambda fd: order.append(("close", fd))
                    )
                )
                stack.enter_context(patch.object(bootstrap.os, "umask"))
                stack.enter_context(patch.object(bootstrap.os, "O_NOFOLLOW", 0, create=True))
                stack.enter_context(patch.object(bootstrap.os, "O_NONBLOCK", 0, create=True))
                dup = stack.enter_context(patch.object(bootstrap.os, "dup2"))
                inheritable = stack.enter_context(patch.object(bootstrap.os, "set_inheritable"))
                stack.enter_context(
                    patch.object(bootstrap.os, "get_inheritable", return_value=True)
                )
                stack.enter_context(patch.object(bootstrap.socket, "socket", return_value=listener))
                stack.enter_context(patch.object(bootstrap.socket, "AF_UNIX", 1, create=True))
                execute = stack.enter_context(
                    patch.object(bootstrap.os, "execve", side_effect=RuntimeError("EXEC_SENTINEL"))
                )
                with self.assertRaisesRegex(RuntimeError, "EXEC_SENTINEL"):
                    bootstrap.main(
                        [
                            HOME,
                            HOME + "/S.gpg-agent",
                            hashlib.sha256(b"\x7fELFABC").hexdigest(),
                            str(source_fd),
                        ]
                    )
                self.assertLess(order.index(("close", source_fd)), order.index("bind"))
                inheritable.assert_called_once_with(3, True)
                if listen_fd == 3:
                    dup.assert_not_called()
                else:
                    dup.assert_called_once_with(8, 3, inheritable=True)
                args = execute.call_args.args
                self.assertIn("--supervised", args[1])
                self.assertNotIn("--daemon", args[1])
                self.assertEqual(args[2]["LISTEN_PID"], "123")

    def test_18_assuan_slow_drip_absolute_deadline(self):
        owner = object.__new__(o.Owner)
        owner.c, owner.uid, owner.gid, owner.work_end, owner.end = c, 1001, 1001, 100, 130
        owner.agent = SimpleNamespace(pid=123, poll=lambda: None)
        owner.socket_path, owner.socket_fact = "PRIVATE_TEST", (1,)
        owner.process_identity = lambda: None
        owner.socket_identity = lambda: (1,)

        class SlowSocket:
            def __init__(self):
                self.timeouts = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, value):
                self.timeouts.append(value)

            def connect(self, _):
                pass

            def getsockopt(self, *_):
                return struct.pack("3i", 123, 1001, 1001)

            def recv(self, _):
                return b"O"

        connection = SlowSocket()
        ticks = iter(x / 10 for x in range(1000))
        with (
            patch.object(o.socket, "socket", return_value=connection),
            patch.object(o.socket, "AF_UNIX", 1, create=True),
            patch.object(o.socket, "SO_PEERCRED", 17, create=True),
            patch.object(o.time, "monotonic", side_effect=lambda: next(ticks)),
        ):
            with self.assertRaisesRegex(ValueError, "assuan_deadline"):
                owner.assuan("GETINFO pid")
        self.assertGreater(len(connection.timeouts), 2)
        self.assertLess(connection.timeouts[-1], connection.timeouts[0])

    def test_19_shutdown_join_even_if_control_fails(self):
        owner = object.__new__(o.Owner)
        owner.agent = SimpleNamespace(poll=lambda: None)
        owner.agent_result = result()
        owner.thread = SimpleNamespace(join=lambda _: seen.append("join"), is_alive=lambda: False)
        owner.assuan = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("peer_changed"))
        owner.c, owner.records, owner.end, owner.unknown = c, [], time.monotonic() + 10, False
        owner.stable_tools = lambda: None
        seen = []
        with self.assertRaisesRegex(ValueError, "agent_shutdown_unconfirmed"):
            owner.shutdown()
        self.assertEqual(seen, ["join"])
        self.assertTrue(owner.unknown)

    def test_20_unknown_client_never_healed_by_successful_cleanup(self):
        owner = object.__new__(o.Owner)
        owner.unknown, owner.pending, owner.c = False, True, c
        owner.end = time.monotonic() + 10
        owner.prepare = lambda: None
        owner.start_agent = lambda: None
        owner.fixture = lambda: (_ for _ in ()).throw(ValueError("client_unknown"))
        seen = []
        owner.shutdown = lambda: seen.append("normal_cleanup")
        owner.journal = lambda state: seen.append(state)
        with self.assertRaisesRegex(ValueError, "fixture_unknown"):
            owner.run()
        self.assertEqual(seen, ["normal_cleanup", "UNKNOWN"])

    def composed(self, bad_positive=False):
        self.enterContext(patch.object(o.time, "time", return_value=NOW))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        owner = object.__new__(o.Owner)
        owner.root = Path(directory.name)
        owner.home, owner.c, owner.g, owner.packets = HOME, c, g, p
        owner.assuan = lambda *_: None
        owner.calls = []
        state = {"list": 0, "export": 0}

        def call(args, _home, **_kwargs):
            owner.calls.append(args)
            if "--list-keys" in args:
                state["list"] += 1
                return listing(sub=state["list"] != 1, revoked=state["list"] == 4)
            if "--export" in args:
                state["export"] += 1
                return BEFORE if state["export"] == 1 else AFTER
            if "--detach-sign" in args:
                if "--default-sig-expire" in args:
                    return b"DETACHED_EXPIRED_PUBLIC_SYNTHETIC"
                if "--faked-system-time" in args:
                    return b"DETACHED_FUTURE_PUBLIC_SYNTHETIC"
                return b"DETACHED_PUBLIC_SYNTHETIC"
            if "--verify" in args:
                return b"[GNUPG:] BADSIG SECRET_UID_CANARY\n" if bad_positive else valid_status()
            if "--edit-key" in args:
                return b"".join(f"[GNUPG:] {kind} {name}\n".encode() for kind, name in c.GETS)
            return b""

        owner.call = call
        self.enterContext(patch.object(o.os, "O_NOFOLLOW", 0, create=True))
        self.enterContext(
            patch.object(
                o, "captured", side_effect=lambda path, _cap: (Path(path).read_bytes(), ())
            )
        )
        return owner

    def test_21_composed_fixture_positive_then_revoke_then_actual_guard(self):
        owner = self.composed()
        buffers, primary, signer = owner.fixture()
        self.assertEqual((primary, signer), (P, S))
        self.assertEqual(buffers["certificate-revoked.pgp"], AFTER)
        verify = next(i for i, args in enumerate(owner.calls) if "--verify" in args)
        revoke = next(i for i, args in enumerate(owner.calls) if "--edit-key" in args)
        self.assertLess(verify, revoke)
        self.assertFalse(any("--export-secret" in str(arg) for args in owner.calls for arg in args))

    def test_22_bad_positive_blocks_revocation_and_export(self):
        owner = self.composed(bad_positive=True)
        with self.assertRaisesRegex(ValueError, "status_bad"):
            owner.fixture()
        self.assertFalse(any("--edit-key" in args for args in owner.calls))
        self.assertEqual(sum("--export" in args for args in owner.calls), 1)

    def test_23_cleanup_socket_drift_prevents_unlink(self):
        owner = object.__new__(o.Owner)
        owner.agent = SimpleNamespace(poll=lambda: 0)
        owner.thread = SimpleNamespace(join=lambda _: None, is_alive=lambda: False)
        owner.agent_result = result()
        owner.c, owner.records, owner.end, owner.unknown = c, [], time.monotonic() + 10, False
        owner.stable_tools = lambda: None
        owner.socket_fact, owner.socket_identity = (1,), lambda: (2,)
        with patch.object(o.os, "unlink") as unlink:
            with self.assertRaisesRegex(ValueError, "socket_cleanup_identity"):
                owner.shutdown()
            unlink.assert_not_called()

    def test_24_tool_drift_refuses_after_normal_client(self):
        owner = object.__new__(o.Owner)
        owner.unknown = False
        owner.client_ordinal = 0
        owner.tools = {"/usr/bin/gpg": ("DATA_ONLY", ())}
        owner.h1_journal = lambda *_args, **_kwargs: None
        owner.stable_tools = unittest.mock.Mock(side_effect=[None, ValueError("tool_changed")])
        owner.time_left = lambda: 20
        owner.root, owner.work_end, owner.records = Path("."), time.monotonic() + 20, []
        owner.c = c
        owner.h1 = SimpleNamespace(run_capped=lambda *_args, **_kwargs: result())
        with self.assertRaisesRegex(ValueError, "tool_changed"):
            owner.call(["/usr/bin/gpg", "--version"], HOME)
        self.assertTrue(owner.unknown)
        with self.assertRaisesRegex(ValueError, "sticky_unknown"):
            owner.call(["/usr/bin/gpg", "--version"], HOME)

    def test_25_source_only_no_private_outputs_or_global_kill(self):
        tree = ast.parse(Path(o.__file__).read_text())
        literals = {
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        }
        self.assertNotIn("--kill", literals)
        self.assertNotIn("--steal-socket", literals)
        self.assertNotIn("--remove-socketdir", literals)
        self.assertNotIn("--export-secret-keys", literals)
        self.assertIn("UNKNOWN", literals)
        self.assertIn("PENDING", literals)

    def test_26_actual_client_intent_pid_before_result_and_unknown_sticky(self):
        owner = object.__new__(o.Owner)
        owner.unknown, owner.client_ordinal, owner.c = False, 0, c
        owner.tools = {"/usr/bin/gpg": ("DATA_ONLY", ())}
        owner.stable_tools = lambda: None
        owner.time_left = lambda: 20
        owner.root, owner.work_end, owner.records = Path("."), time.monotonic() + 20, []
        seen = []
        owner.h1_journal = lambda prefix, state, **kw: seen.append((prefix, state, kw.get("pid")))

        def runner(*_args, **kwargs):
            self.assertEqual(seen[-1][1], "intent")
            kwargs["on_spawn"](123)
            self.assertEqual(seen[-1], ("client-01", "pid", 123))
            row = result()
            row.reason = "timeout"
            return row

        owner.h1 = SimpleNamespace(run_capped=runner)
        with self.assertRaisesRegex(ValueError, "client_unknown"):
            owner.call(["/usr/bin/gpg", "--version"], HOME)
        self.assertEqual([row[1] for row in seen], ["intent", "pid", "result", "unknown"])
        self.assertTrue(owner.unknown)

    def test_27_root_tool_parents_alias_and_elf_are_required(self):
        root = SimpleNamespace(
            st_dev=1,
            st_ino=1,
            st_mode=0o40755,
            st_uid=0,
            st_gid=0,
            st_nlink=2,
            st_size=1,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )
        leaf = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=0o100755,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=7,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )
        for bad in (None, "parent_uid", "parent_write", "parent_alias", "leaf_link", "magic"):
            with self.subTest(bad=bad), ExitStack() as stack:
                parent = SimpleNamespace(**vars(root))
                if bad == "parent_uid":
                    parent.st_uid = 1001
                if bad == "parent_write":
                    parent.st_mode = 0o40777

                class FakePath:
                    def __init__(self, name):
                        self.name = str(name)

                    def __str__(self):
                        return self.name

                    def lstat(self):
                        return leaf if self.name == "/usr/bin/gpg" else parent

                    def is_symlink(self):
                        return (
                            bad == "leaf_link"
                            and self.name == "/usr/bin/gpg"
                            or bad == "parent_alias"
                            and self.name == "/usr/bin"
                        )

                stack.enter_context(patch.object(o, "Path", FakePath))
                stack.enter_context(patch.object(o.os, "open", return_value=9))
                stack.enter_context(patch.object(o.os, "close"))
                stack.enter_context(patch.object(o.os, "fstat", return_value=leaf))
                stack.enter_context(
                    patch.object(
                        o.os,
                        "read",
                        side_effect=[b"NOTELF!" if bad == "magic" else b"\x7fELFABC", b""],
                    )
                )
                stack.enter_context(patch.object(o.os, "O_NOFOLLOW", 0, create=True))
                stack.enter_context(patch.object(o.os, "O_NONBLOCK", 0, create=True))
                stack.enter_context(patch.object(o.os, "listxattr", return_value=[], create=True))
                if bad is None:
                    self.assertEqual(
                        o.captured("/usr/bin/gpg", 1024, root_tool=True)[0], b"\x7fELFABC"
                    )
                else:
                    with self.assertRaises(ValueError):
                        o.captured("/usr/bin/gpg", 1024, root_tool=True)

    def test_28_disposable_context_not_just_linux_or_public_ack(self):
        self.assertEqual(c.ci_context(CI)["runner_image"], "ubuntu24")
        for key, value in (
            ("GITHUB_ACTIONS", "false"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("ImageOS", "ubuntu26"),
            ("GITHUB_REPOSITORY", "fork/repo"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_SHA", "bad"),
            ("GITHUB_RUN_ID", "0"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.ci_context({**CI, key: value})
        pr = {**CI, "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/1/merge"}
        with self.assertRaises(ValueError):
            c.ci_context(pr)
        self.assertEqual(
            c.ci_context({**pr, "P1G_HEAD_REPOSITORY": c.REPOSITORY})["event"], "pull_request"
        )

    def test_29_actual_shared_h1_memory_process_and_durable_order(self):
        for exitcode in (0, 1):
            with self.subTest(exitcode=exitcode):
                owner = object.__new__(o.Owner)
                owner.unknown, owner.client_ordinal, owner.c = False, 0, c
                owner.tools = {"/usr/bin/gpg": ("DATA_ONLY", ())}
                owner.root, owner.work_end, owner.records = Path("."), time.monotonic() + 20, []
                owner.stable_tools = lambda: None
                owner.time_left = lambda: 20
                order = []
                owner.h1_journal = lambda prefix, state, **_kw: order.append(state)
                process = SimpleNamespace(
                    pid=123,
                    stdout=io.BytesIO(b"PUBLIC"),
                    stderr=io.BytesIO(),
                    poll=lambda: exitcode,
                    wait=lambda **_kw: exitcode,
                )

                def popen(*_args, **kwargs):
                    self.assertEqual(order, ["intent"])
                    self.assertTrue(kwargs["close_fds"])
                    self.assertTrue(kwargs["start_new_session"])
                    self.assertNotIn("TOKEN", kwargs["env"])
                    return process

                owner.h1 = SimpleNamespace(
                    run_capped=lambda *args, **kw: h1.run_capped(*args, **kw, popen=popen)
                )
                with patch.object(h1.os, "name", "posix"):
                    if exitcode:
                        with self.assertRaisesRegex(ValueError, "client_unknown"):
                            owner.call(["/usr/bin/gpg", "--version"], HOME)
                    else:
                        self.assertEqual(owner.call(["/usr/bin/gpg", "--version"], HOME), b"PUBLIC")
                self.assertEqual(
                    order, ["intent", "pid", "result"] + (["unknown"] if exitcode else [])
                )
                self.assertEqual(owner.unknown, bool(exitcode))
                self.assertTrue(owner.records[0]["owned_child_reaped"])
                self.assertTrue(owner.records[0]["drains_complete"])

    def test_30_creation_only_roles_use_primary_duration_syntax(self):
        times = c.creation_times(NOW)
        self.assertEqual(
            (times["key"], times["future"], times["expired"]), (NOW - 3600, NOW + 3600, NOW - 600)
        )
        paths = {"message": "/private/message"}
        for role, epoch in (
            ("generate", times["key"]),
            ("add_signer", times["key"]),
            ("future_signature", times["future"]),
            ("expired_signature", times["expired"]),
        ):
            args = c.creation_argv(role, HOME, epoch=epoch, primary=P, signer=S, paths=paths)
            self.assertEqual(args[args.index("--faked-system-time") + 1], f"{epoch}!")
            self.assertEqual("--default-sig-expire" in args, role == "expired_signature")
            if role == "expired_signature":
                self.assertEqual(args[args.index("--default-sig-expire") + 1], "seconds=60")
        for role in ("verify", "import", "list", "revoke", "sign", "agent", "Google"):
            with self.assertRaisesRegex(ValueError, "creation_role"):
                c.creation_argv(role, HOME, epoch=NOW, primary=P, signer=S, paths=paths)
        for epoch in (True, -1, 0, 2**32, "123!"):
            with self.assertRaises(ValueError):
                c.creation_argv("generate", HOME, epoch=epoch)

    def test_31_native_creation_fields_and_packet_times_must_agree(self):
        epoch = NOW - 3600
        c.key_creation(listing(sub=False), g, P, None, epoch)
        c.key_creation(listing(), g, P, S, epoch)
        c.packet_key_times(BEFORE, p, P, S, epoch)
        for raw in (
            listing().replace(str(epoch).encode(), str(epoch + 1).encode()),
            listing().replace(str(epoch + 86400).encode(), b"0"),
        ):
            with self.assertRaisesRegex(ValueError, "native_key_creation_time"):
                c.key_creation(raw, g, P, S, epoch)
        with self.assertRaisesRegex(ValueError, "creation_packet_time"):
            c.packet_key_times(BEFORE, p, P, S, epoch + 1)
        self.assertEqual(c.real_clock(NOW, 100, NOW + 3, 103), NOW + 3)
        for wall, mono in ((NOW + 20, 101), (NOW, 99), (NOW + 151, 251)):
            with self.assertRaises(ValueError):
                c.real_clock(NOW, 100, wall, mono)

    def test_32_composed_timed_signatures_after_real_positive_before_revocation(self):
        owner = self.composed()
        buffers, primary, signer = owner.fixture()
        self.assertEqual((primary, signer), (P, S))
        self.assertEqual(set(buffers), set(c.PUBLIC_NAMES))
        positives = [i for i, args in enumerate(owner.calls) if "--verify" in args]
        future = [
            (i, args)
            for i, args in enumerate(owner.calls)
            if "--detach-sign" in args and f"{NOW + 3600}!" in args
        ]
        expired = [
            (i, args)
            for i, args in enumerate(owner.calls)
            if "--detach-sign" in args and "seconds=60" in args
        ]
        revoke = next(i for i, args in enumerate(owner.calls) if "--edit-key" in args)
        self.assertEqual(len(positives), 1)
        self.assertEqual(len(future), 1)
        self.assertEqual(len(expired), 1)
        self.assertTrue(positives[0] < future[0][0] < expired[0][0] < revoke)
        self.assertNotIn("--faked-system-time", owner.calls[positives[0]])
        for _, args in future + expired:
            self.assertIn(S + "!", args)
            self.assertIn("SHA256", args)
        self.assertNotEqual(buffers["signature.sig"], buffers["signature-future.sig"])
        self.assertNotEqual(buffers["signature-future.sig"], buffers["signature-expired.sig"])

    def test_33_bad_timed_creation_cannot_reach_revocation_or_admission(self):
        for role, returned in (
            ("future", b""),
            ("expired", b""),
            ("future", b"X" * (c.MAX_PUBLIC + 1)),
        ):
            with self.subTest(role=role, size=len(returned)):
                owner = self.composed()
                original = owner.call

                def call(args, home, **kw):
                    if "--detach-sign" in args and (
                        role == "future"
                        and f"{NOW + 3600}!" in args
                        or role == "expired"
                        and "seconds=60" in args
                    ):
                        owner.calls.append(args)
                        return returned
                    return original(args, home, **kw)

                owner.call = call
                with self.assertRaisesRegex(ValueError, role + "_signature_bytes"):
                    owner.fixture()
                self.assertFalse(any("--edit-key" in args for args in owner.calls))
        owner = self.composed(bad_positive=True)
        with self.assertRaises(ValueError):
            owner.fixture()
        self.assertEqual(sum("--detach-sign" in args for args in owner.calls), 1)

    def test_34_root_live_supervisor_regression_joined_before_unknown(self):
        owner = object.__new__(o.Owner)
        joins = []
        owner.agent = None
        owner.thread = SimpleNamespace(
            join=lambda seconds: joins.append(seconds), is_alive=lambda: True
        )
        owner.end, owner.unknown = time.monotonic() + 10, False
        with self.assertRaisesRegex(ValueError, "agent_spawn_uncertain"):
            owner.shutdown()
        self.assertEqual(len(joins), 1)
        self.assertTrue(0 < joins[0] <= 10)
        self.assertTrue(owner.unknown)

    def test_35_object_appears_during_join_cleanup_never_heals_unknown(self):
        owner = object.__new__(o.Owner)
        owner.agent, owner.unknown = None, False
        joins = []

        def joined(seconds):
            joins.append(seconds)
            owner.agent = SimpleNamespace(poll=lambda: 0)
            owner.agent_result = result()

        owner.thread = SimpleNamespace(join=joined, is_alive=lambda: False)
        owner.end, owner.c, owner.records = time.monotonic() + 10, c, []
        owner.stable_tools = lambda: None
        owner.socket_fact, owner.socket_identity, owner.socket_path = (1,), lambda: (1,), "OWNED"
        with (
            patch.object(o.os, "unlink") as unlink,
            patch.object(o.os.path, "lexists", return_value=False),
        ):
            owner.shutdown()
            unlink.assert_called_once_with("OWNED")
        self.assertEqual(len(joins), 2)
        self.assertTrue(owner.unknown)
        buffers = dict(
            zip(c.PUBLIC_NAMES, (BEFORE, AFTER, c.MESSAGE, b"POS", b"FUT", b"EXP"), strict=True)
        )
        with self.assertRaisesRegex(ValueError, "fixture_not_admitted"):
            c.export_facts(buffers, P, S, cleanup=True, unknown=owner.unknown)

    def test_36_actual_start_agent_uses_spawn_ceiling_after_slow_prepare(self):
        owner = object.__new__(o.Owner)
        owner.c, owner.home, owner.root = c, HOME, Path("unused")
        owner.end, owner.work_end, owner.started = 280, 250, 100
        owner.source_fd, owner.socket_path = 99, "OWNED"
        owner.tools = {"/usr/bin/gpg-agent": ("a" * 64, (1, 2))}
        owner.spawned = SimpleNamespace(wait=lambda _: True)
        owner.time_left = lambda: 50
        owner.h1_journal = lambda *_args, **_kw: None
        owner.socket_identity = lambda: (1,)
        seen = []
        owner.assuan = lambda command: seen.append(command)

        class Thread:
            def __init__(self, **_kw):
                pass

            def start(self):
                owner.agent = SimpleNamespace(pid=123, poll=lambda: None)
                owner.agent_spawn_monotonic = 187

        with (
            patch.object(o.threading, "Thread", Thread),
            patch.object(o.time, "monotonic", return_value=187),
            patch.object(o.os, "close"),
            patch.object(o.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
            patch.object(o.os.path, "lexists", return_value=True),
        ):
            owner.start_agent()
        self.assertEqual(seen, ["GETINFO pid"])
        self.assertEqual(owner.end, 280)
        self.assertEqual(owner.work_end, 250)

    def test_37_assuan_exact_ok_token_not_okevil(self):
        for response in (b"OK\n", b"OK done\n", b"OKevil\n"):
            owner = object.__new__(o.Owner)
            owner.c, owner.uid, owner.gid, owner.work_end, owner.end = c, 1001, 1001, 100, 130
            owner.agent = SimpleNamespace(pid=123, poll=lambda: None)
            owner.socket_path, owner.socket_fact = "PRIVATE_TEST", (1,)
            owner.process_identity = lambda: None
            owner.socket_identity = lambda: (1,)
            data = iter(bytes([byte]) for byte in b"OK greeting\nD 123\n" + response)

            class Socket:
                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    pass

                def settimeout(self, _):
                    pass

                def connect(self, _):
                    pass

                def getsockopt(self, *_):
                    return struct.pack("3i", 123, 1001, 1001)

                def recv(self, _):
                    return next(data, b"")

                def sendall(self, raw):
                    self.sent = raw

            connection = Socket()
            with (
                self.subTest(response=response),
                patch.object(o.socket, "socket", return_value=connection),
                patch.object(o.socket, "AF_UNIX", 1, create=True),
                patch.object(o.socket, "SO_PEERCRED", 17, create=True),
                patch.object(o.time, "monotonic", return_value=10),
            ):
                if response == b"OKevil\n":
                    with self.assertRaisesRegex(ValueError, "assuan_response"):
                        owner.assuan("GETINFO pid")
                else:
                    owner.assuan("GETINFO pid")
                self.assertEqual(connection.sent, b"GETINFO pid\n")

    def test_38_purpose2_six_names_and_old_aggregate_budget(self):
        self.assertEqual(c.PURPOSE, "pamolive.gpg-selected-signer-revoked-fixture/2")
        self.assertEqual(len(c.PUBLIC_NAMES), 6)
        buffers = dict(
            zip(c.PUBLIC_NAMES, (BEFORE, AFTER, c.MESSAGE, b"POS", b"FUT", b"EXP"), strict=True)
        )
        fact = c.export_facts(buffers, P, S, cleanup=True, unknown=False)
        self.assertFalse(fact["adr034_matrix_complete"])
        self.assertEqual(fact["temporal_signatures"], "CREATED_PENDING_INDEPENDENT_NATIVE_CONSUMER")
        with self.assertRaises(ValueError):
            c.export_facts(
                {key: value for key, value in buffers.items() if not key.endswith("future.sig")},
                P,
                S,
                cleanup=True,
                unknown=False,
            )
        large = {
            name: c.MESSAGE if name == "message.bin" else b"X" * c.MAX_PUBLIC
            for name in c.PUBLIC_NAMES
        }
        with self.assertRaisesRegex(ValueError, "public_total_budget"):
            c.export_facts(large, P, S, cleanup=True, unknown=False)
        args = [
            "owner",
            "--source-manifest-sha256",
            "0" * 64,
            "--github-disposable-ack",
            "pamolive.gpg-selected-signer-revoked-fixture/1",
            "--deadline-monotonic",
            "100",
            "--output",
            "UNUSED",
        ]
        with patch.object(o.sys, "argv", args), patch.object(o, "modules") as modules:
            with self.assertRaisesRegex(ValueError, "disposable_ack"):
                o.main()
            modules.assert_not_called()

    def test_39_future_window_survives_two_frontend_budgets_with_unchanged_guard(self):
        request = c.creation_times(NOW)
        verify_now = NOW + 2 * 870
        self.assertLess(2 * 870 + 300, 3600)
        keys = g.one_primary(listing(), P)
        g.signing_capability(keys, P, S, verify_now)
        self.assertLess(request["future"], int(keys[S]["expires"]))

        def require_actual_future_refusal(timestamp):
            raw = (
                f"[GNUPG:] GOODSIG {S[-16:]} TEST_ONLY\n"
                f"[GNUPG:] VALIDSIG {S} 2026-11-16 {timestamp} 0 4 0 1 8 00 {P}\n"
            ).encode()
            try:
                g.valid_status(raw, P, S, verify_now)
            except ValueError as error:
                self.assertEqual(error.args, ("signature_future",))
                return
            raise ValueError("future_window_not_held")

        require_actual_future_refusal(request["future"])
        # R2's600s is no longer a future-negative at the same permissible handoff time.
        with self.assertRaisesRegex(ValueError, "future_window_not_held"):
            require_actual_future_refusal(NOW + 600)

    def test_40_future_and_unchanged_key_expiry_fit_u32_without_wrapping(self):
        upper = 2**32 - 82800
        request = c.creation_times(upper - 1)
        self.assertEqual(request["key"] + 86400, 2**32 - 1)
        self.assertTrue(0 < request["expired"] < request["anchor"] < request["future"])
        self.assertLess(request["future"], request["key"] + 86400)
        for anchor in (True, 3600, upper, upper + 1, 2**32 - 1):
            with self.subTest(anchor=anchor), self.assertRaisesRegex(ValueError, "creation_anchor"):
                c.creation_times(anchor)

    def test_41_failure_projection_is_closed_and_never_formats_private_exception(self):
        class Poison(Exception):
            def __str__(self):
                raise AssertionError("must_not_format_exception")

        permission = o.failure_marker(PermissionError(13, "PRIVATE_UID_PATH_CANARY"), "agent_exe")
        self.assertEqual(
            (permission["phase"], permission["error"], permission["errno"]),
            ("agent_exe", "permission", 13),
        )
        for error, phase in (
            (Poison("PRIVATE_UID_PATH_CANARY"), "not_a_phase"),
            (ValueError("PRIVATE_UID_PATH_CANARY"), []),
            (OSError(987654321, "PRIVATE_UID_PATH_CANARY"), "fixture"),
        ):
            marker = o.failure_marker(error, phase)
            raw = json.dumps(marker)
            self.assertNotIn("PRIVATE_UID_PATH_CANARY", raw)
            self.assertLess(len(raw), 1024)
            self.assertIs(marker["diagnostic_only"], True)
            self.assertIs(marker["operational_GO"], False)
            self.assertEqual(marker["guard"], "unmapped")
            self.assertIsNone(marker["errno"])

    def diagnostic_owner(self):
        owner = object.__new__(o.Owner)
        owner.c, owner.context = c, c.ci_context(CI)
        owner.unknown, owner.pending = False, True
        owner.failure_code, owner.cleanup_failure = None, None
        owner.out, owner.root = Path("PUBLIC-ONLY"), Path("/tmp/pamolive-fixture-" + "a" * 32)
        owner.home, owner.end, owner.work_end = HOME, 280, 250
        owner.started, owner.phase = 100, "prepare"
        owner.source_manifest_sha256 = "f" * 64
        owner.records = []
        owner.agent, owner.agent_result, owner.thread = None, None, None
        owner.source_fd, owner.socket_path, owner.socket_fact = 99, "OWNED", None
        owner.tools = {"/usr/bin/gpg-agent": ("a" * 64, (1, 2))}
        owner.spawned = SimpleNamespace(wait=lambda _: True)
        owner.time_left = lambda: 50
        owner.h1_journal = lambda *_args, **_kw: None
        owner.prepare = lambda: None
        return owner

    def test_42_actual_readiness_causes_now_have_distinct_primary_markers(self):
        observed = []
        for kind in ("proc_permission", "socket_shape"):
            owner = self.diagnostic_owner()
            owner.fixture = lambda: (_ for _ in ()).throw(AssertionError("fixture_not_reached"))
            owner.assuan = lambda *_a, **_k: (_ for _ in ()).throw(ValueError("socket_peer"))
            packets, order = {}, []

            def saved(path, raw, *args):
                packets[Path(path).name] = json.loads(raw)
                order.append(Path(path).name)

            class Thread:
                def __init__(self, **kwargs):
                    pass

                def start(self):
                    owner.agent = SimpleNamespace(pid=3896, poll=lambda: None)
                    owner.agent_spawn_monotonic = 187

                def join(self, remaining):
                    self.test_remaining = remaining
                    self.primary_before_join = owner.failure_code
                    self.cleanup_before_join = owner.cleanup_failure
                    order.append("join")
                    owner.agent_result = h1.Result(
                        spawn_attempted=True,
                        pid=3896,
                        returncode=-9,
                        reason="timeout",
                        killed_owned_child=True,
                        owned_child_reaped=True,
                        drains_complete=True,
                    )

                def is_alive(self):
                    return False

            if kind == "socket_shape":
                owner.socket_identity = lambda: (_ for _ in ()).throw(ValueError("socket_identity"))
            with (
                patch.object(o, "exclusive", saved),
                patch.object(o.threading, "Thread", Thread),
                patch.object(o.time, "monotonic", return_value=187),
                patch.object(o.os, "close"),
                patch.object(o.os.path, "lexists", return_value=True),
                patch.object(o.os, "stat", side_effect=PermissionError(13, "PRIVATE_CANARY"))
                if kind == "proc_permission"
                else patch.object(o.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                self.assertRaisesRegex(ValueError, "fixture_unknown"),
            ):
                owner.run()
            self.assertLess(order.index("primary-failure.json"), order.index("join"))
            self.assertLess(order.index("cleanup-failure.json"), order.index("join"))
            self.assertIsNotNone(owner.thread.primary_before_join)
            self.assertIsNotNone(owner.thread.cleanup_before_join)
            self.assertFalse(packets["UNKNOWN.json"]["cleanup_complete"])
            self.assertEqual(packets["UNKNOWN.json"]["agent"]["reason"], "timeout")
            self.assertNotIn("PRIVATE_CANARY", json.dumps(packets))
            observed.append(packets["primary-failure.json"])
        self.assertEqual(
            (observed[0]["phase"], observed[0]["error"], observed[0]["errno"]),
            ("agent_exe", "permission", 13),
        )
        self.assertEqual(
            (observed[1]["phase"], observed[1]["guard"]), ("socket_identity", "socket_identity")
        )
        self.assertNotEqual(observed[0], observed[1])

    def test_43_first_primary_and_cleanup_causes_are_independent_and_sticky(self):
        owner = self.diagnostic_owner()
        writes = []
        with patch.object(o, "exclusive", lambda path, raw: writes.append((path, raw))):
            owner.remember_failure(PermissionError(13, "PRIVATE_CANARY"), phase="agent_exe")
            primary = owner.failure_code
            owner.remember_failure(ValueError("agent_unknown"), phase="fixture")
            owner.remember_failure(
                ValueError("socket_peer"), cleanup=True, phase="shutdown_control"
            )
            cleanup = owner.cleanup_failure
            owner.remember_failure(ValueError("client_unknown"), cleanup=True, phase="cleanup")
        self.assertIs(owner.failure_code, primary)
        self.assertIs(owner.cleanup_failure, cleanup)
        self.assertEqual(len(writes), 2)
        self.assertTrue(owner.unknown)
        self.assertNotIn("PRIVATE_CANARY", json.dumps([json.loads(raw) for _, raw in writes]))

    def test_44_failed_diagnostic_write_never_repairs_or_replaces_primary(self):
        owner = self.diagnostic_owner()
        owner.start_agent = lambda: (_ for _ in ()).throw(PermissionError(13, "PRIVATE_CANARY"))
        owner.fixture = lambda: (_ for _ in ()).throw(AssertionError("fixture_not_reached"))
        owner.shutdown = lambda: None
        seen = []
        owner.journal = lambda state: seen.append(state)
        with (
            patch.object(o, "exclusive", side_effect=FileExistsError("PRIVATE_CANARY")),
            self.assertRaisesRegex(ValueError, "fixture_unknown"),
        ):
            owner.run()
        self.assertTrue(owner.unknown)
        self.assertEqual(owner.failure_code["error"], "permission")
        self.assertEqual(seen, ["UNKNOWN"])

    def test_45_unknown_journal_contains_only_closed_diagnostics(self):
        owner = self.diagnostic_owner()
        owner.failure_code = o.failure_marker(ValueError("socket_identity"), "socket_identity")
        owner.cleanup_failure = o.failure_marker(OSError(13, "PRIVATE_CANARY"), "shutdown_control")
        captured = []
        with patch.object(o, "exclusive", lambda path, raw: captured.append(json.loads(raw))):
            owner.journal("UNKNOWN")
        self.assertEqual(captured[0]["failure_code"], owner.failure_code)
        self.assertEqual(captured[0]["cleanup_failure"], owner.cleanup_failure)
        self.assertNotIn("PRIVATE_CANARY", json.dumps(captured))

    def positive_diagnostic_owner(self):
        buffers = dict(
            zip(c.PUBLIC_NAMES, (BEFORE, AFTER, c.MESSAGE, b"POS", b"FUT", b"EXP"), strict=True)
        )
        owner = self.diagnostic_owner()
        owner.start_agent = owner.shutdown = lambda: None
        owner.fixture = lambda: (buffers, P, S)
        owner.source_fd = None
        owner.signature_requests = c.creation_times(NOW)
        owner.version, owner.python_version = "2.4.7", "Python 3.12.16"
        owner.tools[c.PYTHON] = ("b" * 64, ())
        owner.stages = []
        owner.journal = lambda state: owner.stages.append(state)
        return owner

    def test_46_complete_return_and_journal_have_no_new_diagnostic_contract(self):
        owner = self.positive_diagnostic_owner()
        with (
            patch.object(o.time, "monotonic", return_value=187),
            patch.object(o, "exclusive") as diagnostic,
        ):
            new = owner.run()
        self.assertEqual(set(new[0]), set(c.PUBLIC_NAMES))
        self.assertEqual(owner.stages, ["CLEANUP_COMPLETE"])
        self.assertNotIn("failure_code", new[1])
        self.assertNotIn("cleanup_failure", new[1])
        self.assertEqual(new[1]["schema"], c.PURPOSE)
        self.assertEqual(new[1]["purpose"], "TEST_ONLY")
        diagnostic.assert_not_called()


if __name__ == "__main__":
    unittest.main()
