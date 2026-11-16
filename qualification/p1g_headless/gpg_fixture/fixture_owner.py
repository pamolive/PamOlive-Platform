"""Future dedicated Ubuntu24 CI producer; no work occurs at import time.

All native work requires explicit CLI acknowledgement and an external source pin.
No production authority, installation or full ADR034 matrix admission is provided.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

HERE = Path(__file__).parent
SOURCE_FILES = (
    "fixture_owner.py",
    "fixture_contract.py",
    "agent_exec.py",
    "bounded_io.py",
    "crypto_guard.py",
    "public_packets.py",
)


def need(ok, code):
    if not ok:
        raise ValueError(code)


def identity(row):
    return (
        row.st_dev,
        row.st_ino,
        row.st_mode,
        row.st_uid,
        row.st_gid,
        row.st_nlink,
        row.st_size,
        row.st_mtime_ns,
        row.st_ctime_ns,
    )


def captured(path, cap, *, root_tool=False):
    path = Path(path)
    if root_tool:
        need(
            str(path)
            in {
                "/usr/bin/python3.12",
                "/usr/bin/gpg",
                "/usr/bin/gpg-agent",
                "/usr/bin/gpg-connect-agent",
                "/usr/bin/gpgconf",
            },
            "tool_path",
        )
        for parent in (Path("/"), Path("/usr"), Path("/usr/bin")):
            row = parent.lstat()
            need(
                stat.S_ISDIR(row.st_mode)
                and row.st_uid == 0
                and not row.st_mode & 0o022
                and not parent.is_symlink(),
                "tool_parent",
            )
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and not before.st_mode & 0o6022
        and not path.is_symlink()
        and 0 < before.st_size <= cap,
        "file_shape",
    )
    if root_tool:
        need(before.st_uid == 0 and before.st_mode & 0o111, "tool_owner")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need(identity(opened) == identity(before), "file_open_race")
        blocks, total = [], 0
        while block := os.read(fd, min(65536, cap + 1 - total)):
            blocks.append(block)
            total += len(block)
            need(total <= cap, "file_budget")
        raw = b"".join(blocks)
        need(
            len(raw) == opened.st_size
            and identity(os.fstat(fd)) == identity(opened)
            and identity(path.lstat()) == identity(before),
            "file_changed",
        )
        if root_tool:
            need(raw.startswith(b"\x7fELF"), "tool_elf")
            need(
                "security.capability" not in os.listxattr(path, follow_symlinks=False),
                "tool_capability",
            )
        return raw, identity(before)
    finally:
        os.close(fd)


def modules(expected):
    need(re.fullmatch("[0-9a-f]{64}", expected), "external_source_pin")
    raw, _ = captured(HERE / "source-pins.json", 8192)
    need(hashlib.sha256(raw).hexdigest() == expected, "source_manifest_pin")
    rows = json.loads(raw)
    need(type(rows) is dict and set(rows) == set(SOURCE_FILES), "source_manifest_shape")
    buffers = {}
    for name in SOURCE_FILES:
        data, _ = captured(HERE / name, 65536)
        need(rows[name] == hashlib.sha256(data).hexdigest(), "source_pin")
        buffers[name] = data
    result = {}
    for name in ("fixture_contract", "bounded_io", "crypto_guard", "public_packets"):
        spec = importlib.util.spec_from_loader(name, loader=None)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(buffers[name + ".py"], name, "exec"), module.__dict__)
        result[name] = module
    buffers["source-pins.json"] = raw
    return result, buffers


def exclusive(path, raw, mode=0o600):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_BINARY", 0),
        mode,
    )
    try:
        need(os.write(fd, raw) == len(raw), "short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "posix":
        directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def private_dir(path, uid):
    row = Path(path).lstat()
    need(
        stat.S_ISDIR(row.st_mode)
        and row.st_uid == uid
        and stat.S_IMODE(row.st_mode) == 0o700
        and not Path(path).is_symlink(),
        "private_dir",
    )
    return (row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode)


class Owner:
    def __init__(self, loaded, sources, out, *, until, context):
        self.started = time.monotonic()
        self.c = loaded["fixture_contract"]
        self.context = self.c.ci_context(context)
        self.h1 = loaded["bounded_io"]
        self.g = loaded["crypto_guard"]
        self.packets = loaded["public_packets"]
        self.sources = sources
        need(type(sources.get("source-pins.json")) is bytes, "source_manifest_buffer")
        self.source_manifest_sha256 = hashlib.sha256(sources["source-pins.json"]).hexdigest()
        self.out = Path(out)
        need(type(until) in {int, float} and until > self.started + 30, "caller_deadline")
        self.end = min(until, self.started + 180)
        self.work_end = min(self.started + 150, self.end - 30)
        self.unknown = False
        self.failure_code = None
        self.records = []
        self.client_ordinal = 0
        self.tools = {}
        self.agent = None
        self.agent_result = None
        self.thread = None
        self.spawned = threading.Event()
        self.socket_fact = None
        self.agent_start = None
        self.created_dirs = []
        self.no_agent_sockets = []
        self.root = Path("/tmp") / ("pamolive-fixture-" + uuid.uuid4().hex)
        self.home = str(self.root / "home")
        self.uid, self.gid = os.getuid(), os.getgid()
        self.socket_path = None
        self.pending = None

    def journal(self, state):
        # Every transition uses a new exclusive durable file; UNKNOWN never overwrites PENDING.
        packet = {
            "schema": self.c.PURPOSE,
            "state": state,
            "operational_GO": False,
            "context": self.context,
            "owner_nonce": self.root.name[-32:],
            "source_manifest_sha256": self.source_manifest_sha256,
        }
        if state == "UNKNOWN":
            packet["clients"] = self.records
            packet["agent_pid"] = self.agent.pid if self.agent is not None else None
            packet["agent_thread_joined"] = self.thread is None or not self.thread.is_alive()
            packet["agent"] = self.agent_result.facts() if self.agent_result is not None else None
            packet["cleanup_complete"] = False
        raw = json.dumps(packet, sort_keys=True).encode()
        need(len(raw) <= 65536, "journal_budget")
        exclusive(self.out / (state + ".json"), raw)

    def time_left(self, *, cleanup=False):
        left = (self.end - 5 if cleanup else self.work_end) - time.monotonic()
        need(left > 5, "fixture_deadline")
        return left

    def h1_journal(self, prefix, state, *, pid=None, result=None, tool=None):
        need(
            re.fullmatch(r"(?:agent|client-[0-9]{2})", prefix)
            and state in {"intent", "pid", "result", "unknown"},
            "h1_journal_shape",
        )
        packet = {
            "schema": "fixture-owned-process/1",
            "state": state.upper(),
            "operational_GO": False,
        }
        if state == "intent":
            need(tool in self.tools, "h1_intent_tool")
            packet.update(
                {
                    "tool": Path(tool).name,
                    "tool_sha256": self.tools[tool][0],
                    "context": self.context,
                    "owner_nonce": self.root.name[-32:],
                    "source_manifest_sha256": self.source_manifest_sha256,
                }
            )
        if pid is not None:
            need(type(pid) is int and pid > 0, "h1_pid")
            packet["owned_pid"] = pid
        if result is not None:
            packet["facts"] = result.facts()
        raw = json.dumps(packet, sort_keys=True).encode()
        need(len(raw) <= 8192, "h1_journal_budget")
        exclusive(self.out / (prefix + "." + state + ".json"), raw)

    def stable_tools(self):
        need(not os.path.lexists("/usr/bin/gpgconf.ctl"), "unsupported_gpgconf_control")
        need(not any(os.path.lexists(path) for path in self.no_agent_sockets), "unexpected_socket")
        for path, (digest, before) in self.tools.items():
            raw, after = captured(path, 64 * 1024 * 1024, root_tool=True)
            need(after == before and hashlib.sha256(raw).hexdigest() == digest, "tool_changed")

    def call(self, argv, home, *, cap=65536):
        need(not self.unknown, "sticky_unknown")
        need(type(argv) is list and argv and argv[0] in self.tools, "client_tool")
        self.stable_tools()
        remaining = self.time_left()
        need(self.client_ordinal < 40, "client_count")
        self.client_ordinal += 1
        prefix = f"client-{self.client_ordinal:02d}"
        self.h1_journal(prefix, "intent", tool=argv[0])
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": home, "GNUPGHOME": home}
        try:
            result = self.h1.run_capped(
                argv,
                env=env,
                cwd=str(self.root),
                timeout=min(20, remaining),
                work_timeout=min(15, remaining - 5),
                deadline=self.work_end,
                stdout_cap=cap,
                stderr_cap=16384,
                total_cap=cap + 16384,
                on_spawn=lambda pid: self.h1_journal(prefix, "pid", pid=pid),
                owned_session=True,
            )
            self.h1_journal(prefix, "result", result=result)
        except BaseException:
            self.unknown = True
            self.h1_journal(prefix, "unknown")
            raise
        self.records.append(result.facts())
        try:
            self.c.normal(result)
            self.stable_tools()
        except BaseException:
            self.unknown = True
            self.h1_journal(prefix, "unknown", result=result)
            raise
        return result.stdout

    def prepare(self):
        need(
            sys.platform == "linux"
            and self.uid > 0
            and self.gid > 0
            and os.geteuid() == self.uid
            and os.getegid() == self.gid,
            "linux_nonroot",
        )
        os.umask(0o077)
        self.out.mkdir(mode=0o700)
        private_dir(self.out, self.uid)
        self.journal("PENDING")
        self.pending = True
        self.root.mkdir(mode=0o700)
        Path(self.home).mkdir(mode=0o700)
        (self.root / "positive").mkdir(mode=0o700)
        (self.root / "negative").mkdir(mode=0o700)
        self.root_fact = private_dir(self.root, self.uid)
        for path in [self.c.PYTHON] + ["/usr/bin/" + name for name in self.c.TOOLS]:
            raw, row = captured(path, 64 * 1024 * 1024, root_tool=True)
            self.tools[path] = (hashlib.sha256(raw).hexdigest(), row)
        versions = [
            self.c.version(self.call(self.c.version_argv(n, self.home), self.home, cap=16384), n)
            for n in self.c.TOOLS
        ]
        need(len(set(versions)) == 1, "tool_version_mismatch")
        self.version = versions[0]
        python_version = self.call(
            [self.c.PYTHON, "-I", "-B", "-S", "--version"], self.home, cap=1024
        )
        need(re.fullmatch(rb"Python 3\.12\.[0-9]{1,3}\n", python_version), "python_version")
        self.python_version = python_version.decode("ascii").strip()
        self.prepare_socket()
        # Pin the child source by captured bytes, keep its sole FD open until owned spawn.
        self.source_path = self.root / "agent-exec.py"
        exclusive(self.source_path, self.sources["agent_exec.py"])
        self.source_fd = os.open(self.source_path, os.O_RDONLY | os.O_NOFOLLOW)
        self.source_identity = identity(os.fstat(self.source_fd))

    def prepare_socket(self):
        runtime = Path(f"/run/user/{self.uid}")
        exists = os.path.lexists(runtime)
        # Source also has other compiled runtime bases. Refuse them before list-dirs can mkdir.
        for path in (f"/run/gnupg/user/{self.uid}", f"/var/run/gnupg/user/{self.uid}"):
            need(not os.path.lexists(path), "unsupported_runtime_base")
        need(exists or not os.path.lexists(f"/var/run/user/{self.uid}"), "runtime_alias_only")
        if exists:
            private_dir(runtime, self.uid)
        self.socket_path = self.c.socket_route(self.home, self.uid, exists)
        need(len(os.fsencode(self.socket_path)) < 104, "socket_path_budget")
        need(not os.path.lexists(Path(self.home) / "S.gpg-agent"), "home_socket_exists")
        if exists:
            parent = runtime / "gnupg"
            if not os.path.lexists(parent):
                # PENDING already durable. Never create/adopt /run/user/UID.
                parent.mkdir(mode=0o700)
                self.created_dirs.append((parent, private_dir(parent, self.uid)))
            else:
                private_dir(parent, self.uid)
        for home in (self.home, str(self.root / "positive"), str(self.root / "negative")):
            expected = self.c.socket_route(home, self.uid, exists)
            if exists:
                leaf = Path(expected).parent
                need(not os.path.lexists(leaf), "nonce_socket_dir_exists")
                leaf.mkdir(mode=0o700)
                self.created_dirs.append((leaf, private_dir(leaf, self.uid)))
            need(not os.path.lexists(expected), "socket_exists")
            if expected != self.socket_path:
                self.no_agent_sockets.append(expected)
            home_socket = str(Path(home) / "S.gpg-agent")
            if home_socket != self.socket_path and home_socket not in self.no_agent_sockets:
                self.no_agent_sockets.append(home_socket)
            # list-dirs may mkdir: its finite route was commissioned BEFORE the call.
            got = self.call(
                ["/usr/bin/gpgconf", "--homedir", home, "--list-dirs", "agent-socket"],
                home,
                cap=4096,
            )
            need(got == os.fsencode(expected) + b"\n", "gpg_socket_route")
            need(not os.path.lexists(expected), "socket_appeared")
        self.socket_parent = private_dir(Path(self.socket_path).parent, self.uid)

    def start_agent(self):
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": self.home,
            "GNUPGHOME": self.home,
        }
        command = [
            self.c.PYTHON,
            "-I",
            "-B",
            "-S",
            f"/proc/self/fd/{self.source_fd}",
            self.home,
            self.socket_path,
            self.tools["/usr/bin/gpg-agent"][0],
            str(self.source_fd),
        ]

        def popen(args, **kwargs):
            need(
                self.agent is None and identity(os.fstat(self.source_fd)) == self.source_identity,
                "agent_source_changed",
            )
            self.agent = subprocess.Popen(args, pass_fds=(self.source_fd,), **kwargs)
            return self.agent

        def spawned(pid):
            need(self.agent is not None and pid == self.agent.pid, "agent_spawn_binding")
            self.agent_spawn_monotonic = time.monotonic()
            self.h1_journal("agent", "pid", pid=pid)
            self.spawned.set()  # Immediate; no socket/client work before H1 drains start.

        def supervise():
            try:
                self.agent_result = self.h1.run_capped(
                    command,
                    env=env,
                    cwd=str(self.root),
                    timeout=self.end - time.monotonic(),
                    deadline=self.end,
                    work_timeout=self.end - time.monotonic() - 5,
                    stdout_cap=16384,
                    stderr_cap=16384,
                    total_cap=32768,
                    on_spawn=spawned,
                    popen=popen,
                    owned_session=True,
                )
                self.h1_journal("agent", "result", result=self.agent_result)
            except BaseException:
                self.unknown = True
                try:
                    self.h1_journal("agent", "unknown")
                except BaseException:
                    pass  # Keep UNKNOWN; never emit an unbounded thread traceback.
            finally:
                self.spawned.set()

        self.h1_journal("agent", "intent", tool="/usr/bin/gpg-agent")
        self.thread = threading.Thread(target=supervise, daemon=True)
        self.thread.start()
        need(
            self.spawned.wait(min(5, self.time_left())) and self.agent is not None,
            "agent_spawn_unknown",
        )
        # No listener or fd3 in parent; close only our source descriptor after spawn.
        os.close(self.source_fd)
        self.source_fd = None
        agent_tool = self.tools["/usr/bin/gpg-agent"][1]
        while True:
            need(
                self.agent.poll() is None
                and time.monotonic() < min(self.work_end, self.agent_spawn_monotonic + 15),
                "agent_not_ready",
            )
            try:
                row = os.stat(f"/proc/{self.agent.pid}/exe")
                execed = (row.st_dev, row.st_ino) == agent_tool[:2]
            except FileNotFoundError:
                execed = False
            if execed and os.path.lexists(self.socket_path):
                break
            time.sleep(0.01)
        self.socket_fact = self.socket_identity()
        self.assuan("GETINFO pid")

    def socket_identity(self):
        row = os.lstat(self.socket_path)
        need(
            stat.S_ISSOCK(row.st_mode)
            and row.st_uid == self.uid
            and row.st_gid == self.gid
            and row.st_nlink == 1
            and stat.S_IMODE(row.st_mode) == 0o700,
            "socket_identity",
        )
        need(
            private_dir(Path(self.socket_path).parent, self.uid) == self.socket_parent,
            "socket_parent_changed",
        )
        return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid, row.st_nlink)

    def process_identity(self):
        need(self.agent is not None and self.agent.poll() is None, "agent_not_alive")
        pid = self.agent.pid
        with open(f"/proc/{pid}/stat", "rb") as stream:
            raw = stream.read(8193)
        need(len(raw) <= 8192 and b") " in raw, "agent_proc_shape")
        fields = raw.rsplit(b") ", 1)[1].split()
        need(
            len(fields) >= 20
            and int(fields[1]) == os.getpid()
            and int(fields[2]) == int(fields[3]) == pid,
            "agent_proc_ownership",
        )
        row = os.stat(f"/proc/{pid}/exe")
        tool = self.tools["/usr/bin/gpg-agent"][1]
        need((row.st_dev, row.st_ino) == tool[:2], "agent_not_execed")
        start = fields[19]
        need(
            start.isdigit() and (self.agent_start is None or self.agent_start == start),
            "agent_pid_reuse",
        )
        self.agent_start = start

    def assuan(self, command, *, cleanup=False):
        need(command in {"GETINFO pid", "KILLAGENT"}, "assuan_command")
        self.process_identity()
        need(self.socket_identity() == self.socket_fact, "socket_changed")
        deadline = min(self.end - 5 if cleanup else self.work_end, time.monotonic() + 2)
        need(time.monotonic() < deadline, "assuan_deadline")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(max(0.001, deadline - time.monotonic()))
            client.connect(self.socket_path)
            peer = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            self.c.peer_ok(peer, self.agent.pid, self.uid, self.gid, self.agent.poll() is None)
            total = 0

            def line():
                nonlocal total
                result = bytearray()
                while True:
                    left = deadline - time.monotonic()
                    need(left > 0, "assuan_deadline")
                    client.settimeout(left)
                    byte = client.recv(1)
                    need(byte != b"", "assuan_eof")
                    total += 1
                    need(total <= 16384 and len(result) < 2048, "assuan_budget")
                    result.extend(byte)
                    if byte == b"\n":
                        return bytes(result)

            greeting = line()
            need(greeting == b"OK\n" or greeting.startswith(b"OK "), "assuan_greeting")
            need(time.monotonic() < deadline, "assuan_deadline")
            client.sendall(command.encode() + b"\n")
            if command == "GETINFO pid":
                need(line() == b"D " + str(self.agent.pid).encode() + b"\n", "assuan_pid")
            response = line()
            need(response == b"OK\n" or response.startswith(b"OK "), "assuan_response")
            if command == "GETINFO pid":
                self.process_identity()
                need(self.socket_identity() == self.socket_fact, "socket_changed")

    def fixture(self):
        self.signature_requests = self.c.creation_times(int(time.time()))
        self.creation_monotonic = time.monotonic()
        message = self.root / "message.bin"
        commands = self.root / "commands.txt"
        exclusive(message, self.c.MESSAGE)
        exclusive(commands, self.c.COMMANDS)
        self.call(
            self.c.creation_argv("generate", self.home, epoch=self.signature_requests["key"]),
            self.home,
        )
        now = self.real_now()
        raw = self.call(self.c.argv("list", self.home), self.home)
        p, s = self.c.discover(raw, self.g, now=now)
        need(s is None, "initial_subkey_present")
        self.c.key_creation(raw, self.g, p, None, self.signature_requests["key"])
        self.call(
            self.c.creation_argv(
                "add_signer", self.home, primary=p, epoch=self.signature_requests["key"]
            ),
            self.home,
        )
        raw = self.call(self.c.argv("list", self.home), self.home)
        now = self.real_now()
        p, s = self.c.discover(raw, self.g, primary=p, now=now)
        need(s is not None, "missing_test_signer")
        self.c.key_creation(raw, self.g, p, s, self.signature_requests["key"])
        signature = self.call(
            self.c.argv("sign", self.home, p, s, {"message": str(message)}), self.home
        )
        before = self.call(self.c.argv("export", self.home, p), self.home)
        self.c.packet_key_times(before, self.packets, p, s, self.signature_requests["key"])
        cert = self.root / "before.pgp"
        sig = self.root / "signature.sig"
        exclusive(cert, before)
        exclusive(sig, signature)
        public_home = self.root / "positive"
        public_home = str(public_home)
        # Positive-only public homes contain no secret and must never start another agent.
        self.call(self.public_argv("import", public_home, {"certificate": str(cert)}), public_home)
        raw = self.call(self.public_argv("list", public_home), public_home)
        keys = self.g.one_primary(raw, p)
        need(set(keys) == {p, s}, "positive_keys")
        now = self.real_now()
        self.g.signing_capability(keys, p, s, now)
        status = self.call(
            self.public_argv(
                "verify", public_home, {"signature": str(sig), "message": str(message)}
            ),
            public_home,
        )
        now = self.real_now()
        fact = self.g.valid_status(status, p, s, now)
        vals = [
            row.split()
            for row in status.decode("ascii").splitlines()
            if row.startswith("[GNUPG:] VALIDSIG ")
        ]
        need(len(vals) == 1 and vals[0][9] == "8", "positive_SHA256")
        self.g.signing_capability(keys, p, s, now, fact["timestamp"])
        # These creation results are not native temporal verification evidence.
        self.real_now()
        future = self.call(
            self.c.creation_argv(
                "future_signature",
                self.home,
                epoch=self.signature_requests["future"],
                primary=p,
                signer=s,
                paths={"message": str(message)},
            ),
            self.home,
        )
        need(
            type(future) is bytes and 0 < len(future) <= self.c.MAX_PUBLIC, "future_signature_bytes"
        )
        self.real_now()
        expired = self.call(
            self.c.creation_argv(
                "expired_signature",
                self.home,
                epoch=self.signature_requests["expired"],
                primary=p,
                signer=s,
                paths={"message": str(message)},
            ),
            self.home,
        )
        need(
            type(expired) is bytes and 0 < len(expired) <= self.c.MAX_PUBLIC,
            "expired_signature_bytes",
        )
        self.real_now()
        need(captured(commands, 1024)[0] == self.c.COMMANDS, "command_file_changed")
        self.assuan("GETINFO pid")
        status = self.call(
            self.c.argv("revoke", self.home, p, paths={"commands": str(commands)}),
            self.home,
            cap=16384,
        )
        self.c.transcript(status, self.g.BAD)
        need(captured(commands, 1024)[0] == self.c.COMMANDS, "command_file_changed")
        after = self.call(self.c.argv("export", self.home, p), self.home)
        self.c.lineage(before, after, self.packets, p, s)
        revoked_path = self.root / "after.pgp"
        exclusive(revoked_path, after)
        negative_home = self.root / "negative"
        negative_home = str(negative_home)
        self.call(
            self.public_argv("import", negative_home, {"certificate": str(revoked_path)}),
            negative_home,
        )
        listing = self.call(self.public_argv("list", negative_home), negative_home)
        self.c.revoked(listing, p, s, self.g, self.real_now())
        self.assuan("GETINFO pid")
        need(captured(message, 1024)[0] == self.c.MESSAGE, "message_changed")
        return (
            {
                "certificate-before.pgp": before,
                "certificate-revoked.pgp": after,
                "message.bin": self.c.MESSAGE,
                "signature.sig": signature,
                "signature-future.sig": future,
                "signature-expired.sig": expired,
            },
            p,
            s,
        )

    def real_now(self):
        return self.c.real_clock(
            self.signature_requests["anchor"],
            self.creation_monotonic,
            int(time.time()),
            time.monotonic(),
        )

    def public_argv(self, role, home, paths=None):
        need(home in {str(self.root / "positive"), str(self.root / "negative")}, "public_home")
        # Same closed base options; replace exactly the validated synthetic homedir token.
        argv = self.c.argv(role, self.home, paths=paths)
        need(argv[3] == self.home, "home_option")
        argv[3] = home
        return argv

    def shutdown(self):
        if self.agent is None and self.thread is not None:
            # A thread can still be inside Popen before assigning the owned object.
            # Give that SAME H1 supervisor its remaining absolute budget; never heal uncertainty.
            self.unknown = True
            self.thread.join(max(0, self.end - time.monotonic()))
            need(not self.thread.is_alive(), "agent_spawn_uncertain")
        if self.agent is None:
            need(self.thread is None, "agent_spawn_unconfirmed")
            return
        need(self.thread is not None, "agent_thread_missing")
        control_ok = True
        try:
            if self.agent.poll() is None:
                self.assuan("KILLAGENT", cleanup=True)
        except BaseException:
            control_ok = False
            self.unknown = True
        finally:
            # Always await the original H1 owner, even when targeted shutdown was refused.
            self.thread.join(max(0, self.end - time.monotonic()))
        need(not self.thread.is_alive() and self.agent_result is not None, "agent_unknown")
        self.c.normal(self.agent_result)
        self.records.append(self.agent_result.facts())
        self.stable_tools()
        need(control_ok, "agent_shutdown_unconfirmed")
        need(
            self.socket_fact is not None and self.socket_identity() == self.socket_fact,
            "socket_cleanup_identity",
        )
        os.unlink(self.socket_path)
        need(not os.path.lexists(self.socket_path), "socket_not_removed")

    def remove_private(self):
        need(private_dir(self.root, self.uid) == self.root_fact, "private_root_changed")
        count, total = 0, 0

        def remove(path, depth):
            nonlocal count, total
            need(depth <= 6 and time.monotonic() < self.end, "private_cleanup_budget")
            info = path.lstat()
            count += 1
            need(
                count <= 512 and info.st_uid == self.uid and not path.is_symlink(),
                "private_cleanup_shape",
            )
            if stat.S_ISDIR(info.st_mode):
                need(not info.st_mode & 0o077, "private_cleanup_directory")
                # No private file contents are read; only this new owned tree is traversed.
                with os.scandir(path) as entries:
                    children = []
                    for entry in entries:
                        need(
                            len(children) < 512 and entry.name not in {".", ".."},
                            "private_cleanup_budget",
                        )
                        children.append(path / entry.name)
                for child in children:
                    remove(child, depth + 1)
                need(
                    (path.lstat().st_dev, path.lstat().st_ino) == (info.st_dev, info.st_ino),
                    "private_cleanup_changed",
                )
                path.rmdir()
            else:
                total += info.st_size
                need(
                    stat.S_ISREG(info.st_mode)
                    and info.st_nlink == 1
                    and not info.st_mode & 0o077
                    and total <= 64 * 1024 * 1024,
                    "private_cleanup_file",
                )
                need(identity(path.lstat()) == identity(info), "private_cleanup_changed")
                path.unlink()

        remove(self.root, 0)
        for path, expected in reversed(self.created_dirs):
            need(private_dir(path, self.uid) == expected, "runtime_dir_changed")
            # rmdir only succeeds when EMPTY; no enumeration/adoption of other profiles.
            path.rmdir()

    def run(self):
        buffers = None
        try:
            self.prepare()
            self.start_agent()
            buffers, p, s = self.fixture()
        except BaseException:
            self.unknown = True
        finally:
            try:
                self.shutdown()
                if hasattr(self, "source_fd") and self.source_fd is not None:
                    os.close(self.source_fd)
                    self.source_fd = None
                if hasattr(self, "root_fact"):
                    self.remove_private()
            except BaseException:
                self.unknown = True
            if self.pending and self.unknown:
                self.journal("UNKNOWN")
        need(
            not self.unknown and buffers is not None and time.monotonic() < self.end,
            "fixture_unknown",
        )
        fact = self.c.export_facts(buffers, p, s, cleanup=True, unknown=self.unknown)
        fact["context"] = self.context
        fact["signature_requests"] = self.signature_requests
        fact["key_creation_epoch_verified"] = self.signature_requests["key"]
        fact["source_manifest_sha256"] = self.source_manifest_sha256
        fact["tools"] = {
            Path(path).name: {"sha256": value[0], "version": self.version}
            for path, value in self.tools.items()
            if path != self.c.PYTHON
        }
        fact["python_bootstrap"] = {
            "path": self.c.PYTHON,
            "sha256": self.tools[self.c.PYTHON][0],
            "version": self.python_version,
        }
        fact["h1"] = self.records
        # Admission is returned only after cleanup; the caller writes these same immutable buffers.
        self.journal("CLEANUP_COMPLETE")
        return buffers, fact


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--github-disposable-ack", required=True)
    parser.add_argument("--deadline-monotonic", type=float, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    need(
        args.github_disposable_ack == "pamolive.gpg-selected-signer-revoked-fixture/2",
        "disposable_ack",
    )
    need(os.name == "posix" and sys.platform == "linux", "linux_only")
    loaded, sources = modules(args.source_manifest_sha256)
    owner = Owner(loaded, sources, args.output, until=args.deadline_monotonic, context=os.environ)
    buffers, facts = owner.run()
    for name, raw in buffers.items():
        exclusive(args.output / name, raw, 0o400)
    exclusive(args.output / "fixture-facts.json", json.dumps(facts, sort_keys=True).encode(), 0o400)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # No exception text/UID/private status/argv/home appears on the public stream.
        sys.stderr.write('{"schema":"fixture-owner/1","state":"REFUSED_OR_UNKNOWN"}\n')
        raise SystemExit(42) from None
