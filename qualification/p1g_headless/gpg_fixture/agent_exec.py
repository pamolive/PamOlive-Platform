"""Owned child only: create one listener then exec the agent in the same PID."""

import hashlib
import json
import os
import re
import socket
import stat
import sys


def need(ok):
    if not ok:
        raise ValueError("agent_bootstrap_refused")


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


def main(args):
    need(os.name == "posix" and len(args) == 4 and os.getuid() > 0)
    home, target, agent_sha, source_fd = args
    need(re.fullmatch(r"/tmp/pamolive-fixture-[0-9a-f]{32}/home", home))
    need(re.fullmatch("[0-9a-f]{64}", agent_sha) and source_fd.isdecimal())
    need(
        target == home + "/S.gpg-agent"
        or re.fullmatch(rf"/run/user/{os.getuid()}/gnupg/d\.[a-z1-9]{{24}}/S\.gpg-agent", target)
    )
    need(len(os.fsencode(target)) < 104 and not os.path.lexists(target))
    for directory in (home, os.path.dirname(target)):
        row = os.lstat(directory)
        need(
            stat.S_ISDIR(row.st_mode)
            and row.st_uid == os.getuid()
            and stat.S_IMODE(row.st_mode) == 0o700
            and not os.path.islink(directory)
        )
    agent = "/usr/bin/gpg-agent"
    for parent in ("/", "/usr", "/usr/bin"):
        row = os.lstat(parent)
        need(
            stat.S_ISDIR(row.st_mode)
            and row.st_uid == 0
            and not row.st_mode & 0o022
            and not os.path.islink(parent)
        )
    info = os.lstat(agent)
    need(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and not info.st_mode & 0o6022
        and 0 < info.st_size <= 64 * 1024 * 1024
    )
    fd = os.open(agent, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino))
        digest = hashlib.sha256()
        first = True
        total = 0
        while block := os.read(fd, min(65536, 64 * 1024 * 1024 + 1 - total)):
            total += len(block)
            need(total <= 64 * 1024 * 1024)
            if first:
                need(block.startswith(b"\x7fELF"))
                first = False
            digest.update(block)
        need(
            total == opened.st_size
            and digest.hexdigest() == agent_sha
            and identity(os.fstat(fd)) == identity(opened)
            and identity(os.lstat(agent)) == identity(info)
        )
    finally:
        os.close(fd)
    os.umask(0o077)
    # Python has compiled this source already. Close its inherited descriptor BEFORE fd3 reuse.
    os.close(int(source_fd))
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(target)
    listener.listen(5)
    # No parent listener FD exists. Preserve this child's listener at exec, including fd==3.
    if listener.fileno() != 3:
        os.dup2(listener.fileno(), 3, inheritable=True)
    os.set_inheritable(3, True)
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": home,
        "GNUPGHOME": home,
        "LISTEN_PID": str(os.getpid()),
        "LISTEN_FDS": "1",
        "LISTEN_FDNAMES": "std",
    }
    need(
        env["LISTEN_PID"] == str(os.getpid())
        and env["LISTEN_FDS"] == "1"
        and env["LISTEN_FDNAMES"] == "std"
        and os.get_inheritable(3)
    )
    # LISTEN_PID mismatch is merely logged by GnuPG; this bootstrap enforces it.
    argv = [
        agent,
        "--no-options",
        "--homedir",
        home,
        "--supervised",
        "--batch",
        "--disable-scdaemon",
        "--no-allow-external-cache",
        "--no-allow-mark-trusted",
        "--quiet",
    ]
    os.execve(agent, argv, env)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except BaseException:
        # No path, free exception, key data or environment value is published.
        sys.stderr.write(json.dumps({"schema": "fixture-agent-bootstrap/1", "refused": True}))
        raise SystemExit(42) from None
