"""Bounded local reads and owned-process pipes; no product imports or commands."""

import os
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


def read_regular(path, maximum):
    path = Path(path)
    info = path.lstat()

    def valid(row):
        return (
            stat.S_ISREG(row.st_mode)
            and row.st_nlink == 1
            and not getattr(row, "st_file_attributes", 0) & 1024
            and 0 <= row.st_size <= maximum
        )

    if not valid(info) or path.is_symlink():
        raise ValueError("regular file type/size budget")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not valid(opened) or (opened.st_dev, opened.st_ino) != (
            info.st_dev,
            info.st_ino,
        ):
            raise ValueError("file identity/type/size changed before read")
        data = stream.read(maximum + 1)
        if len(data) > maximum or len(data) != opened.st_size:
            raise ValueError("file size changed during bounded read")
    return data


@dataclass
class Result:
    spawn_attempted: bool = False
    pid: int | None = None
    returncode: int | None = None
    reason: str | None = None
    exception_type: str | None = None
    killed_owned_child: bool = False
    owned_child_reaped: bool = False
    drains_complete: bool = False
    cleanup_exception_type: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)

    @property
    def ok(self):
        return (
            self.reason is None
            and self.returncode == 0
            and self.owned_child_reaped
            and self.drains_complete
        )

    def facts(self):
        return {key: value for key, value in vars(self).items() if key not in {"stdout", "stderr"}}


def run_capped(
    command,
    *,
    env,
    cwd,
    timeout,
    stdout_cap,
    stderr_cap,
    stdout_sink=None,
    stderr_sink=None,
    on_spawn=None,
    popen=None,
):
    """Retain at most each cap; a one-byte probe detects excess without storing it.

    Threads support Windows anonymous pipes. Only the returned Popen object may
    be killed. All paths wait/reap that object; an incomplete drain is a failure.
    No unbounded communicate(), read(), capture_output or direct-to-file child IO.
    """
    if timeout <= 0 or min(stdout_cap, stderr_cap) < 0:
        raise ValueError("positive timeout and nonnegative stream caps required")
    result = Result(spawn_attempted=True)
    popen = subprocess.Popen if popen is None else popen
    stop = threading.Event()
    lock = threading.Lock()
    chunks = {"stdout": [], "stderr": []}
    threads = []
    process = None

    def fail(reason, error=None):
        with lock:
            if result.reason is None:
                result.reason = reason
                result.exception_type = type(error).__name__ if error else None
        stop.set()

    def drain(name, stream, ceiling, sink):
        retained = 0
        try:
            while not stop.is_set():
                remaining = ceiling - retained
                # No retained allocation/write beyond ceiling: probe is discarded.
                block = stream.read(min(65536, remaining) if remaining else 1)
                if not block:
                    return
                if not remaining:
                    fail(name + "_overflow")
                    return
                if len(block) > remaining:
                    # Defensive contract for a mocked or nonconforming stream.
                    fail(name + "_read_contract")
                    return
                if sink is None:
                    chunks[name].append(block)
                else:
                    written = sink.write(block)
                    if written != len(block):
                        raise OSError("short bounded log write")
                retained += len(block)
                setattr(result, name + "_bytes", retained)
        except BaseException as caught:
            fail(name + "_drain_error", caught)

    try:
        process = popen(
            command,
            env=env,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        result.pid = process.pid
        if on_spawn is not None:
            on_spawn(process.pid)
        for name, cap, sink in (
            ("stdout", stdout_cap, stdout_sink),
            ("stderr", stderr_cap, stderr_sink),
        ):
            thread = threading.Thread(
                target=drain,
                args=(name, getattr(process, name), cap, sink),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + timeout
        while True:
            if stop.is_set():
                break
            if process.poll() is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("timeout")
                break
            stop.wait(min(0.01, remaining))
    except BaseException as caught:
        fail("spawn_error" if process is None else "controller_error", caught)
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                    result.killed_owned_child = True
                result.returncode = process.wait(timeout=5)
                result.owned_child_reaped = True
            except BaseException as caught:
                result.cleanup_exception_type = type(caught).__name__
                fail("reap_error", caught)
            drain_deadline = time.monotonic() + 5
            for thread in threads:
                thread.join(max(0, drain_deadline - time.monotonic()))
            stopped = all(not thread.is_alive() for thread in threads)
            result.drains_complete = len(threads) == 2 and stopped
            if not result.drains_complete:
                fail("drain_incomplete")
            if stopped:
                for stream in (process.stdout, process.stderr):
                    try:
                        stream.close()
                    except BaseException as caught:
                        result.cleanup_exception_type = type(caught).__name__
                        fail("pipe_close_error", caught)
        result.stdout = b"".join(chunks["stdout"])
        result.stderr = b"".join(chunks["stderr"])
        if result.reason is None and result.returncode != 0:
            result.reason = "nonzero_exit"
    return result
