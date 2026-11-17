"""One existing H172 client lifecycle; UNKNOWN is sticky, no operator retries."""

import subprocess
import time
from pathlib import Path

from . import bounded_io
from .contract import canonical, need
from .files import exclusive


class Commands:
    def __init__(self, root, env, *, runner=bounded_io.run_capped, now=time.monotonic):
        self.root = Path(root)
        self.env = dict(env)
        self.runner = runner
        self.now = now
        self.until = now() + 600
        self.count = 0
        self.unknown = False
        self.last_result = None

    def run(self, argv, *, timeout=65, work=60, cap=2 * 1024**2, fd=None, env=None):
        need(not self.unknown, "origin_sticky_UNKNOWN")
        need(
            self.count < 64 and self.until - self.now() > timeout + 30,
            "origin_frontend_or_deadline",
        )
        self.count += 1
        stem = self.root / f"client-{self.count:02}"
        exclusive(
            str(stem) + "-intent.json",
            canonical(
                {
                    "state": "PENDING",
                    "ordinal": self.count,
                    "timeout": timeout,
                    "stdout_cap": cap,
                    "stderr_cap": 262144,
                }
            ),
        )

        def spawned(pid):
            exclusive(str(stem) + "-pid.json", canonical({"pid": pid, "state": "PENDING"}))

        def popen(argv, **kwargs):
            if fd is not None:
                kwargs["pass_fds"] = (fd,)
            return subprocess.Popen(argv, **kwargs)

        try:
            result = self.runner(
                argv,
                env=self.env if env is None else env,
                cwd=self.root,
                timeout=timeout,
                work_timeout=work,
                deadline=self.until - 30,
                stdout_cap=cap,
                stderr_cap=262144,
                on_spawn=spawned,
                popen=popen,
                owned_session=True,
            )
            self.last_result = result
            complete = (
                result.ok
                and result.spawn_attempted
                and type(result.pid) is int
                and result.pid > 0
                and type(result.returncode) is int
                and result.returncode == 0
                and not result.killed_owned_child
                and result.exception_type is None
                and result.cleanup_exception_type is None
            )
            self.unknown |= not complete
            # Private only: filenames do not expose argv, URLs, token or free errors.
            exclusive(str(stem) + "-facts.json", canonical(result.facts()))
            exclusive(str(stem) + "-stdout.private", result.stdout, cap)
            exclusive(str(stem) + "-stderr.private", result.stderr, 262144)
            need(complete, "origin_child_UNKNOWN")
            return result.stdout
        except BaseException:
            self.unknown = True
            raise
