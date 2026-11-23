"""Own the native test engine and keep its diagnostics private."""

import os
import signal
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager, nullcontext, suppress
from pathlib import Path

BINARY = Path("/opt/pamolive-guac/sbin/guacd")
LOG_TAIL_BYTES = 64 * 1024


def read_log_tail(path):
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - LOG_TAIL_BYTES))
        return stream.read(LOG_TAIL_BYTES)


@contextmanager
def guacd_fixture(*, owned_by_worker=False, log=None):
    if not BINARY.is_file():
        raise RuntimeError("Native engine missing from the admitted test image")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with (
        tempfile.TemporaryDirectory(prefix="pamolive-guacd-") as directory,
        (tempfile.TemporaryFile() if log is None else nullcontext(log)) as diagnostics,
    ):
        process = subprocess.Popen(
            [
                str(BINARY), "-f", "-b", "127.0.0.1", "-l", str(port),
                "-p", str(Path(directory) / "guacd.pid"), "-L", "error",
            ],
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LD_LIBRARY_PATH": "/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib",
                "HOME": directory,
                "GUACAMOLE_HOME": directory,
            },
            stdout=diagnostics,
            stderr=subprocess.STDOUT,
            # The bounded browser worker supervises its own process group.
            start_new_session=not owned_by_worker,
        )

        def stop(sig):
            with suppress(ProcessLookupError):
                if owned_by_worker:
                    process.send_signal(sig)
                else:
                    os.killpg(process.pid, sig)

        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        pass
                except OSError:
                    time.sleep(0.02)
                else:
                    break
            else:
                raise RuntimeError("Native test engine failed to start")
            yield port, process
        finally:
            stop(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stop(signal.SIGKILL)
                process.wait(timeout=5)
