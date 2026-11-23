"""Own the native test engine and keep its diagnostics private."""

import os
import signal
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager, suppress
from pathlib import Path

BINARY = Path("/opt/pamolive-guac/sbin/guacd")


@contextmanager
def guacd_fixture(*, owned_by_worker=False):
    if not BINARY.is_file():
        raise RuntimeError("Native engine missing from the admitted test image")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with (
        tempfile.TemporaryDirectory(prefix="pamolive-guacd-") as directory,
        tempfile.TemporaryFile() as log,
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
            stdout=log,
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
