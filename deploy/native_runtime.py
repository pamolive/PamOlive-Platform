"""Runs only as UID 1001, with no application/database secrets in its environment."""

import os
import tempfile

directory = tempfile.mkdtemp(prefix="pamolive-engine-")
os.chmod(directory, 0o700)
os.environ["HOME"] = directory
os.environ["GUACAMOLE_HOME"] = directory
binary = "/opt/pamolive-guac/sbin/guacd"
os.execve(
    binary,
    [
        binary,
        "-f",
        "-b",
        "127.0.0.1",
        "-l",
        "4822",
        "-p",
        directory + "/guacd.pid",
        "-L",
        "error",
    ],
    os.environ,
)
