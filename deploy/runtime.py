"""One container; web/jobs UID 1000, private native engine UID 1001.

The small supervisor needs only SETUID/SETGID/KILL. Neither child role inherits
capabilities; the engine never receives application/database secrets.
"""

import os
import signal
import subprocess
import sys
import time

children = []
stopping = False

secret = os.environ.get("SECRET_KEY", "")
if (
    len(secret) < 40
    or secret.startswith(("change-", "insecure-"))
    or not secret.strip()
    or not secret.isprintable()
):
    raise SystemExit("Configurez une SECRET_KEY aléatoire d’au moins 40 caractères.")
encryption_key = os.environ.get("PAMOLIVE_ENCRYPTION_KEY")
if encryption_key is not None and (
    len(encryption_key) < 40 or not encryption_key.strip() or not encryption_key.isprintable()
):
    raise SystemExit(
        "PAMOLIVE_ENCRYPTION_KEY doit contenir au moins 40 caractères imprimables "
        "et ne peut pas être composée uniquement d’espaces."
    )
if not os.environ.get("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
    raise SystemExit("Le conteneur serveur requiert une DATABASE_URL PostgreSQL.")
if os.geteuid() != 0:
    raise SystemExit("Le superviseur doit pouvoir démarrer ses deux utilisateurs isolés.")
web_env = dict(os.environ, HOME="/home/pamolive")


def stop(signum=None, frame=None):
    global stopping
    stopping = True
    for process in children:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
children.append(
    subprocess.Popen(
        [sys.executable, "deploy/native_runtime.py"],
        user=1001,
        group=1001,
        extra_groups=[],
        start_new_session=True,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LD_LIBRARY_PATH": "/opt/pamolive-guac/lib",
            "PYTHONUNBUFFERED": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
)
children.append(
    subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "config.asgi:application",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--workers",
            os.environ.get("WEB_WORKERS", "3"),
            "--no-proxy-headers",
            "--ws-max-size",
            "65536",
            "--ws-per-message-deflate",
            "false",
            "--limit-concurrency",
            "256",
            "--timeout-graceful-shutdown",
            "10",
        ],
        user=1000,
        group=1000,
        extra_groups=[],
        start_new_session=True,
        env=web_env,
    )
)
children.append(
    subprocess.Popen(
        [sys.executable, "manage.py", "runjobs"],
        user=1000,
        group=1000,
        extra_groups=[],
        start_new_session=True,
        env=web_env,
    )
)
try:
    while not stopping and all(p.poll() is None for p in children):
        time.sleep(0.5)
finally:
    unexpected_exit = not stopping
    stop()
    for process in children:
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
sys.exit(1 if unexpected_exit else 0)
