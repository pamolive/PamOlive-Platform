"""Run the web process and lightweight durable job runner in one application container."""

import os
import signal
import subprocess
import sys
import time

children = []
stopping = False

secret = os.environ.get("SECRET_KEY", "")
if len(secret) < 40 or secret.startswith(("change-", "insecure-")):
    raise SystemExit("Configurez une SECRET_KEY aléatoire d’au moins 40 caractères.")
if not os.environ.get("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
    raise SystemExit("Le conteneur serveur requiert une DATABASE_URL PostgreSQL.")


def stop(signum=None, frame=None):
    global stopping
    stopping = True
    for process in children:
        if process.poll() is None:
            process.terminate()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
children.append(
    subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gunicorn",
            "config.wsgi:application",
            "--bind",
            "0.0.0.0:8000",
            "--workers",
            os.environ.get("WEB_WORKERS", "3"),
            "--access-logfile",
            "-",
            "--error-logfile",
            "-",
        ]
    )
)
children.append(subprocess.Popen([sys.executable, "manage.py", "runjobs"]))
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
            process.kill()
            process.wait()
sys.exit(1 if unexpected_exit else 0)
