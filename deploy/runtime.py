"""One container; web/jobs UID 1000, private native engine UID 1001.

The small supervisor needs only SETUID/SETGID/KILL. Neither child role inherits
capabilities; the engine never receives application/database secrets.
"""

import os
import signal
import subprocess
import sys
import time

NATIVE_LIBRARIES = "/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib"
APPLICATION_PATH = "/usr/local/bin:/usr/bin:/bin"
APP_HOME = "/home/pamolive"
LOCALE = "C.UTF-8"
LOADER_VARIABLES = {
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_PROFILE",
    "LD_ORIGIN_PATH",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "PYTHONHOME",
    "PYTHONPATH",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "GIO_MODULE_DIR",
    "GIO_EXTRA_MODULES",
    "GI_TYPELIB_PATH",
}
PYTHON_ENVIRONMENT = {
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}
# Metadata from the official Python base image, not interpreter switches.
PYTHON_METADATA = {"PYTHON_VERSION", "PYTHON_SHA256"}
REMOVED_VARIABLES = {"LANGUAGE", "LOCPATH", "NLSPATH", "DISPLAY", "XAUTHORITY"}


def removed_environment_name(name):
    return name in REMOVED_VARIABLES or name.startswith(("FONTCONFIG", "XDG_", "LC_"))


def loader_environment_name(name):
    return (
        name in LOADER_VARIABLES
        or (name.startswith("LD_") and name != "LD_LIBRARY_PATH")
        or (
            name.startswith("PYTHON")
            and name not in PYTHON_ENVIRONMENT
            and name not in PYTHON_METADATA
        )
    )


def validate_launch_environment(environment):
    """Compose pre-interpreter checks; preserve unrelated application variables."""
    if type(environment) is not dict or any(
        type(name) is not str or type(value) is not str for name, value in environment.items()
    ):
        raise ValueError("Invalid process environment types.")
    for name, value in environment.items():
        if not name or "=" in name or "\0" in name or "\0" in value:
            raise ValueError("Invalid process environment format.")
        if loader_environment_name(name):
            raise ValueError("Unapproved loader or interpreter environment.")
        if name in PYTHON_ENVIRONMENT and value != PYTHON_ENVIRONMENT[name]:
            raise ValueError("Unapproved interpreter environment value.")
        if name == "LD_LIBRARY_PATH" and value != NATIVE_LIBRARIES:
            raise ValueError("Only image native library prefixes are permitted.")
        if name == "PATH" and value != APPLICATION_PATH:
            raise ValueError("Unapproved executable search path.")
        if name == "HOME" and value != APP_HOME:
            raise ValueError("Unapproved application home.")
        if name == "LANG" or name.startswith("LC_"):
            if value != LOCALE:
                raise ValueError("Only the reviewed locale is permitted.")
        elif removed_environment_name(name):
            raise ValueError("Unapproved locale, display or font environment.")


def application_environment(environment):
    """Fixed child locale/search paths, no display or user font configuration."""
    result = dict(environment)
    # Loader configuration acts before Python starts. Preflight must also reject
    # these overrides before container launch; sanitizing a child is not enough.
    if (
        any(loader_environment_name(name) for name in result)
        or any(
            name in result and result[name] != value for name, value in PYTHON_ENVIRONMENT.items()
        )
        or ("LD_LIBRARY_PATH" in result and result["LD_LIBRARY_PATH"] != NATIVE_LIBRARIES)
    ):
        raise SystemExit("Unapproved loader or interpreter environment.")
    for name in list(result):
        if removed_environment_name(name):
            del result[name]
    result.update(
        HOME=APP_HOME,
        PATH=APPLICATION_PATH,
        LANG=LOCALE,
        LC_ALL=LOCALE,
        LD_LIBRARY_PATH=NATIVE_LIBRARIES,
    )
    return result


children = []
stopping = False


def stop(signum=None, frame=None):
    global stopping
    stopping = True
    for process in children:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def main():
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
    web_env = application_environment(os.environ)

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
                "LD_LIBRARY_PATH": "/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib",
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
    return 1 if unexpected_exit else 0


if __name__ in ("__main__", "<run_path>"):
    sys.exit(main())
