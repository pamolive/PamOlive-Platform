"""Exercise a signed wheel as a separately installed Django app in this same image."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from tests.extension_fixtures import signed_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres", action="store_true")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pamolive-extension-gate-") as temporary:
        directory = Path(temporary)
        wheel, _, _, _, trust, catalog = signed_fixture(directory)
        installed = directory / "installed"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--no-compile",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--target",
                str(installed),
                str(wheel),
            ],
            check=True,
        )
        env = os.environ.copy()
        env.pop("PAMOLIVE_EXTENSION_TRUST_KEYS_FILE", None)
        env.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.pathsep.join([str(installed), str(Path.cwd())]),
                "PAMOLIVE_EXTENSION_CATALOG": str(catalog),
                "PAMOLIVE_EXTENSION_TRUST_KEYS": json.dumps(trust),
                "SECRET_KEY": "isolated-extension-gate-only",
                "PAMOLIVE_ENCRYPTION_KEY": "isolated-extension-gate-only",
            }
        )
        if options.postgres:
            if not env.get("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
                raise RuntimeError(
                    "The PostgreSQL extension gate requires an explicit database URL."
                )
            env["PAMOLIVE_TEST_DATABASE_NAME"] = "test_pamolive_extensions"
        else:
            env["DATABASE_URL"] = "sqlite:///:memory:"
            env.pop("PAMOLIVE_TEST_DATABASE_NAME", None)
        subprocess.run(
            [sys.executable, "manage.py", "makemigrations", "--check", "--dry-run"],
            env=env,
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                "manage.py",
                "test",
                "tests.test_extensions_runtime",
                "--keepdb",
                "--noinput",
                "-v",
                "2",
            ],
            env=env,
            check=True,
        )
        marker = directory / "initializer-executed"
        initializer = installed / "pamolive_ext_notes" / "__init__.py"
        initializer.write_text(
            f"from pathlib import Path; Path({str(marker)!r}).touch()", encoding="utf8"
        )
        # This refusal must happen before Django can import the edited initializer.
        env["DATABASE_URL"] = "sqlite:///:memory:"
        env.pop("PAMOLIVE_TEST_DATABASE_NAME", None)
        result = subprocess.run(
            [sys.executable, "manage.py", "check"], env=env, capture_output=True
        )
        if result.returncode == 0 or marker.exists() or b"ExtensionError" not in result.stderr:
            raise RuntimeError("A modified extension was not refused before import.")
        print(
            "Signed extension gate passed: real wheel, migrations, per-tenant activation, "
            "service permissions, MFA, audit, preservation and pre-import tamper refusal."
        )


if __name__ == "__main__":
    main()
