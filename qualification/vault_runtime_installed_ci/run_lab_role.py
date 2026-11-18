"""Run the installed Vault test role after a system-Python prelaunch check."""

import argparse
import os
import sys
from pathlib import Path

CONTROLLER = Path("/inputs/controller")
PREFIX = Path("/opt/vault")
PYTHON = PREFIX / "bin/python"
SERVE = Path("/inputs/runtime/integration/serve_lab.py")
CLIENT = Path("/inputs/lab/installed_ten.py")
PREPARE = Path("/inputs/lab/lab_prepare.py")
RESTORE = Path("/inputs/lab/restore_child.py")
PHASES = ("before-dump", "after-restore", "after-commission")


def command(args, schema):
    if args.restore and args.role != "preparer":
        raise ValueError("vault_lab_role_arguments")
    if (args.phase is not None) != (args.role == "restore-probe"):
        raise ValueError("vault_lab_role_arguments")
    if args.role == "preparer":
        if (
            args.database is None
            or not schema.digest(args.input_sha256)
            or args.test_sha256 is not None
        ):
            raise ValueError("vault_lab_role_arguments")
        return [
            str(PYTHON),
            "-I",
            "-B",
            str(PREPARE),
            "--database",
            args.database,
            "--input-sha256",
            args.input_sha256,
            *(["--restore"] if args.restore else []),
        ]
    if args.database is not None:
        raise ValueError("vault_lab_role_arguments")
    if args.role in ("server", "restore-hold"):
        if args.input_sha256 is not None or args.test_sha256 is not None:
            raise ValueError("vault_lab_role_arguments")
        if args.role == "restore-hold":
            return [str(PYTHON), "-I", "-B", "-c", "import time; time.sleep(120)"]
        return [
            str(PYTHON),
            "-I",
            "-B",
            str(SERVE),
            "--execute-new-synthetic-lab",
            "--manifest",
            "/lab/manifest.json",
        ]
    if not (schema.digest(args.input_sha256) and schema.digest(args.test_sha256)):
        raise ValueError("vault_lab_role_arguments")
    if args.role == "restore-probe":
        return [
            str(PYTHON),
            "-I",
            "-B",
            str(RESTORE),
            "--execute-new-synthetic-lab",
            "--phase",
            args.phase,
            "--input-sha256",
            args.input_sha256,
            "--test-sha256",
            args.test_sha256,
        ]
    return [
        str(PYTHON),
        "-I",
        "-B",
        str(CLIENT),
        "--execute-new-synthetic-lab",
        "--controller-dir",
        str(CONTROLLER),
        "--installed-input",
        "/inputs/descriptor.json",
        "--installed-input-sha256",
        args.input_sha256,
        "--integration-dir",
        str(SERVE.parent),
        "--test-lab-sha256",
        args.test_sha256,
        "--manifest",
        "/lab/manifest.json",
        "--report",
        "/work/report.json",
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "role", choices=("preparer", "server", "client", "restore-hold", "restore-probe")
    )
    parser.add_argument("--database")
    parser.add_argument("--input-sha256")
    parser.add_argument("--test-sha256")
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--phase", choices=PHASES)
    args = parser.parse_args()
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
            raise ValueError("vault_lab_role_interpreter")
        user = 0 if args.role == "preparer" else 1000
        if os.getuid() != user or os.getgid() != user:
            raise ValueError("vault_lab_role_identity")
        sys.path.insert(0, str(CONTROLLER))
        import adapter_v2
        import schema

        adapter_v2.runtime_prelaunch(PREFIX / "lib/python3.12/site-packages")
        os.execv(str(PYTHON), command(args, schema))
    except Exception:
        print("Vault test role refused startup.", file=sys.stderr)
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
