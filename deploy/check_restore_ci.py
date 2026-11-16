"""Populated restore qualification from the already validated private HA environment."""

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit, urlunsplit

from deploy.check_active_active import validate_configuration
from deploy.check_restore import (
    RestoreQualification,
    compose_client,
    identifier,
    qualify_and_cleanup,
)


def write_private(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


PUBLIC_TRUST_ENV = {
    "PAM_TRUST_INSTALLATION_ID",
    "PAM_TRUST_RP_ID",
    "PAM_TRUST_ORIGIN",
    "PAM_TRUST_COMMISSIONING_KEYS",
    "PAM_TRUST_CHECKPOINT_KEYS",
}


def public_trust_environment(raw):
    """Finite synthetic public anchors captured before backup, never from the archive."""
    if len(raw) > 16384:
        raise RuntimeError("Invalid synthetic public trust configuration.")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError("Duplicate synthetic public trust field.")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if (
        type(value) is not dict
        or set(value) != PUBLIC_TRUST_ENV
        or any(
            type(item) is not str or len(item) > 8192 or any(c in item for c in "'\r\n\\")
            for item in value.values()
        )
        or value["PAM_TRUST_INSTALLATION_ID"] != "synthetic-isolated-installation"
        or value["PAM_TRUST_RP_ID"] != "pam.example.test"
        or value["PAM_TRUST_ORIGIN"] != "https://pam.example.test"
    ):
        raise RuntimeError("Invalid synthetic public trust configuration.")
    organizations = None
    for name, key_id in (
        ("PAM_TRUST_COMMISSIONING_KEYS", "commissioner"),
        ("PAM_TRUST_CHECKPOINT_KEYS", "witness"),
    ):
        keys = json.loads(value[name], object_pairs_hook=unique)
        if (
            type(keys) is not dict
            or len(keys) != 1
            or any(
                not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", org)
                or type(mapping) is not dict
                or set(mapping) != {key_id}
                or type(mapping[key_id]) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", mapping[key_id])
                for org, mapping in keys.items()
            )
            or organizations is not None
            and set(keys) != organizations
        ):
            raise RuntimeError("Invalid synthetic public trust key mapping.")
        organizations = set(keys)
    return value


def require_extended_corpus(report):
    for name, minimum, exact in (
        ("pam_trust_registries_verified", 1, True),
        ("pam_personal_authorizations_verified", 2, False),
        ("governance_exception_proofs_checked", 3, True),
        ("legacy_events_checked", 1, True),
        ("legacy_v7_evaluations_checked", 1, True),
        ("provenance_receipts_checked", 1, False),
    ):
        observed = report.get(name)
        if type(observed) is not int or (observed != minimum if exact else observed < minimum):
            raise RuntimeError("The synthetic corpus lacks required verified evidence.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--postgres-container", required=True)
    parser.add_argument("--ha-env-file", type=Path, required=True)
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=Path(__file__).with_name("compose.active-active-check.yml"),
    )
    parser.add_argument("--public-report", type=Path)
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix="pamolive-populated-restore-"))
    environment_file, archive = (directory / name for name in ("application.env", "source.dump"))
    environment_files = [environment_file]
    admin = RestoreQualification(
        SimpleNamespace(docker=args.docker, postgres_container=args.postgres_container)
    )
    created, source_oid, owner_oid = False, None, None
    source_removed = False
    source_name = "test_pamolive_restore_source"

    def command(arguments, *, content=None, environment=None):
        try:
            return subprocess.run(
                arguments, input=content, check=True, capture_output=True, env=environment
            ).stdout
        except subprocess.CalledProcessError as error:
            diagnostic = directory / ("private-error-" + secrets.token_hex(4) + ".json")
            write_private(
                diagnostic,
                json.dumps(
                    {
                        "stdout": (error.stdout or b"").decode(errors="replace"),
                        "stderr": (error.stderr or b"").decode(errors="replace"),
                    }
                ),
            )
            raise

    try:
        config = json.loads(
            command(
                [
                    args.docker,
                    "compose",
                    "--env-file",
                    str(args.ha_env_file.resolve()),
                    "-f",
                    str(args.compose_file.resolve()),
                    "config",
                    "--format",
                    "json",
                ]
            )
        )
        validate_configuration(config)
        service = config["services"]["node-a"]
        values = service["environment"]
        parsed = urlsplit(values["DATABASE_URL"])
        owner = unquote(parsed.username)
        identifier(owner)
        image = service["image"]
        network = config["networks"]["database"]["name"]
        source_url = urlunsplit(parsed._replace(path="/" + source_name))
        source_env = {key: values[key] for key in ("SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY")}
        source_env.update(DATABASE_URL=source_url, PAMOLIVE_RESTORE_FIXTURE="1", DEBUG="false")
        if any(any(character in value for character in "'\r\n\\") for value in source_env.values()):
            raise RuntimeError("Unsupported synthetic environment value.")
        write_private(
            environment_file, "".join(f"{key}='{value}'\n" for key, value in source_env.items())
        )
        owner_oid = int(admin.sql(f"SELECT oid FROM pg_roles WHERE rolname='{owner}';"))
        admin.sql(f"CREATE DATABASE {identifier(source_name)} OWNER {identifier(owner)};")
        created = True
        source_oid = int(admin.sql(f"SELECT oid FROM pg_database WHERE datname='{source_name}';"))
        admin.sql(f"REVOKE ALL ON DATABASE {identifier(source_name)} FROM PUBLIC;")

        def application(arguments, bind=None):
            prefix, process_env = compose_client(
                args.docker,
                image,
                environment_file,
                network,
                bind or Path(__file__).with_name("restore_application_check.py"),
                "pamolive-restore-fixture-" + directory.name.rsplit("-", 1)[-1],
            )
            return command(prefix + ["checker"] + arguments, environment=process_env)

        # Use -c/runpy so /app remains on sys.path in an older matching image.
        prepared = application(
            ["-c", "import runpy; runpy.run_path('/qualification.py',run_name='__main__')"],
            Path(__file__).with_name("prepare_restore_fixture.py"),
        )
        source_env.update(public_trust_environment(prepared))
        # Fresh host-side env companion; no anchor is learned from the restored DB.
        anchored_environment = directory / "application-with-public-trust.env"
        write_private(
            anchored_environment, "".join(f"{key}='{value}'\n" for key, value in source_env.items())
        )
        environment_files.append(anchored_environment)
        environment_file = anchored_environment
        check = RestoreQualification(
            SimpleNamespace(
                docker=args.docker,
                postgres_container=args.postgres_container,
                database_network=network,
                application_image=image,
                application_env=environment_file,
                archive=archive,
                source_database=source_name,
                expected_manifest=None,
                report_directory=directory / "result",
                require_populated=True,
            )
        )
        original_command, injected = check.command, False

        def concurrent_write(arguments, **kwargs):
            nonlocal injected
            if "pamolive-snapshot-backup" in arguments and not injected:
                application(
                    [
                        "-c",
                        "import os; "
                        "os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); "
                        "import django; django.setup(); "
                        "from platform_core.models import BusinessRole; "
                        "BusinessRole.objects.create(key='after-snapshot',"
                        "name='Concurrent synthetic write')",
                    ]
                )
                injected = True
            return original_command(arguments, **kwargs)

        check.command = concurrent_write
        report, failed = qualify_and_cleanup(check, record_report=False)
        if failed:
            print(json.dumps(report, sort_keys=True))
            raise SystemExit(1)
        require_extended_corpus(report)
        if report.get("certificate_possession_proofs_checked") != 1:
            raise RuntimeError("Missing or invalid restored certificate possession proof.")
        if not injected:
            raise RuntimeError("The exported snapshot concurrency gate did not run.")
        observed = application(
            [
                "-c",
                "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); "
                "import django; django.setup(); from platform_core.models import BusinessRole; "
                "assert BusinessRole.objects.filter(key='after-snapshot').exists(); "
                "print('present')",
            ]
        )
        if observed.strip() != b"present":
            raise RuntimeError("The concurrent source change did not commit.")
        report.update(
            concurrent_source_write_isolated=True,
            isolated_copy_removed=True,
            temporary_role_removed=True,
        )
    except Exception as error:
        report = {
            "result": "failed",
            "phase": "populated restore qualification",
            "error": type(error).__name__,
        }
        print(json.dumps(report, sort_keys=True))
        raise SystemExit(1) from None
    finally:
        # No termination/force or broad cleanup. Refuse a reused source or changed owner.
        primary_pending = sys.exc_info()[0] is not None
        try:
            if created:
                identity = admin.sql(
                    f"SELECT oid || ':' || datdba FROM pg_database WHERE datname='{source_name}';"
                )
                sessions = int(
                    admin.sql(
                        f"SELECT count(*) FROM pg_stat_activity WHERE datname='{source_name}';"
                    )
                )
                if source_oid is None or identity != f"{source_oid}:{owner_oid}" or sessions:
                    raise RuntimeError("Synthetic source retained for inspection.")
                if admin.sql(f"DROP DATABASE {identifier(source_name)};") != "":
                    raise RuntimeError("Synthetic source DROP acknowledgement is unknown.")
                source_removed = True
            for owned_environment in environment_files:
                if owned_environment.exists():
                    owned_environment.unlink()
        except Exception:
            print(
                json.dumps(
                    {
                        "result": "failed",
                        "phase": "synthetic source cleanup",
                        "error": "RestoreCleanupFailure",
                        "cleanup_code": "source_cleanup_failed",
                    },
                    sort_keys=True,
                )
            )
            if not primary_pending:
                raise SystemExit(1) from None
    if not source_removed:
        raise RuntimeError("Synthetic source cleanup was not confirmed.")
    report["synthetic_source_removed"] = source_removed
    write_private(directory / "result" / "report.json", json.dumps(report, sort_keys=True))
    if args.public_report is not None:
        # Root-owned helper integrates separately; called only after ALL cleanup succeeded.
        from deploy.restore_public_report import write_public_restore_report

        write_public_restore_report(report, args.public_report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
