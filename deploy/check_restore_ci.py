"""Populated restore qualification from the already validated private HA environment."""

import argparse
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit, urlunsplit

from deploy.check_active_active import validate_configuration
from deploy.check_restore import RestoreQualification, compose_client, identifier


def write_private(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


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
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix="pamolive-populated-restore-"))
    environment_file, archive = (directory / name for name in ("application.env", "source.dump"))
    admin = RestoreQualification(
        SimpleNamespace(docker=args.docker, postgres_container=args.postgres_container)
    )
    created, source_oid, owner_oid = False, None, None
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

        application(
            [
                "-c",
                "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); "
                "import django; django.setup(); from django.db import connection; "
                "assert connection.settings_dict['NAME']=='test_pamolive_restore_source'; "
                "cursor=connection.cursor(); cursor.execute('SELECT current_database()'); "
                "assert cursor.fetchone()[0]=='test_pamolive_restore_source'; "
                "from django.core.management import call_command; "
                "call_command('migrate',interactive=False)",
            ]
        )
        # Use -c/runpy so /app remains on sys.path in an older matching image.
        application(
            ["-c", "import runpy; runpy.run_path('/qualification.py',run_name='__main__')"],
            Path(__file__).with_name("prepare_restore_fixture.py"),
        )
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
        try:
            report = check.execute()
        finally:
            check.cleanup()
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
        write_private(directory / "result" / "report.json", json.dumps(report, sort_keys=True))
        print(json.dumps(report, sort_keys=True))
    finally:
        # No termination/force or broad cleanup. Refuse a reused source or changed owner.
        if created:
            identity = admin.sql(
                f"SELECT oid || ':' || datdba FROM pg_database WHERE datname='{source_name}';"
            )
            sessions = int(
                admin.sql(f"SELECT count(*) FROM pg_stat_activity WHERE datname='{source_name}';")
            )
            if source_oid is None or identity != f"{source_oid}:{owner_oid}" or sessions:
                raise RuntimeError(
                    "Synthetic source is still active or changed; retained for inspection."
                )
            admin.sql(f"DROP DATABASE {identifier(source_name)};")
        if environment_file.exists():
            environment_file.unlink()


if __name__ == "__main__":
    main()
