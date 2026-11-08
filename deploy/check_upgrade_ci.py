"""Qualify the controlled a8 upgrade with an actual restricted disposable login."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

from deploy.check_active_active import validate_configuration
from deploy.check_restore import RestoreQualification, compose_client
from deploy.check_restore_ci import write_private
from deploy.restore_application_check import restore_url


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
    directory = Path(tempfile.mkdtemp(prefix="pamolive-controlled-upgrade-"))
    environment_file = directory / "application.env"
    scope = RestoreQualification(
        SimpleNamespace(docker=args.docker, postgres_container=args.postgres_container)
    )

    def command(arguments, *, content=None, environment=None):
        try:
            return subprocess.run(
                arguments, input=content, env=environment, check=True, capture_output=True
            ).stdout
        except subprocess.CalledProcessError as error:
            write_private(
                directory / "private-error.json",
                json.dumps(
                    dict(
                        stdout=(error.stdout or b"").decode(errors="replace"),
                        stderr=(error.stderr or b"").decode(errors="replace"),
                    )
                ),
            )
            raise RuntimeError(
                "Controlled upgrade qualification failed; private diagnostics retained"
            ) from None

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
        image = json.loads(command([args.docker, "image", "inspect", service["image"]]))[0]["Id"]
        network = config["networks"]["database"]["name"]
        scope.create_isolated_database()
        private = {key: values[key] for key in ("SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY")}
        private.update(
            DATABASE_URL=restore_url(
                values["DATABASE_URL"], scope.database, scope.role, scope.password
            ),
            PAMOLIVE_UPGRADE_FIXTURE="1",
            DEBUG="false",
        )
        if any(any(character in value for character in "'\r\n\\") for value in private.values()):
            raise RuntimeError("Unsupported synthetic environment")
        write_private(
            environment_file, "".join(f"{key}='{value}'\n" for key, value in private.items())
        )

        def application(arguments, content=None):
            prefix, environment = compose_client(
                args.docker,
                image,
                environment_file,
                network,
                Path(__file__).with_name("restore_application_check.py"),
                scope.database.replace("_", "-"),
            )
            return json.loads(
                command(prefix + ["checker"] + arguments, content=content, environment=environment)
            )

        seeded = application(["-m", "deploy.prepare_upgrade_fixture"])
        if not seeded["populated"]:
            raise RuntimeError("Historical data were not prepared")
        plan_args = ["-m", "deploy.controlled_upgrade", "plan", "--database", scope.database]
        plan = application(plan_args)
        if len(plan["migrations"]) != 11:
            raise RuntimeError("Unexpected historical upgrade path")
        common = ["--database", scope.database, "--reviewed-plan", "-", "--offline-ack"]
        encoded = json.dumps(plan).encode()
        rollback = application(
            ["-m", "deploy.controlled_upgrade", "probe-rollback"] + common, encoded
        )
        if rollback["committed"] or not rollback["rollback_schema_and_rows_verified"]:
            raise RuntimeError("Whole-upgrade rollback was not established")
        if application(plan_args) != plan:
            raise RuntimeError("The rollback did not preserve the migration journal")
        applied = application(["-m", "deploy.controlled_upgrade", "apply"] + common, encoded)
        if not applied["committed"] or applied["new_models"] != 22:
            raise RuntimeError("Upgrade commit or schema delta is unexpected")
        verified = application(
            [
                "-c",
                "import os,json; "
                "os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); "
                "import django; django.setup(); "
                "from deploy.restore_application_check import verify_application; "
                "print(json.dumps(verify_application(),sort_keys=True))",
            ]
        )
        if not verified["audit_valid"] or verified["encrypted_values_checked"] < 1:
            raise RuntimeError("Historical security values or audit were not preserved")
        report = dict(
            applied,
            application_image=image,
            restricted_login=True,
            rollback_schema_and_rows_verified=True,
            audit_valid=True,
            historical_encryption_verified=True,
            synthetic_only=True,
        )
    finally:
        scope.cleanup()
        if environment_file.exists():
            environment_file.unlink()
    report.update(
        isolated_copy_removed=not scope.database_created,
        temporary_role_removed=not scope.role_created,
    )
    write_private(directory / "report.json", json.dumps(report, sort_keys=True))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
