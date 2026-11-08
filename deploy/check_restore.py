"""Restore a trusted custom archive into a new restricted, disposable database.

Python 3.8+ and Docker only. The live application is never stopped or redirected.
No global cleanup, volume deletion, --clean, --create or DROP OWNED is used.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import time
from pathlib import Path


def identifier(value):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
        raise ValueError("Unsafe PostgreSQL identifier.")
    return '"' + value + '"'


def scram_verifier(password):
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
    client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encode = lambda value: base64.b64encode(value).decode()  # noqa: E731
    return (
        "SCRAM-SHA-256$4096:"
        + encode(salt)
        + "$"
        + encode(hashlib.sha256(client).digest())
        + ":"
        + encode(server)
    )


def private_file(path):
    path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or (os.name != "nt" and info.st_mode & 0o077):
        raise ValueError("Input must be an owner-only regular file.")
    return path


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class RestoreQualification:
    def __init__(self, args):
        self.args = args
        self.database = "pamolive_restore_check_" + secrets.token_hex(8)
        self.role = self.database + "_role"
        self.password = secrets.token_urlsafe(40)
        self.role_oid = self.database_oid = None
        self.role_created = self.database_created = self.directory_created = False
        self.phase = "input validation"
        self.directory = None

    def command(self, arguments, *, content=None, environment=None, output=None):
        return subprocess.run(
            arguments,
            input=content,
            stdout=output or subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=True,
        ).stdout

    def sql(self, statement):
        # Explicit Unix socket/database; no client rc, service file or inherited PG options.
        script = (
            "unset PGSERVICE PGSERVICEFILE PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD PGOPTIONS; "
            "exec psql -X -qAt -v ON_ERROR_STOP=1 -h /var/run/postgresql -p 5432 "
            '-U "$POSTGRES_USER" -d postgres'
        )
        result = self.command(
            [self.args.docker, "exec", "-i", self.args.postgres_container, "sh", "-c", script],
            content=statement.encode(),
        )
        return result.decode().strip()

    def json_file(self, name, data):
        descriptor = os.open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True)

    def application_command(self, action, *, wrong_key=False, wrong_password=False, database=None):
        source = Path(__file__).with_name("restore_application_check.py").resolve(strict=True)
        if "," in str(source):
            raise ValueError("The qualification source path must not contain a comma.")
        command = [
            self.args.docker,
            "run",
            "--rm",
            "-i",
            "--no-healthcheck",
            "--memory",
            "512m",
            "--pids-limit",
            "64",
            "--read-only",
            "--user",
            "1000:1000",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/tmp:size=64m,mode=1777",
            "--network",
            self.args.database_network,
            "--env-file",
            str(self.args.application_env),
            "--mount",
            "type=bind,source=" + str(source) + ",target=/restore_application_check.py,readonly",
            "-e",
            "PAMOLIVE_RESTORE_PASSWORD",
            "--entrypoint",
            "python",
        ]
        if wrong_key:
            command.extend(
                ["-e", "PAMOLIVE_ENCRYPTION_KEY=deliberately-wrong-restoration-check-key"]
            )
        command.extend(
            [
                self.image,
                "/restore_application_check.py",
                action,
                "--database",
                database or self.database,
                "--role",
                self.role,
                "--archive-sha256",
                getattr(self, "archive_hash", ""),
            ]
        )
        environment = dict(
            os.environ,
            PAMOLIVE_RESTORE_PASSWORD="deliberately-wrong-login-password"
            if wrong_password
            else self.password,
        )
        return command, environment

    def application(self, action, *, bundle=None, wrong_key=False, wrong_password=False):
        command, environment = self.application_command(
            action, wrong_key=wrong_key, wrong_password=wrong_password
        )
        return json.loads(
            self.command(
                command, content=json.dumps(bundle or {}).encode(), environment=environment
            )
        )

    def create_consistent_backup(self):
        identifier(self.args.source_database)
        self.args.archive = self.args.archive.resolve()
        parent = self.args.archive.parent.stat()
        if os.name != "nt" and parent.st_mode & 0o077:
            raise ValueError("A private owner-only archive directory is required.")
        command, environment = self.application_command(
            "snapshot-session", database=self.args.source_database
        )
        descriptor = os.open(
            self.directory / "source-stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as diagnostic:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=diagnostic,
                env=environment,
            )
            try:
                line = process.stdout.readline(8 * 1024 * 1024 + 1)
                if len(line) > 8 * 1024 * 1024:
                    raise ValueError("Source manifest is too large.")
                header = json.loads(line)
                snapshot = header.get("snapshot", "")
                if not re.fullmatch(r"[A-Fa-f0-9-]{1,128}", snapshot):
                    raise RuntimeError("Source did not export a PostgreSQL snapshot.")
                self.json_file("manifest.json", header["manifest"])
                descriptor = os.open(self.args.archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as archive:
                    script = (
                        "unset PGSERVICE PGSERVICEFILE PGHOST PGPORT PGDATABASE "
                        "PGUSER PGPASSWORD PGOPTIONS; "
                        'exec pg_dump -h /var/run/postgresql -p 5432 -U "$POSTGRES_USER" '
                        '-d "$1" -Fc --snapshot="$2"'
                    )
                    self.command(
                        [
                            self.args.docker,
                            "exec",
                            self.args.postgres_container,
                            "sh",
                            "-c",
                            script,
                            "pamolive-snapshot-backup",
                            self.args.source_database,
                            snapshot,
                        ],
                        output=archive,
                    )
                self.archive_hash = file_sha256(self.args.archive)
                process.stdin.write((self.archive_hash + "\n").encode())
                process.stdin.close()
                probe = json.loads(process.stdout.readline(1024 * 1024))
                if process.wait() != 0:
                    raise RuntimeError("Source snapshot process did not finish successfully.")
                return header["manifest"], probe
            finally:
                try:
                    if not process.stdin.closed:
                        process.stdin.close()
                except BrokenPipeError:
                    pass
                # Drain without printing row/probe data and let EOF release the read-only snapshot.
                while process.stdout.read(1024 * 1024):
                    pass
                process.wait()

    def create_isolated_database(self):
        role, database = identifier(self.role), identifier(self.database)
        # Only a random temporary password's SCRAM verifier enters SQL, never plaintext.
        verifier = scram_verifier(self.password)
        self.sql(
            f"CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
            f"NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3 PASSWORD '{verifier}';"
        )
        self.role_created = True
        self.role_oid = int(self.sql(f"SELECT oid FROM pg_roles WHERE rolname='{self.role}';"))
        self.sql(f"CREATE DATABASE {database} OWNER {role} TEMPLATE template0;")
        self.database_created = True
        self.database_oid = int(
            self.sql(f"SELECT oid FROM pg_database WHERE datname='{self.database}';")
        )
        self.sql(f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;")

    def restore_archive(self):
        environment = dict(
            os.environ,
            PGPASSWORD=self.password,
            PGOPTIONS="-c statement_timeout=120000 -c lock_timeout=5000",
        )
        command = [
            self.args.docker,
            "exec",
            "-i",
            "-e",
            "PGPASSWORD",
            "-e",
            "PGOPTIONS",
            self.args.postgres_container,
            "pg_restore",
            "-h",
            "127.0.0.1",
            "-p",
            "5432",
            "-U",
            self.role,
            "--dbname",
            self.database,
            "--single-transaction",
            "--exit-on-error",
            "--no-owner",
            "--no-privileges",
            "--no-tablespaces",
            "--no-publications",
            "--no-subscriptions",
            "--no-security-labels",
        ]
        # No timeout kills the Docker observation while an exec could still be alive.
        # PostgreSQL bounds statements and connects locally; observe this process to completion.
        with self.args.archive.open("rb") as stream:
            subprocess.run(
                command,
                stdin=stream,
                capture_output=True,
                env=environment,
                check=True,
            )

    def cleanup(self):
        if not self.role_created:
            return
        if (
            not re.fullmatch(r"pamolive_restore_check_[a-f0-9]{16}", self.database)
            or self.role != self.database + "_role"
        ):
            raise RuntimeError("Cleanup refuses a name outside its generated restoration scope.")
        if self.role_oid is None:
            raise RuntimeError("Created role identity is unconfirmed; retain it for inspection.")
        role, database = identifier(self.role), identifier(self.database)
        role_oid = self.sql(f"SELECT oid FROM pg_roles WHERE rolname='{self.role}';")
        if role_oid != str(self.role_oid):
            raise RuntimeError("Restore role identity changed; no cleanup attempted.")
        self.sql(f"ALTER ROLE {role} NOLOGIN PASSWORD NULL;")
        if self.database_created:
            if self.database_oid is None:
                raise RuntimeError(
                    "Created database identity is unconfirmed; sealed copy retained."
                )
            value = self.sql(
                f"SELECT oid || ':' || datdba FROM pg_database WHERE datname='{self.database}';"
            )
            if value != f"{self.database_oid}:{self.role_oid}":
                raise RuntimeError(
                    "Restore database identity or owner changed; no deletion attempted."
                )
            sessions = int(
                self.sql(f"SELECT count(*) FROM pg_stat_activity WHERE datname='{self.database}';")
            )
            if sessions:
                raise RuntimeError(
                    "A restore session is still active; sealed copy retained for inspection."
                )
            self.sql(f"DROP DATABASE {database};")
            self.database_oid = None
            self.database_created = False
        self.sql(f"DROP ROLE {role};")
        self.role_oid = None
        self.role_created = False

    def execute(self):
        self.args.application_env = private_file(self.args.application_env)
        self.directory = self.args.report_directory.resolve()
        os.mkdir(self.directory, 0o700)
        self.directory_created = True
        self.image = json.loads(
            self.command([self.args.docker, "image", "inspect", self.args.application_image])
        )[0]["Id"]
        manifest = None
        if self.args.source_database:
            self.phase = "consistent source snapshot and new backup"
            manifest, probe = self.create_consistent_backup()
        else:
            self.args.archive = private_file(self.args.archive)
            with self.args.archive.open("rb") as stream:
                if stream.read(5) != b"PGDMP":
                    raise ValueError("Only a trusted PostgreSQL custom archive is accepted.")
            self.archive_hash = file_sha256(self.args.archive)
            self.phase = "archive-bound key companion"
            probe = self.application("key-probe")
        if self.args.expected_manifest:
            manifest = json.loads(
                private_file(self.args.expected_manifest).read_text(encoding="utf-8")
            )
        self.json_file("key-check.json", probe)
        self.phase = "restricted isolated database creation"
        self.create_isolated_database()
        self.phase = "restricted network authentication"
        self.application("connection")
        try:
            self.application("connection", wrong_password=True)
        except subprocess.CalledProcessError as error:
            negative = json.loads(error.stdout)
            if (
                negative.get("error") != "OperationalError"
                or negative.get("phase") != "database scope"
            ):
                raise RuntimeError("Wrong-password probe failed for an unrelated reason.") from None
        else:
            raise RuntimeError("The database network accepts an incorrect restore-role password.")
        self.application("connection")
        self.phase = "restore as a nonadministrative login role"
        self.restore_archive()
        self.phase = "offline application verification"
        bundle = {"manifest": manifest, "key_probe": probe}
        result = self.application("verify", bundle=bundle)
        self.phase = "wrong-key rejection"
        try:
            self.application("verify", bundle=bundle, wrong_key=True)
        except subprocess.CalledProcessError as error:
            negative = json.loads(error.stdout)
            if negative.get("error") != "InvalidToken":
                raise RuntimeError("Wrong-key probe failed for an unrelated reason.") from None
        else:
            raise RuntimeError("A wrong encryption key was accepted.")
        if file_sha256(self.args.archive) != self.archive_hash:
            raise RuntimeError("Source archive changed during qualification.")
        if self.args.require_populated and (
            result["encrypted_values_checked"] < 3
            or result["signed_proofs_checked"] < 1
            or result["sealed_captures_verified"] < 1
            or not result["full_managed_model_manifest"]
        ):
            raise RuntimeError("Synthetic restore fixture did not exercise the required evidence.")
        result.update(
            result="OK",
            archive_sha256=self.archive_hash,
            archive_bytes=self.args.archive.stat().st_size,
            application_image=self.image,
            wrong_key_refused=True,
            wrong_database_password_refused=True,
            source_archive_unchanged=True,
            production_database_replaced=False,
            permanent_containers_added=0,
            safe_to_serve=False,
        )
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--postgres-container", required=True)
    parser.add_argument("--database-network", required=True)
    parser.add_argument("--application-image", required=True)
    parser.add_argument("--application-env", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--expected-manifest", type=Path)
    source.add_argument(
        "--source-database", help="Create a NEW archive and manifest from one exported snapshot"
    )
    parser.add_argument("--report-directory", type=Path, required=True)
    parser.add_argument("--require-populated", action="store_true")
    args = parser.parse_args()
    check = RestoreQualification(args)
    result, failure = None, None
    started = time.monotonic()
    try:
        result = check.execute()
    except Exception as error:
        failure = {"result": "failed", "phase": check.phase, "error": type(error).__name__}
        if check.directory_created and isinstance(error, subprocess.CalledProcessError):
            check.json_file(
                "private-error.json",
                {
                    "stdout": (error.stdout or b"").decode(errors="replace"),
                    "stderr": (error.stderr or b"").decode(errors="replace"),
                },
            )
    finally:
        try:
            check.cleanup()
        except Exception as error:
            failure = {
                "result": "failed",
                "phase": "isolated copy cleanup",
                "error": type(error).__name__,
            }
    report = failure or result
    report.update(
        seconds=round(time.monotonic() - started, 3),
        isolated_copy_removed=not check.database_created,
        temporary_role_removed=not check.role_created,
    )
    if check.directory_created:
        check.json_file("report.json", report)
    print(json.dumps(report, sort_keys=True))
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
