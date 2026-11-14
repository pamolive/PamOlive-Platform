"""Compose parsing only: no Docker Engine, network or NAS connection is used."""

import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import patch

from deploy.runtime import APPLICATION_PATH, NATIVE_LIBRARIES
from deploy.synology_preflight import main, validate, validate_image_runtime, validate_tmpfs

ROOT = Path(__file__).resolve().parents[1]


@skipUnless(shutil.which("docker"), "Docker Compose CLI is required; no daemon is used")
class SynologyPreparationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = tempfile.TemporaryDirectory(prefix="pamolive-p1-compose-")
        cls.addClassCleanup(cls.directory.cleanup)
        folder = Path(cls.directory.name)
        app = folder / "app.env"
        app.write_text(
            "SECRET_KEY="
            + "s" * 64
            + "\nPAMOLIVE_ENCRYPTION_KEY="
            + "e" * 64
            + "\nDATABASE_URL=postgresql://pamolive_test:"
            + "a" * 64
            + "@postgres/test_pamolive_p1\n",
            encoding="utf-8",
        )
        cls.application_env = app
        for name in ("owner", "app", "tls-cert", "tls-key"):
            (folder / (name + ".secret")).write_text("a" * 64, encoding="utf-8")
        env = folder / "config"
        cls.config_file = env
        values = {
            "PAMOLIVE_TEST_PROJECT": "pamolive-p1-local-parser",
            "PAMOLIVE_TEST_IMAGE": "example.invalid/pamolive@sha256:" + "a" * 64,
            "PAMOLIVE_TEST_POSTGRES_IMAGE": "postgres@sha256:" + "b" * 64,
            "PAMOLIVE_TEST_GATEWAY_IMAGE": "nginxinc/nginx-unprivileged@sha256:" + "c" * 64,
            "PAMOLIVE_TEST_APP_ENV": app.as_posix(),
            "PAMOLIVE_TEST_OWNER_PASSWORD_FILE": (folder / "owner.secret").as_posix(),
            "PAMOLIVE_TEST_APP_PASSWORD_FILE": (folder / "app.secret").as_posix(),
            "PAMOLIVE_TEST_TLS_CERTIFICATE_FILE": (folder / "tls-cert.secret").as_posix(),
            "PAMOLIVE_TEST_TLS_KEY_FILE": (folder / "tls-key.secret").as_posix(),
            "PAMOLIVE_TEST_PORT": "18020",
            "PAMOLIVE_TEST_WEB_CPUS": "0.5",
            "PAMOLIVE_TEST_DB_CPUS": "0.5",
            "PAMOLIVE_TEST_WEB_MEMORY": "512m",
            "PAMOLIVE_TEST_DB_MEMORY": "256m",
            "PAMOLIVE_TEST_GATEWAY_CPUS": "0.25",
            "PAMOLIVE_TEST_GATEWAY_MEMORY": "64m",
        }
        env.write_text("\n".join(f"{k}={v}" for k, v in values.items()), encoding="utf-8")
        result = subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(env),
                "-f",
                str(ROOT / "deploy/synology-test/compose.yml"),
                "config",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise AssertionError("Synthetic Compose configuration could not be parsed.")
        cls.plan = json.loads(result.stdout)

    def test_reviewed_configuration_has_private_network_and_restricted_database(self):
        validate(self.plan, application_env=self.application_env)

    def test_tls_and_database_secret_files_cannot_alias(self):
        names = tuple(self.plan["secrets"])
        for index, name in enumerate(names):
            for other in names[:index]:
                plan = copy.deepcopy(self.plan)
                plan["secrets"][name]["file"] = plan["secrets"][other]["file"]
                with self.subTest(name=name, other=other), self.assertRaises(ValueError):
                    validate(plan, application_env=self.application_env)

    def test_secret_cannot_alias_application_environment_or_gateway_config(self):
        for source in (self.application_env, ROOT / "deploy/synology-test/nginx.conf"):
            for name in self.plan["secrets"]:
                plan = copy.deepcopy(self.plan)
                plan["secrets"][name]["file"] = str(source.parent / "." / source.name)
                with self.subTest(name=name, source=source.name), self.assertRaises(ValueError):
                    validate(plan, application_env=self.application_env)

    def test_preflight_cli_forces_explicit_application_env(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "deploy.synology_preflight",
                "--env-file",
                str(self.config_file),
                "--application-env",
                str(self.application_env),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=dict(os.environ, PAMOLIVE_TEST_APP_ENV="unintended-application.env"),
        )
        self.assertEqual(result.returncode, 0, "Synthetic CLI preflight failed.")
        self.assertIn("no container started", result.stdout)
        self.assertNotIn("SECRET_KEY=", result.stdout)

    def test_compose_220_compatible_cli_uses_one_config_call_and_same_env_path(self):
        argv = [
            "synology_preflight",
            "--env-file",
            str(self.config_file),
            "--application-env",
            str(self.application_env),
        ]
        response = SimpleNamespace(returncode=0, stdout=json.dumps(self.plan))
        with (
            patch.object(sys, "argv", argv),
            patch("deploy.synology_preflight.subprocess.run", return_value=response) as run,
            redirect_stdout(io.StringIO()),
        ):
            main()
        run.assert_called_once()
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[-3:], ["config", "--format", "json"])
        self.assertNotIn("--environment", arguments)
        self.assertEqual(
            run.call_args.kwargs["env"]["PAMOLIVE_TEST_APP_ENV"],
            str(self.application_env.resolve()),
        )

    def test_existing_data_mount_and_host_network_are_rejected(self):
        for field, value in (
            (
                "volumes",
                [{"type": "bind", "source": "/existing", "target": "/var/lib/postgresql/data"}],
            ),
            ("network_mode", "host"),
            ("privileged", True),
        ):
            plan = copy.deepcopy(self.plan)
            plan["services"]["postgres"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_wrong_database_and_unpinned_image_are_rejected(self):
        for change in ("database", "image"):
            plan = copy.deepcopy(self.plan)
            if change == "image":
                plan["services"]["web"]["image"] = "pamolive:latest"
            else:
                plan["services"]["web"]["environment"]["DATABASE_URL"] = "postgresql://real/real"
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_lan_port_and_existing_volume_name_are_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan["services"]["gateway"]["ports"][0]["host_ip"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            validate(plan, application_env=self.application_env)
        plan = copy.deepcopy(self.plan)
        plan["volumes"]["postgres_test"]["name"] = "existing-volume"
        with self.assertRaises(ValueError):
            validate(plan, application_env=self.application_env)

    def test_host_namespaces_devices_and_added_capabilities_are_rejected(self):
        for field, value in (
            ("pid", "host"),
            ("ipc", "host"),
            ("devices", [{"source": "/dev/sda"}]),
            ("cap_add", ["SYS_ADMIN"]),
            ("cap_drop", []),
            ("security_opt", []),
            ("entrypoint", ["sh"]),
        ):
            plan = copy.deepcopy(self.plan)
            plan["services"]["web"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_application_egress_and_direct_http_publishing_are_rejected(self):
        for name in ("web", "postgres"):
            for field, value in (
                ("networks", {"database": {}, "ingress": {}}),
                ("ports", [{"host_ip": "127.0.0.1", "target": 8000}]),
            ):
                plan = copy.deepcopy(self.plan)
                plan["services"][name][field] = value
                with self.subTest(service=name, field=field), self.assertRaises(ValueError):
                    validate(plan, application_env=self.application_env)

    def test_gateway_root_capabilities_and_application_secrets_are_rejected(self):
        for field, value in (
            ("user", "0:0"),
            ("cap_add", ["NET_ADMIN"]),
            ("environment", {"DATABASE_URL": "postgresql://private"}),
            ("secrets", [{"source": "database_owner_password"}]),
            ("volumes", []),
        ):
            plan = copy.deepcopy(self.plan)
            plan["services"]["gateway"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_proxy_trust_bootstrap_empty_or_one_host_only(self):
        for value in ("", "172.31.10.9/32", "fd00::9/128"):
            plan = copy.deepcopy(self.plan)
            plan["services"]["web"]["environment"]["PAMOLIVE_TRUSTED_PROXY_NETWORKS"] = value
            validate(plan, application_env=self.application_env)
        for value in ("172.31.10.0/24", "0.0.0.0/0", "::/0", "172.31.10.9/32,172.31.10.10/32"):
            plan = copy.deepcopy(self.plan)
            plan["services"]["web"]["environment"]["PAMOLIVE_TRUSTED_PROXY_NETWORKS"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_ingress_must_be_new_and_isolation_cannot_be_disabled(self):
        for network, field, value in (
            ("ingress", "external", True),
            ("ingress", "name", "existing-network"),
            ("frontend", "internal", False),
            ("database", "internal", False),
        ):
            plan = copy.deepcopy(self.plan)
            plan["networks"][network][field] = value
            with self.subTest(network=network, field=field), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_gateway_cannot_join_database_network(self):
        plan = copy.deepcopy(self.plan)
        plan["services"]["gateway"]["networks"]["database"] = {}
        with self.assertRaises(ValueError):
            validate(plan, application_env=self.application_env)

    def test_five_profile_mutations_are_refused_before_container_launch(self):
        for change in ("command", "user", "font_tmpfs", "locale", "display"):
            plan = copy.deepcopy(self.plan)
            web = plan["services"]["web"]
            if change == "command":
                web["command"] = ["python", "manage.py", "runserver"]
            elif change == "user":
                web["user"] = "1000:1000"
            elif change == "font_tmpfs":
                web["tmpfs"] = ["/etc/fonts:size=64m,mode=1777"]
            elif change == "locale":
                web["environment"].update(LANGUAGE="synthetic", LANG="synthetic.UTF-8")
            else:
                web["environment"]["DISPLAY"] = ":99"
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_empty_entrypoint_command_and_user_type_overrides_are_not_defaults(self):
        for field, value in (
            ("entrypoint", []),
            ("entrypoint", ""),
            ("command", []),
            ("command", "python deploy/runtime.py"),
            ("user", 0),
            ("working_dir", "/tmp"),
            ("configs", [{"source": "synthetic", "target": "/etc/fonts/fonts.conf"}]),
        ):
            plan = copy.deepcopy(self.plan)
            plan["services"]["web"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)

    def test_tmpfs_types_sizes_permissions_unknown_options_and_shadows_are_refused(self):
        for value in (
            "/tmp:size=64m,mode=1777",
            {"/tmp": "size=64m"},
            [],
            ["/tmp:size=65m,mode=1777"],
            ["/tmp:size=64m,mode=0777"],
            ["/tmp:size=64m,mode=1777,exec"],
            ["/tmp:size=64m,mode=1777,suid"],
            ["/tmp:size=64m,mode=1777,unknown=value"],
            ["/tmp:size=64m,mode=1777,size=1m"],
            ["/tmp:size=64m,mode=1777,uid=1000"],
            ["/usr/lib:size=64m,mode=1777"],
            ["/app:size=64m,mode=1777"],
            ["/tmp/../etc/fonts:size=64m,mode=1777"],
        ):
            plan = copy.deepcopy(self.plan)
            plan["services"]["web"]["tmpfs"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)
        plan = copy.deepcopy(self.plan)
        plan["services"]["web"]["tmpfs"] = ["/tmp:size=64m,mode=1777,noexec,nosuid,nodev"]
        validate(plan, application_env=self.application_env)

    def test_all_service_tmpfs_destinations_are_bounded_and_socket_owner_is_fixed(self):
        for service in ("gateway", "postgres"):
            plan = copy.deepcopy(self.plan)
            plan["services"][service]["tmpfs"] = ["/etc/fonts:size=1m,mode=1777"]
            with self.subTest(service=service), self.assertRaises(ValueError):
                validate(plan, application_env=self.application_env)
        plan = copy.deepcopy(self.plan)
        plan["services"]["postgres"]["tmpfs"][1] = (
            "/var/run/postgresql:size=8m,mode=0775,uid=1000,gid=999"
        )
        with self.assertRaises(ValueError):
            validate(plan, application_env=self.application_env)

    def test_unsafe_preinterpreter_and_font_environment_is_refused_without_values(self):
        for name, value in (
            ("LD_PRELOAD", "/tmp/synthetic.so"),
            ("LD_AUDIT", "/tmp/synthetic.so"),
            ("LD_LIBRARY_PATH", "/tmp"),
            ("PYTHONPATH", "/tmp"),
            ("PYTHONHOME", "/tmp"),
            ("LC_ALL", "fr_FR.UTF-8"),
            ("FONTCONFIG_FILE", "/tmp/fonts.conf"),
            ("FONTCONFIG_PATH", "/tmp"),
            ("XAUTHORITY", "/tmp/xauth"),
            ("XDG_CONFIG_HOME", "/tmp"),
            ("NLSPATH", "/tmp/%N"),
            ("LOCPATH", "/tmp"),
            ("GCONV_PATH", "/tmp"),
            ("LD_UNKNOWN_LOADER", "synthetic"),
            ("LD_PRELOAD", ""),
            ("PYTHONINSPECT", "1"),
            ("PYTHONUSERBASE", "/tmp"),
            ("PYTHONUNKNOWN", "synthetic"),
            ("GLIBC_TUNABLES", "synthetic"),
        ):
            plan = copy.deepcopy(self.plan)
            plan["services"]["web"]["environment"][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError) as raised:
                validate(plan, application_env=self.application_env)
            if value:
                self.assertNotIn(value, str(raised.exception))

    def test_safe_native_paths_and_application_configuration_are_preserved(self):
        plan = copy.deepcopy(self.plan)
        plan["services"]["web"]["environment"].update(
            {
                "LD_LIBRARY_PATH": NATIVE_LIBRARIES,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PAMOLIVE_OIDC_CLIENT_ID": "synthetic-app",
                "PAMOLIVE_EVENT_MANUAL_DAILY_LIMIT": "5",
                "PAMOLIVE_CONNECTOR_HOSTS": "synthetic.invalid",
                "WEB_WORKERS": "1",
            }
        )
        validate(plan, application_env=self.application_env)

    def test_qualified_image_config_has_fixed_command_entrypoint_user_and_workdir(self):
        image = {
            "Cmd": ["python", "deploy/runtime.py"],
            "Entrypoint": None,
            "User": "root",
            "WorkingDir": "/app",
            "Env": [
                "LANG=C.UTF-8",
                "LD_LIBRARY_PATH=" + NATIVE_LIBRARIES,
                "PATH=" + APPLICATION_PATH,
            ],
        }
        validate(self.plan, application_env=self.application_env, image_config=image)
        for key, value in (
            ("Cmd", ["python", "manage.py", "runserver"]),
            ("Entrypoint", ["sh"]),
            ("User", "1000"),
            ("WorkingDir", "/tmp"),
            ("Env", ["LD_PRELOAD=/tmp/synthetic.so"]),
            ("Env", ["LANG=C.UTF-8", "LANG=fr_FR.UTF-8"]),
            ("Env", image["Env"] + ["PATH=/tmp"]),
            ("Env", image["Env"] + ["PYTHONINSPECT=1"]),
        ):
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate_image_runtime({**image, key: value})

    def test_cli_exposes_image_config_limit_and_validates_supplied_config_without_engine(self):
        config = Path(self.directory.name) / "image-config.json"
        config.write_text(
            json.dumps(
                {
                    "Cmd": ["python", "deploy/runtime.py"],
                    "User": "root",
                    "WorkingDir": "/app",
                    "Env": [
                        "LANG=C.UTF-8",
                        "LD_LIBRARY_PATH=" + NATIVE_LIBRARIES,
                        "PATH=" + APPLICATION_PATH,
                    ],
                }
            ),
            encoding="utf-8",
        )
        base = [
            "synology_preflight",
            "--env-file",
            str(self.config_file),
            "--application-env",
            str(self.application_env),
        ]
        response = SimpleNamespace(returncode=0, stdout=json.dumps(self.plan))
        for arguments, expected in (
            (base, "inherited image command and environment are unverified"),
            (base + ["--image-config", str(config)], "Supplied image Config validated"),
        ):
            output = io.StringIO()
            with (
                patch.object(sys, "argv", arguments),
                patch("deploy.synology_preflight.subprocess.run", return_value=response) as run,
                redirect_stdout(output),
            ):
                main()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][-3:], ["config", "--format", "json"])
            self.assertIn(expected, output.getvalue())
        config.write_text('{"Cmd":["synthetic-private-command"]}', encoding="utf-8")
        with (
            patch.object(sys, "argv", base + ["--image-config", str(config)]),
            patch("deploy.synology_preflight.subprocess.run", return_value=response),
            self.assertRaises(SystemExit) as raised,
        ):
            main()
        self.assertNotIn("synthetic-private-command", str(raised.exception))


class PureRuntimeProfileTests(TestCase):
    """Security helpers remain testable when the Compose CLI is unavailable."""

    def test_tmpfs_destinations_options_and_sizes_fail_closed_without_docker(self):
        validate_tmpfs("web", ["/tmp:size=64m,mode=1777"])
        for mount in (
            "/etc:size=64m,mode=1777",
            "/etc/fonts:size=64m,mode=1777",
            "/app:size=64m,mode=1777",
            "/usr/lib:size=64m,mode=1777",
            "/tmp:size=65m,mode=1777",
            "/tmp:size=64m,mode=1777,unknown",
            "/tmp:size=64m,mode=1777,exec",
            "/tmp:size=64m,mode=777",
        ):
            with self.subTest(mount=mount), self.assertRaises(ValueError):
                validate_tmpfs("web", [mount])

    def test_image_config_checks_unknown_loader_and_inherited_command_without_docker(self):
        config = {
            "Cmd": ["python", "deploy/runtime.py"],
            "User": "root",
            "WorkingDir": "/app",
            "Env": [
                "LANG=C.UTF-8",
                "LD_LIBRARY_PATH=" + NATIVE_LIBRARIES,
                "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PYTHON_VERSION=3.12.16",
                "PYTHONUNBUFFERED=1",
            ],
        }
        validate_image_runtime(config)
        for name in ("LD_FUTURE_FLAG", "PYTHONINSPECT", "XDG_UNKNOWN", "FONTCONFIG_UNKNOWN"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_image_runtime({**config, "Env": config["Env"] + [name + "=synthetic"]})
        for path in ("/tmp:/usr/bin", "/usr/local/bin::/usr/bin", "/usr/local/bin:."):
            changed = [item for item in config["Env"] if not item.startswith("PATH=")]
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_image_runtime({**config, "Env": changed + ["PATH=" + path]})
