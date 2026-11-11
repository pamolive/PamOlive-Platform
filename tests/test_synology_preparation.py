"""Compose parsing only: no Docker Engine, network or NAS connection is used."""

import copy
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, skipUnless

from deploy.synology_preflight import validate

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
            "SECRET_KEY=" + "s" * 64 + "\nPAMOLIVE_ENCRYPTION_KEY=" + "e" * 64
            + "\nDATABASE_URL=postgresql://pamolive_test:"
            + "a" * 64 + "@postgres/test_pamolive_p1\n", encoding="utf-8",
        )
        for name in ("owner", "app"):
            (folder / (name + ".secret")).write_text("a" * 64, encoding="utf-8")
        env = folder / "config"
        values = {
            "PAMOLIVE_TEST_PROJECT": "pamolive-p1-local-parser",
            "PAMOLIVE_TEST_IMAGE": "example.invalid/pamolive@sha256:" + "a" * 64,
            "PAMOLIVE_TEST_POSTGRES_IMAGE": "postgres@sha256:" + "b" * 64,
            "PAMOLIVE_TEST_APP_ENV": app.as_posix(),
            "PAMOLIVE_TEST_OWNER_PASSWORD_FILE": (folder / "owner.secret").as_posix(),
            "PAMOLIVE_TEST_APP_PASSWORD_FILE": (folder / "app.secret").as_posix(),
            "PAMOLIVE_TEST_PORT": "18020", "PAMOLIVE_TEST_WEB_CPUS": "0.5",
            "PAMOLIVE_TEST_DB_CPUS": "0.5", "PAMOLIVE_TEST_WEB_MEMORY": "512m",
            "PAMOLIVE_TEST_DB_MEMORY": "256m",
        }
        env.write_text("\n".join(f"{k}={v}" for k, v in values.items()), encoding="utf-8")
        result = subprocess.run(
            ["docker", "compose", "--env-file", str(env), "-f",
             str(ROOT / "deploy/synology-test/compose.yml"), "config", "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise AssertionError("Synthetic Compose configuration could not be parsed.")
        cls.plan = json.loads(result.stdout)

    def test_reviewed_configuration_has_private_network_and_restricted_database(self):
        validate(self.plan)

    def test_existing_data_mount_and_host_network_are_rejected(self):
        for field, value in (("volumes", [{"type": "bind", "source": "/existing",
                                          "target": "/var/lib/postgresql/data"}]),
                             ("network_mode", "host"), ("privileged", True)):
            plan = copy.deepcopy(self.plan)
            plan["services"]["postgres"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(plan)

    def test_wrong_database_and_unpinned_image_are_rejected(self):
        for change in ("database", "image"):
            plan = copy.deepcopy(self.plan)
            if change == "image":
                plan["services"]["web"]["image"] = "pamolive:latest"
            else:
                plan["services"]["web"]["environment"]["DATABASE_URL"] = "postgresql://real/real"
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(plan)

    def test_lan_port_and_existing_volume_name_are_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan["services"]["web"]["ports"][0]["host_ip"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            validate(plan)
        plan = copy.deepcopy(self.plan)
        plan["volumes"]["postgres_test"]["name"] = "existing-volume"
        with self.assertRaises(ValueError):
            validate(plan)

    def test_host_namespaces_devices_and_added_capabilities_are_rejected(self):
        for field, value in (("pid", "host"), ("ipc", "host"),
                             ("devices", [{"source": "/dev/sda"}]),
                             ("cap_add", ["SYS_ADMIN"]), ("cap_drop", []),
                             ("security_opt", []), ("entrypoint", ["sh"])):
            plan = copy.deepcopy(self.plan)
            plan["services"]["web"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(plan)
