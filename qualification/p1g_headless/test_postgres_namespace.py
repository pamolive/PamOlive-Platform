"""Synthetic contracts for selecting a private PostgreSQL namespace."""

import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from qualification.p1g_headless import postgres_namespace as postgres


class PostgresNamespaceTests(TestCase):
    def test_admission_requires_exact_unpublished_container(self):
        identity = {
            "container_id": "a" * 64,
            "image_id": "sha256:" + "b" * 64,
            "name": "pamolive-p1g-postgres-25-1",
        }
        row = {
            "id": identity["container_id"], "config_id": identity["image_id"],
            "name": "/" + identity["name"], "reference": postgres.IMAGE,
            "network_mode": "none", "running": True, "port_bindings": {},
            "privileged": False, "read_only": True, "publish_all": False,
            "sandbox": "/run/docker/netns/123456789abc",
        }
        self.assertEqual(postgres.admit(row, **identity), row["sandbox"])
        for field, invalid in (
            ("id", "b" * 64), ("reference", "postgres:latest"), ("name", "/another"),
            ("network_mode", "host"), ("port_bindings", {"5432/tcp": [{}]}),
            ("publish_all", True), ("privileged", True), ("read_only", False),
            ("sandbox", "/proc/1/ns/net"), ("sandbox", "/run/docker/netns/../other"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                postgres.admit({**row, field: invalid}, **identity)

    def test_cleanup_uses_the_id_admitted_before_the_worker(self):
        identity = {"revision": "c" * 40, "run": "25", "attempt": "1"}
        owner, cid, image = "pamolive-p1g-postgres-25-1", "a" * 64, "sha256:" + "b" * 64
        row = {
            "id": cid, "config_id": image, "name": "/" + owner, "reference": postgres.IMAGE,
            "network_mode": "none", "running": True, "port_bindings": {},
            "privileged": False, "read_only": True, "publish_all": False,
            "sandbox": "/run/docker/netns/123456789abc",
        }

        def response(private, arguments, **_):
            match arguments[0]:
                case "image":
                    return image.encode()
                case "run":
                    (private / "postgres.cid").write_text(cid, encoding="ascii")
                    return cid.encode()
                case "inspect":
                    self.assertEqual(arguments[-1], cid)
                    return json.dumps(row).encode()
                case "rm":
                    self.assertEqual(arguments, ["rm", "--force", cid])
                    return cid.encode()
                case _:
                    return b""

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            postgres, "docker", side_effect=response,
        ):
            directory, receipt = Path(temporary), {}
            with postgres.service(directory, identity, receipt) as (namespace, container):
                self.assertEqual(namespace, row["sandbox"])
                self.assertEqual(container, cid)
                (directory / "postgres.cid").unlink()
            self.assertTrue(receipt["postgres_container_removed"])
