"""Constructor, ownership and cleanup tests under an inert Docker double."""

import copy
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_installed_lab as scenario  # noqa: E402
from lab_docker import ENDPOINTS, Container, Lab, Volume  # noqa: E402

TOKEN = "pv-" + "a" * 32
CID = "1" * 64
NET = "2" * 64
IMAGE = "sha256:" + "3" * 64


class EngineDouble:
    def __init__(self):
        self.rows = {}
        self.commands = []
        self.deadline = 480
        self.clock = lambda: 0

    def exists(self, kind, name):
        return (kind, name) in self.rows

    def identity_exists(self, kind, identity):
        return any(
            group == kind and r.get("Id") == identity for (group, _name), r in self.rows.items()
        )

    def inspect(self, kind, key):
        rows = (row for (group, _name), row in self.rows.items() if group == kind)
        return next(row for row in rows if key in (row.get("Id"), row["Name"].lstrip("/")))

    def checked(self, *args, **options):
        self.commands.append((args, options))
        kind, action, *rest = args
        if action == "rm":
            row = self.inspect(kind, rest[-1])
            del self.rows[(kind, row["Name"].lstrip("/"))]
        return b""


class LabOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.engine = EngineDouble()
        self.journal = []
        self.lab = Lab(
            Path(__file__).resolve().parent / "inert-lab-tests",
            engine=self.engine,
            reservation=TOKEN,
            journal=lambda _path, data: self.journal.append(copy.deepcopy(data)),
        )

    def container(self, role="server"):
        user, ip, alias = ENDPOINTS[role]
        spec = Container(
            IMAGE, role, user, ("/bin/expected",), (Volume(role, "/lab"),), address=ip, alias=alias
        )
        self.lab.network, self.lab.network_id = TOKEN + "-network", NET
        name = TOKEN + "-" + role
        self.lab.volumes[role] = name
        item = self.lab.reserve("container", role, name)
        row = {
            "Id": CID,
            "Image": IMAGE,
            "Name": "/" + name,
            "Config": {
                "Labels": self.lab.labels(role),
                "User": user,
                "Cmd": list(spec.command),
                "Entrypoint": [spec.entrypoint] if spec.entrypoint else None,
                "Env": [],
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "PublishAllPorts": False,
                "PortBindings": {},
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": 256 * 1024**2,
                "MemorySwap": 256 * 1024**2,
                "PidsLimit": 128,
                "NanoCpus": 10**9,
                "IpcMode": "private",
                "LogConfig": {"Type": "none", "Config": {}},
                "Tmpfs": None,
                "NetworkMode": self.lab.network,
            },
            "Mounts": [{"Type": "volume", "Name": name, "Destination": "/lab", "RW": False}],
            "NetworkSettings": {
                "Networks": {
                    self.lab.network: {
                        "NetworkID": NET,
                        "IPAMConfig": {"IPv4Address": ip},
                        "IPAddress": ip,
                        "Aliases": [alias],
                    }
                }
            },
            "State": {"Status": "running", "Running": True, "OOMKilled": False, "ExitCode": 0},
        }
        self.engine.rows[("container", name)] = row
        return spec, item, row

    def test_reservation_precedes_any_mutation_and_captures_exact_identity(self):
        spec, item, row = self.container()
        self.assertIsNone(self.journal[-1]["objects"][0]["identity"])
        self.assertEqual(self.engine.commands, [])
        self.assertIs(self.lab.container_profile(item, spec), row)
        self.assertEqual(self.journal[-1]["objects"][0]["identity"], CID)

    def test_runtime_profile_refuses_write_access_port_publish_and_cross_network(self):
        spec, item, row = self.container()
        mutations = (
            (row["Mounts"][0], "RW", True),
            (row["HostConfig"], "PortBindings", {"9443/tcp": [{}]}),
            (row["HostConfig"], "Privileged", True),
            (row["Config"], "Cmd", ["/bin/unexpected"]),
            (row["NetworkSettings"]["Networks"][self.lab.network], "NetworkID", "f" * 64),
        )
        for mapping, key, foreign in mutations:
            with self.subTest(key=key):
                previous = mapping[key]
                mapping[key] = foreign
                with self.assertRaises(ValueError):
                    self.lab.container_profile(item, spec)
                mapping[key] = previous
        self.assertEqual(self.engine.commands, [])

    def test_preparer_has_only_chown_none_network_and_no_persistent_logs(self):
        for name in ("postgres", "server", "client"):
            self.lab.volumes[name] = TOKEN + "-" + name
        spec = Container(
            IMAGE,
            "preparer",
            "0:0",
            ("/bin/declared",),
            (
                Volume("postgres", "/stage/pg", False),
                Volume("server", "/stage/server", False),
                Volume("client", "/stage/client", False),
            ),
            chown=True,
        )
        args = self.lab.switches(spec)
        self.assertEqual(args[args.index("--cap-add") + 1], "CAP_CHOWN")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--log-driver") + 1], "none")
        self.assertNotIn("--publish", args)

    def test_existing_name_never_enters_the_cleanup_reservation(self):
        name = TOKEN + "-client"
        self.engine.rows[("container", name)] = {"Name": "/" + name}
        with self.assertRaises(ValueError):
            self.lab.reserve("container", "client", name)
        self.assertTrue(self.lab.cleanup())
        self.assertEqual(self.engine.commands, [])

    def test_refuses_cleanup_after_foreign_identity_or_labels(self):
        spec, item, row = self.container()
        self.lab.container_profile(item, spec)
        row["Config"]["Labels"] = {"unrelated": "true"}
        self.assertFalse(self.lab.cleanup())
        self.assertEqual(self.engine.commands, [])
        self.assertTrue(self.engine.exists("container", item["name"]))

    def test_cleanup_removes_only_the_exact_owned_id_before_its_volume(self):
        volname = TOKEN + "-server"
        self.lab.reserve("volume", "server", volname)
        self.engine.rows[("volume", volname)] = {
            "Name": volname,
            "Labels": self.lab.labels("server"),
        }
        self.container()
        self.assertTrue(self.lab.cleanup())
        self.assertEqual(
            [args for args, _ in self.engine.commands],
            [
                ("container", "rm", "--force", CID),
                ("volume", "rm", volname),
            ],
        )
        self.assertTrue(all(item["removed"] for item in self.journal[-1]["objects"]))

    def test_missing_unconfirmed_creation_remains_uncertain(self):
        self.lab.reserve("volume", "client", TOKEN + "-client")
        self.assertFalse(self.lab.cleanup())
        self.assertEqual(self.engine.commands, [])

    def test_missing_name_with_still_live_reserved_id_refuses_cleanup_proof(self):
        spec, item, row = self.container()
        self.lab.container_profile(item, spec)
        del self.engine.rows[("container", item["name"])]
        row["Name"] = "/renamed-owned-container"
        self.engine.rows[("container", "renamed-owned-container")] = row
        self.assertFalse(self.lab.cleanup())
        self.assertEqual(self.engine.commands, [])


class ScenarioTests(unittest.TestCase):
    def laboratory(self):
        lab = Mock()
        lab.work = Path("synthetic-fixture")
        lab.reservation = TOKEN
        lab.image.return_value = IMAGE
        lab.exec.return_value = SimpleNamespace(returncode=0, stderr=b"")
        lab.engine.checked.return_value = b"0\n"
        lab.container_profile.return_value = {
            "State": {"Status": "exited", "ExitCode": 0, "OOMKilled": False}
        }
        roles = [
            ({"identity": CID, "role": name}, name)
            for name in ("preparer", "postgres", "server", "client")
        ]
        return lab, roles

    def test_foreign_database_refuses_before_acknowledging_or_starting_vault(self):
        lab, roles = self.laboratory()
        report = {}
        with (
            patch.object(scenario, "read_regular", return_value=b"synthetic"),
            patch.object(scenario, "create", return_value=roles),
            patch.object(scenario, "staged_sql", return_value=b"fixture") as capture,
            patch.object(scenario, "wait"),
            patch.object(
                scenario,
                "run_pg",
                return_value=SimpleNamespace(returncode=0, stdout=scenario.pg_bootstrap.REFUSED),
            ),
            self.assertRaises(ValueError),
        ):
            scenario.run(lab, report)
        self.assertEqual(report["phase"], "postgres_provisioning")
        self.assertNotIn("empty_cluster_verified", report)
        self.assertEqual(lab.start.call_count, 2)
        self.assertEqual(capture.call_count, 1)
        lab.exec.assert_not_called()

    def test_success_requires_exact_client_test_counts_after_commissioning(self):
        lab, roles = self.laboratory()
        raw = b"synthetic"
        counts = {
            "run": 10,
            "failures": 0,
            "errors": 0,
            "skips": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        result = {
            "ok": True,
            "tests": counts,
            "authorized": False,
            "installed_input_sha256": scenario.sha(raw),
            "test_lab_sha256": scenario.TEST_SHA,
        }
        lab.start.return_value = SimpleNamespace(
            returncode=0, stderr=b"", stdout=json.dumps(result).encode("ascii")
        )
        report = {}
        with (
            patch.object(scenario, "read_regular", return_value=raw),
            patch.object(scenario, "create", return_value=roles),
            patch.object(scenario, "staged_sql", return_value=b"fixture"),
            patch.object(scenario, "wait"),
            patch.object(
                scenario,
                "run_pg",
                side_effect=[
                    SimpleNamespace(returncode=0, stdout=scenario.pg_bootstrap.READY),
                    SimpleNamespace(returncode=0, stdout=scenario.postgres_stage.SLOT_READY),
                ],
            ),
        ):
            scenario.run(lab, report)
        self.assertEqual(
            report, {"phase": "complete", "empty_cluster_verified": True, "tests": counts}
        )
        self.assertEqual(
            [args.args[1] for args in lab.start.call_args_list],
            ["preparer", "postgres", "server", "client"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
