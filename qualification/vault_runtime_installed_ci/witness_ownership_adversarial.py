"""W01 ownership under inert Docker actors; no daemon, PG, network or writes.

These tests establish source-level allocation/profile/cleanup decisions. They do
not establish native tmpfs isolation, PG privileges, TLS or witness authority.
"""

import ast
import copy
import hashlib
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_docker as ownership  # noqa: E402
from lab import witness_prepare  # noqa: E402
from lab_docker import (  # noqa: E402
    WITNESS_ENDPOINTS,
    WITNESS_PREPARER_MOUNTS,
    WITNESS_VOLUMES,
    Container,
    Engine,
    Lab,
    Volume,
    WitnessClusterRestoreLab,
    WitnessLab,
    WitnessRecoveryLab,
    WitnessRestoreLab,
)

TOKEN = "pv-" + "a" * 32
IMAGE = "sha256:" + "3" * 64
PG_TMPFS = (
    ("/var/lib/postgresql/data", "rw,nosuid,nodev,size=268435456,mode=0700,uid=999,gid=999"),
    ("/var/run/postgresql", "rw,nosuid,nodev,size=8388608,mode=0755,uid=999,gid=999"),
    ("/tmp", "rw,noexec,nosuid,nodev,size=33554432,mode=1777"),
)


def specs(profile=WitnessLab):
    preparer = Container(
        IMAGE,
        "preparer",
        "0:0",
        ("/inputs/w01-prepare",),
        profile.preparer_mounts,
        (("/work", "rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=0,gid=0"),),
        chown=True,
    )
    result = [preparer]
    for role, (user, address, alias) in profile.endpoints.items():
        pg = role in profile.postgres_roles
        tmpfs = PG_TMPFS if pg else ()
        if role == "driver":
            tmpfs = (("/work", "rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=1000,gid=1000"),)
        result.append(
            Container(
                IMAGE,
                role,
                user,
                ("postgres",) if pg else ("/inputs/" + role,),
                (Volume(role, "/lab"),),
                tmpfs,
                ("PGDATA=/var/lib/postgresql/data",) if pg else (),
                address,
                alias,
            )
        )
    return result


class EngineActor:
    """Finite fake inspection records; no command is passed to a subprocess."""

    def __init__(self):
        self.rows = {}
        self.commands = []
        self.now = 0
        self.clock = lambda: self.now
        self.deadline = 480
        self.sequence = 0
        self.fail_role = None
        self.fail_after_create = False
        self.stall_inspection = False
        self.stop_exit_code = 143
        self.specs = {spec.role: spec for spec in specs()}

    def bound(self):
        if self.clock() >= self.deadline:
            raise ValueError("actor_deadline")

    def exists(self, kind, name):
        self.bound()
        return (kind, name) in self.rows

    def identity_exists(self, kind, identity):
        self.bound()
        return any(
            group == kind and row.get("Id") == identity for (group, _), row in self.rows.items()
        )

    def inspect(self, kind, key):
        if self.stall_inspection:
            self.now += 46
        self.bound()
        return next(
            row
            for (group, _), row in self.rows.items()
            if group == kind and key in (row.get("Id"), row["Name"].lstrip("/"))
        )

    def row(self, spec, identity, name):
        network = self.lab.network
        networks = {}
        if spec.address is not None:
            networks[network] = {
                "NetworkID": self.lab.network_id,
                "IPAMConfig": {"IPv4Address": spec.address},
                "IPAddress": "",
                "Aliases": [spec.alias] if spec.alias else [],
            }
        return {
            "Id": identity,
            "Name": "/" + name,
            "Image": spec.image,
            "Config": {
                "Labels": self.lab.labels(spec.role),
                "User": spec.user,
                "Cmd": list(spec.command),
                "Entrypoint": [spec.entrypoint] if spec.entrypoint else None,
                "Env": list(spec.environment),
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "PublishAllPorts": False,
                "PortBindings": {},
                "CapDrop": ["ALL"],
                "CapAdd": ["CAP_CHOWN"] if spec.chown else None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": 256 * 1024**2,
                "MemorySwap": 256 * 1024**2,
                "PidsLimit": 128,
                "NanoCpus": 10**9,
                "IpcMode": "private",
                "LogConfig": {"Type": "none", "Config": {}},
                "Tmpfs": dict(spec.tmpfs),
                "NetworkMode": network if spec.address else "none",
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": self.lab.volumes[m.role],
                    "Destination": m.destination,
                    "RW": not m.readonly,
                }
                for m in spec.volumes
            ],
            "NetworkSettings": {"Networks": networks},
            "State": {"Status": "created", "Running": False, "OOMKilled": False},
        }

    def checked(self, *args, **options):
        self.bound()
        self.commands.append((args, options, self.deadline))
        kind, action = args[:2]
        if action == "create":
            name = args[args.index("--name") + 1] if kind == "container" else args[-1]
            role = next(
                text.removeprefix(ownership.PART + "=")
                for text in args
                if text.startswith(ownership.PART + "=")
            )
            assert self.lab.owned[-1] == self.lab.journal_rows[-1]["objects"][-1]
            assert self.lab.owned[-1]["identity"] is None
            if role == self.fail_role and not self.fail_after_create:
                raise ValueError("actor_create_failure")
            self.sequence += 1
            identity = f"{self.sequence:064x}"
            if kind == "container":
                row = self.row(self.specs[role], identity, name)
            else:
                row = {
                    "Name": name,
                    "Labels": self.lab.labels(role),
                    "Driver": "local" if kind == "volume" else "bridge",
                    "Scope": "local",
                }
                if kind == "network":
                    row.update(
                        Id=identity,
                        Internal=True,
                        EnableIPv6=False,
                        Containers={},
                        IPAM={"Config": [{"Subnet": ownership.SUBNET}]},
                    )
            self.rows[(kind, name)] = row
            if role == self.fail_role:
                raise ValueError("actor_lost_create_response")
            return (name if kind == "volume" else identity).encode("ascii") + b"\n"
        if action == "rm":
            row = self.inspect(kind, args[-1])
            if kind == "volume":
                assert not any(
                    mount["Name"] == row["Name"]
                    for (group, _), container in self.rows.items()
                    if group == "container"
                    for mount in container["Mounts"]
                )
            del self.rows[(kind, row["Name"].lstrip("/"))]
            return b""
        if action == "start" and kind == "container":
            row = self.inspect(kind, args[-1])
            row["State"].update(Status="running", Running=True)
            endpoint = row["NetworkSettings"]["Networks"].get(self.lab.network)
            if endpoint is not None:
                endpoint["IPAddress"] = endpoint["IPAMConfig"]["IPv4Address"]
            return b""
        if action == "stop" and kind == "container":
            row = self.inspect(kind, args[-1])
            assert row["State"]["Running"] is True
            row["State"].update(Status="exited", Running=False, ExitCode=self.stop_exit_code)
            return b""
        raise AssertionError("unexpected inert command")


class WitnessOwnershipTests(unittest.TestCase):
    def setUp(self):
        # Ambient subprocess use is a test failure, including accidental Docker.
        self.no_process = patch.object(ownership.subprocess, "Popen", side_effect=AssertionError)
        self.no_process.start()
        self.addCleanup(self.no_process.stop)
        self.engine = EngineActor()
        journal = []
        self.lab = WitnessLab(
            Path(__file__).resolve().parent / "inert-w01-not-created",
            engine=self.engine,
            reservation=TOKEN,
            journal=lambda _path, data: journal.append(copy.deepcopy(data)),
        )
        self.lab.journal_rows = journal
        self.engine.lab = self.lab

    def allocate_mounts(self):
        self.lab.create_network()
        for role in WITNESS_ENDPOINTS:
            self.lab.create_volume(role)

    def allocate(self):
        self.allocate_mounts()
        return [(self.lab.create_container(spec), spec) for spec in specs()]

    def test_exact_six_containers_five_volumes_and_two_private_pgdata(self):
        items = self.allocate()
        self.assertEqual(len(self.lab.owned), 12)
        self.assertEqual(len(items), 6)
        self.assertEqual(len(self.lab.volumes), 5)
        self.assertEqual(len(set(self.lab.volumes.values())), 5)
        postgres = [(item, spec) for item, spec in items if spec.user == "999:999"]
        self.assertEqual(len({item["identity"] for item, _ in postgres}), 2)
        for item, spec in postgres:
            self.assertEqual(spec.tmpfs, PG_TMPFS)
            row = self.lab.container_profile(item, spec)
            self.assertEqual(row["Mounts"][0]["Destination"], "/lab")
            self.assertFalse(row["Mounts"][0]["RW"])
        expected = {
            "w-postgres": ("999:999", "10.253.249.2", "w-n0-db.test"),
            "witness": ("1000:1000", "10.253.249.3", "witness.synthetic.invalid"),
            "driver": ("1000:1000", "10.253.249.4", None),
            "v-postgres": ("999:999", "10.253.249.5", "v-n0-db.test"),
            "vault": ("1000:1000", "10.253.249.6", "vault-v.test"),
        }
        self.assertEqual(WITNESS_ENDPOINTS, expected)

    def test_preparer_alone_has_five_writable_mounts_chown_and_no_network(self):
        self.allocate_mounts()
        args = self.lab.switches(specs()[0])
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cap-add") + 1], "CAP_CHOWN")
        self.assertEqual(args[args.index("--user") + 1], "0:0")
        mounts = [args[index + 1] for index, value in enumerate(args) if value == "--mount"]
        self.assertEqual(len(mounts), 5)
        self.assertTrue(all("readonly" not in mount for mount in mounts))
        for spec in specs()[1:]:
            child = self.lab.switches(spec)
            self.assertNotIn("--cap-add", child)
            self.assertNotIn("--publish", child)
            mount = child[child.index("--mount") + 1]
            self.assertTrue(mount.endswith(",readonly"))

    def test_generated_runtime_arguments_bind_exact_ip_alias_mount_and_entrypoint(self):
        self.allocate_mounts()
        for spec in specs()[1:]:
            with self.subTest(role=spec.role):
                args = self.lab.switches(spec)
                self.assertEqual(args[args.index("--network") + 1], TOKEN + "-network")
                self.assertEqual(args[args.index("--ip") + 1], spec.address)
                self.assertEqual(args[args.index("--user") + 1], spec.user)
                if spec.alias:
                    self.assertEqual(args[args.index("--network-alias") + 1], spec.alias)
                else:
                    self.assertNotIn("--network-alias", args)
                self.assertEqual(
                    args[args.index("--mount") + 1],
                    f"type=volume,src={TOKEN}-{spec.role},dst=/lab,volume-nocopy,readonly",
                )
                entrypoint = "/usr/local/bin/docker-entrypoint.sh" if spec.user == "999:999" else ""
                self.assertEqual(args[args.index("--entrypoint") + 1], entrypoint)
                self.assertEqual(args[args.index("--log-driver") + 1], "none")

    def test_default_lab_refuses_every_w01_role_and_mount_set(self):
        legacy = Lab(
            self.lab.work,
            engine=self.engine,
            reservation="pv-" + "b" * 32,
            journal=lambda *_: None,
        )
        for spec in specs():
            with self.subTest(role=spec.role), self.assertRaises(ValueError):
                legacy.switches(spec)
        for role in WITNESS_VOLUMES:
            with self.subTest(role=role), self.assertRaises(ValueError):
                legacy.create_volume(role)

    def test_unknown_roles_and_foreign_names_refuse_before_mutation(self):
        for kind, role, name in (
            ("container", "openbao", TOKEN + "-openbao"),
            ("volume", "postgres", TOKEN + "-postgres"),
            ("network", "network", "pv-" + "b" * 32 + "-network"),
            ("image", "vault", TOKEN + "-vault"),
        ):
            with self.subTest(kind=kind, role=role), self.assertRaises(ValueError):
                self.lab.reserve(kind, role, name)
        self.assertEqual(self.lab.owned, [])
        self.assertEqual(self.engine.commands, [])

    def test_volume_collision_never_enters_owned_ledger(self):
        name = TOKEN + "-w-postgres"
        self.engine.rows[("volume", name)] = {"Name": name, "Labels": {}}
        with self.assertRaises(ValueError):
            self.lab.create_volume("w-postgres")
        self.assertEqual(self.lab.owned, [])
        self.assertTrue(self.lab.cleanup())
        self.assertIn(("volume", name), self.engine.rows)
        self.assertEqual(self.engine.commands, [])

    def test_container_collision_is_not_removed_during_cleanup(self):
        self.allocate_mounts()
        spec = specs()[1]
        name = TOKEN + "-" + spec.role
        self.engine.rows[("container", name)] = {"Name": "/" + name, "Mounts": []}
        with self.assertRaises(ValueError):
            self.lab.create_container(spec)
        self.assertEqual(len(self.lab.owned), 6)
        self.assertTrue(self.lab.cleanup())
        self.assertIn(("container", name), self.engine.rows)

    def test_cross_mount_rw_extra_mount_and_tmpfs_shadow_refuse_before_create(self):
        self.allocate_mounts()
        spec = next(spec for spec in specs() if spec.role == "vault")
        bad = (
            replace(spec, volumes=(Volume("witness", "/lab"),)),
            replace(spec, volumes=(Volume("vault", "/lab", False),)),
            replace(spec, volumes=(*spec.volumes, Volume("witness", "/private/w"))),
            replace(spec, tmpfs=(("/lab", "rw,size=8388608"),)),
            replace(spec, tmpfs=(("/private/witness", "rw,size=8388608"),)),
        )
        before = len(self.engine.commands)
        for candidate in bad:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.lab.create_container(candidate)
        self.assertEqual(len(self.engine.commands), before)

    def test_preparer_mount_swaps_and_partial_mount_sets_refuse(self):
        self.allocate_mounts()
        spec = specs()[0]
        swapped = list(spec.volumes)
        swapped[0] = Volume("v-postgres", "/stage/w-postgres", False)
        for mounts in (tuple(swapped), spec.volumes[:-1], tuple(reversed(spec.volumes))):
            with self.subTest(mounts=mounts), self.assertRaises(ValueError):
                self.lab.create_container(replace(spec, volumes=mounts))

    def test_volume_dictionary_cannot_alias_two_mount_roles(self):
        self.allocate_mounts()
        self.lab.volumes["vault"] = self.lab.volumes["witness"]
        spec = next(spec for spec in specs() if spec.role == "vault")
        with self.assertRaises(ValueError):
            self.lab.create_container(spec)

    def test_uid_ip_alias_caps_and_service_environment_are_closed(self):
        self.allocate_mounts()
        spec = next(spec for spec in specs() if spec.role == "witness")
        for change in (
            {"user": "0:0"},
            {"address": "10.253.249.6"},
            {"alias": "vault-v.test"},
            {"chown": True},
            {"environment": ("DATABASE_URL=foreign",)},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.lab.create_container(replace(spec, **change))

    def test_inspection_rejects_cross_mount_ports_extra_network_and_resource_drift(self):
        items = self.allocate()
        item, spec = next(pair for pair in items if pair[1].role == "vault")
        row = self.engine.inspect("container", item["identity"])
        for mutate in (
            lambda r: r["Mounts"][0].update(Name=self.lab.volumes["witness"]),
            lambda r: r["Mounts"][0].update(RW=True),
            lambda r: r["HostConfig"].update(PortBindings={"9443/tcp": [{}]}),
            lambda r: r["NetworkSettings"]["Networks"].update(foreign={}),
            lambda r: r["HostConfig"].update(CapAdd=["CAP_CHOWN"]),
            lambda r: r["HostConfig"].update(Memory=512 * 1024**2),
        ):
            original = copy.deepcopy(row)
            mutate(row)
            with self.assertRaises(ValueError):
                self.lab.container_profile(item, spec)
            row.clear()
            row.update(original)

    def test_item_and_spec_cannot_be_swapped_or_supplied_outside_the_ledger(self):
        items = self.allocate()
        item, spec = next(pair for pair in items if pair[1].role == "vault")
        foreign_spec = next(spec for _, spec in items if spec.role == "witness")
        with self.assertRaises(ValueError):
            self.lab.container_profile(item, foreign_spec)
        with self.assertRaises(ValueError):
            self.lab.container_profile(copy.deepcopy(item), spec)

    def test_replaced_identity_or_foreign_endpoint_never_starts_a_container(self):
        items = self.allocate()
        item, spec = next(pair for pair in items if pair[1].role == "witness")
        row = self.engine.rows[("container", item["name"])]
        before = len(self.engine.commands)
        identity = row["Id"]
        row["Id"] = "f" * 64
        with self.assertRaises((ValueError, StopIteration)):
            self.lab.start(item, spec)
        row["Id"] = identity
        endpoint = row["NetworkSettings"]["Networks"][self.lab.network]
        for field, value in (
            ("Aliases", ["vault-v.test"]),
            ("IPAMConfig", {"IPv4Address": "10.253.249.6"}),
        ):
            original = endpoint[field]
            endpoint[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.lab.start(item, spec)
            endpoint[field] = original
        self.assertEqual(len(self.engine.commands), before)

    def test_cleanup_containers_then_five_volumes_then_network_ids_absent(self):
        self.allocate()
        self.assertTrue(self.lab.cleanup())
        removals = [args for args, _, _ in self.engine.commands if args[1] == "rm"]
        self.assertEqual(
            [args[0] for args in removals], ["container"] * 6 + ["volume"] * 5 + ["network"]
        )
        self.assertTrue(all(args[2] == "--force" for args in removals[:6]))
        self.assertTrue(all(len(args[-1]) == 64 for args in (*removals[:6], removals[-1])))
        self.assertEqual(self.engine.rows, {})
        self.assertTrue(all(item["removed"] for item in self.lab.owned))
        self.assertEqual(self.engine.deadline, 480)

    def test_partial_allocation_with_lost_create_response_is_owned_and_cleaned(self):
        self.allocate_mounts()
        self.engine.fail_role = "witness"
        self.engine.fail_after_create = True
        spec = next(spec for spec in specs() if spec.role == "witness")
        with self.assertRaises(ValueError):
            self.lab.create_container(spec)
        self.assertIsNone(self.lab.owned[-1]["identity"])
        self.assertTrue(self.lab.cleanup())
        self.assertEqual(self.engine.rows, {})

    def test_unconfirmed_missing_creation_remains_unknown(self):
        self.allocate_mounts()
        self.engine.fail_role = "witness"
        spec = next(spec for spec in specs() if spec.role == "witness")
        with self.assertRaises(ValueError):
            self.lab.create_container(spec)
        with self.assertRaises(ValueError):
            self.lab.reserve("container", "witness", TOKEN + "-witness")
        self.assertFalse(self.lab.cleanup())

    def test_foreign_labels_and_renamed_live_ids_prevent_cleanup_success(self):
        items = self.allocate()
        item, _ = next(pair for pair in items if pair[1].role == "witness")
        row = self.engine.rows.pop(("container", item["name"]))
        row["Name"] = "/renamed-witness"
        self.engine.rows[("container", "renamed-witness")] = row
        foreign, _ = next(pair for pair in items if pair[1].role == "vault")
        self.engine.rows[("container", foreign["name"])]["Config"]["Labels"] = {}
        self.assertFalse(self.lab.cleanup())
        removed_ids = {args[-1] for args, _, _ in self.engine.commands if args[1] == "rm"}
        self.assertNotIn(item["identity"], removed_ids)
        self.assertNotIn(foreign["identity"], removed_ids)
        self.assertTrue(self.engine.identity_exists("container", item["identity"]))

    def test_cleanup_has_one_shared_horizon_and_restores_owner_deadline(self):
        self.allocate()
        self.engine.now = 100
        self.engine.stall_inspection = True
        before = len(self.engine.commands)
        self.assertFalse(self.lab.cleanup())
        self.assertEqual(self.engine.deadline, 480)
        self.assertEqual(len(self.engine.commands), before)
        self.assertEqual(self.engine.now, 146)

    def test_engine_expired_deadline_never_invokes_even_a_docker_inspection(self):
        invocations = []
        now = [0]
        engine = Engine(
            self.lab.work, clock=lambda: now[0], invoke=lambda *a, **k: invocations.append(a)
        )
        now[0] = 481
        with self.assertRaises(ValueError):
            engine.inspect("container", "synthetic")
        self.assertEqual(invocations, [])

    def test_historical_ownership_cleanup_and_engine_ast_are_unchanged(self):
        tree = ast.parse(Path(ownership.__file__).read_text(encoding="utf-8"))
        engine = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Engine"
        )
        lab = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Lab"
        )
        methods = [
            node
            for node in lab.body
            if isinstance(node, ast.FunctionDef)
            and node.name not in {"switches", "create_volume", "validate_spec"}
        ]
        self.assertEqual(
            hashlib.sha256(ast.dump(engine, include_attributes=False).encode()).hexdigest(),
            "7f5ef5d9854f6900c12421fc0006cb8ed8f9afd42af645b13bab03877aa83daf",
        )
        self.assertEqual(
            hashlib.sha256(
                "\n".join(ast.dump(node, include_attributes=False) for node in methods).encode()
            ).hexdigest(),
            "6570ab7409e5f730868f737781e6d989786170528b6e4b238781aba2a4ad222e",
        )


class WitnessRecoveryFixture(unittest.TestCase):
    profile = WitnessRecoveryLab

    def setUp(self):
        no_process = patch.object(ownership.subprocess, "Popen", side_effect=AssertionError)
        no_process.start()
        self.addCleanup(no_process.stop)
        self.engine = EngineActor()
        self.engine.specs = {spec.role: spec for spec in specs(self.profile)}
        journal = []
        self.lab = self.profile(
            Path(__file__).resolve().parent / "inert-recovery-not-created",
            engine=self.engine,
            reservation=TOKEN,
            journal=lambda _path, data: journal.append(copy.deepcopy(data)),
        )
        self.lab.journal_rows = journal
        self.engine.lab = self.lab
        self.lab.create_network()
        for role in self.lab.endpoints:
            self.lab.create_volume(role)
        self.witness = self.engine.specs["witness"]
        self.recovery = self.engine.specs["witness-recovery"]

    def start_recovery(self):
        witness = self.lab.create_container(self.witness)
        row = self.engine.inspect("container", witness["identity"])
        row["State"].update(Status="exited", ExitCode=43)
        self.lab.retire_witness(witness, self.witness)
        history = self.lab.create_container(self.recovery)
        self.lab.start(history, self.recovery)
        return history


class WitnessRecoveryOwnershipTests(WitnessRecoveryFixture):
    def test_separate_readonly_mount_with_the_same_authenticated_endpoint(self):
        preparer = self.engine.specs["preparer"]
        self.lab.validate_spec(preparer)
        self.assertEqual(
            preparer.volumes,
            (
                *WITNESS_PREPARER_MOUNTS,
                Volume("witness-recovery", "/stage/witness-recovery", False),
            ),
        )
        self.lab.validate_spec(self.recovery)
        self.assertEqual(self.recovery.volumes, (Volume("witness-recovery", "/lab"),))
        self.assertEqual(
            (self.recovery.address, self.recovery.alias),
            (self.witness.address, self.witness.alias),
        )
        with self.assertRaises(ValueError):
            self.lab.validate_spec(replace(self.recovery, volumes=self.witness.volumes))

    def test_recovery_requires_the_exact_refused_witness_to_be_absent(self):
        with self.assertRaises(ValueError):
            self.lab.create_container(self.recovery)
        witness = self.lab.create_container(self.witness)
        with self.assertRaises(ValueError):
            self.lab.create_container(self.recovery)
        row = self.engine.inspect("container", witness["identity"])
        row["State"].update(Status="exited", ExitCode=42)
        with self.assertRaises(ValueError):
            self.lab.retire_witness(witness, self.witness)
        row["State"]["ExitCode"] = 43
        self.lab.retire_witness(witness, self.witness)
        self.assertTrue(witness["removed"])
        self.assertEqual(self.engine.commands[-1][0], ("container", "rm", witness["identity"]))
        history = self.lab.create_container(self.recovery)
        # A renamed live identity must prevent restart even after journal retirement.
        self.engine.rows[("container", "renamed-witness")] = row
        with self.assertRaises(ValueError):
            self.lab.start(history, self.recovery)
        del self.engine.rows[("container", "renamed-witness")]
        self.lab.start(history, self.recovery)
        self.assertNotEqual(history["identity"], witness["identity"])
        self.assertTrue(self.lab.cleanup())
        self.assertEqual(self.engine.rows, {})

    def test_preparer_stages_only_observer_and_shared_tls_slot_material_for_recovery(self):
        preparer = witness_prepare
        run = "0123456789abcdef"
        source = b"inert witness source ledger"
        originals = {name: name.encode() for name in preparer.WITNESS_FILES}
        frame = preparer.encode(
            {
                "files": {name: preparer.b64(raw) for name, raw in originals.items()},
                "bindings": {
                    "source_sha256": preparer.sha(source),
                    "slot_sha256": preparer.sha(originals["slot.json"]),
                    "materials_sha256": preparer.sha(originals["materials.bin"]),
                },
            }
        )
        credentials = {
            "usage_anchor_runtime": "inert-runtime",
            "usage_anchor_observer": "inert-observer",
        }
        state = {
            "credentials": {"wpg": credentials},
            "witness_mount": [1, 1],
            "recovery_mount": [1, 2],
        }
        cluster = SimpleNamespace(
            role="wpg",
            hostname="w-n0-db.test",
            address="10.253.249.2",
            port=5432,
            database=f"w01_{run}_wpg",
        )
        pair = SimpleNamespace(clusters={"wpg": cluster})
        state["restore_mount"] = [1, 3]
        run_bytes = run.encode()
        with (
            patch.object(
                preparer, "read_regular",
                side_effect=(run_bytes, run_bytes, run_bytes, source),
            ),
            patch.object(preparer, "restore_base", return_value=(state, {"wpg": {"ca": b"inert"}})),
            patch.object(preparer, "pair_for", return_value=pair),
            patch.object(preparer, "stage_directory") as stage,
        ):
            with self.assertRaises(ValueError):
                preparer.stage_witness(123, run, frame)
            with self.assertRaises(ValueError):
                preparer.stage_witness(123, run, frame, restore_witness=True)
            with self.assertRaises(ValueError):
                preparer.stage_witness(123, run, frame, recovery=True)
            stage.assert_not_called()
            self.assertEqual(
                preparer.stage_witness(123, run, frame, recovery=True, restore_witness=True),
                "W01_WITNESS_READY",
            )
        live, cold, restored = stage.call_args_list
        self.assertEqual(live.args, (123, "witness"))
        self.assertEqual(cold.args, (123, "witness-recovery"))
        self.assertEqual(cold.kwargs["expected"], [1, 2])
        files = cold.kwargs["files"]
        self.assertEqual(
            set(files),
            {"ca.crt", "server.crt", "server.key", "slot.json", "bindings.json",
             "runtime.json", "sql-ca.crt"},
        )
        protected = json.loads(files["runtime.json"][0])
        self.assertEqual(protected["user"], "usage_anchor_observer")
        self.assertEqual(protected["password"], credentials["usage_anchor_observer"])
        self.assertNotIn(credentials["usage_anchor_runtime"], repr(files))
        self.assertEqual(
            set(json.loads(files["bindings.json"][0])), {"source_sha256", "slot_sha256"}
        )
        self.assertEqual(restored.args, (123, "witness-restored"))
        self.assertEqual(restored.kwargs["expected"], [1, 3])
        copy_files = restored.kwargs["files"]
        self.assertEqual(set(copy_files), set(files))
        self.assertEqual(copy_files["runtime.json"][1:], files["runtime.json"][1:])
        self.assertEqual(
            json.loads(copy_files["runtime.json"][0]),
            {**protected, "dbname": f"w01_{run}_wpg_restored"},
        )
        self.assertEqual(
            {name: entry for name, entry in copy_files.items() if name != "runtime.json"},
            {name: entry for name, entry in files.items() if name != "runtime.json"},
        )


class WitnessRestoreOwnershipTests(WitnessRecoveryFixture):
    profile = WitnessRestoreLab

    def test_restore_uses_only_its_volume_and_requires_verified_listener_retirement(self):
        copy_spec = self.engine.specs["witness-restored"]
        self.lab.validate_spec(copy_spec)
        self.assertEqual(copy_spec.volumes, (Volume("witness-restored", "/lab"),))
        self.assertEqual(
            self.lab.preparer_mounts,
            (*WitnessRecoveryLab.preparer_mounts,
             Volume("witness-restored", "/stage/witness-restored", False)),
        )
        self.assertEqual(
            (copy_spec.address, copy_spec.alias),
            (self.witness.address, self.witness.alias),
        )
        with self.assertRaises(ValueError):
            self.lab.validate_spec(replace(copy_spec, volumes=self.recovery.volumes))
        with self.assertRaises(ValueError):
            self.lab.create_container(copy_spec)
        history = self.start_recovery()
        with self.assertRaises(ValueError):
            self.lab.create_container(copy_spec)
        row = self.engine.inspect("container", history["identity"])
        self.lab.retire_recovery(history, self.recovery)
        identifier = history["identity"]
        self.assertEqual(
            [entry[0] for entry in self.engine.commands[-2:]],
            [("container", "stop", "--time", "2", identifier), ("container", "rm", identifier)],
        )
        self.assertTrue(history["removed"])
        restored = self.lab.create_container(copy_spec)
        self.engine.rows[("container", "renamed-recovery")] = row
        with self.assertRaises(ValueError):
            self.lab.start(restored, copy_spec)
        del self.engine.rows[("container", "renamed-recovery")]
        self.lab.start(restored, copy_spec)
        self.assertNotEqual(restored["identity"], identifier)
        self.assertTrue(self.lab.cleanup())
        self.assertEqual(self.engine.rows, {})

    def test_foreign_identity_and_ungraceful_shutdown_cannot_release_the_slot(self):
        history = self.start_recovery()
        copy_spec = self.engine.specs["witness-restored"]
        row = self.engine.inspect("container", history["identity"])
        identity = row["Id"]
        row["Id"] = "e" * 64
        count = len(self.engine.commands)
        with self.assertRaises((ValueError, StopIteration)):
            self.lab.retire_recovery(history, self.recovery)
        self.assertEqual(len(self.engine.commands), count)
        row["Id"] = identity
        self.engine.stop_exit_code = 137
        with self.assertRaises(ValueError):
            self.lab.retire_recovery(history, self.recovery)
        self.assertEqual(len(self.engine.commands), count + 1)
        self.assertFalse(history.get("removed"))
        with self.assertRaises(ValueError):
            self.lab.create_container(copy_spec)


class WitnessClusterRestoreOwnershipTests(WitnessRecoveryFixture):
    profile = WitnessClusterRestoreLab

    def start_source(self):
        spec = self.engine.specs["w-postgres"]
        item = self.lab.create_container(spec)
        self.lab.start(item, spec)
        return item, spec

    def test_new_database_starts_only_after_source_exit_and_listener_retirement(self):
        source, source_spec = self.start_source()
        target_spec = self.engine.specs["w-postgres-restore"]
        target = self.lab.create_container(target_spec)
        self.assertEqual(target_spec.address, "10.253.249.7")
        self.assertEqual(target_spec.alias, "w-n0-recovery-db.test")
        self.assertEqual(target_spec.volumes, (Volume("w-postgres-restore", "/lab"),))
        self.assertEqual(target_spec.tmpfs, source_spec.tmpfs)
        self.assertEqual(target_spec.entrypoint, "/usr/local/bin/docker-entrypoint.sh")
        self.assertNotEqual(target["identity"], source["identity"])
        with self.assertRaises(ValueError):
            self.lab.start(target, target_spec)
        with self.assertRaises(ValueError):
            self.lab.retire_source(source, source_spec)
        history = self.start_recovery()
        self.lab.retire_recovery(history, self.recovery)
        self.engine.stop_exit_code = 0
        self.lab.retire_source(source, source_spec)
        self.assertEqual(
            self.engine.commands[-1][0], ("container", "stop", "--time", "5", source["identity"])
        )
        self.assertFalse(source.get("removed"))
        self.assertTrue(self.engine.identity_exists("container", source["identity"]))
        with self.assertRaises(ValueError):
            self.lab.create_container(self.engine.specs["witness-restored"])
        before = len(self.engine.commands)
        with self.assertRaises(ValueError):
            self.lab.start(target, replace(target_spec, environment=()))
        self.assertEqual(len(self.engine.commands), before)
        self.lab.start(target, target_spec)
        restored_spec = self.engine.specs["witness-restored"]
        restored = self.lab.create_container(restored_spec)
        source_state = self.engine.inspect("container", source["identity"])["State"]
        source_state.update(Status="running", Running=True)
        with self.assertRaises(ValueError):
            self.lab.start(restored, restored_spec)
        source_state.update(Status="exited", Running=False)
        self.lab.start(restored, restored_spec)
        self.assertTrue(self.lab.cleanup())
        self.assertEqual(self.engine.rows, {})

    def test_failed_source_shutdown_leaves_target_and_listener_closed(self):
        source, source_spec = self.start_source()
        target_spec = self.engine.specs["w-postgres-restore"]
        target = self.lab.create_container(target_spec)
        history = self.start_recovery()
        self.lab.retire_recovery(history, self.recovery)
        self.engine.stop_exit_code = 137
        with self.assertRaises(ValueError):
            self.lab.retire_source(source, source_spec)
        with self.assertRaises(ValueError):
            self.lab.start(target, target_spec)
        with self.assertRaises(ValueError):
            self.lab.create_container(self.engine.specs["witness-restored"])

    def test_cluster_staging_binds_independent_sql_trust_and_same_witness_slot(self):
        prepare = witness_prepare
        run = "0123456789abcdef"
        ledger = b"inert source ledger"
        originals = {name: name.encode() for name in prepare.WITNESS_FILES}
        frame = prepare.encode({
            "files": {name: prepare.b64(raw) for name, raw in originals.items()},
            "bindings": {
                "source_sha256": prepare.sha(ledger),
                "slot_sha256": prepare.sha(originals["slot.json"]),
                "materials_sha256": prepare.sha(originals["materials.bin"]),
            },
        })
        repository = Path(__file__).resolve().parents[2]
        schema_sources = dict(zip(
            prepare.SCHEMAS.values(),
            ("components/usage-anchor/sql/schema.sql",
             "components/vault/runtime/sql/schema.sql", "components/usage-anchor/sql/mirror.sql"),
            strict=True,
        ))
        location = {role: (1, index) for index, role in enumerate(prepare.MOUNTS)}
        staged, private = {}, {"provision.ready": run.encode()}

        def read(path, _cap):
            if path in schema_sources:
                return (repository / schema_sources[path]).read_bytes()
            if path == prepare.SOURCE_LEDGER:
                return ledger
            return private[path.name]

        def stage(_root, role, *, expected=None, files=None, restore_cluster=False):
            if files is not None:
                self.assertEqual(expected, list(location[role]))
                self.assertEqual(files.keys(), prepare.mount_layout(
                    role, restore_cluster=restore_cluster
                ).keys())
                self.assertNotIn(role, staged)
                staged[role] = files
            return location[role]

        def tls(host, _now):
            return {
                key: f"-----BEGIN {key}-----\n{host}\n-----END {key}-----\n".encode()
                for key in ("ca", "certificate", "key")
            }

        synthetic = iter(f"SYNTHETIC_{index}_".ljust(40, "x") for index in range(20))
        with (
            patch.object(prepare, "read_regular", side_effect=read),
            patch.object(prepare.secrets, "token_urlsafe", side_effect=lambda _: next(synthetic)),
            patch.object(prepare, "certificate_pair", side_effect=tls),
            patch.object(prepare.role_files, "names", return_value=set()),
            patch.object(prepare, "stage_directory", side_effect=stage),
            patch.object(prepare, "write_private",
                         side_effect=lambda _work, name, raw: private.update({name: raw})),
        ):
            for profile in (
                {"restore_cluster": True},
                {"recovery": True, "restore_cluster": True, "restore_witness": True},
            ):
                with self.assertRaises(ValueError):
                    prepare.base(2, 3, run, **profile)
            self.assertEqual(staged, {})
            self.assertEqual(
                prepare.base(2, 3, run, recovery=True, restore_cluster=True),
                "W01_BASE_READY",
            )
            with self.assertRaises(ValueError):
                prepare.stage_witness(2, run, frame, recovery=True, restore_witness=True)
            self.assertEqual(
                prepare.stage_witness(2, run, frame, recovery=True, restore_cluster=True),
                "W01_WITNESS_READY",
            )
        config = json.loads(staged["driver"]["driver.json"][0])
        observer = prepare.OBSERVER
        wpg, restored = config["databases"]["wpg"], config["database_restored"]
        self.assertEqual(
            (restored["host"], restored["hostaddr"]), prepare.witness_postgres.RESTORE_HOST
        )
        self.assertEqual(restored["dbname"], f"w01_{run}_wpg_restored")
        self.assertEqual(set(restored["credentials"]), {observer})
        self.assertNotEqual(restored["credentials"][observer], wpg["credentials"][observer])
        self.assertNotIn(restored["dbname"].encode(), staged["w-postgres"]["pg_hba.conf"][0])
        self.assertIn(f"W01_{run}_wpr_EMPTY".encode(), private["wpr-preflight.sql"])
        self.assertIn(f"W01_{run}_wpr_PROVISIONED".encode(), private["wpr-provision.sql"])
        runtime = staged["witness-restored"]
        self.assertEqual(runtime["slot.json"][0], originals["slot.json"])
        self.assertEqual(runtime["server.crt"][0], originals["server.crt"])
        self.assertEqual(runtime["sql-ca.crt"], staged["driver"]["wpr-ca.crt"])
        self.assertNotEqual(runtime["sql-ca.crt"], staged["witness-recovery"]["sql-ca.crt"])
        expected = {name: value for name, value in restored.items() if name != "credentials"}
        self.assertEqual(
            json.loads(runtime["runtime.json"][0]),
            {**expected, "user": observer, "password": restored["credentials"][observer]},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
