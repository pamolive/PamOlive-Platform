"""Own and supervise a single synthetic Vault lab on its ephemeral CI runner."""

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from uuid import uuid4

from support import load, need

ID = re.compile(r"[0-9a-f]{64}")
POSTGRES_IMAGE = (
    "docker.io/library/postgres@sha256:"
    "6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788"
)
SUBNET = "10.253.249.0/28"
SCOPE = "org.pamolive.vault-lab"
PART = "org.pamolive.vault-lab.role"
ROLES = frozenset({"postgres", "server", "client", "preparer"})
VOLUMES = frozenset({"postgres", "server", "client"})
ENDPOINTS = {
    "postgres": ("999:999", "10.253.249.2", "vault-n0-db.test"),
    "server": ("1000:1000", "10.253.249.3", "vault-n0.test"),
    "client": ("1000:1000", "10.253.249.4", None),
}


def resource_id(value):
    need(isinstance(value, str) and ID.fullmatch(value) is not None)
    return value


@dataclass(frozen=True)
class Volume:
    role: str
    destination: str
    readonly: bool = True


@dataclass(frozen=True)
class Container:
    image: str
    role: str
    user: str
    command: tuple[str, ...]
    volumes: tuple[Volume, ...]
    tmpfs: tuple[tuple[str, str], ...] = ()
    environment: tuple[str, ...] = ()
    address: str | None = None
    alias: str | None = None
    chown: bool = False

    @property
    def entrypoint(self):
        postgres = self.role in {"postgres", "w-postgres", "v-postgres", "w-postgres-restore"}
        return "/usr/local/bin/docker-entrypoint.sh" if postgres else ""


class Engine:
    def __init__(self, work, *, clock=time.monotonic, invoke=None):
        self.work = work
        self.clock = clock
        self.deadline = clock() + 480
        self.invoke = load("bounded_io.py").run_capped if invoke is None else invoke
        self.command = (
            "docker",
            "--config",
            str(work / "docker-config"),
            "-H",
            "unix:///var/run/docker.sock",
        )
        self.environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(work / "home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def run(self, *args, data=None, timeout=10, stdout_cap=65536, stdin_cap=256 * 1024):
        limit = min(timeout, self.deadline - self.clock())
        need(limit > 0)
        options = {
            "env": self.environment,
            "cwd": str(self.work),
            "timeout": limit,
            "stdout_cap": stdout_cap,
            "stderr_cap": 16384,
        }
        command = [*self.command, *args]
        if data is None:
            result = self.invoke(command, **options)
        else:
            need(type(stdin_cap) is int and 0 < stdin_cap <= 8 * 1024 * 1024)
            need(type(data) is bytes and 0 < len(data) <= stdin_cap)
            fd = os.memfd_create("vault-synthetic-stdin", os.MFD_CLOEXEC)
            with os.fdopen(fd, "w+b") as source:
                source.write(data)
                source.seek(0)

                def popen(argv, **kwargs):
                    return subprocess.Popen(argv, **{**kwargs, "stdin": source})

                result = self.invoke(command, **options, popen=popen)
        need(result.spawn_attempted and result.owned_child_reaped and result.drains_complete)
        need(
            not result.killed_owned_child
            and result.exception_type is None
            and result.cleanup_exception_type is None
        )
        need((result.reason is None and result.returncode == 0) or result.reason == "nonzero_exit")
        return result

    def checked(self, *args, **options):
        result = self.run(*args, **options)
        need(result.returncode == 0 and not result.stderr)
        return result.stdout

    def inspect(self, kind, name):
        raw = self.checked(kind, "inspect", "--format", "{{json .}}", name)
        row = json.loads(raw)
        need(type(row) is dict)
        return row

    def exists(self, kind, name):
        container = kind == "container"
        flags = ("--all",) if container else ()
        pattern = f"^/{name}$" if container else f"^{name}$"
        args = (
            kind,
            "ls",
            *flags,
            "--filter",
            f"name={pattern}",
            "--format",
            "{{.Names}}" if container else "{{.Name}}",
        )
        rows = self.checked(*args).decode("ascii").splitlines()
        need(rows in ([], [name]))
        return bool(rows)

    def identity_exists(self, kind, identity):
        need(kind in {"container", "network"})
        resource_id(identity)
        flags = ("--all",) if kind == "container" else ()
        rows = (
            self.checked(
                kind,
                "ls",
                *flags,
                "--no-trunc",
                "--filter",
                f"id={identity}",
                "--format",
                "{{.ID}}",
            )
            .decode("ascii")
            .splitlines()
        )
        need(rows in ([], [identity]))
        return bool(rows)


class Lab:
    volume_roles = VOLUMES

    def __init__(self, work, *, engine=None, reservation=None, journal=None):
        self.work = work
        control = load("controller.py")
        if engine is None:
            control.ci_guard(work)
        self.engine = Engine(work) if engine is None else engine
        self.journal = control.atomic if journal is None else journal
        self.path = work / "vault-lab-reservation.json"
        need(not self.path.exists() and not self.path.is_symlink())
        self.reservation = "pv-" + uuid4().hex if reservation is None else reservation
        need(re.fullmatch(r"pv-[0-9a-f]{32}", self.reservation) is not None)
        self.owned = []
        self.volumes = {}
        self.network = None
        self.network_id = None
        self.save()

    def save(self):
        self.journal(self.path, {"allocation": self.reservation, "objects": self.owned})

    def labels(self, role):
        return {SCOPE: self.reservation, PART: role}

    def label_args(self, role):
        return tuple(
            part
            for key, value in self.labels(role).items()
            for part in ("--label", f"{key}={value}")
        )

    def reserve(self, kind, role, name):
        need(not self.engine.exists(kind, name))
        item = {"kind": kind, "role": role, "name": name, "identity": None}
        self.owned.append(item)
        self.save()
        return item

    def observe(self, item):
        kind, name = item["kind"], item["name"]
        row = self.engine.inspect(kind, item["identity"] or name)
        labels = row.get("Config", {}).get("Labels") if kind == "container" else row["Labels"]
        need(
            type(labels) is dict
            and all(labels.get(k) == v for k, v in self.labels(item["role"]).items())
        )
        need(row["Name"] == ("/" + name if kind == "container" else name))
        identity = name if kind == "volume" else resource_id(row["Id"])
        need(item["identity"] is None or item["identity"] == identity)
        item["identity"] = identity
        self.save()
        return row

    def create_network(self):
        need(self.network is None)
        name = self.reservation + "-network"
        item = self.reserve("network", "network", name)
        raw = self.engine.checked(
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--subnet",
            SUBNET,
            *self.label_args("network"),
            name,
        )
        item["identity"] = resource_id(raw.decode("ascii").strip())
        row = self.observe(item)
        need(row["Driver"] == "bridge" and row["Scope"] == "local" and row["Internal"] is True)
        need(row["EnableIPv6"] is False and not row["Containers"])
        need([entry["Subnet"] for entry in row["IPAM"]["Config"]] == [SUBNET])
        self.network, self.network_id = name, item["identity"]

    def create_volume(self, role):
        need(role in self.volume_roles and role not in self.volumes)
        name = self.reservation + "-" + role
        item = self.reserve("volume", role, name)
        raw = self.engine.checked(
            "volume", "create", "--driver", "local", *self.label_args(role), name
        )
        need(raw.decode("ascii").strip() == name)
        item["identity"] = name
        row = self.observe(item)
        need(row["Driver"] == "local" and row["Scope"] == "local" and not row.get("Options"))
        self.volumes[role] = name

    def validate_spec(self, spec):
        need(spec.role in ROLES and spec.image.startswith("sha256:"))
        resource_id(spec.image.removeprefix("sha256:"))
        need(
            spec.user in {"0:0", "999:999", "1000:1000"}
            and bool(spec.chown) == (spec.user == "0:0")
        )
        if spec.role == "preparer":
            need(spec.chown and spec.address is None and not spec.alias)
            need(
                spec.volumes
                == (
                    Volume("postgres", "/stage/pg", False),
                    Volume("server", "/stage/server", False),
                    Volume("client", "/stage/client", False),
                )
            )
        else:
            need(not spec.chown and (spec.user, spec.address, spec.alias) == ENDPOINTS[spec.role])
            need(spec.volumes == (Volume(spec.role, "/lab"),))
        need(not spec.environment or spec.role == "postgres")
        need(all(m.destination.startswith(("/stage/", "/private/", "/lab")) for m in spec.volumes))
        need(len({m.role for m in spec.volumes}) == len(spec.volumes))

    def switches(self, spec):
        self.validate_spec(spec)
        args = [
            "--pull",
            "never",
            "--platform",
            "linux/amd64",
            "--read-only",
            "--user",
            spec.user,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "128",
            "--cpus",
            "1",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--ipc",
            "private",
            "--log-driver",
            "none",
            "--entrypoint",
            spec.entrypoint,
        ]
        if spec.chown:
            args.extend(("--cap-add", "CAP_CHOWN"))
        if spec.address is None:
            args.extend(("--network", "none"))
        else:
            need(self.network is not None)
            args.extend(("--network", self.network, "--ip", spec.address))
            if spec.alias:
                args.extend(("--network-alias", spec.alias))
        for mount in spec.volumes:
            name = self.volumes[mount.role]
            mode = ",readonly" if mount.readonly else ""
            args.extend(
                ("--mount", f"type=volume,src={name},dst={mount.destination},volume-nocopy{mode}")
            )
        for target, parameters in spec.tmpfs:
            args.extend(("--tmpfs", f"{target}:{parameters}"))
        for text in spec.environment:
            args.extend(("--env", text))
        return args

    def create_container(self, spec):
        switches = self.switches(spec)
        name = self.reservation + "-" + spec.role.replace("_", "-")
        item = self.reserve("container", spec.role, name)
        raw = self.engine.checked(
            "container",
            "create",
            "--name",
            name,
            *self.label_args(spec.role),
            *switches,
            spec.image,
            *spec.command,
        )
        item["identity"] = resource_id(raw.decode("ascii").strip())
        self.container_profile(item, spec)
        return item

    def container_profile(self, item, spec):
        row = self.observe(item)
        host, config = row["HostConfig"], row["Config"]
        need(row["Image"] == spec.image and config["User"] == spec.user)
        need(config["Cmd"] == list(spec.command))
        need((config["Entrypoint"] or []) == ([spec.entrypoint] if spec.entrypoint else []))
        need(set(spec.environment) <= set(config["Env"] or []))
        need(
            host["ReadonlyRootfs"] is True
            and host["Privileged"] is False
            and not host["PublishAllPorts"]
            and not host.get("PortBindings")
        )
        need(not host.get("Binds") and not host.get("Devices") and not host.get("DeviceRequests"))
        need(not host.get("PidMode") and not host.get("UTSMode") and not host.get("Links"))
        need(
            host["CapDrop"] == ["ALL"]
            and (host.get("CapAdd") or []) == (["CAP_CHOWN"] if spec.chown else [])
        )
        need(host["SecurityOpt"] in (["no-new-privileges:true"], ["no-new-privileges"]))
        need(host["Memory"] == host["MemorySwap"] == 256 * 1024**2 and host["PidsLimit"] == 128)
        need(host["NanoCpus"] == 10**9 and host["IpcMode"] == "private")
        need(host["LogConfig"] == {"Type": "none", "Config": {}})
        need((host.get("Tmpfs") or {}) == dict(spec.tmpfs))
        mounts = row["Mounts"]
        need(
            all(
                r["Type"] == "volume"
                or (r["Type"] == "tmpfs" and r["Destination"] in dict(spec.tmpfs))
                for r in mounts
            )
        )
        actual = [(r["Name"], r["Destination"], r["RW"]) for r in mounts if r["Type"] == "volume"]
        need(
            sorted(actual)
            == sorted((self.volumes[m.role], m.destination, not m.readonly) for m in spec.volumes)
        )
        if spec.address is None:
            need(host["NetworkMode"] == "none")
            need(set(row["NetworkSettings"]["Networks"]) <= {"none"})
        else:
            networks = row["NetworkSettings"]["Networks"]
            need(host["NetworkMode"] == self.network and set(networks) == {self.network})
            endpoint = networks[self.network]
            need(endpoint["IPAMConfig"]["IPv4Address"] == spec.address)
            if row["State"]["Running"]:
                need(
                    endpoint["NetworkID"] == self.network_id
                    and endpoint["IPAddress"] == spec.address
                )
            else:
                need(endpoint["NetworkID"] in ("", self.network_id))
            if spec.alias:
                need(spec.alias in endpoint["Aliases"])
        return row

    def start(self, item, spec, *, attach=False, timeout=30, stdout_cap=65536):
        row = self.container_profile(item, spec)
        need(row["State"]["Status"] == "created" and row["State"]["Running"] is False)
        identifier = item["identity"]
        if attach:
            result = self.engine.run(
                "container", "start", "--attach", identifier, timeout=timeout, stdout_cap=stdout_cap
            )
            state = self.container_profile(item, spec)["State"]
            need(state["Status"] == "exited" and state["OOMKilled"] is False)
            need(state["ExitCode"] == result.returncode)
            return result
        self.engine.checked("container", "start", identifier, timeout=timeout)
        need(self.container_profile(item, spec)["State"]["Running"] is True)

    def image(self, reference, *, pull=False):
        if pull:
            need(reference == POSTGRES_IMAGE)
            self.engine.checked(
                "image",
                "pull",
                "--platform",
                "linux/amd64",
                reference,
                timeout=90,
                stdout_cap=16384,
            )
        row = self.engine.inspect("image", reference)
        need(row["Os"] == "linux" and row["Architecture"] == "amd64")
        identifier = row["Id"]
        need(identifier.startswith("sha256:"))
        resource_id(identifier.removeprefix("sha256:"))
        accepted = {reference, reference.removeprefix("docker.io/library/")}
        need(accepted.intersection({identifier, *(row["RepoDigests"] or [])}))
        return identifier

    def exec(self, item, spec, *argv, **options):
        state = self.container_profile(item, spec)["State"]
        need(state["Running"] is True and state["OOMKilled"] is False)
        return self.engine.run(
            "exec", "--interactive", "--user", spec.user, item["identity"], *argv, **options
        )

    def cleanup(self):
        failures = []
        saved = self.engine.deadline
        self.engine.deadline = self.engine.clock() + 45
        try:
            for item in reversed(self.owned):
                try:
                    kind, name = item["kind"], item["name"]
                    identity = item["identity"]
                    if not self.engine.exists(kind, name):
                        if identity is None or (
                            kind != "volume" and self.engine.identity_exists(kind, identity)
                        ):
                            failures.append(item["role"])
                        continue
                    self.observe(item)
                    flags = ("--force",) if kind == "container" else ()
                    self.engine.checked(kind, "rm", *flags, item["identity"])
                    need(not self.engine.exists(kind, name))
                    if kind != "volume":
                        need(not self.engine.identity_exists(kind, item["identity"]))
                    item["removed"] = True
                    self.save()
                except Exception:
                    failures.append(item["role"])
        finally:
            self.engine.deadline = saved
        return not failures


# Source-defined W01 topology only. These names are allocation keys, never
# capabilities from a fixture or a caller-supplied profile. The historical Lab
# still accepts only ROLES/VOLUMES/ENDPOINTS above.
WITNESS_ENDPOINTS = {
    "w-postgres": ("999:999", "10.253.249.2", "w-n0-db.test"),
    "witness": ("1000:1000", "10.253.249.3", "witness.synthetic.invalid"),
    "driver": ("1000:1000", "10.253.249.4", None),
    "v-postgres": ("999:999", "10.253.249.5", "v-n0-db.test"),
    "vault": ("1000:1000", "10.253.249.6", "vault-v.test"),
}
WITNESS_VOLUMES = frozenset(WITNESS_ENDPOINTS)
WITNESS_ROLES = WITNESS_VOLUMES | {"preparer"}
WITNESS_PREPARER_MOUNTS = tuple(Volume(role, "/stage/" + role, False) for role in WITNESS_ENDPOINTS)


class WitnessLab(Lab):
    """One W01 allocation; two PG containers, Vault, witness and one driver.

    Reuses the existing journal, identity checks and bounded cleanup unchanged.
    The trusted coordinator supplies pinned image/commands, exact PG tmpfs and
    environment, and independently validated role contents. This class neither
    commissions inputs nor establishes DB/KMS/application authority.
    """

    volume_roles = WITNESS_VOLUMES
    container_roles = WITNESS_ROLES
    endpoints = WITNESS_ENDPOINTS
    preparer_mounts = WITNESS_PREPARER_MOUNTS
    postgres_roles = frozenset({"w-postgres", "v-postgres"})

    def reserve(self, kind, role, name):
        allowed = {
            "network": {"network"},
            "volume": self.volume_roles,
            "container": self.container_roles,
        }
        need(kind in allowed and role in allowed[kind])
        need(name == self.reservation + "-" + role)
        need(not any(item["kind"] == kind and item["role"] == role for item in self.owned))
        return super().reserve(kind, role, name)

    def validate_spec(self, spec):
        need(spec.role in self.container_roles and spec.image.startswith("sha256:"))
        resource_id(spec.image.removeprefix("sha256:"))
        if spec.role == "preparer":
            need(spec.user == "0:0" and spec.chown is True)
            need(spec.address is None and spec.alias is None)
            need(spec.volumes == self.preparer_mounts)
        else:
            need(spec.chown is False)
            need((spec.user, spec.address, spec.alias) == self.endpoints[spec.role])
            need(spec.volumes == (Volume(spec.role, "/lab"),))
        need(not spec.environment or spec.role in self.postgres_roles)
        need(all(self.volumes.get(m.role) == self.reservation + "-" + m.role for m in spec.volumes))
        # Tmpfs never shadows a role mount or introduces a second fixture tree.
        targets = {
            "preparer": {"/work"},
            "driver": {"/work"},
            **dict.fromkeys(
                self.postgres_roles, {"/var/lib/postgresql/data", "/var/run/postgresql", "/tmp"}
            ),
        }
        need(len(dict(spec.tmpfs)) == len(spec.tmpfs))
        need(set(dict(spec.tmpfs)) <= targets.get(spec.role, set()))

    def container_profile(self, item, spec):
        self.validate_spec(spec)
        need(any(item is owned for owned in self.owned))
        need(item["kind"] == "container" and item["role"] == spec.role)
        return super().container_profile(item, spec)


class WitnessRecoveryLab(WitnessLab):
    """Keep one W TLS identity and mount separate credentials after retirement."""

    endpoints = {**WITNESS_ENDPOINTS, "witness-recovery": WITNESS_ENDPOINTS["witness"]}
    volume_roles = WITNESS_VOLUMES | {"witness-recovery"}
    container_roles = WITNESS_ROLES | {"witness-recovery"}
    preparer_mounts = (
        *WITNESS_PREPARER_MOUNTS,
        Volume("witness-recovery", "/stage/witness-recovery", False),
    )

    def retire_witness(self, item, spec):
        need(spec.role == "witness" and not item.get("removed"))
        state = self.container_profile(item, spec)["State"]
        need(
            state["Status"] == "exited"
            and state["Running"] is False
            and state["OOMKilled"] is False
            and state["ExitCode"] == 43
        )
        # No force and no name-based removal. Only retire the owned CID whose
        # closed-context startup refusal has been observed.
        self.engine.checked("container", "rm", item["identity"])
        self._record_retired_witness(item)

    def _record_retired_witness(self, item):
        self._require_absent_witness(item)
        item["removed"] = True
        self.save()

    def _require_absent_witness(self, item):
        identifier = resource_id(item["identity"])
        need(not self.engine.exists("container", item["name"]))
        need(not self.engine.identity_exists("container", identifier))

    def _require_retired_witness(self, role="witness"):
        matches = [
            item for item in self.owned
            if item["kind"] == "container" and item["role"] == role
        ]
        need(len(matches) == 1 and matches[0].get("removed") is True)
        self._require_absent_witness(matches[0])

    def create_container(self, spec):
        if spec.role == "witness-recovery":
            self._require_retired_witness()
        return super().create_container(spec)

    def start(self, item, spec, **options):
        if spec.role == "witness-recovery":
            self._require_retired_witness()
        return super().start(item, spec, **options)


class WitnessRestoreLab(WitnessRecoveryLab):
    """Bind the restored listener only after both earlier listeners retire."""

    endpoints = {
        **WitnessRecoveryLab.endpoints, "witness-restored": WITNESS_ENDPOINTS["witness"]
    }
    volume_roles = WitnessRecoveryLab.volume_roles | {"witness-restored"}
    container_roles = WitnessRecoveryLab.container_roles | {"witness-restored"}
    preparer_mounts = (
        *WitnessRecoveryLab.preparer_mounts,
        Volume("witness-restored", "/stage/witness-restored", False),
    )

    def retire_recovery(self, item, spec):
        self._require_retired_witness()
        need(spec.role == "witness-recovery" and not item.get("removed"))
        state = self.container_profile(item, spec)["State"]
        need(
            state["Status"] == "running"
            and state["Running"] is True
            and state["OOMKilled"] is False
        )
        identifier = item["identity"]
        self.engine.checked("container", "stop", "--time", "2", identifier, timeout=5)
        state = self.container_profile(item, spec)["State"]
        need(
            state["Status"] == "exited"
            and state["Running"] is False
            and state["OOMKilled"] is False
            and state["ExitCode"] in (0, 143)
        )
        self.engine.checked("container", "rm", identifier)
        self._record_retired_witness(item)

    def _require_restore_slot(self):
        self._require_retired_witness()
        self._require_retired_witness("witness-recovery")

    def create_container(self, spec):
        if spec.role == "witness-restored":
            self._require_restore_slot()
        return super().create_container(spec)

    def start(self, item, spec, **options):
        if spec.role == "witness-restored":
            self._require_restore_slot()
        return super().start(item, spec, **options)


class WitnessClusterRestoreLab(WitnessRestoreLab):
    """Use a new PGDATA after both old listeners and the original PG stop."""

    role = "w-postgres-restore"
    endpoints = {
        **WitnessRestoreLab.endpoints,
        role: ("999:999", "10.253.249.7", "w-n0-recovery-db.test"),
    }
    volume_roles = WitnessRestoreLab.volume_roles | {role}
    container_roles = WitnessRestoreLab.container_roles | {role}
    postgres_roles = WitnessRestoreLab.postgres_roles | {role}
    preparer_mounts = (
        *WitnessRestoreLab.preparer_mounts,
        Volume(role, "/stage/w-postgres-restore", False),
    )
    _stopped_source = None
    _started_target = None

    def retire_source(self, item, spec):
        super()._require_restore_slot()
        need(self._stopped_source is None and spec.role == "w-postgres")
        state = self.container_profile(item, spec)["State"]
        need(state["Status"] == "running" and state["Running"] is True and not state["OOMKilled"])
        self.engine.checked("container", "stop", "--time", "5", item["identity"], timeout=8)
        self._assert_source_stopped(item, spec)
        self._stopped_source = item, spec

    def _assert_source_stopped(self, item, spec):
        state = self.container_profile(item, spec)["State"]
        need(
            state["Status"] == "exited"
            and state["Running"] is False
            and state["OOMKilled"] is False
            and state["ExitCode"] == 0
        )

    def _require_restore_slot(self):
        super()._require_restore_slot()
        need(self._stopped_source is not None and self._started_target is not None)
        self._assert_source_stopped(*self._stopped_source)
        state = self.container_profile(*self._started_target)["State"]
        need(state["Status"] == "running" and state["Running"] is True and not state["OOMKilled"])

    def start(self, item, spec, **options):
        if spec.role != self.role:
            return super().start(item, spec, **options)
        super()._require_restore_slot()
        need(self._stopped_source is not None and self._started_target is None)
        self._assert_source_stopped(*self._stopped_source)
        _, source = self._stopped_source
        need(
            (spec.image, spec.command, spec.tmpfs, spec.environment)
            == (source.image, source.command, source.tmpfs, source.environment)
        )
        result = super().start(item, spec, **options)
        self._started_target = item, spec
        return result
