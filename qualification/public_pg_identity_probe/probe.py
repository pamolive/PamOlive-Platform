"""Public PG identity DATA probe seam. Import performs no operational IO."""

import hashlib
import json
import re
import time
from pathlib import Path

LABEL = "pamolive.w.pg-identity.run"
API_VERSION = "1.52"
VERSION_TEMPLATE = (
    '{"client_version":{{json .Client.Version}},"client_api":{{json .Client.APIVersion}},'
    '"client_os":{{json .Client.Os}},"client_arch":{{json .Client.Arch}},'
    '"server_version":{{json .Server.Version}},"server_api_max":{{json .Server.APIVersion}},'
    '"server_api_min":{{json .Server.MinAPIVersion}},'
    '"server_os":{{json .Server.Os}},"server_arch":{{json .Server.Arch}}}'
)
LEGACY_LABEL = "pamolive.b0pre.run"
IMAGE = (
    "docker.io/library/postgres@sha256:"
    "6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788"
)
MANIFEST = IMAGE.split("@", 1)[1]
CONFIG = "sha256:140936e8665d5274aa58df31b722693b4b451c541bb0f1a263a345d424bfacb4"
PROFILE_CANON_SHA = "33ff92a047c08743f6e31f645ac4ec3977a748f2a32b07714125692bd1989408"
PGDATA = "/var/lib/postgresql/data"
TMPFS = {
    PGDATA: "ro,nosuid,nodev,noexec,size=4m,mode=0700",
    "/tmp": "ro,nosuid,nodev,noexec,size=1m,mode=1777",
}
HOST = {
    "Memory": 64 * 1024**2,
    "MemorySwap": 64 * 1024**2,
    "NanoCpus": 100000000,
    "PidsLimit": 16,
    "ShmSize": 4 * 1024**2,
    "ReadonlyRootfs": True,
    "Privileged": False,
    "CapDrop": ["ALL"],
    "CapAdd": None,
    "SecurityOpt": ["no-new-privileges:true"],
    "IpcMode": "private",
    "PidMode": "",
    "CgroupnsMode": "private",
    "NetworkMode": "none",
    "PortBindings": {},
    "PublishAllPorts": False,
    "Binds": None,
    "Tmpfs": TMPFS,
    "GroupAdd": None,
    "Init": False,
    "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
    "LogConfig": {"Type": "json-file", "Config": {"max-size": "16k", "max-file": "1"}},
    "Ulimits": [
        {"Name": "core", "Hard": 0, "Soft": 0},
        {"Name": "nofile", "Hard": 64, "Soft": 64},
    ],
}


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def arguments():
    """No host mount/port/socket, entrypoint bypassed, no inherited PG startup."""
    args = [
        "--init=false",
        "--pull",
        "never",
        "--platform",
        "linux/amd64",
        "--user",
        "0:0",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--pids-limit",
        "16",
        "--cpus",
        "0.10",
        "--memory",
        "64m",
        "--memory-swap",
        "64m",
        "--shm-size",
        "4m",
        "--ulimit",
        "nofile=64:64",
        "--ulimit",
        "core=0:0",
        "--restart",
        "no",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=16k",
        "--log-opt",
        "max-file=1",
        "--env",
        "LANG=C",
        "--env",
        "LC_ALL=C",
        "--entrypoint",
        "/usr/bin/getent",
    ]
    for target, value in TMPFS.items():
        args += ["--tmpfs", target + ":" + value]
    return [*args, IMAGE, "passwd", "postgres"]


def verify_profile_binding(profile):
    need(
        hashlib.sha256(
            json.dumps(profile, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        == PROFILE_CANON_SHA,
        "PINNED_PUBLIC_PROFILE",
    )


def verify_version(value):
    expected = {
        "client_version": "29.4.2",
        "client_api": "1.52",
        "client_os": "linux",
        "client_arch": "amd64",
        "server_version": "29.4.2",
        "server_api_max": "1.54",
        "server_api_min": "1.40",
        "server_os": "linux",
        "server_arch": "amd64",
    }
    need(type(value) is dict and same(value, expected), "EXACT_CONTAINERD_2942_API152")
    return dict(value)


def verify_store(value):
    expected = {
        "DockerRootDir": "/var/lib/docker",
        "Driver": "overlayfs",
        "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
    }
    need(type(value) is dict and same(value, expected), "EXACT_CONTAINERD_STORE")
    return {
        "driver": "overlayfs",
        "driver_type": "io.containerd.snapshotter.v1",
        "DockerRootDir": "/var/lib/docker",
        "real_storage_root_received": False,
    }


def verify_image(row, profile):
    verify_profile_binding(profile)
    fields = profile["image_config_fields_exact_presence"]
    need(
        row["Descriptor"]["digest"] == MANIFEST
        and row["Descriptor"]["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
        and type(row["Descriptor"]["size"]) is int
        and row["Descriptor"]["size"] == 3628,
        "PG_MANIFEST_DESCRIPTOR",
    )
    need(row["RepoDigests"] == ["postgres@" + MANIFEST], "PG_REPOSITORY_MANIFEST")
    need(
        row["Id"] == MANIFEST
        and row["Os"] == "linux"
        and row["Architecture"] == "amd64"
        and row["RootFS"] == {"Type": "layers", "Layers": profile["rootfs_diff_ids"]},
        "IMAGE_IDENTITY",
    )
    for key in fields:
        need(
            (key in row["Config"]) is fields[key]["present"]
            and same(row["Config"].get(key), fields[key]["value"]),
            "IMAGE_DECLARATION",
        )
    need(
        same(row["Config"], {key: row["value"] for key, row in fields.items() if row["present"]}),
        "IMAGE_CONFIG_CLOSED",
    )
    need(fields["Volumes"]["value"] == {PGDATA: {}}, "PGDATA_DECLARATION")


def inspect_profile(row, run, profile):
    need(type(run) is str and re.fullmatch(r"w-pg-id-[0-9a-f]{32}", run), "RUN")
    need(
        row["Name"] == "/" + run + "-stage0"
        and row["Image"] == MANIFEST
        and re.fullmatch(r"[a-f0-9]{64}", row["Id"]),
        "OWNERSHIP",
    )
    config = row["Config"]
    expected_env = dict(profile["declared_public_image_env"], LANG="C", LC_ALL="C")
    env = config["Env"]
    need(type(env) is list and all(type(item) is str for item in env), "ENV_TYPES")
    pairs = [value.partition("=") for value in env]
    need(
        all(separator == "=" for _, separator, _ in pairs)
        and len({key for key, _, _ in pairs}) == len(pairs)
        and dict((key, value) for key, _, value in pairs) == expected_env,
        "ENV_EXACT",
    )
    for key, expected in {
        "Image": IMAGE,
        "User": "0:0",
        "Entrypoint": ["/usr/bin/getent"],
        "Cmd": ["passwd", "postgres"],
        "Labels": {LABEL: run},
        "WorkingDir": "",
        "Tty": False,
        "OpenStdin": False,
    }.items():
        need(key in config and same(config[key], expected), "CONFIG_EXACT")
    need(row["Path"] == "/usr/bin/getent" and row["Args"] == ["passwd", "postgres"], "ARGV")
    for key, expected in HOST.items():
        need(key in row["HostConfig"] and same(row["HostConfig"][key], expected), "HOST_PROFILE")
    need("Mounts" not in row["HostConfig"], "HOST_MOUNTS_MUST_BE_ABSENT")
    need(row["Mounts"] == [], "NO_HOST_OR_ANONYMOUS_VOLUME")
    state = row["State"]
    need(
        type(state["Running"]) is bool
        and type(state["OOMKilled"]) is bool
        and type(state["ExitCode"]) is int
        and 0 <= state["ExitCode"] <= 255,
        "STATE_TYPES",
    )
    return {
        "Id": row["Id"],
        "Name": row["Name"],
        "Image": row["Image"],
        "Run": config["Labels"][LABEL],
        "User": config["User"],
        "Running": state["Running"],
        "OOMKilled": state["OOMKilled"],
        "ExitCode": state["ExitCode"],
    }


def require_create_ack(state, cid):
    """A confirmed CREATE response is necessary for any subsequent mutation."""
    ack = state.get("create_ack")
    need(
        type(ack) is dict and set(ack) == {"cid", "run", "manifest", "user", "io_index"},
        "CREATE_ACK",
    )
    need(
        type(cid) is str
        and re.fullmatch(r"[a-f0-9]{64}", cid)
        and ack["cid"] == cid
        and ack["run"] == state["run"]
        and ack["manifest"] == MANIFEST
        and ack["user"] == "0:0"
        and type(ack["io_index"]) is int
        and 0 <= ack["io_index"] < len(state["IO"]),
        "CREATE_ACK_BINDING",
    )
    io = state["IO"][ack["io_index"]]
    need(
        io.get("operation") == "create"
        and type(io.get("returncode")) is int
        and io["returncode"] == 0
        and io.get("spawn_attempted") is True
        and type(io.get("pid")) is int
        and io["pid"] > 0
        and io.get("owned_child_reaped") is True
        and io.get("drains_complete") is True
        and io.get("killed_owned_child") is False
        and io.get("reason") is None
        and io.get("exception_type") is None
        and io.get("cleanup_exception_type") is None,
        "CREATE_ACK_H1",
    )


def inspect_owned(row, state, cid):
    """Minimal cleanup identity; does not grant permission to START."""
    require_create_ack(state, cid)
    config, status = row["Config"], row["State"]
    need(
        row["Id"] == cid
        and row["Name"] == "/" + state["run"] + "-stage0"
        and row["Image"] == MANIFEST
        and config["User"] == "0:0"
        and same(config["Labels"], {LABEL: state["run"]}),
        "CLEANUP_OWNERSHIP",
    )
    need(
        type(status["Running"]) is bool
        and type(status["OOMKilled"]) is bool
        and type(status["ExitCode"]) is int
        and 0 <= status["ExitCode"] <= 255,
        "CLEANUP_STATE_TYPES",
    )
    need(not status["Running"] or state.get("started") is True, "UNEXPECTED_RUNNING_NO_STOP")
    return {
        "Id": cid,
        "Name": row["Name"],
        "Image": MANIFEST,
        "Run": state["run"],
        "User": "0:0",
        "Running": status["Running"],
        "OOMKilled": status["OOMKilled"],
        "ExitCode": status["ExitCode"],
    }


def inspect_projection(row, run, profile, phase):
    """Closed public schema. Unknown strings/keys and all Env bytes are withheld."""

    def project(value, expected):
        result = {"type": type(value).__name__, "matches_expected": same(value, expected)}
        if value is None or type(value) is bool or type(value) is int and -1 <= value <= 2**40:
            result["value"] = value
        elif type(value) is str and value == expected:
            result["value"] = expected
        elif type(value) is list and type(expected) is list:
            if not value:
                result["value"] = []
            elif len(value) == len(expected):
                result["items"] = [project(a, b) for a, b in zip(value, expected)]
        elif type(value) is dict and type(expected) is dict:
            result["fields"] = {k: field(value, k, v) for k, v in expected.items()}
        return result

    def field(container, key, expected):
        if type(container) is not dict or key not in container:
            return {"present": False}
        return {"present": True, **project(container[key], expected)}

    config = row.get("Config") if type(row) is dict else None
    env = config.get("Env") if type(config) is dict else None
    expected_env = dict(profile["declared_public_image_env"], LANG="C", LC_ALL="C")
    env_ok = False
    if type(env) is list and all(type(v) is str and "=" in v for v in env):
        pairs = [v.split("=", 1) for v in env]
        env_ok = len({k for k, _ in pairs}) == len(pairs) and dict(pairs) == expected_env
    configs = {
        "Image": IMAGE,
        "User": "0:0",
        "Entrypoint": ["/usr/bin/getent"],
        "Cmd": ["passwd", "postgres"],
        "WorkingDir": "",
        "Tty": False,
        "OpenStdin": False,
    }
    result = {
        "phase": phase,
        "Config": {k: field(config, k, v) for k, v in configs.items()},
        "Env": {
            "present": type(config) is dict and "Env" in config,
            "type": type(env).__name__,
            "matches_expected": env_ok,
        },
        "Labels_match": type(config) is dict and same(config.get("Labels"), {LABEL: run}),
        "HostConfig": {k: field(row.get("HostConfig"), k, v) for k, v in HOST.items()},
        "HostConfig_Mounts": field(row.get("HostConfig"), "Mounts", []),
        "Path": field(row, "Path", "/usr/bin/getent"),
        "Args": field(row, "Args", ["passwd", "postgres"]),
        "Mounts": field(row, "Mounts", []),
        "State": {
            k: field(row.get("State"), k, v)
            for k, v in {"Running": False, "OOMKilled": False, "ExitCode": 0}.items()
        },
        "identity_matches": type(config) is dict
        and row.get("Name") == "/" + run + "-stage0"
        and row.get("Image") == MANIFEST
        and type(row.get("Id")) is str
        and bool(re.fullmatch(r"[a-f0-9]{64}", row["Id"])),
    }
    need(len(json.dumps(result)) <= 16384, "PROJECTION_BUDGET")
    return result


def parse_passwd(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "PASSWD_BUDGET")
    need(raw.endswith(b"\n") and raw.count(b"\n") == 1, "PASSWD_ONE_RECORD")
    need(all(32 <= value < 127 for value in raw[:-1]), "PASSWD_ASCII")
    fields = raw[:-1].decode("ascii").split(":")
    need(len(fields) == 7 and fields[:2] == ["postgres", "x"], "PASSWD_FIELDS")
    for value in fields[2:4]:
        need(re.fullmatch(r"[1-9][0-9]{0,9}", value), "PASSWD_NUMBER")
        need(int(value) <= 2**32 - 2, "PASSWD_NUMBER_RANGE")
    need(
        len(fields[4]) <= 256
        and all(0 < len(value) <= 256 and value.startswith("/") for value in fields[5:]),
        "PASSWD_PUBLIC_METADATA",
    )
    return {"uid": int(fields[2]), "gid": int(fields[3])}


def make_client(legacy, linux, bounded, work, state, save, profile, *, runner=None, clock=None):
    """Reuse named/remove/reserve/reconcile and durable H1; no helper globals patched."""
    work, clock = Path(work), clock or time.monotonic
    now = clock()
    need(
        type(state["work_deadline"]) in (int, float)
        and type(state["cleanup_deadline"]) in (int, float)
        and 0 < state["work_deadline"] - now <= 90
        and 0 < state["cleanup_deadline"] - state["work_deadline"] <= 30,
        "DEADLINE_BOUNDS",
    )

    class Client(legacy.LocalDocker):
        def __init__(self):
            self.cleaning = False
            self.prefix = [
                "/usr/bin/docker",
                "--host",
                "unix:///var/run/docker.sock",
                "--config",
                str(work / "docker-config"),
            ]
            self.env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(work / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "DOCKER_API_VERSION": API_VERSION,
            }

        def command(self, *args, timeout=15):
            args = list(args)
            if args[0] == "create":
                marker = LEGACY_LABEL + "=" + state["run"]
                need(args.count(marker) == 1, "LEGACY_CREATE_LABEL")
                args[args.index(marker)] = LABEL + "=" + state["run"]
            deadline = state["cleanup_deadline"] if self.cleaning else state["work_deadline"]
            need(clock() < deadline, "DEADLINE")
            pending = linux.begin_io(state, args[0])
            save()  # Before Popen, including create/inspect/cleanup.
            try:
                result = (runner or bounded.run_capped)(
                    self.prefix + args,
                    cwd=str(work),
                    env=self.env,
                    timeout=min(timeout, deadline - clock()),
                    stdout_cap=4096 if args[:2] == ["start", "--attach"] else 32768,
                    stderr_cap=4096,
                )
                pending.clear()
                pending.update({"operation": args[0], **result.facts()})
                linux.io_history_released(state)
                save()
                need(
                    result.owned_child_reaped is True
                    and result.drains_complete is True
                    and result.cleanup_exception_type is None
                    and result.spawn_attempted is True
                    and type(result.pid) is int
                    and result.pid > 0
                    and result.killed_owned_child is False
                    and result.exception_type is None
                    and result.reason in (None, "nonzero_exit"),
                    "CLI_UNCONFIRMED",
                )
                if args[0] == "create" and result.returncode == 0 and result.stderr == b"":
                    need(re.fullmatch(rb"[a-f0-9]{64}\n", result.stdout), "CREATE_RESPONSE")
                    need("create_ack" not in state, "ONE_CREATE_ACK")
                    state["create_ack"] = {
                        "cid": result.stdout[:-1].decode("ascii"),
                        "run": state["run"],
                        "manifest": MANIFEST,
                        "user": "0:0",
                        "io_index": len(state["IO"]) - 1,
                    }
                    save()  # Durable CID acknowledgement precedes all inspect validation.
                return result.returncode, result.stdout, result.stderr
            except BaseException:
                state["IO_uncertain"] = True
                save()
                raise

        def inspect_row(self, cid, phase):
            state["inspect_phase"] = phase
            save()
            rows = self.json("inspect", cid)
            need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, "INSPECT_SHAPE")
            diagnostics = state.setdefault("inspect_diagnostics", [])
            if len(diagnostics) < 4:
                diagnostics.append(inspect_projection(rows[0], state["run"], profile, phase))
                save()
            need(rows[0]["Id"] == cid, "INSPECT_ID")
            return rows[0]

        def checked_inspect(self, cid, phase, full):
            try:
                row = self.inspect_row(cid, phase)
                if full:
                    return inspect_profile(row, state["run"], profile)
                return inspect_owned(row, state, cid)
            except (Refusal, KeyError, TypeError, ValueError, AttributeError) as error:
                codes = {
                    "RUN",
                    "OWNERSHIP",
                    "ENV_TYPES",
                    "ENV_EXACT",
                    "CONFIG_EXACT",
                    "ARGV",
                    "HOST_PROFILE",
                    "HOST_MOUNTS_MUST_BE_ABSENT",
                    "NO_HOST_OR_ANONYMOUS_VOLUME",
                    "STATE_TYPES",
                    "CREATE_ACK",
                    "CREATE_ACK_BINDING",
                    "CREATE_ACK_H1",
                    "CLEANUP_OWNERSHIP",
                    "CLEANUP_STATE_TYPES",
                    "UNEXPECTED_RUNNING_NO_STOP",
                    "INSPECT_SHAPE",
                    "INSPECT_ID",
                    "PROJECTION_BUDGET",
                }
                code = (
                    str(error)
                    if type(error) is Refusal and str(error) in codes
                    else "MALFORMED_OR_UNCONFIRMED"
                )
                records = state.setdefault("inspect_refusals", [])
                if len(records) < 4:
                    records.append({"phase": phase, "code": code})
                save()
                raise

        def inspect(self, cid):
            phase = "CLEANUP_IDENTITY" if self.cleaning else "CREATE_IDENTITY"
            return self.checked_inspect(cid, phase, False)

        def inspect_start(self, cid):
            return self.checked_inspect(cid, "START_PROFILE", True)

        def inspect_final(self, cid):
            return self.checked_inspect(cid, "FINAL_PROFILE", True)

    return Client()


def observe(client, legacy, linux, lease, state, save, profile):
    """Future owner supplies received lease, fresh paths, pinned helpers and image data.

    A separately pinned Linux CI owner closes the CLI lifecycle. This function's DATA
    result cannot commission a UID, ownership, PGDATA or an image automatically.
    """
    measurement, failure, cleanup, released = None, None, None, False
    version, store = None, None
    verify_profile_binding(profile)
    need(
        state["image_config"] == CONFIG
        and state["image_manifest"] == MANIFEST
        and state["user"] == "0:0"
        and type(state["run"]) is str
        and re.fullmatch(r"w-pg-id-[a-f0-9]{32}", state["run"]),
        "RESERVATION_BINDINGS",
    )
    lease.acquire()  # Busy lease raises before any Engine command.
    try:
        version = verify_version(client.json("version", "--format", VERSION_TEMPLATE))
        store = verify_store(client.info())
        rows = client.json("image", "inspect", IMAGE)
        need(type(rows) is list and len(rows) == 1, "IMAGE_SHAPE")
        verify_image(rows[0], profile)
        state["metadata_verified"] = True
        save()
        cid = reserve_owned(client, legacy, state, save)
        client.inspect_start(cid)  # Full R3 predicate, unchanged, before any START intent.
        state["start_profile_cid"] = cid
        state["started"] = True
        save()
        code, raw, error = client.command("start", "--attach", cid, timeout=15)
        need(code == 0 and error == b"", "GETENT_FAILED")
        final = client.inspect_final(cid)
        need(
            final["Running"] is False and final["OOMKilled"] is False and final["ExitCode"] == 0,
            "GETENT_FINAL_STATE",
        )
        measurement = parse_passwd(raw)
    except BaseException:
        failure = "PROBE_FAILED_OR_UNKNOWN"
    finally:
        client.cleaning = True
        state["owner_cleaning"] = True
        save()
        try:
            cleanup = reconcile_owned(client, legacy, state, save)
            released = cleanup.get("released") is True and linux.io_history_released(state)
        except BaseException:
            state["IO_uncertain"] = True
            released = False
        lease_status = lease.release(released)
        save()
    ok = (
        failure is None
        and released
        and lease_status.get("released") is True
        and type(cleanup.get("exit_code")) is int
        and cleanup.get("exit_code") == 0
        and cleanup.get("OOMKilled") is False
    )
    if failure is None and not ok:
        failure = "FINAL_OR_CLEANUP_UNCONFIRMED"
    return {
        "schema": "pamolive.W-public-PG-identity-DATA/1",
        "ok": ok,
        "measurement": measurement if ok else None,
        "failure": failure,
        "container_released": cleanup.get("released") is True if type(cleanup) is dict else False,
        "clients_released": linux.io_history_released(state),
        "resources_released": released and lease_status.get("released") is True,
        "image_manifest": MANIFEST,
        "image_config": CONFIG,
        "engine_client": version,
        "store": store,
        "postgres_passwd_not_PGDATA_owner": True,
        "independent_Root_comparison_required": True,
        "commissioned": False,
        "PGDATA_ownership_measured": False,
        "authority": False,
        "inspect_diagnostics": state.get("inspect_diagnostics", []),
        "inspect_refusals": state.get("inspect_refusals", []),
    }


def legacy_reservation_view(state):
    """Only this received helper record's legacy image_config key means manifest.

    Canonical state image_config remains config140936. No helper body/global is
    changed and no classic config ID is an alternative ownership identity.
    """
    need(
        state["image_manifest"] == MANIFEST and state["image_config"] == CONFIG,
        "CANONICAL_MANIFEST_CONFIG_BINDING",
    )
    need(
        state["user"] == "0:0"
        and type(state["run"]) is str
        and re.fullmatch(r"w-pg-id-[a-f0-9]{32}", state["run"]),
        "CANONICAL_RESERVATION",
    )
    value = {"run": state["run"], "user": state["user"], "image_config": MANIFEST}
    if "legacy_reservation" in state:
        value["create"] = state["legacy_reservation"]
        item = value["create"]
        need(type(item) is dict and item.get("image_config") == MANIFEST, "LEGACY_MANIFEST_BINDING")
        need(
            set(item) == {"name", "run", "image_config", "user", "cid", "attempted", "outcome"},
            "LEGACY_RECORD_SHAPE",
        )
        need(
            item["name"] == state["run"] + "-stage0"
            and item["run"] == state["run"]
            and item["user"] == "0:0"
            and type(item["attempted"]) is bool
            and item["outcome"] in {"reserved", "pending", "confirmed", "unknown", "removed"}
            and (
                item["cid"] is None
                or type(item["cid"]) is str
                and re.fullmatch(r"[a-f0-9]{64}", item["cid"])
            ),
            "LEGACY_RECORD_BINDING",
        )
    return value


def reserve_owned(client, legacy, state, save):
    value = legacy_reservation_view(state)

    def persist():
        if "create" in value:
            state["legacy_reservation"] = value["create"]
        save()

    return legacy.reserve_create(client, value, persist, arguments())


def reconcile_owned(client, legacy, state, save):
    value = legacy_reservation_view(state)

    def persist():
        if "create" in value:
            state["legacy_reservation"] = value["create"]
        save()

    return legacy.reconcile(client, value, persist)


def verify_public_binding(buffers):
    """Actual public bytes bind manifest/config/diffIDs; never NSS account data."""
    manifest_raw, config_raw = buffers["data/amd64-manifest.json"], buffers["data/config.json"]
    need(
        type(manifest_raw) is bytes
        and len(manifest_raw) == 3628
        and "sha256:" + hashlib.sha256(manifest_raw).hexdigest() == MANIFEST,
        "PUBLIC_MANIFEST_PIN",
    )
    need(
        type(config_raw) is bytes
        and len(config_raw) == 10147
        and "sha256:" + hashlib.sha256(config_raw).hexdigest() == CONFIG,
        "PUBLIC_CONFIG_PIN",
    )
    manifest, config = json.loads(manifest_raw), json.loads(config_raw)
    profile = json.loads(buffers["data/profile.json"])
    verify_profile_binding(profile)
    need(same(manifest["config"], profile["config_descriptor"]), "MANIFEST_CONFIG_LINK")
    need(
        same(config["rootfs"], {"type": "layers", "diff_ids": profile["rootfs_diff_ids"]}),
        "CONFIG_DIFFIDS_LINK",
    )
    need(len(config["rootfs"]["diff_ids"]) == len(manifest["layers"]) == 14, "FOURTEEN_DIFFIDS")
    return profile
