"""Stage0 CI only: explicit bounded pull, fresh two-file spool, owned-object cleanup."""

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
ENGINE = "unix:///var/run/docker.sock"
LABEL = "pamolive.b0pre.run"
ASSETS = {"stage0.cjs": 16384, "pins-stage0.json": 8192}
MIB = 1024**2


class Refusal(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(path, maximum):
    initial = path.lstat()
    need(
        stat.S_ISREG(initial.st_mode)
        and initial.st_nlink == 1
        and not getattr(initial, "st_file_attributes", 0) & 0x400
        and 0 < initial.st_size <= maximum,
        "B0_PRE_FILE_TYPE_ALIAS_OR_BUDGET",
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        need(
            (initial.st_dev, initial.st_ino) == (info.st_dev, info.st_ino),
            "B0_PRE_FILE_IDENTITY_CHANGED",
        )
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and 0 < info.st_size <= maximum,
            "B0_PRE_FILE_TYPE_ALIAS_OR_BUDGET",
        )
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        need(
            len(raw) == info.st_size <= maximum
            and (info.st_dev, info.st_ino, info.st_size)
            == (after.st_dev, after.st_ino, after.st_size),
            "B0_PRE_FILE_CHANGED",
        )
    need(not path.is_symlink(), "B0_PRE_FILE_ALIAS")
    return raw


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "B0_PRE_JSON_DUPLICATE")
            result[key] = value
        return result

    def finite(value):
        number = float(value)
        need(math.isfinite(number), "B0_PRE_JSON_NONFINITE")
        return number

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique,
        parse_float=finite,
        parse_constant=lambda _: need(False, "B0_PRE_JSON_NONFINITE"),
    )


def closed(value, keys):
    need(type(value) is dict and set(value) == set(keys), "B0_PRE_JSON_SCHEMA")


def verified_assets(source, manifest_sha):
    raw = regular_bytes(source / "assets-manifest.json", 8192)
    need(
        re.fullmatch("[a-f0-9]{64}", manifest_sha) and digest(raw) == manifest_sha,
        "B0_PRE_REVIEW_MANIFEST_CHANGED",
    )
    manifest = strict_json(raw)
    closed(manifest, ("schema", "assets", "authority"))
    need(
        manifest["schema"] == "pamolive.b0-stage0-assets/2" and manifest["authority"] is False,
        "B0_PRE_MANIFEST_SCHEMA",
    )
    closed(manifest["assets"], ASSETS)
    buffers = {}
    for name, maximum in ASSETS.items():
        row = manifest["assets"][name]
        closed(row, ("bytes", "sha256"))
        need(
            type(row["bytes"]) is int
            and 0 < row["bytes"] <= maximum
            and re.fullmatch("[a-f0-9]{64}", row["sha256"]),
            "B0_PRE_ASSET_DESCRIPTOR",
        )
        data = regular_bytes(source / name, maximum)
        need(len(data) == row["bytes"] and digest(data) == row["sha256"], "B0_PRE_ASSET_CHANGED")
        buffers[name] = data
    # Hash/linkage above precedes interpretation; parse exactly that verified buffer.
    pins = strict_json(buffers["pins-stage0.json"])
    expected = {
        "schema",
        "image",
        "image_config",
        "index_information_only",
        "chromium_revision",
        "chromium_version",
        "node_min_major",
        "memory_MiB",
        "cpus",
        "tmp_MiB",
        "shm_MiB",
        "pids",
        "min_memory_MiB",
        "min_store_free_MiB",
        "pull_timeout_seconds",
        "authority",
    }
    closed(pins, expected)
    need(
        pins["schema"] == "pamolive.b0-stage0-pins/2"
        and pins["authority"] is False
        and pins["image"]
        == "mcr.microsoft.com/playwright@sha256:"
        "ee15712262f017b8157421b212b12099146645f44b1bc5c0514cbbe6a229b1d0"
        and pins["image_config"]
        == "sha256:a0d7b2b49ffa0e99787a00b7ec2af46eca58020082713f002ca9f0f1cfd1a017"
        and pins["index_information_only"]
        == "sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f"
        and pins["chromium_revision"] == "1248"
        and pins["chromium_version"] == "156.0.8078.4",
        "B0_PRE_M0_PINS_CHANGED",
    )
    for key, value in {
        "node_min_major": 20,
        "memory_MiB": 256,
        "tmp_MiB": 64,
        "shm_MiB": 16,
        "pids": 256,
        "min_memory_MiB": 3072,
        "min_store_free_MiB": 8192,
        "pull_timeout_seconds": 480,
    }.items():
        need(type(pins[key]) is int and pins[key] == value, "B0_PRE_BUDGET_PINS_CHANGED")
    need(pins["cpus"] == "0.5", "B0_PRE_CPU_PIN_CHANGED")
    return pins, buffers


def spool(work, buffers):
    target = work / "inputs"
    target.mkdir(mode=0o700)
    for name in ASSETS:
        with (target / name).open("xb") as stream:
            stream.write(buffers[name])
        (target / name).chmod(0o400)
    target.chmod(0o500)
    check_spool(target, buffers)
    return target


def check_spool(target, buffers):
    need(
        not target.is_symlink() and set(path.name for path in target.iterdir()) == set(ASSETS),
        "B0_PRE_SPOOL_NOT_CLOSED",
    )
    for name, maximum in ASSETS.items():
        need(regular_bytes(target / name, maximum) == buffers[name], "B0_PRE_SPOOL_CHANGED")


def atomic(path, value):
    temporary = path.with_suffix(".new")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if os.name == "posix":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class LocalDocker:
    def __init__(self, work):
        self.prefix = ["docker", "--config", str(work / "docker-config"), "-H", ENGINE]

    def command(self, *args, timeout=30):
        """Bound bytes while draining, before allocation; no raw output is published."""
        process = subprocess.Popen(
            self.prefix + list(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        outputs, total, deadline = {1: bytearray(), 2: bytearray()}, 0, time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, 1)
                selector.register(process.stderr, selectors.EVENT_READ, 2)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("B0_PRE_CONTROL_TIMEOUT")
                    for key, _ in selector.select(0.2):
                        block = os.read(key.fileobj.fileno(), min(8192, 65537 - total))
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(block)
                        need(total <= 65536, "B0_PRE_CONTROL_OUTPUT_BUDGET")
                        outputs[key.data].extend(block)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return code, bytes(outputs[1]), bytes(outputs[2])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def json(self, *args):
        code, data, _ = self.command(*args)
        need(code == 0, "B0_PRE_DOCKER_QUERY_FAILED")
        return strict_json(data)

    def image(self, pins):
        row = self.json(
            "image",
            "inspect",
            pins["image"],
            "--format",
            '{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},'
            '"RepoDigests":{{json .RepoDigests}},"Volumes":{{json .Config.Volumes}}}',
        )
        need(
            row["Id"] == pins["image_config"]
            and row["Os"] == "linux"
            and row["Architecture"] == "amd64"
            and row["Volumes"] in (None, {})
            and any(
                value.endswith("@" + pins["image"].split("@")[1]) for value in row["RepoDigests"]
            ),
            "B0_PRE_IMAGE_IDENTITY_REFUSED",
        )

    def info(self):
        return self.json(
            "info",
            "--format",
            '{"DockerRootDir":{{json .DockerRootDir}},"Driver":{{json .Driver}},'
            '"DriverStatus":{{json .DriverStatus}}}',
        )

    def named(self, name):
        code, raw, _ = self.command(
            "container",
            "ls",
            "-a",
            "--no-trunc",
            "--filter",
            "name=^/" + name + "$",
            "--format",
            "{{.ID}}",
        )
        need(code == 0, "B0_PRE_NAME_QUERY_FAILED")
        ids = raw.decode("ascii").splitlines()
        need(
            len(ids) <= 1 and all(re.fullmatch("[a-f0-9]{64}", value) for value in ids),
            "B0_PRE_NAME_AMBIGUOUS",
        )
        return ids

    def inspect(self, cid):
        return self.json(
            "inspect",
            cid,
            "--format",
            '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
            '"Run":{{json (index .Config.Labels "pamolive.b0pre.run")}},'
            '"User":{{json .Config.User}},"Running":{{json .State.Running}},'
            '"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}},'
            '"Mounts":{{json .Mounts}},"Profile":{"Memory":{{json .HostConfig.Memory}},'
            '"MemorySwap":{{json .HostConfig.MemorySwap}},"NanoCpus":{{json .HostConfig.NanoCpus}},'
            '"PidsLimit":{{json .HostConfig.PidsLimit}},"ShmSize":{{json .HostConfig.ShmSize}},'
            '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},'
            '"Privileged":{{json .HostConfig.Privileged}},"CapDrop":{{json .HostConfig.CapDrop}},'
            '"CapAdd":{{json .HostConfig.CapAdd}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},'
            '"IpcMode":{{json .HostConfig.IpcMode}},"PidMode":{{json .HostConfig.PidMode}},'
            '"NetworkMode":{{json .HostConfig.NetworkMode}},'
            '"PortBindings":{{json .HostConfig.PortBindings}},'
            '"PublishAllPorts":{{json .HostConfig.PublishAllPorts}},'
            '"Tmpfs":{{json .HostConfig.Tmpfs}}}}',
        )

    def remove(self, cid, running):
        if running:
            need(self.command("stop", "--time", "5", cid)[0] == 0, "B0_PRE_STOP_FAILED")
        final = self.inspect(cid)
        need(not final["Running"], "B0_PRE_STOP_NOT_CONFIRMED")
        need(self.command("rm", cid)[0] == 0, "B0_PRE_REMOVE_FAILED")
        return final

    def pull(self, pins):
        # Explicit separate CLI, no logs at all, no retry and no automatic fallback.
        return subprocess.run(
            self.prefix + ["pull", "--platform", "linux/amd64", pins["image"]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=pins["pull_timeout_seconds"],
            check=False,
        ).returncode


def storage_observation(client, minimum, observe, stat_fn=os.stat, free_fn=shutil.disk_usage):
    info = client.info()
    closed(info, ("DockerRootDir", "Driver", "DriverStatus"))
    root = info["DockerRootDir"]
    need(
        type(root) is str and root.startswith("/") and ".." not in root.split("/"),
        "B0_PRE_STORE_PATH_UNKNOWN",
    )
    driver = info["Driver"]
    need(
        type(driver) is str and re.fullmatch("[a-zA-Z0-9_.-]{1,64}", driver),
        "B0_PRE_DRIVER_UNKNOWN",
    )
    rows = info["DriverStatus"] or []
    need(
        type(rows) is list
        and len(rows) <= 32
        and all(
            type(row) is list
            and len(row) == 2
            and all(type(item) is str and len(item) <= 256 for item in row)
            for row in rows
        ),
        "B0_PRE_DRIVER_STATUS_UNKNOWN",
    )
    containerd = any(
        key == "driver-type" and value.startswith("io.containerd.") for key, value in rows
    )
    store_type = (
        "containerd"
        if containerd
        else "classic"
        if driver in ("overlay2", "vfs", "btrfs", "zfs", "aufs")
        else "unknown"
    )
    observe.update(
        {
            "driver": driver,
            "content_store_type": store_type,
            "DockerRootDir": root,
            "filesystems": [],
            "containerd_measurement": None,
            "hard_disk_quota_enforced": False,
        }
    )
    try:
        observe["filesystems"].append(
            {"path": root, "device": stat_fn(root).st_dev, "free_bytes": free_fn(root).free}
        )
    except OSError as error:
        raise Refusal("B0_PRE_DOCKER_STORAGE_UNOBSERVABLE") from error
    need(
        observe["filesystems"][0]["free_bytes"] >= minimum * MIB, "B0_PRE_DOCKER_DISK_INSUFFICIENT"
    )
    # No guessed root, config-file reading or silent assumption about containerd.
    need(store_type != "containerd", "B0_PRE_CONTAINERD_STORAGE_UNPROVEN")
    need(store_type == "classic", "B0_PRE_STORAGE_DRIVER_UNSUPPORTED")


def owns(row, reservation):
    return (
        row["Name"] == "/" + reservation["name"]
        and row["Run"] == reservation["run"]
        and row["Image"] == reservation["image_config"]
        and row["User"] == reservation["user"]
        and re.fullmatch("[a-f0-9]{64}", row["Id"]) is not None
    )


def reserve_create(client, state, save, arguments):
    reservation = {
        "name": state["run"] + "-stage0",
        "run": state["run"],
        "image_config": state["image_config"],
        "user": state["user"],
        "cid": None,
        "attempted": False,
        "outcome": "reserved",
    }
    state["create"] = reservation
    save()  # Intent is durable before even checking or sending create.
    need(not client.named(reservation["name"]), "B0_PRE_NAME_ALREADY_EXISTS")
    reservation["attempted"], reservation["outcome"] = True, "pending"
    save()
    try:
        code, raw, _ = client.command(
            "create",
            "--name",
            reservation["name"],
            "--label",
            LABEL + "=" + state["run"],
            *arguments,
        )
        need(code == 0, "B0_PRE_CREATE_FAILED")
        cid = raw.decode("ascii").strip()
        need(re.fullmatch("[a-f0-9]{64}", cid), "B0_PRE_CID_INVALID")
        row = client.inspect(cid)
        need(owns(row, reservation), "B0_PRE_CREATED_OWNERSHIP_REFUSED")
        reservation.update({"cid": cid, "outcome": "confirmed"})
        save()
        return cid
    except BaseException:
        reservation["outcome"] = "unknown"
        save()
        raise


def reconcile(client, state, save):
    item = state.get("create")
    if not item or not item["attempted"]:
        return {"status": "not_created", "released": True}
    try:
        ids = client.named(item["name"])
        if not ids:
            # A lost create response may still materialize later. Absence is not proof.
            released = item["outcome"] == "removed"
            return {"status": "released" if released else "unknown", "released": released}
        row = client.inspect(ids[0])
        need(
            owns(row, item) and (item["cid"] is None or item["cid"] == row["Id"]),
            "B0_PRE_CLEANUP_OWNERSHIP_REFUSED",
        )
        item["cid"] = row["Id"]
        save()
        final = client.remove(row["Id"], row["Running"])
        need(not client.named(item["name"]), "B0_PRE_REMOVE_NOT_CONFIRMED")
        item["outcome"] = "removed"
        save()
        return {
            "status": "released",
            "released": True,
            "exit_code": final["ExitCode"],
            "OOMKilled": final["OOMKilled"],
        }
    except BaseException:
        return {"status": "unknown", "released": False}


def validate_evidence(value, pins):
    flags = {
        "certutilPresent",
        "certutilFunctional",
        "nssEmpty",
        "browserPresent",
        "nonroot",
        "rootReadOnly",
        "capsZero",
        "noNewPrivs",
    }
    closed(value, flags | {"code", "ok", "nodeVersion", "browserVersion", "authority"})
    need(
        type(value["ok"]) is bool
        and value["authority"] is False
        and re.fullmatch("B0_PRE_[A-Z0-9_]{1,80}", value["code"])
        and re.fullmatch(r"v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", value["nodeVersion"])
        and value["browserVersion"] in (None, pins["chromium_version"])
        and all(value[key] is None or type(value[key]) is bool for key in flags),
        "B0_PRE_EVIDENCE_VALUES",
    )
    if value["code"] == "B0_PRE_CERTUTIL_MISSING":
        need(
            value["certutilPresent"] is False
            and all(
                value[key] is None
                for key in ("certutilFunctional", "nssEmpty", "browserPresent", "browserVersion")
            ),
            "B0_PRE_UNOBSERVED_MISREPORTED",
        )
    if value["ok"]:
        need(
            value["code"] == "B0_PRE_STAGE0_PREREQUISITES_READY"
            and all(value[key] is True for key in flags)
            and value["browserVersion"] == pins["chromium_version"],
            "B0_PRE_SUCCESS_UNPROVEN",
        )
        need(
            int(value["nodeVersion"][1:].split(".")[0]) >= pins["node_min_major"],
            "B0_PRE_SUCCESS_NODE_ENGINE_REFUSED",
        )
    return value


def create_arguments(work, pins, state):
    inputs, evidence = work / "inputs", work / "evidence"
    return [
        "--pull",
        "never",
        "--platform",
        "linux/amd64",
        "--init",
        "--user",
        state["user"],
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--cpus",
        pins["cpus"],
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--pids-limit",
        "256",
        "--ipc",
        "private",
        "--shm-size",
        "16m",
        "--ulimit",
        "core=0",
        "--network",
        "none",
        "--no-healthcheck",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=64k",
        "--log-opt",
        "max-file=1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--env",
        "HOME=/tmp/b0-home",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "LC_ALL=C.UTF-8",
        "--env",
        "B0_PINS_SHA256=" + state["pins_sha256"],
        "--mount",
        f"type=bind,source={inputs},target=/inputs,readonly",
        "--mount",
        f"type=bind,source={evidence},target=/evidence",
        "--entrypoint",
        "/bin/sh",
        pins["image"],
        "-c",
        "if ! command -v node >/dev/null 2>&1; then "
        'printf \'{"code":"B0_PRE_NODE_MISSING","ok":false}\\n\'; '
        "exit 42; fi; exec node /inputs/stage0.cjs",
    ]


def validate_profile(row, work):
    profile = row["Profile"]
    need(
        profile["Memory"] == profile["MemorySwap"] == 256 * MIB
        and profile["NanoCpus"] == 500_000_000
        and profile["PidsLimit"] == 256
        and profile["ShmSize"] == 16 * MIB
        and profile["ReadonlyRootfs"] is True
        and profile["Privileged"] is False
        and profile["CapDrop"] == ["ALL"]
        and profile["CapAdd"] in (None, [])
        and profile["IpcMode"] == "private"
        and profile["PidMode"] == ""
        and profile["NetworkMode"] == "none"
        and profile["PortBindings"] in (None, {})
        and profile["PublishAllPorts"] is False
        and any(
            value in ("no-new-privileges:true", "no-new-privileges")
            for value in profile["SecurityOpt"]
        )
        and not any("unconfined" in value for value in profile["SecurityOpt"]),
        "B0_PRE_ENGINE_PROFILE_REFUSED",
    )
    need(
        profile["Tmpfs"] == {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"},
        "B0_PRE_TMPFS_PROFILE_REFUSED",
    )
    mounts = {
        (entry["Type"], entry["Source"], entry["Destination"], entry["RW"])
        for entry in row["Mounts"]
    }
    need(
        mounts
        == {
            ("bind", str(work / "inputs"), "/inputs", False),
            ("bind", str(work / "evidence"), "/evidence", True),
        },
        "B0_PRE_MOUNTS_REFUSED",
    )


def ci_guard(work):
    need(
        sys.platform == "linux"
        and os.getuid() > 0
        and os.getgid() > 0
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("CI") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "B0_PRE_EPHEMERAL_CI_REQUIRED",
    )
    need(
        not any(
            os.environ.get(key)
            for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
        ),
        "B0_PRE_ENGINE_OVERRIDE_REFUSED",
    )
    root = Path(os.environ["RUNNER_TEMP"]).resolve()
    need(
        work.parent == root and work.name.startswith("pamolive-b0-pre-") and "," not in str(work),
        "B0_PRE_WORK_PATH_REFUSED",
    )


def memory_guard(minimum):
    match = re.search(r"^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)
    need(match, "B0_PRE_MEMORY_UNKNOWN")
    available = int(match[1]) * 1024
    groups = [
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    ]
    need(len(groups) == 1, "B0_PRE_CGROUP_V2_REQUIRED")
    group = (Path("/sys/fs/cgroup") / groups[0].lstrip("/")).resolve()
    need(group.is_relative_to(Path("/sys/fs/cgroup")), "B0_PRE_CGROUP_PATH_REFUSED")
    limit = (group / "memory.max").read_text().strip()
    if limit != "max":
        available = min(available, int(limit) - int((group / "memory.current").read_text()))
    need(available >= minimum * MIB, "B0_PRE_MEMORY_INSUFFICIENT")
    return available


def public_report(work, state, code, ok, cleanup):
    pull_unknown = state.get("pull") in ("pending", "unknown", "failed")
    report = {
        "schema": "pamolive.b0-stage0-report/2",
        "code": code,
        "ok": ok,
        "storage": state.get("storage"),
        "storage_after_pull": state.get("storage_after_pull"),
        "storage_before_stage0": state.get("storage_before_stage0"),
        "memory_available_bytes": state.get("memory_available_bytes"),
        "stage0": state.get("stage0"),
        "pull_outcome": state.get("pull", "not_attempted"),
        "cleanup": cleanup,
        "resources_released": cleanup["released"] and not pull_unknown,
        "hard_disk_quota_enforced": False,
        "TLS_observed": False,
        "sandbox_observed": False,
        "CDP_observed": False,
        "product_or_PAM_or_human_authority": False,
        "build_verified": False,
        "attestation_verified": False,
        "release_qualified": False,
    }
    atomic(work / "public-report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "pull", "stage0", "cleanup"))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    pins, buffers = verified_assets(SOURCE, args.manifest_sha256)
    work = args.work_dir.resolve()
    ci_guard(work)
    os.umask(0o077)
    if args.mode == "prepare":
        need(not work.exists(), "B0_PRE_WORK_NOT_FRESH")
        work.mkdir(mode=0o700)
        (work / "docker-config").mkdir(mode=0o700)
        (work / "evidence").mkdir(mode=0o700)
        state = {
            "run": "pamolive-b0-pre-" + uuid.uuid4().hex,
            "user": f"{os.getuid()}:{os.getgid()}",
            "image_config": pins["image_config"],
            "pins_sha256": digest(buffers["pins-stage0.json"]),
            "create": None,
            "pull": "not_attempted",
            "stage0": None,
            "storage": None,
        }
        spool(work, buffers)
    else:
        state = strict_json(regular_bytes(work / "state.json", 32768))
        need(
            re.fullmatch("pamolive-b0-pre-[a-f0-9]{32}", state["run"])
            and state["user"] == f"{os.getuid()}:{os.getgid()}"
            and state["image_config"] == pins["image_config"]
            and state["pins_sha256"] == digest(buffers["pins-stage0.json"]),
            "B0_PRE_STATE_REFUSED",
        )
        check_spool(work / "inputs", buffers)
    client = LocalDocker(work)

    def save():
        atomic(work / "state.json", state)

    save()
    code, ok = "B0_PRE_STAGE0_REFUSED", False
    try:
        if args.mode == "cleanup":
            previous = strict_json(regular_bytes(work / "public-report.json", 32768))
            need(
                type(previous["ok"]) is bool
                and re.fullmatch("B0_PRE_[A-Z0-9_]+", previous["code"]),
                "B0_PRE_PREVIOUS_REPORT_REFUSED",
            )
            code, ok = previous["code"], previous["ok"]
        elif args.mode == "prepare":
            state["memory_available_bytes"] = memory_guard(pins["min_memory_MiB"])
            need(
                shutil.disk_usage(work).free >= pins["min_store_free_MiB"] * MIB,
                "B0_PRE_WORK_DISK_INSUFFICIENT",
            )
            state["storage"] = {}
            storage_observation(client, pins["min_store_free_MiB"], state["storage"])
            code, ok = "B0_PRE_RESOURCES_AND_SPOOL_READY", True
        elif args.mode == "pull":
            need(
                state["pull"] == "not_attempted" and state["storage"], "B0_PRE_PULL_ONE_USE_REFUSED"
            )
            state["memory_available_bytes"] = memory_guard(pins["min_memory_MiB"])
            state["storage"] = {}
            storage_observation(client, pins["min_store_free_MiB"], state["storage"])
            state["pull"] = "pending"
            save()
            try:
                need(client.pull(pins) == 0, "B0_PRE_PULL_FAILED")
                client.image(pins)
            except BaseException:
                state["pull"] = "unknown"
                save()
                raise Refusal("B0_PRE_PULL_DAEMON_OUTCOME_UNKNOWN") from None
            state["pull"] = "ready"
            state["storage_after_pull"] = {}
            storage_observation(client, pins["min_store_free_MiB"], state["storage_after_pull"])
            code, ok = "B0_PRE_EXPLICIT_IMAGE_READY", True
        else:
            need(
                state["pull"] == "ready" and state["create"] is None,
                "B0_PRE_STAGE0_ONE_USE_OR_IMAGE_REFUSED",
            )
            client.image(pins)
            state["memory_available_bytes"] = memory_guard(pins["min_memory_MiB"])
            state["storage_before_stage0"] = {}
            storage_observation(client, pins["min_store_free_MiB"], state["storage_before_stage0"])
            cid = reserve_create(client, state, save, create_arguments(work, pins, state))
            validate_profile(client.inspect(cid), work)
            need(client.command("start", cid)[0] == 0, "B0_PRE_START_FAILED")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                row = client.inspect(cid)
                need(owns(row, state["create"]), "B0_PRE_RUNTIME_OWNERSHIP_REFUSED")
                if not row["Running"]:
                    need(not row["OOMKilled"], "B0_PRE_CONTAINER_OOM")
                    break
                time.sleep(0.2)
            else:
                raise Refusal("B0_PRE_STAGE0_TIMEOUT")
            evidence = work / "evidence/stage0.json"
            if not evidence.exists():
                status, logs, _ = client.command("logs", "--tail", "5", cid)
                need(status == 0 and b"B0_PRE_NODE_MISSING" in logs, "B0_PRE_NODE_EVIDENCE_MISSING")
                raise Refusal("B0_PRE_NODE_MISSING")
            state["stage0"] = validate_evidence(strict_json(regular_bytes(evidence, 8192)), pins)
            code, ok = state["stage0"]["code"], state["stage0"]["ok"]
            need(ok and row["ExitCode"] == 0, code)
    except BaseException as error:
        code = str(error) if isinstance(error, Refusal) else "B0_PRE_CONTROLLER_REFUSED"
        ok = False
    finally:
        cleanup = reconcile(client, state, save)
        save()
        report = public_report(work, state, code, ok, cleanup)
    print(json.dumps({"code": code, "ok": ok}))
    raise SystemExit(0 if ok and report["resources_released"] else 42)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        code = str(error) if isinstance(error, Refusal) else "B0_PRE_CONTROLLER_REFUSED"
        print(
            json.dumps(
                {
                    "code": code
                    if re.fullmatch("B0_PRE_[A-Z0-9_]+", code)
                    else "B0_PRE_CONTROLLER_REFUSED",
                    "ok": False,
                }
            )
        )
        raise SystemExit(42) from None
