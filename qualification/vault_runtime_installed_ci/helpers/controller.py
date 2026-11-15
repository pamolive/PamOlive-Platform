"""GitHub Linux installed-library runner. No Docker or qualification at import."""

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import sys
import time
import uuid
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ENGINE = "unix:///var/run/docker.sock"
LABEL = "pamolive.p2.installed.run"
CLI = Path("/usr/bin/docker")
TYPE = "pamolive.p2-installed-ci-state/1"
PHASE = "installed_public_v1_materials_only"
SUPPORT = {
    "legacy_controller.py": "7f3bfa46307673ba51c3a21fa3b70171ab9f931547e1903adce2fc02a29e02ce",
    "bounded_io.py": "98233b610f2d53dfd698d0d91f61f3d3ebcb1693a847983f0472f89a885f414f",
}
ASSETS = {
    "controller.py",
    "entrypoint.py",
    "legacy_controller.py",
    "bounded_io.py",
    "pins.json",
    "base-config.json",
    "selected-inputs.json",
    "materials-plan.json",
}
MIB = 1024**2
MAX_STATE = 256 * 1024
MAX_PUBLIC = 512 * 1024
MAX_IO = 32
IO_FIELDS = frozenset(
    {
        "operation",
        "spawn_attempted",
        "pid",
        "returncode",
        "reason",
        "exception_type",
        "killed_owned_child",
        "owned_child_reaped",
        "drains_complete",
        "cleanup_exception_type",
        "stdout_bytes",
        "stderr_bytes",
    }
)


class Refusal(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, maximum, empty=False):
    path = Path(path).absolute()
    for parent in path.parents:
        need(stat.S_ISDIR(parent.lstat().st_mode), "INPUT_PARENT_ALIAS")
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and (empty or before.st_size > 0)
        and before.st_size <= maximum,
        "INPUT_TYPE_SIZE",
    )
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        need(
            (before.st_dev, before.st_ino, before.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size)
            and stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1,
            "INPUT_OPEN_IDENTITY",
        )
        raw = stream.read(maximum + 1)
    need(len(raw) == before.st_size and len(raw) <= maximum, "INPUT_READ_BUDGET")
    return raw


def load_buffer(name, raw, filename):
    class Loader(importlib.machinery.SourceFileLoader):
        def get_code(self, _fullname):
            return compile(raw, str(filename), "exec", dont_inherit=True)

    loader = Loader(name, str(filename))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def supports():
    modules = {}
    for filename, digest in SUPPORT.items():
        raw = regular(HERE / filename, 1024 * 1024)
        need(sha(raw) == digest, "SUPPORT_PIN")
        modules[filename] = load_buffer("p2_ci_" + filename[:-3], raw, HERE / filename)
    legacy = modules["legacy_controller.py"]
    legacy.LABEL = LABEL  # Private module parameter; frozen source remains unchanged.
    return legacy, modules["bounded_io.py"]


def assets(expected_sha):
    legacy, bounded = supports()
    raw = regular(HERE / "assets.json", 16384)
    need(sha(raw) == expected_sha, "ASSET_MANIFEST_PIN")
    manifest = legacy.strict_json(raw)
    need(
        set(manifest) == {"schema", "files", "authority"}
        and manifest["schema"] == "pamolive.p2-installed-ci-assets/1"
        and manifest["authority"] is False
        and set(manifest["files"]) == ASSETS,
        "ASSET_SCHEMA",
    )
    buffers = {}
    for name, row in manifest["files"].items():
        need(type(row["bytes"]) is int and 0 < row["bytes"] <= MIB, "ASSET_SIZE")
        data = regular(HERE / name, row["bytes"])
        need(len(data) == row["bytes"] and sha(data) == row["sha256"], "ASSET_BYTES")
        buffers[name] = data
    pins = legacy.strict_json(buffers["pins.json"])
    need(
        pins["schema"] == "pamolive.p2-installed-ci-pins/1"
        and pins["authority"] is False
        and pins["execution_GO"] is False,
        "PINS_TYPE",
    )
    need(
        sha(buffers["selected-inputs.json"]) == pins["selected_inputs_sha256"]
        and sha(buffers["materials-plan.json"]) == pins["materials_plan_sha256"],
        "DATA_PINS",
    )
    need("sha256:" + sha(buffers["base-config.json"]) == pins["image_config"], "BASE_CONFIG_PIN")
    return legacy, bounded, pins, buffers


def encode(value, maximum=MAX_STATE):
    total, chunks = 0, []
    for chunk in json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).iterencode(value):
        data = chunk.encode()
        need(total + len(data) + 1 <= maximum, "HOST_JSON_BUDGET")
        total += len(data)
        chunks.append(data)
    return b"".join(chunks) + b"\n"


def atomic(path, value, maximum=MAX_STATE):
    raw = encode(value, maximum)
    temporary = path.with_suffix(".new")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def io_record_released(row):
    """One complete observation only; nonspawn is not an imaginary owned process."""
    if type(row) is not dict or set(row) != IO_FIELDS:
        return False
    if (
        type(row["operation"]) is not str
        or not re.fullmatch(r"[a-z-]{1,32}", row["operation"])
        or any(
            type(row[key]) is not bool
            for key in (
                "spawn_attempted",
                "killed_owned_child",
                "owned_child_reaped",
                "drains_complete",
            )
        )
    ):
        return False
    for key in ("reason", "exception_type", "cleanup_exception_type"):
        if row[key] is not None and (
            type(row[key]) is not str or not re.fullmatch(r"[A-Za-z0-9_]{1,80}", row[key])
        ):
            return False
    for key, maximum in (("stdout_bytes", 524288), ("stderr_bytes", 16384)):
        if type(row[key]) is not int or not 0 <= row[key] <= maximum:
            return False
    if row["pid"] is not None and (type(row["pid"]) is not int or not 0 < row["pid"] < 2**31):
        return False
    if row["returncode"] is not None and (
        type(row["returncode"]) is not int or not -(2**31) <= row["returncode"] < 2**31
    ):
        return False
    if row["spawn_attempted"] is False:
        return (
            row["pid"] is None
            and row["returncode"] is None
            and row["killed_owned_child"] is False
            and row["owned_child_reaped"] is False
            and row["drains_complete"] is False
            and row["stdout_bytes"] == row["stderr_bytes"] == 0
        )
    return (
        row["pid"] is not None
        and type(row["returncode"]) is int
        and row["owned_child_reaped"] is True
        and row["drains_complete"] is True
        and row["cleanup_exception_type"] is None
    )


def io_history_released(state):
    """Uncertainty is durable and monotone, including malformed/missing history."""
    rows, count, uncertain = state.get("IO"), state.get("IO_total"), state.get("IO_uncertain")
    valid = (
        type(rows) is list
        and type(count) is int
        and 0 <= count <= MAX_IO
        and len(rows) == count
        and type(uncertain) is bool
    )
    if (
        valid
        and count == 0
        and (state.get("started") is True or state.get("pull") not in (None, "not_attempted"))
    ):
        valid = False
    confirmed = valid and all(io_record_released(row) for row in rows)
    state["IO_uncertain"] = uncertain is not False or not confirmed
    return not state["IO_uncertain"]


def persist_io(work, state):
    atomic(work / "state.json", state)


def begin_io(state, operation):
    # Preserve malformed history rather than replacing it with an empty list.
    rows, count = state.get("IO"), state.get("IO_total")
    if (
        type(rows) is not list
        or type(count) is not int
        or len(rows) != count
        or not 0 <= count < MAX_IO
    ):
        state["IO_uncertain"] = True
        raise Refusal("IO_HISTORY_MALFORMED_OR_FULL")
    row = {
        "operation": operation,
        "spawn_attempted": None,
        "pid": None,
        "returncode": None,
        "reason": "pending",
        "exception_type": None,
        "killed_owned_child": False,
        "owned_child_reaped": False,
        "drains_complete": False,
        "cleanup_exception_type": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    rows.append(row)
    state["IO_total"] = count + 1
    return row


def ci_guard(work):
    need(
        sys.platform == "linux"
        and os.getuid() > 0
        and os.getgid() > 0
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("CI") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "EPHEMERAL_CI_ONLY",
    )
    forbidden = (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_AUTH_CONFIG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    )
    need(not any(key in os.environ for key in forbidden), "AMBIENT_ENGINE_AUTH_PROXY_REFUSED")
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    need(
        work.parent == root
        and re.fullmatch(r"pamolive-p2-installed-[0-9]+-[0-9]+", work.name)
        and not re.search(r"[,\s]", str(work)),
        "CI_WORK_PATH",
    )


def safe_name(name):
    path = PurePosixPath(name)
    need(
        type(name) is str
        and not path.is_absolute()
        and path.as_posix() == name
        and all(value not in ("", ".", "..") for value in path.parts)
        and ":" not in name
        and "\\" not in name,
        "INPUT_RELATIVE_PATH",
    )
    return path


def closed_files(directory, expected, count_limit=1024):
    actual = set()
    need(not directory.is_symlink() and directory.is_dir(), "INPUT_ROOT")
    for count, path in enumerate(directory.rglob("*"), 1):
        need(count <= count_limit, "INPUT_TREE_BUDGET")
        mode = path.lstat().st_mode
        need(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "INPUT_TREE_ALIAS_TYPE")
        if stat.S_ISREG(mode):
            actual.add(path.relative_to(directory).as_posix())
    need(actual == set(expected), "INPUT_CLOSED_FILES")


def stage_file(target, raw):
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with target.open("xb") as stream:
        stream.write(raw)
    target.chmod(0o444)


def verify_selected(repository, pins, buffers, legacy):
    """Pin every selected host script BEFORE acquisition can execute it."""
    selection = legacy.strict_json(buffers["selected-inputs.json"])
    need(len(selection["files"]) == 369, "SELECTED_COUNT")
    groups = {"components/pam-trust-verifier/": set(), "qualification/pam_trust_verifier/": set()}
    total = 0
    for name, row in selection["files"].items():
        safe_name(name)
        raw = regular(repository / name, 2 * MIB, empty=True)
        total += len(raw)
        need(
            total <= 8 * MIB and len(raw) == row["bytes"] and sha(raw) == row["sha256"],
            "SELECTED_BYTES",
        )
        prefix = next((prefix for prefix in groups if name.startswith(prefix)), None)
        need(prefix is not None, "SELECTED_PREFIX")
        groups[prefix].add(name[len(prefix) :])
    need([len(values) for values in groups.values()] == [354, 15], "SELECTED_GROUPS")
    for prefix, names in groups.items():
        closed_files(repository / prefix, names)
    for name, digest in selection["inherited_existing_checkout_files"].items():
        safe_name(name)
        need(sha(regular(repository / name, MIB)) == digest, "INHERITED_PUBLIC_GATE_PIN")
    return {"selected_files": 369, "source": 354, "controller": 15, "authority": False}


def prepare(work, repository, material_directory, pins, buffers, legacy):
    ci_guard(work)
    need(not work.exists(), "ONE_USE_WORK")
    verify_selected(repository, pins, buffers, legacy)
    selection = legacy.strict_json(buffers["selected-inputs.json"])
    need(len(selection["files"]) == 369, "SELECTED_COUNT")
    groups = {"source": {}, "controller": {}}
    for name, row in selection["files"].items():
        safe_name(name)
        for prefix, group in (
            ("components/pam-trust-verifier/", "source"),
            ("qualification/pam_trust_verifier/", "controller"),
        ):
            if name.startswith(prefix):
                groups[group][name[len(prefix) :]] = (repository / name, row)
                break
        else:
            raise Refusal("SELECTED_PREFIX")
    need(len(groups["source"]) == 354 and len(groups["controller"]) == 15, "SELECTED_GROUPS")
    closed_files(repository / "components/pam-trust-verifier", groups["source"])
    closed_files(repository / "qualification/pam_trust_verifier", groups["controller"])
    material_rows = legacy.strict_json(buffers["materials-plan.json"])["selected_materials"]
    need(
        len(material_rows) == 13 and sum(row["size"] for row in material_rows.values()) == 8939939,
        "MATERIAL_PLAN",
    )
    expected_wheels = {row["filename"] for row in material_rows.values()}
    closed_files(material_directory, expected_wheels | {"acquisition.json"}, 32)
    acquisition = legacy.strict_json(regular(material_directory / "acquisition.json", 32768))
    need(
        acquisition["state"] == "THIRTEEN_PUBLIC_WHEELS_ACQUIRED_AND_CHECKED"
        and acquisition["authority"] is False
        and acquisition["installed_or_built"] is False
        and set(acquisition["files"]) == expected_wheels,
        "ACQUISITION_RECEIPT",
    )
    work.mkdir(mode=0o700)
    for directory in ("controller", "source", "materials"):
        (work / directory).mkdir(mode=0o755)
    identities = {}
    for group, items in groups.items():
        total = 0
        for relative, (origin, row) in items.items():
            raw = regular(origin, 2 * MIB, empty=True)
            total += len(raw)
            need(
                total <= 8 * MIB and len(raw) == row["bytes"] and sha(raw) == row["sha256"],
                "SELECTED_BYTES",
            )
            stage_file(work / group / relative, raw)
            identities[group + "/" + relative] = sha(raw)
    for row in material_rows.values():
        safe_name(row["filename"])
        raw = regular(material_directory / row["filename"], 8 * MIB)
        receipt = acquisition["files"][row["filename"]]
        need(
            len(raw) == row["size"] == receipt["bytes"]
            and sha(raw) == row["sha256"] == receipt["sha256"]
            and receipt["ZIP_RECORD_checked"] is True,
            "MATERIAL_BYTES",
        )
        stage_file(work / "materials" / row["filename"], raw)
        identities["materials/" + row["filename"]] = sha(raw)
    (work / "home").mkdir(mode=0o700)
    (work / "docker-config").mkdir(mode=0o700)
    (work / "docker-config/config.json").write_bytes(b'{"auths":{},"proxies":{}}\n')
    state = {
        "type": TYPE,
        "phase": PHASE,
        "run": "pamolive-p2-installed-" + uuid.uuid4().hex,
        "user": "1000:1000",
        "image_config": pins["image_config"],
        "pull": "not_attempted",
        "started": False,
        "identities": identities,
        "assets_sha256": sha(regular(HERE / "assets.json", 16384)),
        "packet": None,
        "failure": None,
        "IO": [],
        "IO_total": 0,
        "IO_uncertain": False,
    }
    atomic(work / "state.json", state)
    return state


def check_inputs(work, state):
    for directory in ("controller", "source", "materials"):
        names = {
            name[len(directory) + 1 :]
            for name in state["identities"]
            if name.startswith(directory + "/")
        }
        closed_files(work / directory, names)
    for name, digest in state["identities"].items():
        safe_name(name)
        need(sha(regular(work / name, 8 * MIB, empty=True)) == digest, "STAGED_BYTES_CHANGED")


def create_arguments(work, pins, entry_raw):
    return [
        "--pull",
        "never",
        "--platform",
        "linux/amd64",
        "--init",
        "--user",
        "1000:1000",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--pids-limit",
        "128",
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
        "/work:rw,nosuid,nodev,exec,size=256m,mode=0700,uid=1000,gid=1000",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--env",
        "HOME=/tmp/p2-installed-home",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "LC_ALL=C.UTF-8",
        *[
            arg
            for name in ("controller", "source", "materials")
            for arg in ("--mount", f"type=bind,source={work / name},target=/{name},readonly")
        ],
        "--entrypoint",
        "/usr/local/bin/python3",
        pins["image"],
        "-I",
        "-B",
        "-c",
        entry_raw.decode("utf-8"),
    ]


def validate_profile(row, work, entry_raw=None, expected_environment=None):
    p = row["Profile"]
    need(
        all(
            type(p[key]) is int
            for key in ("Memory", "MemorySwap", "NanoCpus", "PidsLimit", "ShmSize")
        )
        and type(row["Running"]) is bool
        and type(row["OOMKilled"]) is bool
        and type(row["ExitCode"]) is int
        and 0 <= row["ExitCode"] <= 255,
        "CONTAINER_PROFILE_TYPES",
    )
    need(
        p["Memory"] == p["MemorySwap"] == 512 * MIB
        and p["NanoCpus"] == 1000000000
        and p["PidsLimit"] == 128
        and p["ShmSize"] == 16 * MIB
        and p["ReadonlyRootfs"] is True
        and p["Privileged"] is False
        and p["CapDrop"] == ["ALL"]
        and p["CapAdd"] in (None, [])
        and p["IpcMode"] == "private"
        and p["PidMode"] == ""
        and p["NetworkMode"] == "none"
        and p["PortBindings"] in (None, {})
        and p["PublishAllPorts"] is False,
        "CONTAINER_PROFILE",
    )
    need(
        type(p["SecurityOpt"]) is list
        and p["SecurityOpt"] in (["no-new-privileges:true"], ["no-new-privileges"]),
        "CONTAINER_SECURITY",
    )
    need(
        p["Tmpfs"]
        == {
            "/work": "rw,nosuid,nodev,exec,size=256m,mode=0700,uid=1000,gid=1000",
            "/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777",
        },
        "CONTAINER_TMPFS",
    )
    mounts = row["Mounts"]
    need(type(mounts) is list and len(mounts) == 3, "CONTAINER_MOUNT_COUNT")
    need(
        all(
            type(item["RW"]) is bool
            and item["RW"] is False
            and item.get("Propagation") == "rprivate"
            for item in mounts
        ),
        "CONTAINER_MOUNT_OPTIONS",
    )
    actual = [(item["Type"], item["Source"], item["Destination"], item["RW"]) for item in mounts]
    need(
        len(set(actual)) == 3
        and set(actual)
        == {
            ("bind", str(work / name), "/" + name, False)
            for name in ("controller", "source", "materials")
        },
        "CONTAINER_MOUNTS",
    )
    if entry_raw is not None:
        need(
            row["Entrypoint"] == ["/usr/local/bin/python3"]
            and row["Cmd"] == ["-I", "-B", "-c", entry_raw.decode("utf-8")]
            and row["Init"] is True
            and row["GroupAdd"] in (None, [])
            and row["LogConfig"]
            == {"Type": "json-file", "Config": {"max-size": "64k", "max-file": "1"}},
            "CONTAINER_COMMAND_INIT_LOGS",
        )
        env = {}
        for value in row["Env"]:
            name, separator, content = value.partition("=")
            need(separator == "=" and name not in env, "CONTAINER_ENV_DUPLICATE")
            env[name] = content
        need(env == expected_environment, "CONTAINER_ENVIRONMENT")


def docker_class(legacy, bounded):
    class Docker(legacy.LocalDocker):
        def __init__(self, work, pins, state, work_deadline=None):
            raw = regular(CLI, 128 * MIB)
            self.binary_sha256 = sha(raw)
            self.work, self.pins, self.state = work, pins, state
            self.prefix = [str(CLI), "--config", str(work / "docker-config"), "--host", ENGINE]
            self.env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(work / "home"),
                "DOCKER_CONFIG": str(work / "docker-config"),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            }
            self.work_deadline = work_deadline or time.monotonic() + 300
            self.cleanup_deadline = self.work_deadline + 60
            self.cleaning = False
            self.entry_raw = regular(HERE / "entrypoint.py", MIB)
            base = legacy.strict_json(regular(HERE / "base-config.json", MIB))
            self.expected_environment = dict(value.split("=", 1) for value in base["config"]["Env"])
            self.expected_environment.update(
                HOME="/tmp/p2-installed-home", LANG="C.UTF-8", LC_ALL="C.UTF-8"
            )

        def json(self, *args):
            # Reuse the legacy projection, changing its label parameter and adding
            # immutable command/profile fields. Lifecycle primitives are unchanged.
            if args[0] == "inspect" and args[-2] == "--format":
                projection = args[-1]
                need(projection.count('"pamolive.b0pre.run"') == 1, "LEGACY_INSPECT_TEMPLATE")
                projection = projection.replace('"pamolive.b0pre.run"', '"' + LABEL + '"')
                projection = (
                    projection[:-1]
                    + ',"Entrypoint":{{json .Config.Entrypoint}},"Cmd":{{json .Config.Cmd}},'
                    '"Env":{{json .Config.Env}},"Init":{{json .HostConfig.Init}},'
                    '"GroupAdd":{{json .HostConfig.GroupAdd}},'
                    '"LogConfig":{{json .HostConfig.LogConfig}}}'
                )
                args = (*args[:-1], projection)
            return super().json(*args)

        def command(self, *args, timeout=30):
            deadline = self.cleanup_deadline if self.cleaning else self.work_deadline
            remaining = deadline - time.monotonic()
            need(remaining > 0, "HOST_DEADLINE")
            attaching = args[:2] == ("start", "--attach")
            try:
                record = begin_io(self.state, args[0])
            except BaseException:
                persist_io(self.work, self.state)
                raise
            persist_io(self.work, self.state)  # PENDING is durable before any Popen.
            try:
                result = bounded.run_capped(
                    self.prefix + list(args),
                    env=self.env,
                    cwd=str(self.work),
                    timeout=min(timeout, remaining),
                    stdout_cap=512 * 1024 if attaching else 32768,
                    stderr_cap=16384,
                )
                record.clear()
                record.update({"operation": args[0], **result.facts()})
            except BaseException:
                self.state["IO_uncertain"] = True
                persist_io(self.work, self.state)
                raise
            io_history_released(self.state)
            persist_io(self.work, self.state)
            failure_attach = (
                attaching
                and result.reason == "nonzero_exit"
                and type(result.returncode) is int
                and result.returncode == 42
                and result.spawn_attempted is True
                and type(result.pid) is int
                and result.pid > 0
                and result.killed_owned_child is False
                and result.exception_type is None
                and result.cleanup_exception_type is None
            )
            need(
                (result.reason is None or failure_attach)
                and result.owned_child_reaped
                and result.drains_complete,
                "OWNED_CLI_UNCONFIRMED",
            )
            return result.returncode, result.stdout, result.stderr

        def pull(self, pins):
            return self.command("pull", "--platform", "linux/amd64", pins["image"], timeout=300)[0]

        def image(self, pins):
            row = self.json(
                "image",
                "inspect",
                pins["image"],
                "--format",
                '{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},'
                '"Layers":{{json .RootFS.Layers}},"Volumes":{{json (index .Config "Volumes")}}}',
            )
            need(
                row
                == {
                    "Id": pins["image_config"],
                    "Os": "linux",
                    "Architecture": "amd64",
                    "Layers": pins["diff_ids"],
                    "Volumes": None,
                },
                "CLASSIC_IMAGE_CONTENT_IDENTITY",
            )

        def inspect(self, cid):
            row = super().inspect(cid)
            validate_profile(row, self.work, self.entry_raw, self.expected_environment)
            return row

    return Docker


def validate_packet(value, pins, entry):
    need(
        set(value)
        == {
            "schema",
            "phase",
            "ok",
            "code",
            "qualifier_sha256",
            "adapter_plan_sha256",
            "payload_manifest_sha256",
            "materials_plan_sha256",
            "execution_sha256",
            "execution_bytes",
            "execution",
            "parent_summary",
            "exception_type",
            "authority",
            "build_verified",
            "attestation_verified",
            "full_P0_acceptance",
            "human_independence",
            "Vault_binding",
        },
        "PACKET_FIELDS",
    )
    need(
        value["schema"] == "pamolive.p2-installed-stdout-public/1"
        and value["phase"] == PHASE
        and type(value["ok"]) is bool,
        "PACKET_TYPE",
    )
    need(
        value["qualifier_sha256"] == pins["qualifier_sha256"]
        and value["adapter_plan_sha256"] == pins["adapter_plan_sha256"]
        and value["payload_manifest_sha256"] == pins["payload_manifest_sha256"]
        and value["materials_plan_sha256"] == pins["materials_plan_sha256"],
        "PACKET_PINS",
    )
    need(
        all(
            value[key] is False
            for key in (
                "authority",
                "build_verified",
                "attestation_verified",
                "full_P0_acceptance",
                "human_independence",
                "Vault_binding",
            )
        ),
        "PACKET_AUTHORITY",
    )
    if value["execution"] is not None:
        need(
            type(value["execution_bytes"]) is int
            and 0 < value["execution_bytes"] <= pins["execution_file_bytes"]
            and type(value["execution_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", value["execution_sha256"]),
            "PACKET_EXECUTION_IDENTITY",
        )
        entry.check_execution(value["execution"])
    else:
        need(
            value["execution_bytes"] is None and value["execution_sha256"] is None,
            "PACKET_NO_EXECUTION",
        )
    if value["ok"]:
        need(
            value["code"] == "INSTALLED_PUBLIC_FIXTURES_PASS" and value["exception_type"] is None,
            "PACKET_SUCCESS",
        )
        entry.success(value["execution"], value["parent_summary"])
    return value


def validate_failure_packet(value, entry):
    """Admit only bounded public failure metadata, never a successful exit42."""
    need(value["ok"] is False, "FAILURE_PACKET_NOT_SUCCESS")
    need(
        value["code"]
        in {
            "QUALIFIER_FAILED",
            "PUBLIC_EXECUTION_UNAVAILABLE_OR_REFUSED",
            "PUBLIC_EXPORT_BUDGET_REFUSED",
        },
        "FAILURE_PACKET_CODE",
    )
    need(
        value["exception_type"]
        in {
            None,
            "Refusal",
            "ValueError",
            "OSError",
            "SystemExit",
            "MemoryError",
            "QualificationFailure",
        },
        "FAILURE_PACKET_EXCEPTION",
    )
    if value["parent_summary"] is not None:
        entry.parse_summary(entry.encode(value["parent_summary"], 8192))
    if value["code"] == "QUALIFIER_FAILED":
        need(
            value["execution"] is not None
            and value["exception_type"] is not None
            and value["parent_summary"] is None,
            "FAILURE_PACKET_QUALIFIER",
        )
    else:
        need(value["execution"] is None, "FAILURE_PACKET_NO_EXECUTION")
        if value["code"] == "PUBLIC_EXPORT_BUDGET_REFUSED":
            need(
                value["parent_summary"] is None and value["exception_type"] is None,
                "FAILURE_PACKET_EXPORT",
            )
    return value


def report(work, state, cleanup, pins):
    clients_released = io_history_released(state)
    packet = None
    if state.get("packet"):
        try:
            raw = regular(work / "packet-public.json", pins["packet_bytes"])
            need(
                len(raw) == state["packet"]["bytes"] and sha(raw) == state["packet"]["sha256"],
                "PUBLIC_PACKET_IDENTITY",
            )
            entry_raw = regular(HERE / "entrypoint.py", MIB)
            entry = load_buffer("p2_ci_report_validator", entry_raw, HERE / "entrypoint.py")
            packet = validate_packet(entry.parse(raw, pins["packet_bytes"]), pins, entry)
        except BaseException:
            state["failure"] = state.get("failure") or "PUBLIC_PACKET_UNAVAILABLE_OR_CHANGED"
    ok = bool(
        packet
        and packet["ok"]
        and state.get("failure") is None
        and cleanup.get("released") is True
        and cleanup.get("exit_code") == 0
        and cleanup.get("OOMKilled") is False
        and state["pull"] == "ready"
        and clients_released
    )
    value = {
        "schema": "pamolive.p2-installed-ci-public-report/1",
        "phase": PHASE,
        "ok": ok,
        "state": "INSTALLED_PUBLIC_FIXTURES_PASS" if ok else "FAILED_OR_UNKNOWN",
        "failure": state.get("failure"),
        "image": pins["image"],
        "image_config": pins["image_config"],
        "payload_manifest_sha256": pins["payload_manifest_sha256"],
        "cleanup": cleanup,
        "container_released": cleanup.get("released") is True,
        "clients_released": clients_released,
        "IO_uncertain": state["IO_uncertain"],
        "IO_total": state.get("IO_total"),
        "resources_released": cleanup.get("released") is True
        and clients_released
        and state["pull"] not in ("pending", "unknown"),
        "packet": packet,
        "IO": state["IO"],
        "authority": False,
        "build_verified": False,
        "attestation_verified": False,
        "full_P0_acceptance": False,
        "human_independence": False,
    }
    try:
        encode(value, MAX_PUBLIC)
    except Refusal:
        # Metadata growth cannot erase the bounded public failure/cleanup state.
        value.update(
            ok=False,
            state="PUBLIC_REPORT_BUDGET_REFUSED",
            failure="PUBLIC_REPORT_BUDGET_REFUSED",
            packet=None,
            IO=[],
        )
    atomic(work / "public-report.json", value, MAX_PUBLIC)
    return value


def execute(mode, work, pins, buffers, legacy, bounded, *, factory=None):
    ci_guard(work)
    state = legacy.strict_json(regular(work / "state.json", MAX_STATE))
    need(
        state["type"] == TYPE
        and state["phase"] == PHASE
        and state["user"] == "1000:1000"
        and state["image_config"] == pins["image_config"]
        and state["assets_sha256"] == sha(regular(HERE / "assets.json", 16384)),
        "STATE_TYPE_PIN",
    )
    check_inputs(work, state)

    def save():
        io_history_released(state)
        atomic(work / "state.json", state)

    save()  # Missing/malformed or abandoned pending records remain uncertain.

    client = (factory or docker_class(legacy, bounded))(
        work,
        pins,
        state,
        time.monotonic() + (900 if mode == "run" else 0 if mode == "cleanup" else 300),
    )
    if mode in ("pull", "run"):
        code, active, stderr = client.command("ps", "--format", "{{.ID}}")
        need(code == 0 and not active.strip() and not stderr, "CI_DAEMON_NOT_EXCLUSIVE")
    if mode == "pull":
        need(state["pull"] == "not_attempted", "PULL_ONE_ATTEMPT")
        state["pull"] = "pending"
        save()
        try:
            storage = {}
            legacy.storage_observation(client, 4096, storage)
            legacy.memory_guard(2048)
            need(client.pull(pins) == 0, "PINNED_PULL_FAILED")
            client.image(pins)
            state["pull"] = "ready"
        except BaseException:
            state["pull"] = "unknown"
            state["failure"] = "PULL_FAILED_OR_UNKNOWN"
            raise
        finally:
            save()
        return state
    if mode == "run":
        need(state["pull"] == "ready" and state["started"] is False, "RUN_ONE_ATTEMPT")
        state["started"] = True
        save()
        try:
            storage = {}
            legacy.storage_observation(client, 4096, storage)
            legacy.memory_guard(2048)
            client.image(pins)
            cid = legacy.reserve_create(
                client, state, save, create_arguments(work, pins, buffers["entrypoint.py"])
            )
            row = client.inspect(cid)
            need(
                legacy.owns(row, state["create"]) and row["Running"] is False, "PRESTART_OWNERSHIP"
            )
            check_inputs(work, state)
            code, raw, stderr = client.command("start", "--attach", cid, timeout=900)
            need(not stderr and 0 < len(raw) <= pins["packet_bytes"], "PUBLIC_ATTACH_OUTPUT")
            entry = load_buffer(
                "p2_ci_entry_validator", buffers["entrypoint.py"], HERE / "entrypoint.py"
            )
            value = validate_packet(entry.parse(raw, pins["packet_bytes"]), pins, entry)
            if code == 42:
                validate_failure_packet(value, entry)
            encoded_packet = encode(value, pins["packet_bytes"])
            atomic(work / "packet-public.json", value, pins["packet_bytes"])
            state["packet"] = {
                "sha256": sha(encoded_packet),
                "bytes": len(encoded_packet),
                "ok": value["ok"],
            }
            need(code == 0 and value["ok"], "QUALIFICATION_FAILED")
        except BaseException as error:
            state["failure"] = state.get("failure") or (
                str(error) if isinstance(error, Refusal) else "QUALIFICATION_UNCONFIRMED"
            )
        finally:
            save()
    client.cleaning = True
    cleanup = legacy.reconcile(client, state, save)
    previous_cleanup = state.get("cleanup")
    if (
        cleanup.get("released") is True
        and (state.get("create") or {}).get("outcome") == "removed"
        and previous_cleanup
        and previous_cleanup.get("released") is True
    ):
        for field in ("exit_code", "OOMKilled"):
            if field not in cleanup and field in previous_cleanup:
                cleanup[field] = previous_cleanup[field]
    state["cleanup"] = cleanup
    try:
        check_inputs(work, state)
    except BaseException:
        state["failure"] = "INPUTS_CHANGED"
    save()
    result = report(work, state, cleanup, pins)
    save()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("verify", "prepare", "pull", "run", "cleanup"))
    parser.add_argument("--assets-sha256", required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--materials", type=Path)
    args = parser.parse_args()
    work = args.work.resolve()
    legacy, bounded, pins, buffers = assets(args.assets_sha256)
    if args.mode == "verify":
        ci_guard(work)
        need(args.repository is not None, "VERIFY_REPOSITORY")
        print(
            json.dumps(verify_selected(args.repository.resolve(strict=True), pins, buffers, legacy))
        )
        return
    if args.mode == "cleanup" and not (work / "state.json").exists():
        ci_guard(work)
        earlier_directory = work.exists()
        work.mkdir(mode=0o700, exist_ok=True)
        value = {
            "schema": "pamolive.p2-installed-ci-public-report/1",
            "phase": PHASE,
            "ok": False,
            "state": "REPORT_UNAVAILABLE_OR_UNKNOWN" if earlier_directory else "NOT_STARTED",
            "resources_released": None,
            "cleanup": {"status": "not_observed", "released": None},
            "authority": False,
            "build_verified": False,
            "attestation_verified": False,
        }
        atomic(work / "public-report.json", value, MAX_PUBLIC)
        raise SystemExit(1)
    if args.mode == "prepare":
        need(args.repository is not None and args.materials is not None, "PREPARE_INPUTS")
        result = prepare(
            work,
            args.repository.resolve(strict=True),
            args.materials.resolve(strict=True),
            pins,
            buffers,
            legacy,
        )
        print(json.dumps({"phase": PHASE, "state": "PREPARED_NOT_EXECUTED", "authority": False}))
        return
    result = execute(args.mode, work, pins, buffers, legacy, bounded)
    print(
        json.dumps({"phase": PHASE, "state": result.get("state", "PULL_READY"), "authority": False})
    )
    if args.mode in ("run", "cleanup") and not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
