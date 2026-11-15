"""Source-only offline build/install workload; never invoked by this delivery."""

import os
import sys
import time
from pathlib import Path

import adapter_v2
import records
import schema
import wheel_gate
from support import ROOT, load, need, read_regular, sha

PAYLOAD_SHA = "e958ce089e79dc8ed87943d9c74fe559bb7e930c4e7898f778a219a6a10f12fe"
WORK = Path("/work/vault-installed")
BOOTSTRAP = (
    "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
    "sys.argv[0]='pip'; runpy.run_module('pip',run_name='__main__')"
)


class Failed(RuntimeError):
    pass


def target(work):
    need(work == WORK and not work.exists())
    need(sys.platform == "linux" and sys.implementation.name == "cpython")
    need(sys.version_info[:3] == (3, 12, 16) and sys.base_prefix == "/usr/local")
    need(os.getuid() == os.getgid() == 1000)


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def source_payloads(source_root=Path("/source")):
    need(source_root.is_absolute() and source_root == source_root.resolve(strict=True))
    raw = read_regular(ROOT / "payloads.json", 65536)
    need(sha(raw) == PAYLOAD_SHA)
    value = schema.parse(raw, 65536)
    need(set(value["groups"]) == {"runtime", "verifier", "contracts"})
    buffers = {}
    for group, rows in {**value["groups"], "runtime-tests": value["runtime_tests"]}.items():
        directory = source_root / group
        actual = set()
        dirs = {
            parent.as_posix()
            for name in rows
            for parent in Path(name).parents
            if str(parent) != "."
        }
        for path in directory.rglob("*"):
            need(
                not path.is_symlink() and not getattr(path.lstat(), "st_file_attributes", 0) & 1024
            )
            name = path.relative_to(directory).as_posix()
            if path.is_file():
                need(name in rows)
                data = read_regular(path, 1024**2)
                need({"bytes": len(data), "sha256": sha(data)} == rows[name])
                actual.add(name)
                buffers[(group, name)] = data
            else:
                need(name in dirs)
        need(actual == set(rows))
    return value, buffers


def description(payload):
    module_files = {}
    for group, (_, module) in wheel_gate.PACKAGES.items():
        prefix = module + "/" if group == "runtime" else "src/" + module + "/"
        module_files[module] = {
            name[len(prefix) :]: row["sha256"]
            for name, row in payload["groups"][group].items()
            if name.startswith(prefix)
        }
    return adapter_v2.descriptor(
        {
            "schema": "pamolive.vault-runtime-installed-input/2",
            "distributions": adapter_v2.distributions(),
            "module_files": module_files,
            "stage_files": {name: row["sha256"] for name, row in payload["runtime_tests"].items()},
            "source_sha256": PAYLOAD_SHA,
            "sql_sha256": adapter_v2.SQL_SHA,
        }
    )


def build_environment(value, expected):
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "operation",
            "state",
            "authority",
            "venv",
            "forbidden_attempts",
            "intentional_guard_probes",
            "elapsed_seconds",
            "installed_wheel_only",
            "OS_network_sandbox_claimed",
            "full_P0_acceptance",
            "build_attestation",
        }
    )
    need(
        value["schema"] == "pamolive.public-pam-verifier-installed-child/1"
        and value["operation"] == "probe"
    )
    need(value["state"] == "INSTALLED_ONLY_PROBE_PASS" and value["authority"] is False)
    need(value["installed_wheel_only"] is True and value["OS_network_sandbox_claimed"] is False)
    need(value["full_P0_acceptance"] is False and value["build_attestation"] is False)
    need(value["forbidden_attempts"] == {})
    probes = dict.fromkeys(
        (
            "socket.constructor",
            "DNS",
            "sqlite3.connect",
            "subprocess.Popen",
            "import.django",
            "file.read_outside_roots",
        ),
        1,
    )
    need(
        value["intentional_guard_probes"] == probes
        and all(type(number) is int for number in value["intentional_guard_probes"].values())
    )
    need(
        type(value["venv"]) is dict
        and value["venv"]
        == {
            "distributions": expected,
            "origins_within_venv": {"pip": "lib/python3.12/site-packages/pip/__init__.py"},
            "global_site_fallback": False,
            "application_or_SDK_importable": False,
        }
    )
    need(type(value["elapsed_seconds"]) in (int, float) and 0 <= value["elapsed_seconds"] <= 900)
    return expected


def run(
    material_directory, work=WORK, *, sources=Path("/source"), invoke=None, clock=time.monotonic
):
    deadline = clock() + 900
    target(work)
    payload, buffers = source_payloads(sources)
    plan = adapter_v2.materials()
    for name, key in (
        ("requirements-bootstrap.lock", "bootstrap_lock"),
        ("requirements-build.lock", "build_lock"),
        ("requirements-runtime-linux.lock", "runtime_lock"),
    ):
        raw_lock = read_regular(ROOT / name, 65536)
        need({"bytes": len(raw_lock), "sha256": sha(raw_lock)} == plan[key])
    material_rows = plan["selected_materials"]
    need(
        {path.name for path in material_directory.iterdir()}
        == {row["filename"] for row in material_rows.values()} | {"acquisition.json"}
    )
    gate, qualifier = load("python_materials.py"), load("qualify_installed.py")
    for name, row in material_rows.items():
        raw = gate.verify_file(material_directory / row["filename"], row)
        need(
            qualifier.zip_inventory(raw, name=name, version=row["version"])["RECORD_checked"]
            is True
        )
    work.mkdir(mode=0o700)
    report = {
        "schema": "pamolive.vault-installed-workload-execution/2",
        "state": "FAILED",
        "source_sha256": PAYLOAD_SHA,
        "materials_sha256": adapter_v2.MATERIALS,
        "processes": [],
        "build_environment": None,
        "built_wheels": [],
        "records": [],
        "pip_checks": {"build": False, "runtime": False},
        "child": None,
        "input_sha256": sha(schema.encode(description(payload))),
        "inputs_unchanged": False,
        "failure": None,
        "secondary_failure": None,
        "authority": False,
        "attestation_verified": False,
    }
    bounded = load("bounded_io.py")
    invoke = invoke if invoke is not None else bounded.run_capped
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp/p2-installed-home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    phase = "prepare"

    def call(name, command, *, failed_child=False):
        nonlocal phase
        phase = name
        need(len(report["processes"]) < 24)
        remaining = deadline - clock()
        need(remaining > 0)
        result = invoke(
            command,
            env=env,
            cwd=str(work),
            timeout=min(300, remaining),
            stdout_cap=8192,
            stderr_cap=8192,
        )
        report["processes"].append({"phase": name, **result.facts()})
        need(result.spawn_attempted and result.owned_child_reaped and result.drains_complete)
        need(
            not result.killed_owned_child
            and result.exception_type is None
            and result.cleanup_exception_type is None
        )
        if not (result.reason is None and result.returncode == 0):
            if failed_child and result.reason == "nonzero_exit" and result.returncode == 1:
                return result
            raise Failed(name)
        return result

    def prelaunch(python):
        if python == work / "runtime/bin/python":
            adapter_v2.runtime_prelaunch(work / "runtime/lib/python3.12/site-packages")

    def python_call(name, python, arguments, **options):
        prelaunch(python)
        return call(name, [str(python), "-I", "-B", *map(str, arguments)], **options)

    def pip(name, python, *arguments):
        return python_call(
            name, python, ["-m", "pip", "--isolated", "--disable-pip-version-check", *arguments]
        )

    def install(name, python, lock, links):
        return pip(
            name,
            python,
            "install",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--no-compile",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--find-links",
            str(links),
            "-r",
            str(lock),
        )

    try:
        for (group, name), raw in buffers.items():
            if group != "runtime-tests":
                write(work / "build-source" / group / name, raw)
        skeleton = work / "source-skeleton"
        for name, raw in (
            (name, raw) for (group, name), raw in buffers.items() if group == "runtime"
        ):
            write(skeleton / "components/vault/runtime" / name, raw)
        write(skeleton / "LICENSE", buffers[("runtime", "LICENSE")])
        interpreters = {}
        for name in ("build", "runtime"):
            call(
                "venv-" + name,
                [sys.executable, "-I", "-B", "-m", "venv", "--without-pip", str(work / name)],
            )
            python = work / name / "bin/python"
            interpreters[name] = python
            python_call(
                "no-pip-" + name,
                python,
                ["-c", "import importlib.util; assert importlib.util.find_spec('pip') is None"],
            )
            python_call(
                "bootstrap-" + name,
                python,
                [
                    "-c",
                    BOOTSTRAP,
                    str(material_directory / material_rows["pip"]["filename"]),
                    "--isolated",
                    "--disable-pip-version-check",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--require-hashes",
                    "--no-compile",
                    "--no-cache-dir",
                    "--only-binary=:all:",
                    "--find-links",
                    str(material_directory),
                    "-r",
                    str(ROOT / "requirements-bootstrap.lock"),
                ],
            )
        install(
            "install-build",
            interpreters["build"],
            ROOT / "requirements-build.lock",
            material_directory,
        )
        pip("pipcheck-build", interpreters["build"], "check")
        report["pip_checks"]["build"] = True
        build_expected = {
            name: material_rows[name]["version"] for name in plan["build_and_bootstrap_names"]
        }
        write(work / "build-expected.json", schema.encode(build_expected))
        (work / "empty-stage").mkdir()
        python_call(
            "probe-build",
            interpreters["build"],
            [
                ROOT / "helpers/installed_tests.py",
                "probe",
                "--expected",
                work / "build-expected.json",
                "--stage",
                work / "empty-stage",
                "--report",
                work / "build-probe.json",
            ],
        )
        build_probe = schema.parse(read_regular(work / "build-probe.json", 65536), 65536)
        report["build_environment"] = build_environment(build_probe, build_expected)
        built = work / "built"
        locks, inventories, wheels = [], {}, {}
        for kind in ("verifier", "contracts", "runtime"):
            destination = built / kind
            destination.mkdir(parents=True)
            pip(
                "wheel-" + kind,
                interpreters["build"],
                "wheel",
                "--no-index",
                "--no-build-isolation",
                "--no-deps",
                "--no-cache-dir",
                "--wheel-dir",
                str(destination),
                str(work / "build-source" / kind),
            )
            paths = list(destination.iterdir())
            distribution, _ = wheel_gate.PACKAGES[kind]
            need(
                len(paths) == 1
                and paths[0].name == distribution.replace("-", "_") + "-0.1.0a1-py3-none-any.whl"
            )
            inventory = wheel_gate.validate(
                read_regular(paths[0], 2 * 1024**2), sources / kind, kind, repository=skeleton
            )
            inventories[kind], wheels[kind] = inventory, paths[0]
            report["built_wheels"].append(
                {
                    key: inventory[key]
                    for key in (
                        "name",
                        "version",
                        "wheel_sha256",
                        "wheel_bytes",
                        "wheel_RECORD_checked",
                        "source_notice_metadata_exact",
                    )
                }
            )
            locks.append(
                inventory["name"]
                + " @ "
                + records.canonical_url(paths[0])
                + " --hash=sha256:"
                + inventory["wheel_sha256"]
            )
        internal_lock = work / "internal.lock"
        write(internal_lock, ("\n".join(locks) + "\n").encode())
        install(
            "install-public",
            interpreters["runtime"],
            ROOT / "requirements-runtime-linux.lock",
            material_directory,
        )
        install("install-internal", interpreters["runtime"], internal_lock, built)
        adapter_v2.runtime_prelaunch(work / "runtime/lib/python3.12/site-packages")
        pip("pipcheck-runtime", interpreters["runtime"], "check")
        report["pip_checks"]["runtime"] = True
        for kind in ("verifier", "contracts", "runtime"):
            report["records"].append(
                records.check(work / "runtime", inventories[kind], wheels[kind])
            )
        stage = work / "stage/components/vault/runtime"
        for name in payload["runtime_tests"]:
            write(stage / name, buffers[("runtime-tests", name)])
        raw_input = schema.encode(description(payload))
        write(work / "input.json", raw_input)
        result = python_call(
            "child52",
            interpreters["runtime"],
            [
                ROOT / "installed_runner.py",
                "--descriptor",
                work / "input.json",
                "--descriptor-sha256",
                sha(raw_input),
                "--stage",
                stage,
                "--report",
                work / "runtime-child-report.json",
            ],
            failed_child=True,
        )
        child_raw = read_regular(work / "runtime-child-report.json", schema.MAX_CHILD)
        child = schema.child(schema.parse(child_raw), description(payload)["distributions"])
        need(child_raw == schema.encode(child) and child["input_sha256"] == sha(raw_input))
        report["child"] = child
        need(result.returncode == 0 and child["state"] == "INSTALLED_RUNTIME_52_PASS")
        phase = "post-check"
        for kind in ("verifier", "contracts", "runtime"):
            need(sha(read_regular(wheels[kind], 2 * 1024**2)) == inventories[kind]["wheel_sha256"])
        after_records = [
            records.check(work / "runtime", inventories[kind], wheels[kind])
            for kind in ("verifier", "contracts", "runtime")
        ]
        need(after_records == report["records"])
        report["state"] = "INSTALLED_VAULT_WORKLOAD_PASS"
    except BaseException as error:
        report["failure"] = {
            "phase": phase,
            "code": "OWNED_PROCESS_FAILED"
            if isinstance(error, Failed)
            else "DATA_OR_ENVIRONMENT_REFUSED",
            "exception_type": type(error).__name__
            if type(error) in (Failed, ValueError, AssertionError)
            else "Other",
        }
    finally:
        try:
            _, after = source_payloads(sources)
            need(after == buffers)
            for row in material_rows.values():
                gate.verify_file(material_directory / row["filename"], row)
            report["inputs_unchanged"] = True
        except BaseException:
            report["secondary_failure"] = "INPUTS_CHANGED_OR_UNKNOWN"
            report["state"] = "FAILED"
        try:
            write(work / "execution.json", schema.encode(report))
        except BaseException:
            # The entrypoint still owns this in-memory observation and can
            # export it. Never replace sixteen real process facts by a fake
            # preflight/empty history merely because persistence failed.
            report["secondary_failure"] = "REPORT_PERSISTENCE_FAILED"
            report["state"] = "FAILED"
    return report
