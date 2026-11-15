"""Review-gated Linux installed verifier qualification; no acquisition command."""

import argparse
import base64
import csv
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import platform
import re
import stat
import sys
import sysconfig
import time
import zipfile
from email.parser import BytesParser
from io import BytesIO, StringIO
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
IO_HASH = "98233b610f2d53dfd698d0d91f61f3d3ebcb1693a847983f0472f89a885f414f"
MATERIALS_HASH = "9984894027d99aa19b51625f1f73ee106272635120d832d7d1fede94243b9d74"
SOURCE_MANIFEST = "3628a50534a0bb37c142ffcee201ca3aaa232d926d13db65b552033627d1c340"
PACKAGE = "pamolive_pam_trust_verifier"
DISTRIBUTION = "pamolive-pam-trust-verifier"
VERSION = "0.1.0a1"
BUILD_NAMES = {"packaging", "setuptools", "wheel"}
RUNTIME_NAMES = {
    "cbor2",
    "cffi",
    "cryptography",
    "pyasn1",
    "pyasn1-modules",
    "pycparser",
    "pyopenssl",
    "typing-extensions",
    "webauthn",
}
IO = None


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    require(
        type(name) is str
        and not path.is_absolute()
        and path.as_posix() == name
        and ".." not in path.parts
        and ":" not in name
        and "\\" not in name,
        "relative_path",
    )
    return path


def bootstrap_read(path, maximum=1024 * 1024):
    path = Path(path)
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and not getattr(before, "st_file_attributes", 0) & 1024
        and 0 <= before.st_size <= maximum
        and not path.is_symlink(),
        "file_type_size",
    )
    with path.open("rb") as stream:
        after = os.fstat(stream.fileno())
        require(
            (before.st_dev, before.st_ino, before.st_size)
            == (after.st_dev, after.st_ino, after.st_size)
            and stat.S_ISREG(after.st_mode)
            and after.st_nlink == 1,
            "opened_identity",
        )
        raw = stream.read(maximum + 1)
    require(len(raw) == before.st_size and len(raw) <= maximum, "bounded_read")
    return raw


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_JSON")
        result[key] = value
    return result


def document(path, expected=None, maximum=256 * 1024):
    raw = bootstrap_read(path, maximum)
    require(expected is None or sha(raw) == expected, "document_hash")
    return json.loads(raw, object_pairs_hook=unique), raw


def load_io():
    raw = bootstrap_read(ROOT / "bounded_io.py")
    require(sha(raw) == IO_HASH, "reviewed_IO_hash")

    class PinnedLoader(importlib.machinery.SourceFileLoader):
        def get_code(self, _fullname):
            return compile(raw, self.path, "exec")

    name = "installed_qualification_bounded_io"
    loader = PinnedLoader(name, str(ROOT / "bounded_io.py"))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def normalized(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def target():
    require(
        sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 12, 16),
        "CPython31216",
    )
    require(sys.platform == "linux" and platform.machine() == "x86_64", "linux_amd64")
    require(sysconfig.get_config_var("SOABI") == "cpython-312-x86_64-linux-gnu", "SOABI")
    require(
        not sysconfig.get_config_var("Py_DEBUG")
        and not sysconfig.get_config_var("Py_GIL_DISABLED"),
        "regular_ABI",
    )
    libc, version = platform.libc_ver()
    require(
        libc == "glibc"
        and re.fullmatch(r"2\.[0-9]{2}", version)
        and int(version.split(".")[1]) >= 34,
        "glibc234",
    )
    require(os.geteuid() != 0, "nonroot")


def lock_rows(raw):
    rows = {}
    for line in raw.decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([a-z0-9-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})", line)
        require(match is not None, "hash_lock_syntax")
        name, version, digest = match.groups()
        require(name not in rows, "hash_lock_duplicate")
        rows[name] = (version, digest)
    return rows


def check_locks(materials):
    names = {
        "requirements-bootstrap.lock": {"pip"},
        "requirements-build.lock": BUILD_NAMES,
        "requirements-runtime.lock": RUNTIME_NAMES,
    }
    for path, selected in names.items():
        actual = lock_rows(bootstrap_read(ROOT / path, 65536))
        expected = {
            name: (materials[name]["version"], materials[name]["sha256"]) for name in selected
        }
        require(actual == expected, "exact_material_hash_lock")


def zip_inventory(raw, *, name, version, pure=False, source_files=None):
    require(len(raw) <= 8 * 1024 * 1024, "wheel_input_budget")
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(
            0 < len(entries) <= 4096 and len({entry.filename for entry in entries}) == len(entries),
            "wheel_member_count",
        )
        total, files = 0, {}
        for entry in entries:
            safe_path(entry.filename.rstrip("/"))
            require(
                not entry.flag_bits & 1
                and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
                "wheel_member_type",
            )
            require(
                0 <= entry.file_size <= 24 * 1024 * 1024
                and total + entry.file_size <= 64 * 1024 * 1024,
                "wheel_expansion_budget",
            )
            total += entry.file_size
            if entry.is_dir():
                continue
            if entry.filename.endswith(".pth"):
                require(
                    name == "setuptools"
                    and entry.filename == "distutils-precedence.pth"
                    and not pure,
                    "wheel_PTH",
                )
            require(not entry.filename.endswith(".pyc"), "wheel_bytecode")
            if pure:
                require(
                    not entry.filename.endswith((".so", ".pyd", ".dll", ".exe", ".pth")),
                    "new_package_pure",
                )
            with archive.open(entry) as stream:
                data = stream.read(entry.file_size + 1)
            require(len(data) == entry.file_size, "wheel_entry_read")
            files[entry.filename] = data
        metadata_names = [
            path for path in files if path.count("/") == 1 and path.endswith(".dist-info/METADATA")
        ]
        require(len(metadata_names) == 1, "wheel_distribution_metadata")
        info = metadata_names[0].split("/", 1)[0]
        metadata = BytesParser().parsebytes(files[metadata_names[0]])
        require(
            normalized(metadata["Name"]) == name and metadata["Version"] == version,
            "wheel_name_version",
        )
        record_name = info + "/RECORD"
        record = list(csv.reader(StringIO(files[record_name].decode("utf-8"))))
        require(
            len(record) <= 4096 and all(len(row) == 3 for row in record),
            "wheel_RECORD_rows",
        )
        require(
            len({row[0] for row in record}) == len(record)
            and {row[0] for row in record} == set(files),
            "wheel_RECORD_closure",
        )
        for path, digest, length in record:
            if path == record_name:
                require(digest == length == "", "wheel_RECORD_self")
            else:
                expected = "sha256=" + base64.urlsafe_b64encode(
                    hashlib.sha256(files[path]).digest()
                ).decode().rstrip("=")
                require(
                    digest == expected and length == str(len(files[path])),
                    "wheel_RECORD_identity",
                )
        if pure:
            wheel_info = files[info + "/WHEEL"].decode("utf-8")
            require(
                "Root-Is-Purelib: true" in wheel_info and "Tag: py3-none-any" in wheel_info,
                "pure_wheel_tag",
            )
            require(
                sorted(metadata.get_all("Requires-Dist", []))
                == sorted(("cryptography==50.0.2", "webauthn==3.0.1", "cbor2==6.2.1")),
                "new_package_direct_dependencies",
            )
            wanted = {}
            for path, identity in source_files.items():
                if path.startswith("src/"):
                    wanted[path[4:]] = identity["sha256"]
                elif path in {"LICENSE", "LICENSE-DJANGO.txt", "NOTICE.txt"}:
                    wanted[info + "/licenses/" + path] = identity["sha256"]
            allowed = set(wanted) | {
                info + "/" + file for file in ("METADATA", "WHEEL", "RECORD", "top_level.txt")
            }
            require(set(files) == allowed, "new_wheel_closed_files_licenses")
            require(
                all(sha(files[path]) == expected for path, expected in wanted.items()),
                "new_wheel_source_license_bytes",
            )
        return {
            "name": name,
            "version": version,
            "entries": len(entries),
            "expanded_bytes": total,
            "RECORD_checked": True,
            "licenses_and_source_exact": bool(pure),
            "wheel_files_sha256": {
                path: sha(data) for path, data in files.items() if path != record_name
            }
            if pure
            else {},
        }


def source_payload(source):
    manifest, _ = document(source / "PAYLOAD-MANIFEST.json", SOURCE_MANIFEST)
    require(
        type(manifest) is dict
        and set(manifest) == {"schema", "source_origin_freeze_sha256", "files"}
        and manifest["schema"] == "pamolive.public-pam-verifier-integrated-payload/1"
        and manifest["source_origin_freeze_sha256"]
        == "476f4ac4ba06f773daade2840eebc7646e4469810875f447e5f7447df1ebac06",
        "integrated_payload_schema",
    )
    selected = manifest["files"]
    require(type(selected) is dict and len(selected) == 353, "integrated_payload_count")
    top = {
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "LICENSE-DJANGO.txt",
        "NOTICE.txt",
        "P0-CORRESPONDENCE.md",
        "ADR-PROPOSED.md",
        "FIXTURES-NOTICE.md",
    }
    for name, row in selected.items():
        safe_path(name)
        require(
            name.startswith(("src/", "tests/", "fixtures/")) or name in top,
            "integrated_payload_name",
        )
        require(
            type(row) is dict
            and set(row) == {"bytes", "sha256"}
            and type(row["bytes"]) is int
            and 0 <= row["bytes"] <= 2 * 1024 * 1024
            and type(row["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
            "integrated_payload_row",
        )
    require({n for n in selected if "/" not in n} == top, "integrated_payload_top")
    require(
        {n for n in selected if n.startswith("tests/")} == {"tests/test_verifier.py"},
        "integrated_test_module",
    )
    require(not source.is_symlink(), "source_alias")
    actual = set()
    for count, path in enumerate(source.rglob("*"), 1):
        require(count <= 1024, "source_tree_budget")
        info = path.lstat()
        require(
            not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 1024,
            "source_alias",
        )
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "source_type")
        if stat.S_ISREG(info.st_mode):
            actual.add(path.relative_to(source).as_posix())
    require(actual == set(selected) | {"PAYLOAD-MANIFEST.json"}, "source_selected_closure")
    pyfiles = {name for name in selected if name.startswith("src/")}
    require(
        pyfiles
        == {
            "src/" + PACKAGE + "/" + name
            for name in (
                "__init__.py",
                "_api.py",
                "_codec.py",
                "_context.py",
                "_crypto.py",
                "_v1_rules.py",
            )
        },
        "six_source_modules",
    )
    result, total = {}, 0
    for name, row in selected.items():
        safe_path(name)
        require(
            type(row["bytes"]) is int
            and 0 <= row["bytes"] <= 2 * 1024 * 1024
            and total + row["bytes"] <= 8 * 1024 * 1024,
            "source_payload_budget",
        )
        data = bootstrap_read(source / name, row["bytes"])
        require(sha(data) == row["sha256"], "source_payload_hash")
        result[name] = data
        total += len(data)
    return selected, result


def run(plan, source, materials_directory, work):
    require(
        not any(work.is_relative_to(path) for path in (source, materials_directory, ROOT)),
        "work_outside_frozen_inputs",
    )
    require(not work.exists(), "one_use_work")
    work.mkdir(mode=0o700, parents=False)
    report = {
        "schema": "pamolive.public-pam-verifier-installed-qualification/1",
        "state": "INCOMPLETE",
        "authority": False,
        "build_verified": False,
        "attestation_verified": False,
        "processes": [],
        "package_version": VERSION,
        "tests_expected": 30,
        "source_manifest_sha256": SOURCE_MANIFEST,
        "materials_plan_sha256": MATERIALS_HASH,
    }
    started = time.monotonic()
    error = None
    retained_materials, selected = {}, {}
    staged_complete = False
    try:
        public_plan, _ = document(ROOT / "materials-plan.json", MATERIALS_HASH)
        rows = public_plan["selected_materials"]
        require(set(rows) == RUNTIME_NAMES | BUILD_NAMES | {"pip"}, "thirteen_materials")
        check_locks(rows)
        selected, source_bytes = source_payload(source)
        report["source_payload"] = selected
        wheels = work / "public-wheels"
        wheels.mkdir()
        report["public_wheels"] = {}
        for name, row in rows.items():
            safe_path(row["filename"])
            require(
                row["kind"] == "wheel" and 0 < row["size"] <= 8 * 1024 * 1024,
                "material_type_size",
            )
            data = bootstrap_read(materials_directory / row["filename"], row["size"])
            require(sha(data) == row["sha256"], "material_hash")
            facts = zip_inventory(data, name=name, version=row["version"])
            write_new(wheels / row["filename"], data)
            retained_materials[row["filename"]] = row
            report["public_wheels"][name] = {
                "sha256": row["sha256"],
                "bytes": len(data),
                **facts,
            }
        for name in ("home", "tmp", "reports", "logs", "test-stage"):
            (work / name).mkdir(mode=0o700)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(work / "home"),
            "TMPDIR": str(work / "tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PIP_CONFIG_FILE": "/dev/null",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        def call(phase, command, cwd=work):
            remaining = 900 - (time.monotonic() - started)
            require(remaining > 0, "total_time_budget")
            with (
                (work / "logs" / (phase + ".stdout")).open("xb") as out,
                (work / "logs" / (phase + ".stderr")).open("xb") as err,
            ):
                result = IO.run_capped(
                    command,
                    env={
                        **env,
                        "PATH": str(Path(command[0]).parent) + ":/usr/bin:/bin",
                    },
                    cwd=cwd,
                    timeout=min(120, remaining),
                    stdout_cap=1024 * 1024,
                    stderr_cap=256 * 1024,
                    stdout_sink=out,
                    stderr_sink=err,
                )
            report["processes"].append({"phase": phase, **result.facts()})
            require(result.ok, "owned_process_failed")

        def pip(phase, python, *arguments):
            call(phase, [str(python), "-I", "-B", "-m", "pip", *arguments])

        def install(phase, python, lock, links):
            pip(
                phase,
                python,
                "install",
                "--no-index",
                "--no-deps",
                "--only-binary=:all:",
                "--require-hashes",
                "--no-compile",
                "--no-cache-dir",
                "--find-links",
                str(links),
                "-r",
                str(lock),
            )

        interpreters = {}
        for name in ("build", "verifier"):
            location = work / ("venv-" + name)
            call(
                "venv-" + name,
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-m",
                    "venv",
                    "--without-pip",
                    str(location),
                ],
            )
            python = location / "bin/python"
            call(
                "no-pip-" + name,
                [
                    str(python),
                    "-I",
                    "-B",
                    "-c",
                    "import importlib.util; assert importlib.util.find_spec('pip') is None",
                ],
            )
            bootstrap = (
                "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
                "sys.argv[0]='pip'; runpy.run_module('pip',run_name='__main__')"
            )
            args = [
                "install",
                "--ignore-installed",
                "--no-index",
                "--no-deps",
                "--only-binary=:all:",
                "--require-hashes",
                "--no-compile",
                "--no-cache-dir",
                "--find-links",
                str(wheels),
                "-r",
                str(ROOT / "requirements-bootstrap.lock"),
            ]
            call(
                "bootstrap-" + name,
                [
                    str(python),
                    "-I",
                    "-B",
                    "-c",
                    bootstrap,
                    str(wheels / rows["pip"]["filename"]),
                    *args,
                ],
            )
            interpreters[name] = python
        install(
            "install-build-tools",
            interpreters["build"],
            ROOT / "requirements-build.lock",
            wheels,
        )
        install(
            "install-runtime-nine",
            interpreters["verifier"],
            ROOT / "requirements-runtime.lock",
            wheels,
        )
        build_source = work / "build-source"
        for name, data in source_bytes.items():
            if name.startswith(("tests/", "fixtures/")):
                write_new(work / "test-stage" / name, data)
            else:
                write_new(build_source / name, data)
        require(not (work / "test-stage/src").exists(), "stage_without_src")
        staged_complete = True
        built_dir = work / "built"
        built_dir.mkdir()
        pip(
            "build-verifier-wheel",
            interpreters["build"],
            "wheel",
            "--no-index",
            "--no-build-isolation",
            "--no-deps",
            "--no-cache-dir",
            "--wheel-dir",
            str(built_dir),
            str(build_source),
        )
        built_path = built_dir / (PACKAGE + "-" + VERSION + "-py3-none-any.whl")
        require(set(built_dir.iterdir()) == {built_path}, "single_new_wheel")
        built_bytes = bootstrap_read(built_path, 2 * 1024 * 1024)
        built_facts = zip_inventory(
            built_bytes,
            name=DISTRIBUTION,
            version=VERSION,
            pure=True,
            source_files=selected,
        )
        report["built_wheel"] = {
            "filename": built_path.name,
            "sha256": sha(built_bytes),
            "bytes": len(built_bytes),
            **built_facts,
        }
        installed_files = work / "expected-installed-files.json"
        write_new(installed_files, encoded(built_facts["wheel_files_sha256"]))
        own_lock = work / "built-verifier.lock"
        write_new(
            own_lock,
            (DISTRIBUTION + "==" + VERSION + " --hash=sha256:" + sha(built_bytes) + "\n").encode(),
        )
        install("install-local-verifier", interpreters["verifier"], own_lock, built_dir)
        expected = {
            "build": {
                "pip": rows["pip"]["version"],
                **{name: rows[name]["version"] for name in BUILD_NAMES},
            },
            "verifier": {
                "pip": rows["pip"]["version"],
                DISTRIBUTION: VERSION,
                **{name: rows[name]["version"] for name in RUNTIME_NAMES},
            },
        }
        report["venvs"] = {}
        for name, python in interpreters.items():
            expected_path = work / ("expected-" + name + ".json")
            write_new(expected_path, encoded(expected[name]))
            probe_report = work / "reports" / ("probe-" + name + ".json")
            call(
                "probe-" + name,
                [
                    str(python),
                    "-I",
                    "-B",
                    str(ROOT / "installed_tests.py"),
                    "probe",
                    "--expected",
                    str(expected_path),
                    "--stage",
                    str(work / "test-stage"),
                    "--report",
                    str(probe_report),
                    *(["--installed-files", str(installed_files)] if name == "verifier" else []),
                ],
            )
            result, _ = document(probe_report)
            require(
                result["state"] == "INSTALLED_ONLY_PROBE_PASS" and not result["forbidden_attempts"],
                "probe_report",
            )
            report["venvs"][name] = result
            pip("pip-check-" + name, python, "check")
        tests_report = work / "reports/installed-tests.json"
        call(
            "run-installed-30",
            [
                str(interpreters["verifier"]),
                "-I",
                "-B",
                str(ROOT / "installed_tests.py"),
                "tests",
                "--expected",
                str(work / "expected-verifier.json"),
                "--stage",
                str(work / "test-stage"),
                "--report",
                str(tests_report),
                "--installed-files",
                str(installed_files),
            ],
            cwd=work / "test-stage",
        )
        result, _ = document(tests_report)
        require(
            result["state"] == "INSTALLED_VERIFIER_30_TESTS_PASS"
            and not result["forbidden_attempts"]
            and result["tests"] == {"run": 30, "failures": 0, "errors": 0, "skips": 0},
            "installed_test_report",
        )
        report.update(
            state="INSTALLED_VERIFIER_30_MATCHES_CANDIDATE_PUBLIC_FIXTURES",
            tests=result,
            source_test_fallback=False,
            new_P0_run=False,
            context_administration=False,
            full_P0_acceptance=False,
            proof_of_possession_or_MFA_or_counters=False,
        )
    except BaseException as caught:
        error = caught
        report.update(state="FAILED", exception_type=type(caught).__name__)
    finally:
        unchanged = True
        staged_unchanged = True if staged_complete else None
        for name, row in selected.items():
            try:
                unchanged &= sha(bootstrap_read(source / name, row["bytes"])) == row["sha256"]
            except (OSError, ValueError):
                unchanged = False
            if staged_complete:
                try:
                    staged_root = work / (
                        "test-stage" if name.startswith(("tests/", "fixtures/")) else "build-source"
                    )
                    staged_unchanged &= (
                        sha(bootstrap_read(staged_root / name, row["bytes"])) == row["sha256"]
                    )
                except (OSError, ValueError):
                    staged_unchanged = False
        for filename, row in retained_materials.items():
            try:
                unchanged &= (
                    sha(bootstrap_read(materials_directory / filename, row["size"]))
                    == row["sha256"]
                )
                unchanged &= (
                    sha(bootstrap_read(work / "public-wheels" / filename, row["size"]))
                    == row["sha256"]
                )
            except (OSError, ValueError):
                unchanged = False
        report.update(
            inputs_after_hashes_unchanged=bool(unchanged),
            staged_inputs_hashes_unchanged=staged_unchanged,
            elapsed_seconds=time.monotonic() - started,
            no_index_is_not_OS_network_isolation=True,
            hard_resource_quota_claimed=False,
        )
        if error is None and (not unchanged or staged_unchanged is not True):
            report.update(state="FAILED", exception_type="PostRunIdentityMismatch")
        write_new(work / "execution.json", encoded(report))
    if error is not None or not unchanged or staged_unchanged is not True:
        raise SystemExit(1)
    print(json.dumps({"state": report["state"], "methods": 30, "authority": False}))


def main():
    global IO
    parser = argparse.ArgumentParser()
    parser.add_argument("run", choices=("run",))
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--materials", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    plan, raw = document(ROOT / "adapter-plan.json", args.plan_sha256)
    require(plan["execution_authorized_by_plan"] is False, "plan_not_permission")
    for name, expected in plan["files_sha256"].items():
        safe_path(name)
        require(sha(bootstrap_read(ROOT / name)) == expected, "adapter_file_pin")
    IO = load_io()
    target()
    run(
        plan,
        args.source.resolve(strict=True),
        args.materials.resolve(strict=True),
        args.work.resolve(),
    )


if __name__ == "__main__":
    main()
