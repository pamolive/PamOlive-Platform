"""Installed-only probe/tests; guards precede new-package imports, never adds src."""

import argparse
import builtins
import hashlib
import importlib.abc
import importlib.metadata
import importlib.util
import json
import os
import re
import site
import socket
import sqlite3
import stat
import subprocess
import sys
import sysconfig
import time
import unittest
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


class ForbiddenIO(RuntimeError):
    pass


FILESYSTEM_MUTATIONS = frozenset(
    {
        "os.remove",
        "os.rmdir",
        "os.rename",
        "os.mkdir",
        "os.link",
        "os.symlink",
        "os.chmod",
        "os.chown",
        "os.utime",
        "os.truncate",
        "os.chdir",
        "os.chflags",
        "os.setxattr",
        "os.removexattr",
    }
)


def open_mutates(mode, flags, constants=os):
    if type(flags) is not int or flags < 0 or mode is not None and type(mode) is not str:
        raise ValueError("open_arguments")
    temporary = getattr(constants, "O_TMPFILE", 0)
    ordinary = constants.O_CREAT | constants.O_TRUNC | constants.O_APPEND | constants.O_EXCL
    return (
        bool(mode and any(flag in mode for flag in "wax+"))
        or flags & constants.O_ACCMODE != constants.O_RDONLY
        or bool(flags & ordinary)
        # O_TMPFILE is composite on Linux: O_DIRECTORY alone is not a write.
        or bool(temporary and flags & temporary == temporary)
    )


def exclusive_report_open(mode, flags, constants=os):
    required = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
    optional = 0
    for name in ("O_CLOEXEC", "O_BINARY", "O_NOINHERIT"):
        optional |= getattr(constants, name, 0)
    return (
        mode == "x"
        and type(flags) is int
        and flags >= 0
        and flags & required == required
        and flags & constants.O_ACCMODE == constants.O_WRONLY
        and flags & ~(required | optional) == 0
    )


class Guards:
    def __init__(self):
        self.probing = False
        self.probes = Counter()
        self.attempts = Counter()

    def refuse(self, name):
        (self.probes if self.probing else self.attempts)[name] += 1
        raise ForbiddenIO(name)

    def blocked(self, name):
        def invoke(*_args, **_kwargs):
            self.refuse(name)

        return invoke

    def require_clean(self):
        if self.attempts:
            raise ForbiddenIO("forbidden_attempt_count_nonzero")


def require(value, code):
    if not value:
        raise ValueError(code)


def bounded_read(path, maximum):
    path = Path(path)
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & 1024,
        "file_type",
    )
    require(0 <= info.st_size <= maximum, "file_size")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (info.st_dev, info.st_ino, info.st_size)
            and stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1,
            "opened_file",
        )
        raw = stream.read(maximum + 1)
    require(len(raw) == info.st_size and len(raw) <= maximum, "file_read")
    return raw


def bounded_json(path):
    raw = bounded_read(path, 65536)
    return json.loads(raw)


def distribution_probe(expected, module):
    prefix = Path(sys.prefix).resolve()
    require(sys.prefix != sys.base_prefix and not site.ENABLE_USER_SITE, "venv_prefix")
    config = prefix / "pyvenv.cfg"
    require(
        "include-system-site-packages = false" in bounded_read(config, 4096).decode().lower(),
        "system_site",
    )

    def normal(value):
        return re.sub(r"[-_.]+", "-", value).lower()

    items = list(importlib.metadata.distributions())
    actual = {normal(item.metadata["Name"]): item.version for item in items}
    require(len(items) == len(actual) and actual == expected, "minimal_distributions")
    for item in items:
        require(
            Path(item.locate_file("")).resolve().is_relative_to(prefix),
            "distribution_origin",
        )
    for name in (
        "django",
        "platform_core",
        "platform_modules",
        "config",
        "boto3",
        "botocore",
        "requests",
        "psycopg",
        "ldap",
        "sqlalchemy",
        "pamolive_vault_contracts",
        "pamolive_vault_envelope",
    ):
        require(importlib.util.find_spec(name) is None, "application_or_SDK_fallback")
    if module:
        for name in ("setuptools", "wheel", "packaging"):
            require(importlib.util.find_spec(name) is None, "buildtools_in_verifier")
    else:
        for name in (
            "pamolive_pam_trust_verifier",
            "cryptography",
            "webauthn",
            "cbor2",
        ):
            require(importlib.util.find_spec(name) is None, "runtime_in_build")
    origins = {}
    for name in ("pip", module):
        if name:
            spec = importlib.util.find_spec(name)
            require(
                spec and spec.origin and Path(spec.origin).resolve().is_relative_to(prefix),
                "module_origin",
            )
            origins[name] = str(Path(spec.origin).resolve().relative_to(prefix))
    return {
        "distributions": actual,
        "origins_within_venv": origins,
        "global_site_fallback": False,
        "application_or_SDK_importable": False,
    }


def installed_files_probe(expected):
    prefix = Path(sys.prefix).resolve()
    distribution = importlib.metadata.distribution("pamolive-pam-trust-verifier")
    base = Path(distribution.locate_file("")).resolve()
    require(base.is_relative_to(prefix), "installed_distribution_root")
    for name, digest in expected.items():
        path = (base / name).resolve()
        require(
            path.is_relative_to(base) and path.is_file() and not path.is_symlink(),
            "installed_file_path",
        )
        raw = bounded_read(path, 1024 * 1024)
        require(hashlib.sha256(raw).hexdigest() == digest, "installed_file_hash")
    directory = base / "pamolive_pam_trust_verifier"
    actual = {path.relative_to(base).as_posix() for path in directory.rglob("*") if path.is_file()}
    require(
        actual == {name for name in expected if name.startswith("pamolive_pam_trust_verifier/")},
        "installed_six_modules_closed",
    )
    require(not list(base.glob("*.pth")), "verifier_site_PTH")
    return {
        "wheel_files_sha256_matched": len(expected),
        "package_files_closed": len(actual),
        "site_PTH": 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("probe", "tests"))
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--installed-files", type=Path)
    args = parser.parse_args()
    expected = bounded_json(args.expected)
    expected_files = bounded_json(args.installed_files) if args.installed_files else None
    stage = args.stage.resolve(strict=True)
    report_path = args.report.resolve()
    report_admission = {"enabled": False, "used": False}
    guard = Guards()
    report = {
        "schema": "pamolive.public-pam-verifier-installed-child/1",
        "operation": args.operation,
        "state": "INCOMPLETE",
        "authority": False,
    }
    failure = None
    started = time.perf_counter()
    old_import = builtins.__import__
    forbidden_imports = {
        "django",
        "platform_core",
        "platform_modules",
        "config",
        "boto3",
        "botocore",
        "requests",
        "psycopg",
        "ldap",
        "sqlalchemy",
        "pamolive_vault_contracts",
        "pamolive_vault_envelope",
    }
    prefix = Path(sys.prefix).resolve()
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    base_site = (stdlib / "site-packages").resolve()
    read_roots = (prefix, stdlib, stage, Path(__file__).resolve().parent)

    def guarded_import(name, *positional, **keywords):
        if name.split(".", 1)[0].lower() in forbidden_imports:
            guard.refuse("import." + name.split(".", 1)[0].lower())
        return old_import(name, *positional, **keywords)

    def audit(event, values):
        if event in FILESYSTEM_MUTATIONS:
            guard.refuse("file.mutation." + event)
        if (
            event.startswith("socket.")
            or event.startswith("sqlite3.connect")
            or event
            in {
                "subprocess.Popen",
                "os.system",
                "os.posix_spawn",
                "os.exec",
                "os.spawn",
            }
        ):
            guard.refuse(event)
        if event in {"open", "os.listdir", "os.scandir"}:
            path = values[0]
            if type(path) is int:
                guard.refuse("file.descriptor_open")
            try:
                resolved = Path(path).resolve()
            except (OSError, TypeError, ValueError):
                guard.refuse("file.unresolved_path")
            try:
                writing = event == "open" and open_mutates(values[1], values[2])
            except (IndexError, TypeError, ValueError):
                guard.refuse("file.open_arguments")
            if writing:
                if not (
                    resolved == report_path
                    and report_admission["enabled"]
                    and not report_admission["used"]
                    and exclusive_report_open(values[1], values[2])
                ):
                    guard.refuse("file.write")
                report_admission["used"] = True
            elif resolved.is_relative_to(base_site) and not resolved.is_relative_to(prefix):
                guard.refuse("file.global_site")
            elif not any(resolved.is_relative_to(root) for root in read_roots):
                guard.refuse("file.read_outside_roots")

    original_socket = socket.socket

    class NoSocket(original_socket):
        def __init__(self, *_args, **_kwargs):
            guard.refuse("socket.constructor")

    try:
        with ExitStack() as patches:
            patches.enter_context(patch.object(builtins, "__import__", guarded_import))
            patches.enter_context(patch.object(socket, "socket", NoSocket))
            patches.enter_context(patch.object(socket, "getaddrinfo", guard.blocked("DNS")))
            patches.enter_context(
                patch.object(socket, "create_connection", guard.blocked("socket.connect"))
            )
            patches.enter_context(
                patch.object(sqlite3, "connect", guard.blocked("sqlite3.connect"))
            )
            patches.enter_context(
                patch.object(subprocess, "Popen", guard.blocked("subprocess.Popen"))
            )
            sys.addaudithook(audit)
            guard.probing = True
            for callback in (
                lambda: socket.socket(),
                lambda: socket.getaddrinfo("fixture.invalid", 1),
                lambda: sqlite3.connect(":memory:"),
                lambda: subprocess.Popen(["never"]),
                lambda: __import__("django"),
                lambda: open("/must-never-read-fixture-context", "rb"),
            ):
                try:
                    callback()
                except ForbiddenIO:
                    pass
                else:
                    raise AssertionError("guard_probe_failed")
            guard.probing = False
            require(sum(guard.probes.values()) == 6, "guard_probe_count")
            require(not (stage / "src").exists(), "source_fallback_stage")
            module = (
                "pamolive_pam_trust_verifier"
                if args.operation == "tests" or "pamolive-pam-trust-verifier" in expected
                else ""
            )
            report["venv"] = distribution_probe(expected, module)
            if module:
                require(expected_files is not None, "installed_file_proof_required")
                report["installed_files"] = installed_files_probe(expected_files)
            if args.operation == "tests":

                class BlockedFinder(importlib.abc.MetaPathFinder):
                    def find_spec(self, fullname, path=None, target=None):
                        if fullname.split(".", 1)[0].lower() in forbidden_imports:
                            guard.refuse("import." + fullname.split(".", 1)[0].lower())
                        return None

                finder = BlockedFinder()
                sys.meta_path.insert(0, finder)
                patches.callback(sys.meta_path.remove, finder)
                # Guards and distribution/origin checks above precede package import.
                package = __import__(module)
                require(
                    Path(package.__file__).resolve().is_relative_to(prefix),
                    "installed_package_origin",
                )
                require(
                    (stage / "fixtures").is_dir() and (stage / "tests").is_dir(),
                    "tests_and_fixtures_siblings",
                )
                suite = unittest.defaultTestLoader.discover(str(stage / "tests"))
                result = unittest.TextTestRunner(verbosity=2).run(suite)
                report["tests"] = {
                    "run": result.testsRun,
                    "failures": len(result.failures),
                    "errors": len(result.errors),
                    "skips": len(result.skipped),
                }
                require(
                    result.testsRun == 30 and not result.skipped and result.wasSuccessful(),
                    "installed_tests_failed",
                )
                report["case_comparisons"] = sys.modules["test_verifier"].OBSERVATIONS
                require(
                    len(report["case_comparisons"]) == 20
                    and all(row["matches"] for row in report["case_comparisons"]),
                    "case_comparison_count",
                )
            guard.require_clean()
            report["state"] = (
                "INSTALLED_ONLY_PROBE_PASS"
                if args.operation == "probe"
                else "INSTALLED_VERIFIER_30_TESTS_PASS"
            )
    except BaseException as caught:
        failure = caught
        report.update(state="FAILED", exception_type=type(caught).__name__)
    finally:
        report.update(
            forbidden_attempts=dict(guard.attempts),
            intentional_guard_probes=dict(guard.probes),
            elapsed_seconds=time.perf_counter() - started,
            installed_wheel_only=True,
            OS_network_sandbox_claimed=False,
            full_P0_acceptance=False,
            build_attestation=False,
        )
        report_admission["enabled"] = True
        try:
            with report_path.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
        finally:
            report_admission["enabled"] = False
    if failure is not None or guard.attempts:
        raise SystemExit(1)
    print(json.dumps({"state": report["state"], "authority": False}))


if __name__ == "__main__":
    main()
