"""Exact Google package bootstrap for one disposable CI; never admit the old Chrome."""

import argparse
import email.utils
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tarfile
import time
from datetime import timedelta
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TARGET = Path("/opt/google/chrome/chrome")
PIN_PATH = "qualification/p1g_headless/chrome-bootstrap-pins.json"
SOURCE_PATHS = {
    "qualification/p1g_headless/chrome_bootstrap.py",
    "qualification/p1g_headless/chrome_gpg.py",
    "qualification/p1g_headless/lab_support.py",
    "deploy/expat-remediation/bounded_io.py",
}
TEST_PATHS = {
    "qualification/p1g_headless/test_chrome_bootstrap.py",
    "qualification/p1g_headless/run_chrome_pure.py",
}
MATERIALS = {"google-key.asc", "Release", "Release.gpg", "Packages"}
BASE_URL = "https://dl.google.com/linux/chrome/deb/"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
DIAGNOSTICS = {
    "release_identity",
    "release_UTC",
    "release_freshness",
    "release_SHA256_shape",
    "release_Packages_binding",
    "package_exact_stanza",
    "package_path_budget",
    "package_control",
    "dependencies_not_already_satisfied",
    "payload_budget",
    "payload_path",
    "payload_target_type_owner_mode",
    "payload_target_size",
    "payload_target_ELF",
    "payload_target_missing",
    "package_bytes",
    "package_changed",
    "command_UNKNOWN",
    "tool_changed",
    "sudo_role",
    "sudo_changed",
    "root_receipt",
    "installed_payload_mismatch",
    "installed_package_identity",
    "bootstrap_deadline",
    "status_framing",
    "status_bad",
    "signature_ambiguity",
    "signature_fields",
    "signature_authority",
    "signature_future",
    "signature_expired",
    "signature_hash",
    "key_bundle_ambiguity",
    "key_unusable",
    "key_primary",
    "key_fields",
    "key_fingerprint",
    "key_duplicate",
    "signer_not_in_purpose_certificate",
    "key_future",
    "key_expired",
    "signature_before_key",
    "signature_after_key_expiry",
    "signing_capability_missing",
    "tool_alias_refused",
    "tool_type_owner_mode",
    "tool_parent_writable_or_alias",
    "tool_fd_identity",
    "tool_byte_budget",
    "tool_changed_or_not_ELF",
}


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(rows):
    value = {}
    for key, item in rows:
        need(key not in value, "duplicate_JSON")
        value[key] = item
    return value


def read(path, cap):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, "input_regular_budget")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(cap + 1)
        after = path.lstat()
    need(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        and len(raw) == before.st_size
        and before.st_ctime_ns == after.st_ctime_ns,
        "input_changed",
    )
    return raw


def fields(raw):
    result, previous = {}, None
    for line in raw.decode("utf8", "strict").splitlines():
        if line.startswith((" ", "\t")):
            need(previous is not None, "field_continuation")
            result[previous] += " " + line.strip()
            continue
        key, separator, value = line.partition(":")
        need(
            separator and key not in result and re.fullmatch(r"[A-Za-z0-9-]+", key),
            "field_duplicate_shape",
        )
        result[key], previous = value.strip(), key
    return result


def release_check(raw, packages, now):
    row = fields(raw)
    need(
        row.get("Origin") == "Google LLC" and row.get("Suite") == row.get("Codename") == "stable",
        "release_identity",
    )
    date = email.utils.parsedate_to_datetime(row["Date"])
    need(date.tzinfo is not None and date.utcoffset() == timedelta(0), "release_UTC")
    timestamp = int(date.timestamp())
    need(now - 7 * 86400 <= timestamp <= now + 300, "release_freshness")
    # fields unfolds continuations; Release SHA256 entries have fixed three-word tuples.
    tokens = row["SHA256"].split()
    need(len(tokens) % 3 == 0, "release_SHA256_shape")
    entries = [tokens[index : index + 3] for index in range(0, len(tokens), 3)]
    selected = [item for item in entries if item[2] == "main/binary-amd64/Packages"]
    need(
        selected == [[sha(packages), str(len(packages)), "main/binary-amd64/Packages"]],
        "release_Packages_binding",
    )
    return timestamp


def package_check(raw, expected):
    matches = [fields(part) for part in raw.split(b"\n\n") if part.strip()]
    matches = [
        row
        for row in matches
        if row.get("Package") == "google-chrome-stable" and row.get("Architecture") == "amd64"
    ]
    need(
        len(matches) == 1 and all(matches[0].get(key) == value for key, value in expected.items()),
        "package_exact_stanza",
    )
    version = expected["Version"]
    need(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+", version)
        and expected["Filename"]
        == "pool/main/g/google-chrome-stable/" + "google-chrome-stable_" + version + "_amd64.deb"
        and expected["Size"].isdigit()
        and 0 < int(expected["Size"]) <= 256 * 1024**2
        and re.fullmatch(r"[a-f0-9]{64}", expected["SHA256"]),
        "package_path_budget",
    )


def control_check(raw, expected):
    row = fields(raw)
    need(
        set(row) == {"Package", "Version", "Architecture", "Depends"}
        and all(" ".join(row[key].split()) == " ".join(expected[key].split()) for key in row),
        "package_control",
    )


def apt_plan(raw):
    lines = raw.decode("utf8", "strict").splitlines()
    actions = [line.split() for line in lines if line.startswith(("Inst ", "Conf ", "Remv "))]
    need(
        len(actions) == 2
        and [row[0] for row in actions] == ["Inst", "Conf"]
        and all(len(row) >= 2 and row[1] == "google-chrome-stable" for row in actions),
        "dependencies_not_already_satisfied",
    )


def payload_target(stream):
    stream.seek(0)
    target, count, total = None, 0, 0
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for member in archive:
            count, total = count + 1, total + member.size
            need(
                count <= 20000
                and 0 <= member.size <= 512 * 1024**2
                and total <= 1024**3
                and len(member.name) <= 1024,
                "payload_budget",
            )
            name = member.name.removeprefix("./")
            need(
                not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
                "payload_path",
            )
            if name != TARGET.as_posix().removeprefix("/"):
                continue
            need(
                target is None
                and member.isfile()
                and not member.sparse
                and member.uid == member.gid == 0
                and member.mode == 0o755
                and 0 < member.size <= 512 * 1024**2,
                "payload_target_type_owner_mode",
            )
            result, size, magic = hashlib.sha256(), 0, b""
            with archive.extractfile(member) as source:
                while block := source.read(65536):
                    size += len(block)
                    need(size <= member.size, "payload_target_size")
                    magic = magic or block[:4]
                    result.update(block)
            need(size == member.size and magic == b"\x7fELF", "payload_target_ELF")
            target = {"sha256": result.hexdigest(), "bytes": size, "uid": 0, "mode": 0o755}
    need(target is not None, "payload_target_missing")
    return target


def context(root, receipt_path, pins_sha, revision):
    raw = read(root / PIN_PATH, 131072)
    need(sha(raw) == pins_sha, "external_manifest_pin")
    pins = json.loads(raw, object_pairs_hook=unique)
    receipt = json.loads(read(receipt_path, 4 * 1024**2), object_pairs_hook=unique)
    need(
        receipt.get("schema") == "pamolive.committed-build-context.v1"
        and receipt.get("revision") == revision
        and receipt["files"].get(PIN_PATH) == pins_sha,
        "committed_context_pin",
    )
    need(
        pins["schema"] == "pamolive.chrome-bootstrap-pins/1"
        and set(pins["source_files"]) == SOURCE_PATHS
        and set(pins["test_files"]) == TEST_PATHS
        and set(pins["files"]) == MATERIALS
        and pins["Release_max_age_seconds"] == 604800
        and pins["future_tolerance_seconds"] == 300
        and pins["purpose"] == "disposable-p1g-CI-only"
        and pins["primary"] == "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796"
        and pins["signer"] == "0E225917414670F4442C250DFD533C07C264648F"
        and pins["PGP_validity_still_required_in_CI"] is True,
        "finite_manifest",
    )
    captured = {}
    for name, expected in (pins["source_files"] | pins["test_files"]).items():
        body = read(root / name, 131072)
        need(sha(body) == expected == receipt["files"].get(name), "source_context_drift")
        captured[name] = body
    for name, expected in pins["files"].items():
        path = "qualification/p1g_headless/chrome_materials/" + name
        body = read(root / path, 131072)
        need(
            sha(body) == expected["sha256"] == receipt["files"].get(path)
            and len(body) == expected["bytes"],
            "material_context_drift",
        )
        captured[name] = body
    return pins, captured


def load(name, raw, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


class Commands:
    def __init__(self, support, bounded, private, public, *, horizon=870):
        self.support, self.io, self.private, self.public = support, bounded, private, public
        self.number, self.unknown = 0, False
        self.until = time.monotonic() + horizon

    def run(self, argv, *, seconds=30, cap=262144, sink=None, sudo=False):
        need(not self.unknown, "previous_UNKNOWN")
        need(time.monotonic() + seconds + 10 < self.until, "bootstrap_deadline")
        self.number += 1
        journal = self.public / ("command-" + str(self.number))
        journal.mkdir(mode=0o755)
        tool = Path(argv[0])
        if sudo:
            info = tool.lstat()

            def role_identity(row):
                return (
                    row.st_dev,
                    row.st_ino,
                    row.st_mode,
                    row.st_uid,
                    row.st_gid,
                    row.st_nlink,
                    row.st_size,
                    row.st_mtime_ns,
                    row.st_ctime_ns,
                )

            need(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_gid == 0
                and info.st_nlink == 1
                and tool.resolve(strict=True) == tool
                and stat.S_IMODE(info.st_mode) == 0o4755,
                "sudo_role",
            )
            for parent in tool.parents:
                row = parent.lstat()
                need(
                    stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022,
                    "sudo_role",
                )
            pin = {"sha256": sha(read(tool, 16 * 1024**2)), "bytes": info.st_size}
        else:
            pin = self.support.tool_pin(tool)
        self.support.fresh_write(
            journal / "intent.json",
            json.dumps({"state": "PENDING", "tool": pin, "seconds": seconds}).encode(),
            mode=0o444,
        )
        try:
            env = ENV | {"HOME": str(self.private)}
            if sudo:
                env.update(
                    {key: os.environ[key] for key in PRESERVE.split(",") if key in os.environ}
                )
            result = self.io.run_capped(
                argv,
                env=env,
                cwd=str(self.private),
                timeout=seconds + 10,
                work_timeout=seconds,
                stdout_cap=cap,
                stderr_cap=262144,
                total_cap=cap + 262144,
                stdout_sink=sink,
                owned_session=True,
                deadline=self.until,
                on_spawn=lambda pid: self.support.fresh_write(
                    journal / "pid.json", json.dumps({"pid": pid}).encode(), mode=0o444
                ),
            )
            self.support.fresh_write(
                journal / "process.json", json.dumps(result.facts()).encode(), mode=0o444
            )
            need(
                result.ok
                and result.spawn_attempted is True
                and type(result.pid) is int
                and result.pid > 0
                and type(result.returncode) is int
                and result.returncode == 0
                and result.reason is None
                and result.owned_child_reaped is True
                and result.drains_complete is True
                and result.killed_owned_child is False
                and result.exception_type is result.cleanup_exception_type is None,
                "command_UNKNOWN",
            )
            if sudo:
                need(
                    sha(read(tool, 16 * 1024**2)) == pin["sha256"]
                    and role_identity(tool.lstat()) == role_identity(info),
                    "sudo_changed",
                )
            else:
                need(self.support.tool_pin(tool) == pin, "tool_changed")
            # Raw output is private; the sole caller parses bounded public metadata only.
            self.support.fresh_write(self.private / ("stderr-" + str(self.number)), result.stderr)
            return result.stdout
        except BaseException:
            self.unknown = True
            self.support.fresh_write(journal / "UNKNOWN.json", b'{"state":"UNKNOWN"}\n', mode=0o444)
            raise


PRESERVE = (
    "GITHUB_ACTIONS,GITHUB_REPOSITORY,GITHUB_EVENT_NAME,GITHUB_REF,GITHUB_HEAD_REF,"
    "GITHUB_SHA,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,RUNNER_TEMP,P1G_HEAD_REPOSITORY,"
    "PAMOLIVE_P1G_DISPOSABLE,PAMOLIVE_TEST_DATABASE_NAME,DATABASE_URL"
)
APT = [
    "/usr/bin/apt-get",
    "--no-download",
    "--no-remove",
    "--no-install-recommends",
    "--reinstall",
    "-o",
    "Dir::Etc::sourcelist=/dev/null",
    "-o",
    "Dir::Etc::sourceparts=-",
]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--pins-sha", required=True)
    parser.add_argument("--root-install", action="store_true")
    args = parser.parse_args(argv)
    need(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true", "CI_Linux_only")
    os.umask(0o077)
    root = ROOT
    need(root == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) / "p1g-source", "source_root")
    pins, captured = context(
        root,
        Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json",
        args.pins_sha,
        os.environ["GITHUB_SHA"],
    )
    support = load(
        "p1g_chrome_support",
        captured["qualification/p1g_headless/lab_support.py"],
        root / "qualification/p1g_headless/lab_support.py",
    )
    gpg = load(
        "p1g_chrome_gpg",
        captured["qualification/p1g_headless/chrome_gpg.py"],
        root / "qualification/p1g_headless/chrome_gpg.py",
    )
    support.guard(os.environ, uid=int(os.environ["SUDO_UID"]) if args.root_install else os.getuid())
    support.source_binding(
        root, Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", os.environ["GITHUB_SHA"]
    )
    base = Path(os.environ["RUNNER_TEMP"])
    name = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    private = base / ("p1g-chrome-private-" + name)
    public = base / ("p1g-headless-" + name + "-chrome")
    package = private / "chrome.deb"
    if not args.root_install:
        need(os.getuid() > 0, "nonroot_frontend")
        private.mkdir(mode=0o700)
        public.mkdir(mode=0o700)
    else:
        need(os.getuid() == 0, "root_installer_only")
        private = Path("/var/tmp") / ("pamolive-chrome-bootstrap-" + name)
        private.mkdir(mode=0o700)
    command_public = public / ("root" if args.root_install else "frontend")
    command_public.mkdir(mode=0o755)
    commands = Commands(
        support,
        support.bounded(root),
        private,
        command_public,
        horizon=450 if args.root_install else 870,
    )
    phase = "authenticate"
    try:
        support.fresh_write(
            command_public / "resources.json",
            json.dumps(support.resources(private)).encode(),
            mode=0o444,
        )
        # Both frontend and privileged supervisor verify the same frozen inputs.
        release_check(captured["Release"], captured["Packages"], int(time.time()))
        package_check(captured["Packages"], pins["package"])
        staged = private / "materials"
        staged.mkdir(mode=0o700)
        for name, body in captured.items():
            if name in MATERIALS:
                support.fresh_write(staged / name, body, mode=0o400)
        home = private / "gnupg"
        home.mkdir(mode=0o700)
        command = [
            "/usr/bin/gpg",
            "--no-options",
            "--homedir",
            str(home),
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--no-auto-key-import",
            "--auto-key-locate",
            "clear",
            "--no-auto-check-trustdb",
            "--require-cross-certification",
        ]
        commands.run(command + ["--import", str(staged / "google-key.asc")], seconds=10)
        listed = commands.run(
            command
            + [
                "--with-colons",
                "--fixed-list-mode",
                "--fingerprint",
                "--with-subkey-fingerprint",
                "--list-keys",
            ],
            seconds=10,
        )
        keys = gpg.one_primary(listed, pins["primary"])
        status = commands.run(
            command
            + [
                "--status-fd",
                "1",
                "--verify",
                str(staged / "Release.gpg"),
                str(staged / "Release"),
            ],
            seconds=10,
        )
        now = int(time.time())
        valid = gpg.valid_status(status, pins["primary"], pins["signer"], now)
        gpg.signing_capability(keys, pins["primary"], pins["signer"], now, valid["timestamp"])
        # Metadata is parsed again AFTER actual GPG authentication, before DEB processing.
        release_check(captured["Release"], captured["Packages"], now)
        phase = "package_bytes"
        if not args.root_install:
            with package.open("xb") as sink:
                commands.run(
                    [
                        "/usr/bin/curl",
                        "-q",
                        "--proto",
                        "=https",
                        "--tlsv1.2",
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--noproxy",
                        "*",
                        "--max-time",
                        "120",
                        "--max-filesize",
                        pins["package"]["Size"],
                        BASE_URL + pins["package"]["Filename"],
                    ],
                    seconds=130,
                    cap=int(pins["package"]["Size"]),
                    sink=sink,
                )
            package.chmod(0o400)
        need(
            package.stat().st_size == int(pins["package"]["Size"])
            and sha(read(package, 256 * 1024**2)) == pins["package"]["SHA256"],
            "package_bytes",
        )
        if args.root_install:
            # Place verified bytes in a fresh root-owned directory before package tools.
            raw = read(package, 256 * 1024**2)
            need(sha(raw) == pins["package"]["SHA256"], "package_changed")
            package = private / "chrome.deb"
            support.fresh_write(package, raw, mode=0o400)
            del raw
        control_check(
            commands.run(
                [
                    "/usr/bin/dpkg-deb",
                    "--field",
                    str(package),
                    "Package",
                    "Version",
                    "Architecture",
                    "Depends",
                ],
                seconds=10,
            ),
            pins["package"],
        )
        phase = "payload_inspection"
        payload = private / "payload.tar"
        with payload.open("xb+") as stream:
            commands.run(
                ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(package)],
                seconds=60,
                cap=1024**3,
                sink=stream,
            )
            target = payload_target(stream)
        phase = "dependencies"
        apt_plan(commands.run([*APT, "--simulate", "install", str(package)], seconds=30))
        if not args.root_install:
            phase = "root_supervisor"
            python = Path(sys.executable).resolve(strict=True)
            support.tool_pin(python)
            commands.run(
                [
                    "/usr/bin/sudo",
                    "-n",
                    "--preserve-env=" + PRESERVE,
                    "--",
                    str(python),
                    "-I",
                    "-B",
                    "-S",
                    str(HERE / "chrome_bootstrap.py"),
                    "--pins-sha",
                    args.pins_sha,
                    "--root-install",
                ],
                seconds=480,
                sudo=True,
            )
            result = json.loads(read(public / "installed.json", 32768), object_pairs_hook=unique)
            need(
                result["state"] == "INSTALLED_AUTHENTICATED_PACKAGE_ONLY"
                and result["target"] == target
                and result["package_sha256"] == pins["package"]["SHA256"]
                and result["pins_manifest_sha256"] == args.pins_sha
                and result["revision"] == os.environ["GITHUB_SHA"],
                "root_receipt",
            )
        else:
            phase = "install_local_exact"
            release_check(captured["Release"], captured["Packages"], int(time.time()))
            # No remote source, dependency fetching/fix, downgrade consent or mode repair.
            need(sha(read(package, 256 * 1024**2)) == pins["package"]["SHA256"], "package_changed")
            commands.run([*APT, "--assume-yes", "install", str(package)], seconds=180)
            phase = "unchanged_Chrome_guard"
            installed = commands.run(
                [
                    "/usr/bin/dpkg-query",
                    "--show",
                    "--showformat=${Package}\n${Version}\n${Architecture}\n${Status}\n",
                    "google-chrome-stable",
                ],
                seconds=10,
            )
            need(
                installed
                == (
                    "google-chrome-stable\n"
                    + pins["package"]["Version"]
                    + "\namd64\ninstall ok installed\n"
                ).encode(),
                "installed_package_identity",
            )
            need(
                support.tool_pin(TARGET) == target and TARGET.lstat().st_gid == 0,
                "installed_payload_mismatch",
            )
            need(time.monotonic() < commands.until, "bootstrap_deadline")
            support.fresh_write(
                public / "installed.json",
                json.dumps(
                    {
                        "schema": "pamolive.chrome-bootstrap/1",
                        "state": "INSTALLED_AUTHENTICATED_PACKAGE_ONLY",
                        "package_sha256": pins["package"]["SHA256"],
                        "package_version": pins["package"]["Version"],
                        "revision": os.environ["GITHUB_SHA"],
                        "pins_manifest_sha256": args.pins_sha,
                        "context_receipt_sha256": sha(
                            read(Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", 4 * 1024**2)
                        ),
                        "target": target,
                        "signature": valid,
                        "all_OS_descendants_released": False,
                        "browser_executed": False,
                        "operational_GO": False,
                    }
                ).encode(),
                mode=0o444,
            )
        return 0
    except BaseException as error:
        code = (
            error.args[0]
            if (
                type(error) is ValueError
                and len(error.args) == 1
                and type(error.args[0]) is str
                and error.args[0] in DIAGNOSTICS
            )
            else "unknown"
        )
        support.fresh_write(
            public / ("root-UNKNOWN.json" if args.root_install else "UNKNOWN.json"),
            json.dumps(
                {
                    "state": "UNKNOWN",
                    "phase": phase,
                    "code": code,
                    "error_class": type(error).__name__,
                    "all_OS_descendants_released": False,
                    "operational_GO": False,
                }
            ).encode(),
            mode=0o444,
        )
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
