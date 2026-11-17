"""Root-commissioned disposable BuildKit boundary only; no network acquisition here."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

HERE = Path(__file__).absolute().parent
WORK = Path("/expat-apt-work")
PROOF = Path("/expat-apt-proof")
VERSION = b"sqv 1.5.0 (sequoia-openpgp 2.4.1, using Nettle 3.10 (Cv448: true, OCB: true))\n"
IDENTITY = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
APT_SIMULATE_ARGV = (
    "/usr/bin/apt-get",
    "--simulate",
    "--no-download",
    "--no-remove",
    "--no-install-recommends",
    "install",
    "build-essential",
    "binutils",
    "patch",
    "gpg=2.4.7-21+deb13u1+b5",
    "dpkg-dev",
    "debhelper",
    "autoconf",
    "automake",
    "libtool",
    "pkg-config",
    "docbook-to-man",
    "docbook2x",
    "libexpat1-dev=2.9.0-1~deb13u1",
    "ca-certificates",
)
APT_ARCHIVES_ERROR = (
    b"E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?"
)


def apt_failure_diagnostic(result, before_sha, after_sha):
    """Messages only, never solver authority; no buffer fragments leave this function."""
    stable = (
        type(before_sha) is str
        and re.fullmatch("[a-f0-9]{64}", before_sha) is not None
        and type(after_sha) is str
        and after_sha == before_sha
    )
    normal = (
        result.ok is False
        and result.spawn_attempted is True
        and type(result.pid) is int
        and result.pid > 0
        and type(result.returncode) is int
        and result.returncode == 100
        and result.reason == "nonzero_exit"
        and result.exception_type is result.cleanup_exception_type is None
        and result.owned_child_reaped is True
        and result.drains_complete is True
        and result.killed_owned_child is False
    )
    buffers = (("stderr", result.stderr, 262144), ("stdout", result.stdout, 1024**2))
    valid = True
    streams = {}
    # At most 32 hashes per finite severity/stream bucket, even for huge line counts.
    buckets = {(stream, prefix): [] for stream, _, _ in buffers for prefix in (b"E:", b"W:", b"N:")}
    eligible = total_lines = invalid_lines = encoding_invalid_streams = unbounded_streams = 0
    seen_archives_message = False
    for stream, raw, cap in buffers:
        bounded = type(raw) is bytes and len(raw) <= cap
        streams[stream] = {
            "bytes": len(raw) if type(raw) is bytes else None,
            "sha256": sha(raw) if bounded else None,
            "bounded": bounded,
        }
        if not bounded:
            valid = False
            unbounded_streams += 1
            continue
        try:
            raw.decode("utf8")
            encoding = True
        except UnicodeDecodeError:
            encoding = False
            encoding_invalid_streams += 1
        valid = valid and encoding
        start = 0
        while start < len(raw):
            end = raw.find(b"\n", start)
            complete = end >= 0
            if not complete:
                end = len(raw)
            line = raw[start:end]
            start = end + 1
            total_lines += 1
            line_valid = (
                complete and len(line) <= 4096 and b"\r" not in line and b"\x00" not in line
            )
            if not line_valid:
                invalid_lines += 1
                valid = False
                continue
            prefix = line[:2]
            if prefix not in (b"E:", b"W:", b"N:"):
                continue
            eligible += 1
            exact = line == APT_ARCHIVES_ERROR
            seen_archives_message = seen_archives_message or exact
            bucket = buckets[stream, prefix]
            if len(bucket) < 32:
                bucket.append(
                    {
                        "stream": stream,
                        "class": (
                            "archives_missing_no_download"
                            if exact
                            else {
                                b"E:": "apt_error_other",
                                b"W:": "apt_warning_other",
                                b"N:": "apt_notice_other",
                            }[prefix]
                        ),
                        "sha256": sha(line),
                    }
                )
            elif exact and not any(
                row["class"] == "archives_missing_no_download" for row in bucket
            ):
                bucket[-1] = {
                    "stream": stream,
                    "class": "archives_missing_no_download",
                    "sha256": sha(line),
                }
    qualified_message = normal and stable and valid
    selected = []
    if qualified_message:
        # Error stderr first, then other errors, then warnings/notices; not progress.
        for prefix in (b"E:", b"W:", b"N:"):
            for stream, _, _ in buffers:
                selected.extend(buckets[stream, prefix][: 32 - len(selected)])
    return {
        "schema": "pamolive.expat-apt-solver-diagnostic/1",
        "phase": "apt_simulate",
        "state": "REFUSED" if qualified_message else "UNKNOWN",
        "normal_rc100": normal,
        "tool_stable": stable,
        "tool_before_sha256": (
            before_sha
            if type(before_sha) is str and re.fullmatch("[a-f0-9]{64}", before_sha)
            else None
        ),
        "tool_after_sha256": after_sha if stable else None,
        "buffers": streams,
        "input_valid": valid,
        "encoding_invalid_streams": encoding_invalid_streams,
        "unbounded_streams": unbounded_streams,
        "invalid_lines": invalid_lines,
        "total_lines": total_lines,
        "omitted_lines": total_lines - len(selected),
        "eligible_message_lines": eligible,
        "omitted_message_lines": eligible - len(selected),
        "exported_lines": selected,
        "archives_missing_message_observed": qualified_message and seen_archives_message,
        "message_scope_only": True,
        "build_verified": False,
        "materials_complete": False,
        "all_OS_descendants_released": False,
        "operational_GO": False,
    }


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(row):
    return tuple(getattr(row, "st_" + key) for key in IDENTITY)


def read_regular(path, maximum, *, allow_empty=False):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "absolute_input_path")
    for parent in path.parents:
        info = parent.lstat()
        need(
            stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022,
            "input_parent_alias_or_writable",
        )
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and (0 <= before.st_size if allow_empty else 0 < before.st_size)
        and before.st_size <= maximum,
        "regular_input_budget",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", buffering=0) as source:
        need(identity(os.fstat(fd)) == identity(before), "input_FD_changed")
        raw = source.read(maximum + 1)
        need(
            len(raw) == before.st_size
            and identity(os.fstat(fd)) == identity(before)
            and identity(path.lstat()) == identity(before),
            "input_changed",
        )
    return raw


def write_new(path, raw, mode=0o400):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb", buffering=0) as target:
        need(target.write(raw) == len(raw), "short_write")
        os.fsync(fd)
        need(identity(os.fstat(fd)) == identity(path.lstat()), "output_changed")


def load(name, filename, digest):
    path = HERE / filename
    raw = read_regular(path, 131072)
    need(sha(raw) == digest, "reviewed_code_pin")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


class Runner:
    def __init__(self, io, codecs, base, *, until):
        self.io, self.m, self.base, self.until = io, codecs, base, until
        self.ordinal, self.unknown = 0, False
        self.records = []
        self.verifier_sha = None

    def live(self, name):
        path, expected = self.m.resolve(self.base["files"], name, with_path=True)
        need(expected["type"] == "file", "base_bootstrap_not_file")
        raw = read_regular(path, min(self.m.MAX_DEB, max(expected["size"], 1)))
        row = Path(path).lstat()
        need(
            len(raw) == expected["size"]
            and sha(raw) == expected["sha256"]
            and stat.S_IMODE(row.st_mode) == expected["mode"]
            and row.st_uid == expected["uid"]
            and row.st_gid == expected["gid"],
            "base_bootstrap_drift",
        )
        return raw

    def tool_pin(self, path):
        if path == str(WORK / "sqv"):
            raw = read_regular(path, 3 * 1024**2)
            need(sha(raw) == self.verifier_sha, "bootstrap_verifier_changed")
        else:
            need(path in ("/usr/bin/apt-get", "/usr/bin/dpkg-query"), "command_tool")
            raw = self.live(path.lstrip("/"))
        need(raw.startswith(b"\x7fELF"), "bootstrap_not_ELF")
        return sha(raw), identity(Path(path).lstat())

    def replacement_pin(self, path, expected):
        # This role can change only through an exact externally admitted DEB payload.
        need(
            path == "/usr/bin/apt-get"
            and expected.get("type") == "file"
            and expected.get("uid") == expected.get("gid") == 0
            and type(expected.get("mode")) is int
            and not expected["mode"] & 0o6022,
            "replacement_tool_role",
        )
        raw = read_regular(path, self.m.MAX_DEB)
        row = Path(path).lstat()
        need(
            len(raw) == expected["size"]
            and sha(raw) == expected["sha256"]
            and stat.S_IMODE(row.st_mode) == expected["mode"]
            and row.st_uid == row.st_gid == 0
            and raw.startswith(b"\x7fELF"),
            "replacement_tool_not_admitted_payload",
        )
        return sha(raw), identity(row)

    def call(
        self, argv, *, seconds, cap=262144, env=None, post_expected=None, diagnostic_role=None
    ):
        need(
            diagnostic_role is None
            or (
                type(diagnostic_role) is str
                and diagnostic_role == "apt_simulate"
                and type(argv) is list
                and tuple(argv) == APT_SIMULATE_ARGV
                and type(seconds) is int
                and seconds == 90
                and type(cap) is int
                and cap == 1024**2
                and post_expected is None
                and type(env) is dict
                and env
                == {
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "HOME": "/expat-apt-work",
                    "APT_CONFIG": "/expat-apt-work/solver.conf",
                    "DEBIAN_FRONTEND": "noninteractive",
                }
            ),
            "apt_diagnostic_role",
        )
        need(
            not self.unknown
            and type(seconds) is int
            and 0 < seconds <= 600
            and self.ordinal < 16
            and time.monotonic() + seconds + 10 < self.until,
            "client_budget_or_UNKNOWN",
        )
        self.ordinal += 1
        prefix = PROOF / ("command-" + str(self.ordinal))
        pin = self.tool_pin(argv[0])
        write_new(
            str(prefix) + "-intent.json",
            json.dumps({"state": "PENDING", "tool_sha256": pin[0]}).encode(),
        )
        try:
            result = self.io.run_capped(
                argv,
                env=env or {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(WORK)},
                cwd=str(WORK),
                timeout=seconds + 10,
                work_timeout=seconds,
                deadline=self.until,
                stdout_cap=cap,
                stderr_cap=262144,
                total_cap=cap + 262144,
                owned_session=True,
                on_spawn=lambda pid: write_new(
                    str(prefix) + "-pid.json", json.dumps({"pid": pid}).encode()
                ),
            )
            facts = result.facts()
            write_new(str(prefix) + "-result.json", json.dumps(facts).encode())
            if diagnostic_role == "apt_simulate" and not result.ok:
                try:
                    try:
                        post = self.tool_pin(argv[0])
                        after = post[0] if post == pin else None
                    except Exception:
                        after = None
                    packet = apt_failure_diagnostic(result, pin[0], after)
                    raw = (json.dumps(packet, separators=(",", ":")) + "\n").encode()
                    need(len(raw) <= 16384, "apt_diagnostic_output_cap")
                    write_new(str(prefix) + "-apt-diagnostic.json", raw)
                except Exception:
                    # Best effort only; preserve the original fatal guard and UNKNOWN.
                    pass
            need(
                result.ok
                and result.spawn_attempted is True
                and type(result.pid) is int
                and result.pid > 0
                and type(result.returncode) is int
                and result.returncode == 0
                and result.reason is result.exception_type is result.cleanup_exception_type is None
                and result.owned_child_reaped is True
                and result.drains_complete is True
                and result.killed_owned_child is False,
                "client_failed_or_UNKNOWN",
            )
            if post_expected is None:
                post = self.tool_pin(argv[0])
                need(post == pin, "tool_changed_without_admitted_payload")
            else:
                post = self.replacement_pin(argv[0], post_expected)
            write_new(
                str(prefix) + "-tool.json",
                json.dumps(
                    {
                        "before_sha256": pin[0],
                        "after_sha256": post[0],
                        "admitted_DEB_replacement": post_expected is not None,
                    }
                ).encode(),
            )
            self.records.append(facts)
            return result.stdout, result.stderr
        except BaseException:
            self.unknown = True
            write_new(
                str(prefix) + "-UNKNOWN.json",
                b'{"state":"UNKNOWN","all_OS_descendants_released":false}',
            )
            raise

    def simulate(self, argv, *, seconds, cap, env):
        """One H1 frontend becomes APT in the same PID only after a kernel fence."""
        f = self.solver_fence_module
        need(
            type(argv) is list
            and tuple(argv) == f.APT_ARGV
            and type(seconds) is int
            and seconds == 90
            and type(cap) is int
            and cap == 1024**2
            and type(env) is dict
            and env == f.ENV,
            "fenced_solver_role",
        )
        need(
            not self.unknown and self.ordinal < 16 and time.monotonic() + seconds + 10 < self.until,
            "client_budget_or_UNKNOWN",
        )
        self.ordinal += 1
        prefix = PROOF / ("command-" + str(self.ordinal))
        apt = self.tool_pin(f.APT)

        def python_pin():
            raw = self.live(f.PYTHON.lstrip("/"))
            need(raw.startswith(b"\x7fELF"), "solver_python_ELF")
            return sha(raw), identity(Path(f.PYTHON).lstat())

        python = python_pin()
        helper_path = HERE / "solver_fence.py"
        helper_raw = read_regular(helper_path, 131072)
        helper_identity = identity(helper_path.lstat())
        need(
            sha(helper_raw) == self.solver_fence_sha
            and sha(read_regular(HERE / "code-pins.json", 16384)) == self.solver_code_sha,
            "solver_fence_source",
        )
        config = sha(read_regular(f.CONFIG, 16384))
        need(config == f.SOLVER_CONFIG_SHA, "solver_configuration_role")
        outer = f.launch_argv(
            self.solver_fence_sha, self.solver_code_sha, apt[0], python[0], config, self.ordinal
        )
        write_new(
            str(prefix) + "-intent.json",
            json.dumps(
                {
                    "state": "PENDING",
                    "role": f.ROLE,
                    "frontend_python_sha256": python[0],
                    "helper_sha256": self.solver_fence_sha,
                    "payload_APT_sha256": apt[0],
                    "code_pins_sha256": self.solver_code_sha,
                }
            ).encode(),
        )
        try:
            result = self.io.run_capped(
                outer,
                env=env,
                cwd=str(WORK),
                timeout=seconds + 10,
                work_timeout=seconds,
                deadline=self.until,
                stdout_cap=cap,
                stderr_cap=262144,
                total_cap=cap + 262144,
                owned_session=True,
                on_spawn=lambda pid: write_new(
                    str(prefix) + "-pid.json", json.dumps({"pid": pid}).encode()
                ),
            )
            facts = result.facts()
            write_new(str(prefix) + "-result.json", json.dumps(facts).encode())
            lifecycle = (
                result.spawn_attempted is True
                and type(result.pid) is int
                and result.pid > 0
                and type(result.returncode) is int
                and result.owned_child_reaped is True
                and result.drains_complete is True
                and result.killed_owned_child is False
                and result.exception_type is result.cleanup_exception_type is None
                and (
                    (result.returncode == 0 and result.ok is True and result.reason is None)
                    or (
                        result.returncode != 0
                        and result.ok is False
                        and result.reason == "nonzero_exit"
                    )
                )
            )
            observed = False
            if lifecycle:
                try:
                    need(
                        self.tool_pin(f.APT) == apt
                        and python_pin() == python
                        and sha(read_regular(helper_path, 131072)) == self.solver_fence_sha
                        and identity(helper_path.lstat()) == helper_identity
                        and sha(read_regular(HERE / "code-pins.json", 16384))
                        == self.solver_code_sha
                        and sha(read_regular(f.CONFIG, 16384)) == config,
                        "solver_post_tools_or_context",
                    )
                    packet = self.m.json_data(read_regular(str(prefix) + "-fence.json", 4096))
                    f.validate_packet(
                        packet,
                        pid=result.pid,
                        code_sha=self.solver_code_sha,
                        helper_sha=self.solver_fence_sha,
                        python_pin=python,
                        apt_pin=apt,
                        ordinal=self.ordinal,
                    )
                    observed = True
                except Exception:
                    observed = False
            if not result.ok:
                try:
                    packet = apt_failure_diagnostic(result, apt[0], apt[0] if observed else None)
                    raw = (json.dumps(packet, separators=(",", ":")) + "\n").encode()
                    need(len(raw) <= 16384, "apt_diagnostic_output_cap")
                    write_new(str(prefix) + "-apt-diagnostic.json", raw)
                except Exception:
                    pass
            need(lifecycle and result.returncode == 0 and observed, "client_failed_or_UNKNOWN")
            write_new(
                str(prefix) + "-tool.json",
                json.dumps(
                    {
                        "frontend_python_unchanged": True,
                        "helper_source_unchanged": True,
                        "payload_APT_unchanged": True,
                        "fence_observation_received": True,
                        "operational_GO": False,
                    }
                ).encode(),
            )
            self.records.append(facts)
            return result.stdout, result.stderr
        except BaseException:
            self.unknown = True
            try:
                write_new(
                    str(prefix) + "-UNKNOWN.json",
                    b'{"state":"UNKNOWN","all_OS_descendants_released":false}',
                )
            except Exception:
                pass
            raise

    def signature(self, signed, suite, rule):
        source, output = WORK / (suite + ".InRelease"), WORK / (suite + ".Release")
        write_new(source, signed)
        need(not output.exists() and not output.is_symlink(), "release_output_collision")
        stdout, stderr = self.call(
            [
                str(WORK / "sqv"),
                "--keyring=" + str(WORK / "debian-archive-keyring.pgp"),
                "--output=" + str(output),
                "--cleartext",
                str(source),
            ],
            seconds=30,
            cap=65536,
        )
        need(stderr == b"" and stdout.endswith(b"\n") and b"\r" not in stdout, "signature_output")
        certs = tuple(line.decode("ascii") for line in stdout.splitlines())
        need(
            certs
            and len(set(certs)) == len(certs)
            and all(re.fullmatch(r"[A-F0-9]{40}", cert) for cert in certs)
            and set(certs) <= set(rule["allowed_certificates"])
            and set(certs) & set(rule["required_any_current"]),
            "certificate_purpose",
        )
        # The plaintext is unusable before normal H1 + exact output framing above.
        return read_regular(output, 1024**2), certs


def apt_configuration():
    # APT_CONFIG is read before default parts/main; CLI -o alone is too late.
    return b"""Dir::Etc::parts "/expat-apt-work/empty-config";
Dir::Etc::main "/dev/null";
Dir::Etc::sourcelist "/dev/null";
Dir::Etc::sourceparts "/expat-apt-work/empty-sources";
Dir::State::lists "/expat-apt-work/empty-lists";
Dir::Cache::archives "/expat-apt-work/empty-cache";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Acquire::Retries "0";
Acquire::http::Proxy "DIRECT";
Acquire::https::Proxy "DIRECT";
APT::Get::Download "false";
APT::Get::AllowUnauthenticated "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
"""


def apply(runner, gate, material, debs, releases, *, approved_sha):
    gate.admit(material, approved_sha)
    need(
        type(debs) is tuple
        and all(type(name) is str and type(raw) is bytes for name, raw in debs)
        and [(name, sha(raw), len(raw)) for name, raw in debs]
        == [(row["deb"], row["sha256"], row["bytes"]) for row in material["packages"]],
        "install_bytes_not_approved",
    )
    before = gate.status(runner.live("var/lib/dpkg/status"))
    need(
        sha(runner.live("var/lib/dpkg/status")) == material["prestate_sha256"],
        "prestate_changed_before_use",
    )
    for name in ("empty-config", "empty-sources", "empty-lists", "empty-cache"):
        (WORK / name).mkdir(mode=0o700)
    write_new(WORK / "apt.conf", apt_configuration())
    paths = []
    for number, (_name, raw) in enumerate(debs):
        path = WORK / ("material-" + str(number) + ".deb")
        write_new(path, raw)
        paths.append(str(path))
    common = [
        "/usr/bin/apt-get",
        "--no-download",
        "--no-remove",
        "--no-install-recommends",
    ]
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": str(WORK),
        "APT_CONFIG": str(WORK / "apt.conf"),
        "DEBIAN_FRONTEND": "noninteractive",
    }
    gate.freshness(releases, int(time.time()))
    runner.call(
        [*common, "--simulate", "install", *(paths or material["requests"])],
        seconds=60,
        cap=8 * 1024**2,
        env=env,
    )
    replacement = None
    for name, raw in debs:
        _, payload = gate.m.deb(raw, payload=True)
        if "usr/bin/apt-get" in payload:
            need(replacement is None, "multiple_apt_tool_providers")
            replacement = payload["usr/bin/apt-get"]
    gate.freshness(releases, int(time.time()))
    # No sources/index resolution or network acquisition is permitted at this use boundary.
    for path, (_name, raw) in zip(paths, debs, strict=True):
        need(read_regular(path, len(raw)) == raw, "DEB_staged_drift")
    options = {} if replacement is None else {"post_expected": replacement}
    runner.call(
        [*common, "--assume-yes", "install", *(paths or material["requests"])],
        seconds=600,
        cap=8 * 1024**2,
        env=env,
        **options,
    )
    after_raw = read_regular("/var/lib/dpkg/status", 4 * 1024**2)
    after = gate.status(after_raw)
    need(
        after == material["expected_after_state"]
        and set(before) <= set(after)
        and material["transitions"]
        == [
            {"package": name, "before": before.get(name), "after": value}
            for name, value in sorted(after.items())
            if before.get(name) != value
        ],
        "poststate_or_reviewed_transitions_changed",
    )
    for path, (_name, raw) in zip(paths, debs, strict=True):
        need(read_regular(path, len(raw)) == raw, "DEB_staged_drift")
    gate.freshness(releases, int(time.time()))
    write_new(PROOF / "status-after", after_raw)
    return {
        "state": "AUTHENTICATED_INPUTS_INSTALLED_PACKAGE_STATE_ONLY",
        "stage": "expat-prepared",
        "material_set_sha256": sha(gate.m.canonical(material) + b"\n"),
        "poststate_sha256": sha(after_raw),
        "boundary_package_state_verified": True,
        "compiler_SDK_generated_state_closed": False,
        "build_verified": False,
        "materials_complete": False,
        "other_builder_boundaries_closed": False,
        "cryptographic_build_attestation_verified": False,
        "all_OS_descendants_released": False,
    }


def main():
    until = time.monotonic() + 900
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--code-pins-sha", required=True)
    parser.add_argument("--policy-sha", required=True)
    parser.add_argument("--approved-material-set-sha")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--disposable-buildkit-ack", required=True)
    args = parser.parse_args()
    need(
        sys.platform == "linux"
        and os.getuid() == os.geteuid() == 0
        and args.disposable_buildkit_ack == "expat-prepared-only-v1",
        "disposable_Linux_builder_required",
    )
    os.umask(0o077)
    pins_raw = read_regular(HERE / "code-pins.json", 16384)
    need(sha(pins_raw) == args.code_pins_sha, "external_code_pin")
    pins = json.loads(pins_raw)
    need(
        type(pins) is dict
        and set(pins)
        == {
            "transaction.py",
            "gate.py",
            "materials.py",
            "bounded_io.py",
            "capture.py",
            "network_worker.py",
            "solver.py",
            "oci_codec.py",
            "supervisor.py",
            "solver_fence.py",
            "native_fence_tests.py",
        }
        and sha(read_regular(HERE / "transaction.py", 131072)) == pins["transaction.py"],
        "code_closure",
    )
    m = load("expat_apt_materials", "materials.py", pins["materials.py"])
    g = load("expat_apt_gate", "gate.py", pins["gate.py"])
    io = load("expat_apt_bounded_io", "bounded_io.py", pins["bounded_io.py"])
    gate = g.Gate(m)
    if args.capture:
        need(not args.apply and args.approved_material_set_sha is None, "separate_capture_apply")
        capture = load("expat_capture", "capture.py", pins["capture.py"])
        return capture.run(args, pins, m, g, io, sys.modules[__name__], deadline=until + 900)
    policy_raw = read_regular("/c-authority/policy.json", 1024**2)
    gate.policy(policy_raw, args.policy_sha)
    approved = None
    if args.apply:
        approved = gate.approval(
            read_regular("/c-authority/material-set.json", 4 * 1024**2),
            args.approved_material_set_sha,
            args.policy_sha,
        )
    # Independent original OCI bytes, never a map or digest supplied by the solver.
    base = m.base_inventory("/c-base")
    gate.parent(base)
    WORK.mkdir(mode=0o700)
    PROOF.mkdir(mode=0o700)
    runner = Runner(io, m, base, until=until)
    bootstrap = read_regular("/c-bootstrap/sqv.data", 3 * 1024**2)
    need(
        len(bootstrap) == 1935072
        and sha(bootstrap) == g.SQV_SHA
        and bootstrap.startswith(b"\x7fELF"),
        "verifier_supplier_bytes",
    )
    write_new(WORK / "sqv", bootstrap, 0o500)
    runner.verifier_sha = g.SQV_SHA
    write_new(
        WORK / "debian-archive-keyring.pgp",
        runner.live("usr/share/keyrings/debian-archive-keyring.pgp"),
    )
    out, err = runner.call([str(WORK / "sqv"), "--version"], seconds=5, cap=1024)
    need(out == VERSION and err == b"", "maintained_verifier_version")
    before = runner.live("var/lib/dpkg/status")
    spec = read_regular("/c-input/manifest.json", 2 * 1024**2)
    captured = {}

    def read(name, cap):
        m.relative(name)
        raw = read_regular(Path("/c-input") / name, cap, allow_empty=name.endswith(".Packages"))
        need(name not in captured or captured[name] == raw, "capture_input_changed")
        captured[name] = raw
        return raw

    material, debs, releases, files = gate.capture(
        policy_raw,
        args.policy_sha,
        spec,
        read,
        runner.signature,
        base,
        before,
        int(time.time()),
        approved,
    )
    retained = PROOF / "retained"
    retained.mkdir(mode=0o700)
    need(set(captured) == set(files), "captured_file_set")
    retained_map = {}
    for number, name in enumerate(sorted(files)):
        # These exact immutable buffers were authenticated; never reopen the source name.
        raw = captured[name]
        write_new(retained / (str(number) + ".data"), raw)
        retained_map[name] = {
            "file": "retained/" + str(number) + ".data",
            "sha256": sha(raw),
            "bytes": len(raw),
        }
    for suite, cleartext, _rule in releases:
        write_new(retained / (suite + ".Release"), cleartext)
    write_new(PROOF / "retained-map.json", g.canonical(retained_map))
    write_new(PROOF / "policy.json", policy_raw)
    write_new(PROOF / "keyring.pgp", runner.live("usr/share/keyrings/debian-archive-keyring.pgp"))
    write_new(PROOF / "status-before", before)
    write_new(PROOF / "spool-manifest.json", spec)
    write_new(PROOF / "material-set.json", g.canonical(material))
    if args.apply:
        gate.admit(material, args.approved_material_set_sha)
        result = apply(
            runner, gate, material, debs, releases, approved_sha=args.approved_material_set_sha
        )
    else:
        result = {
            "state": "AUTHENTICATED_CANDIDATE_NOT_APPROVED_OR_INSTALLED",
            "stage": g.STAGE,
            "build_verified": False,
            "materials_complete": False,
            "other_builder_boundaries_closed": False,
        }
    result["code_pins_sha256"] = args.code_pins_sha
    need(time.monotonic() < until and not runner.unknown, "boundary_deadline_or_UNKNOWN")
    write_new(PROOF / "result.json", g.canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(
            '{"state":"REFUSED_OR_UNKNOWN","build_verified":false,"materials_complete":false,"all_OS_descendants_released":false}'
        )
        raise SystemExit(42) from None
