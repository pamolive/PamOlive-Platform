"""Closed CI inputs and ephemeral TLS/NSS setup. No operation at import."""

import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

HOST = "pam.example.test"
BRANCH = "agent/p1-g-headless"
STAGE_BRANCH = "agent/p1g-chrome158-private-stage"
NATIVE_BRANCH = "agent/p1g-native-portal-isolated-ci"
BOUNDED_SHA = "72b778ad6e441744e8bd9ac84ba7f47b1f6b577b7885a2e0daf3b4584cc0150a"
SDK_VERSION = "1.65.2"
RELAY_PATH = r"/ws/pam/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/"
SDK_NODE_BYTES = 150348872
SDK_NODE_SHA = "d931c649850ffa7155b8ceffb400dc916ef325866e509cc52ae36e33e8fbb9a9"
BUNDLE_BROWSER_VERSION = "157.0.8103.78"
SANDBOX_URL = "chrome://sandbox/"
APPARMOR_MODES = {"enforce", "complain", "unconfined"}


def need(value, code):
    if not value:
        raise ValueError(code)


def relay_socket_pattern(origin):
    """Return the single WSS route grammar for the synthetic lab origin."""
    match = re.fullmatch(r"https://" + re.escape(HOST) + r":([1-9][0-9]{0,4})", origin)
    need(match and int(match[1]) <= 65535, "native_browser_origin")
    return re.escape("wss://" + origin.removeprefix("https://")) + RELAY_PATH


def guard(env, *, platform=sys.platform, uid=None, stage_only=False, native_lab=False):
    need(type(stage_only) is bool and type(native_lab) is bool and not (
        stage_only and native_lab
    ), "closed_operation_required")
    branch = NATIVE_BRANCH if native_lab else STAGE_BRANCH if stage_only else BRANCH
    uid = os.getuid() if uid is None and platform == "linux" else uid
    need(platform == "linux" and type(uid) is int and uid > 0, "linux_nonroot_required")
    need(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("PAMOLIVE_P1G_DISPOSABLE") == "1"
        and env.get("GITHUB_REPOSITORY") == "pamolive/PamOlive-Platform",
        "disposable_repository_required",
    )
    event = env.get("GITHUB_EVENT_NAME")
    allowed = event == "push" and env.get("GITHUB_REF") == "refs/heads/" + branch
    allowed |= (
        not native_lab
        and event == "pull_request"
        and env.get("GITHUB_HEAD_REF") == branch
        and env.get("P1G_HEAD_REPOSITORY") == "pamolive/PamOlive-Platform"
    )
    if native_lab:
        need(env.get("RUNNER_ENVIRONMENT") == "github-hosted", "native_runner_required")
    need(
        allowed and re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", "")) is not None,
        "closed_event_ref_required",
    )
    need(
        all(
            re.fullmatch(r"[1-9][0-9]{0,19}", env.get(key, "")) is not None
            for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        ),
        "closed_run_identity",
    )
    url = urlsplit(env.get("DATABASE_URL", ""))
    need(
        url.scheme == "postgresql"
        and url.hostname == "127.0.0.1"
        and url.username == "p1g"
        and bool(url.password)
        and url.path == "/pamolive_p1g"
        and url.port is not None
        and 1024 <= url.port <= 65535
        and not url.query
        and not url.fragment,
        "loopback_disposable_database_required",
    )
    need(
        env.get("PAMOLIVE_TEST_DATABASE_NAME") == "test_pamolive_p1g_browser",
        "fresh_test_database_required",
    )


def same_origin(url, origin):
    try:
        parsed, base = urlsplit(url), urlsplit(origin)
        return (
            parsed.scheme == base.scheme == "https"
            and parsed.hostname == base.hostname == HOST
            and parsed.port == base.port
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def sandbox_diagnostic(rows, evaluation):
    need(type(rows) is list and 5 <= len(rows) <= 16, "sandbox_diagnostic_rows")
    flags = {}
    for row in rows:
        need(
            type(row) is list
            and len(row) == 2
            and isinstance(row[0], str)
            and 0 < len(row[0]) <= 80
            and row[0] not in flags
            and row[1]
            in (("SUID", "Namespace", "None") if row[0] == "Layer 1 Sandbox" else ("Yes", "No")),
            "sandbox_diagnostic_shape",
        )
        flags[row[0]] = row[1]
    required = ("PID namespaces", "Network namespaces", "Seccomp-BPF sandbox")
    need(
        evaluation == "You are adequately sandboxed."
        and flags.get("Layer 1 Sandbox") in ("SUID", "Namespace")
        and all(flags.get(name) == "Yes" for name in required),
        "chromium_sandbox_not_active",
    )
    return flags["Layer 1 Sandbox"]


def process_ids(packet):
    need(type(packet) is dict, "sandbox_process_packet")
    rows = packet.get("processInfo")
    need(type(rows) is list and 1 <= len(rows) <= 64, "sandbox_process_list")
    browsers, renderers, seen = [], set(), set()
    for row in rows:
        need(type(row) is dict, "sandbox_process_item")
        pid, kind = row.get("id"), row.get("type")
        need(type(pid) is int and 1 < pid < 2**31 and pid not in seen, "sandbox_process_id")
        seen.add(pid)
        if kind == "browser":
            browsers.append(pid)
        elif kind == "renderer":
            renderers.add(pid)
    need(len(browsers) == 1 and renderers, "sandbox_renderer_missing")
    return browsers[0], renderers


def process_sandbox_status(raw, pid, uid):
    need(type(raw) is bytes and 0 < len(raw) <= 16384, "sandbox_status_budget")
    wanted = {"Pid", "Uid", "NSpid", "CapEff", "NoNewPrivs", "Seccomp", "Seccomp_filters"}
    fields = {}
    for line in raw.decode("ascii").splitlines():
        field, _, value = line.partition(":")
        if field in wanted:
            need(field not in fields, "sandbox_status_duplicate")
            fields[field] = value.strip()
    need(
        fields.keys() == wanted
        and fields["Pid"] == str(pid)
        and fields["Uid"].split() == [str(uid)] * 4
        and uid > 0
        and re.fullmatch(r"[1-9][0-9]*(?:\s+[1-9][0-9]*){0,7}", fields["NSpid"])
        and fields["NSpid"].split()[0] == str(pid)
        and fields["Seccomp"] in ("0", "1", "2")
        and fields["NoNewPrivs"] in ("0", "1")
        and re.fullmatch(r"[0-9a-f]{16}", fields["CapEff"])
        and re.fullmatch(r"[0-9]{1,8}", fields["Seccomp_filters"]),
        "sandbox_status_identity",
    )
    return {
        "pid_depth": len(fields["NSpid"].split()),
        "filters": int(fields["Seccomp_filters"]),
        "restricted": fields["Seccomp"] == "2"
        and fields["NoNewPrivs"] == "1"
        and int(fields["CapEff"], 16) == 0,
    }


def apparmor_mode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "sandbox_apparmor_budget")
    label = raw.decode("ascii").strip()
    if label == "unconfined":
        return label
    mode = re.fullmatch(r"[^\x00-\x1f\x7f]+ \((enforce|complain|unconfined)\)", label)
    need(mode is not None, "sandbox_apparmor_unknown")
    return mode.group(1)


def read_process_field(directory, name, cap):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, dir_fd=directory), "rb") as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "sandbox_proc_field_type")
        raw = stream.read(cap + 1)
    need(0 < len(raw) <= cap, "sandbox_proc_field_budget")
    return raw


def observe_process(pid, uid, *, executable=None):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory = os.open(f"/proc/{pid}", flags)
    try:
        if executable is not None:
            running = os.stat("exe", dir_fd=directory)
            reviewed = executable.lstat()
            need(
                stat.S_ISREG(reviewed.st_mode)
                and (running.st_dev, running.st_ino) == (reviewed.st_dev, reviewed.st_ino),
                "sandbox_running_binary_changed",
            )
        result = process_sandbox_status(read_process_field(directory, "status", 16384), pid, uid)
        result["apparmor"] = apparmor_mode(
            read_process_field(directory, "attr/apparmor/current", 4096)
        )
        return result
    finally:
        os.close(directory)


def renderer_sandboxed(renderer, browser):
    return (
        renderer["restricted"]
        and renderer["filters"] > browser["filters"]
        and renderer["pid_depth"] > browser["pid_depth"]
    )


def sandbox_receipt(value):
    return (
        type(value) is dict
        and value.keys() == {"schema", "browser_apparmor", "renderer_apparmor", "renderers_checked"}
        and value["schema"] == "pamolive.p1g-active-sandbox/1"
        and type(value["browser_apparmor"]) is str
        and value["browser_apparmor"] in APPARMOR_MODES
        and type(value["renderer_apparmor"]) is list
        and 0 < len(value["renderer_apparmor"]) <= 3
        and all(type(mode) is str and mode in APPARMOR_MODES for mode in value["renderer_apparmor"])
        and len(set(value["renderer_apparmor"])) == len(value["renderer_apparmor"])
        and type(value["renderers_checked"]) is int
        and len(value["renderer_apparmor"]) <= value["renderers_checked"] < 64
    )


def observe_browser_sandbox(browser, executable, *, namespace_only=False):
    """Check the running browser before navigations to the synthetic application."""
    uid = os.getuid()
    context = browser.new_context(ignore_https_errors=False, service_workers="block")
    try:

        def restrict(route):
            parsed = urlsplit(route.request.url)
            if parsed.scheme == "chrome" and parsed.netloc in {"sandbox", "resources"}:
                route.continue_()
            else:
                route.abort()

        context.route("**/*", restrict)
        diagnostic = context.new_page()
        diagnostic.goto(SANDBOX_URL, wait_until="load", timeout=10000)
        need(diagnostic.url == SANDBOX_URL, "sandbox_internal_origin")
        rows = diagnostic.locator("#sandbox-status tr").evaluate_all(
            """rows => rows.slice(0, 17).map(row =>
                Array.from(row.cells).slice(0, 3)
                    .map(cell => cell.textContent.trim().slice(0, 81)))"""
        )
        evaluation = diagnostic.locator("#evaluation").text_content(timeout=5000)
        layer_one = sandbox_diagnostic(rows, evaluation)
        need(not namespace_only or layer_one == "Namespace", "sandbox_namespace_required")
        inert = context.new_page()
        inert.set_content("<title>PamOlive sandbox probe</title>", timeout=5000)
        session = browser.new_browser_cdp_session()
        try:
            pid, renderers = process_ids(session.send("SystemInfo.getProcessInfo"))
            host = observe_process(pid, uid, executable=executable)
            apparmor = set()
            for renderer in renderers:
                facts = observe_process(renderer, uid)
                need(renderer_sandboxed(facts, host), "renderer_sandbox_not_active")
                apparmor.add(facts["apparmor"])
            later_pid, later_renderers = process_ids(session.send("SystemInfo.getProcessInfo"))
            need(pid == later_pid and renderers <= later_renderers, "sandbox_process_set_changed")
        finally:
            session.detach()
        proof = {
            "schema": "pamolive.p1g-active-sandbox/1",
            "browser_apparmor": host["apparmor"],
            "renderer_apparmor": sorted(apparmor),
            "renderers_checked": len(renderers),
        }
        need(sandbox_receipt(proof), "sandbox_receipt_invalid")
        return proof
    finally:
        context.close()


def source_binding(repo, receipt, revision, *, additional=()):
    reader = bounded(repo)
    raw = reader.read_regular(receipt, 2 * 1024**2)
    value = json.loads(raw)
    need(
        value.get("schema") == "pamolive.committed-build-context.v1"
        and value.get("revision") == revision
        and isinstance(value.get("files"), dict),
        "source_revision",
    )
    pin_name = "qualification/p1g_headless/ui-input-pins.json"
    pin_raw = reader.read_regular(repo / pin_name, 32768)
    need(
        hashlib.sha256(pin_raw).hexdigest() == value["files"].get(pin_name),
        "UI_pin_manifest_drift",
    )
    pins = json.loads(pin_raw)
    need(isinstance(pins, dict) and len(pins) == 24, "UI_input_pin_budget")
    need(len(additional) <= 24 and not set(additional).intersection(pins), "native_input_budget")
    for name in additional:
        pins[name] = value["files"].get(name)
    result = {}
    for name, expected in pins.items():
        path = Path(name)
        need(
            not path.is_absolute()
            and ".." not in path.parts
            and str(path.as_posix()) == name
            and len(name) <= 256,
            "UI_input_path",
        )
        source = repo / name
        need(
            not source.is_symlink() and source.is_file() and source.stat().st_size <= 1024**2,
            "UI_input_file",
        )
        digest = hashlib.sha256(reader.read_regular(source, 1024**2)).hexdigest()
        need(digest == expected == value["files"].get(name), "UI_input_drift")
        result[name] = digest
    return {
        "revision": revision,
        "context_receipt_SHA256": hashlib.sha256(raw).hexdigest(),
        "reviewed_UI_inputs": result,
    }


def fresh_write(path, body, mode=0o600):
    with path.open("xb") as stream:
        need(stream.write(body) == len(body), "short_write")
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def resources(root):
    with Path("/proc/meminfo").open("rb") as stream:
        body = stream.read(65537)
    need(len(body) <= 65536, "meminfo_budget")
    match = re.findall(rb"(?m)^MemAvailable:\s+([0-9]+) kB$", body)
    need(len(match) == 1, "meminfo_shape")
    available = int(match[0]) * 1024
    disk = os.statvfs(root)
    free = disk.f_bavail * disk.f_frsize
    need(available >= 3072 * 1024**2 and free >= 8 * 1024**3, "browser_resource_minimum")
    return {
        "MemAvailable_bytes": available,
        "workspace_free_bytes": free,
        "reservation_or_continued_availability_claimed": False,
    }


def tool_pin(path, *, root_owner=True, cap=512 * 1024**2):
    need(path.is_absolute() and path.resolve(strict=True) == path, "tool_alias_refused")
    before = path.lstat()

    def identity(row):
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
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and not before.st_mode & 0o6022
        and 0 < before.st_size <= cap
        and before.st_uid == (0 if root_owner else os.getuid()),
        "tool_type_owner_mode",
    )
    if root_owner:
        for parent in path.parents:
            row = parent.lstat()
            need(
                stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022,
                "tool_parent_writable_or_alias",
            )
    digest, count, magic = hashlib.sha256(), 0, b""
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        need(identity(opened) == identity(before), "tool_fd_identity")
        while chunk := stream.read(min(1024**2, cap + 1 - count)):
            count += len(chunk)
            need(count <= cap, "tool_byte_budget")
            if not magic:
                magic = chunk[:4]
            digest.update(chunk)
    after = path.lstat()
    need(
        identity(before) == identity(after) and count == before.st_size and magic == b"\x7fELF",
        "tool_changed_or_not_ELF",
    )
    return {
        "sha256": digest.hexdigest(),
        "bytes": count,
        "uid": before.st_uid,
        "mode": stat.S_IMODE(before.st_mode),
    }


def playwright_node_pin(path):
    facts = tool_pin(path, root_owner=False, cap=SDK_NODE_BYTES)
    need(
        facts["bytes"] == SDK_NODE_BYTES and facts["sha256"] == SDK_NODE_SHA,
        "playwright_driver_identity",
    )
    return facts


def chrome_tool_diagnostic(error, *, phase):
    """Last fixed-path metadata only; neither admission nor the failed stat itself."""
    if phase != "chrome_tool_preflight":
        return None
    codes = {
        "tool_alias_refused",
        "tool_type_owner_mode",
        "tool_parent_writable_or_alias",
        "tool_fd_identity",
        "tool_byte_budget",
        "tool_changed_or_not_ELF",
    }
    code = "unknown"
    if (
        type(error) is ValueError
        and len(error.args) == 1
        and type(error.args[0]) is str
        and error.args[0] in codes
    ):
        code = error.args[0]
    leaf = {
        "state": "unknown",
        "type": "unknown",
        "uid": None,
        "gid": None,
        "mode": None,
        "nlink": None,
        "size_bytes": None,
        "alias": None,
    }
    path = Path("/opt/google/chrome/chrome")
    try:
        info = path.lstat()
        fields = (
            (info.st_mode, 0o177777),
            (info.st_uid, 2**32 - 1),
            (info.st_gid, 2**32 - 1),
            (info.st_nlink, 2**32 - 1),
            (info.st_size, 2**63 - 1),
        )
        if all(type(value) is int and 0 <= value <= bound for value, bound in fields):
            kind = (
                "regular"
                if stat.S_ISREG(info.st_mode)
                else "directory"
                if stat.S_ISDIR(info.st_mode)
                else "symlink"
                if stat.S_ISLNK(info.st_mode)
                else "other"
            )
            leaf.update(
                state="observed",
                type=kind,
                uid=info.st_uid,
                gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode),
                nlink=info.st_nlink,
                size_bytes=info.st_size,
            )
            try:
                leaf["alias"] = path.resolve(strict=True) != path
            except (OSError, RuntimeError, ValueError):
                pass
    except FileNotFoundError:
        leaf.update(state="absent", type="absent")
    except (OSError, RuntimeError, ValueError, AttributeError):
        pass
    return {"schema": "pamolive.p1g-chrome-tool-diagnostic/1", "code": code, "leaf": leaf}


def bounded(repo):
    path = repo / "deploy/expat-remediation/bounded_io.py"
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == BOUNDED_SHA, "bounded_helper_pin")
    spec = importlib.util.spec_from_file_location("p1g_bounded", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def public_command(io, args, home, journal, *, seconds=10, cap=65536):
    before = tool_pin(Path(args[0]))
    journal.mkdir(mode=0o700)
    fresh_write(journal / "intent.json", json.dumps({"state": "PENDING", "tool": before}).encode())
    try:
        result = io.run_capped(
            args,
            env={"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C", "LC_ALL": "C"},
            cwd=str(home),
            timeout=seconds + 5,
            work_timeout=seconds,
            stdout_cap=cap,
            stderr_cap=cap,
            total_cap=2 * cap,
            on_spawn=lambda pid: fresh_write(
                journal / "pid.json", json.dumps({"pid": pid}).encode()
            ),
            owned_session=True,
        )
        fresh_write(journal / "result.json", json.dumps(result.facts()).encode())
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
            and result.exception_type is None
            and result.cleanup_exception_type is None
            and not result.stderr,
            "public_command_failed_or_unknown",
        )
        need(tool_pin(Path(args[0])) == before, "public_tool_changed")
    except BaseException:
        fresh_write(journal / "UNKNOWN.json", b'{"state":"UNKNOWN"}\n')
        raise
    return result.stdout, {"tool": before, "process": result.facts()}


def prepare_tls(private, repo):
    """Only in the explicitly admitted disposable Linux job, never on preparation PC."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(UTC)
    ca_key, leaf_key = (
        ec.generate_private_key(ec.SECP256R1()),
        ec.generate_private_key(ec.SECP256R1()),
    )
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "PamOlive P1G synthetic TLS root")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(ca_key, hashes.SHA256())
    )
    fresh_write(private / "ca.der", ca.public_bytes(serialization.Encoding.DER))
    fresh_write(private / "server.pem", leaf.public_bytes(serialization.Encoding.PEM))
    fresh_write(
        private / "server.key",
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    # No CA private key is written. Server key and empty NSS DB stay private, never artifacts.
    home = private / "browser-home"
    home.mkdir(mode=0o700)
    database = home / ".local/share/pki/nssdb"
    database.mkdir(mode=0o700, parents=True)
    io = bounded(repo)
    base = ["/usr/bin/certutil", "-d", "sql:" + str(database)]
    receipts = []
    for index, args in enumerate(
        (
            base + ["-N", "--empty-password"],
            base
            + [
                "-A",
                "-n",
                "PamOlive P1G synthetic TLS root",
                "-t",
                "C,,",
                "-i",
                str(private / "ca.der"),
            ],
        )
    ):
        out, facts = public_command(io, args, home, private / f"nss-{index}")
        need(out == b"", "nss_unexpected_stdout")
        receipts.append(facts)
    der, facts = public_command(
        io, base + ["-L", "-n", "PamOlive P1G synthetic TLS root", "-r"], home, private / "nss-2"
    )
    need(der == ca.public_bytes(serialization.Encoding.DER), "nss_CA_export_changed")
    receipts.append(facts)
    listing, facts = public_command(io, base + ["-L"], home, private / "nss-3")
    need(
        len(re.findall(rb"(?m)^PamOlive P1G synthetic TLS root\s+C,,\s*$", listing)) == 1,
        "nss_CA_trust_wrong",
    )
    receipts.append(facts)
    return {
        "CA_DER_SHA256": hashlib.sha256(der).hexdigest(),
        "NSS_commands": receipts,
        "browser_home": str(home),
        "server_certificate": str(private / "server.pem"),
        "server_key": str(private / "server.key"),
    }


def chrome_target(repo, *, mode=None):
    """One typed resolver for all three readers; v3 is explicit, never fallback."""
    mode = os.environ.get("P1G_CHROME_MODE", "legacy-installed-v2") if mode is None else mode
    need(mode in {"legacy-installed-v2", "test-bundle-v3"}, "chrome_mode")
    if mode == "legacy-installed-v2":
        path = Path("/opt/google/chrome/chrome")
        return path, tool_pin(path)
    guard(os.environ)
    source_binding(
        repo, Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", os.environ["GITHUB_SHA"]
    )
    reader = bounded(repo)
    context_raw = reader.read_regular(
        Path(os.environ["RUNNER_TEMP"]) / "p1g-source.json", 2 * 1024**2
    )
    context = json.loads(context_raw)
    name = "qualification/p1g_headless/chrome-bootstrap-pins.json"
    pins_raw = reader.read_regular(repo / name, 131072)
    need(
        hashlib.sha256(pins_raw).hexdigest() == context["files"].get(name),
        "bundle_manifest_context",
    )
    pins = json.loads(pins_raw)
    name = "qualification/p1g_headless/chrome_bundle.py"
    raw = reader.read_regular(repo / name, 131072)
    need(
        hashlib.sha256(raw).hexdigest()
        == pins["source_files"].get(name)
        == context["files"].get(name),
        "bundle_helper_context",
    )
    spec = importlib.util.spec_from_file_location("p1g_reviewed_bundle", repo / name)
    bundle = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = bundle
    exec(compile(raw, str(repo / name), "exec"), bundle.__dict__)
    name = "qualification/p1g_headless/chrome-bundle-profile.json"
    profile_raw = reader.read_regular(repo / name, 4 * 1024**2)
    need(
        hashlib.sha256(profile_raw).hexdigest()
        == bundle.PROFILE_SHA
        == pins["source_files"].get(name)
        == context["files"].get(name),
        "bundle_profile_context",
    )
    expected = {
        "revision": os.environ["GITHUB_SHA"],
        "pins_manifest_sha256": hashlib.sha256(pins_raw).hexdigest(),
        "context_receipt_sha256": hashlib.sha256(context_raw).hexdigest(),
        "package_version": pins["package"]["Version"],
    }
    runtime_check, runtime_postcheck = bundle_runtime_checker(
        repo, pins, context, pins_raw, context_raw, reader
    )
    path, pin = bundle.verify(
        os.environ,
        expected,
        profile_raw,
        bundle.PROFILE_SHA,
        until=__import__("time").monotonic() + 30,
        runtime_check=runtime_check,
    )
    runtime_postcheck()
    # Preserve the existing strong ELF/ancestry guard as an additional check.
    need(tool_pin(path) == pin, "bundle_target_changed")
    return path, pin


def bundle_runtime_checker(repo, pins, context, pins_raw, context_raw, reader):
    """Reuse the historical Root proof contract, never a producer boolean."""
    name = "qualification/p1g_headless/chrome_bootstrap.py"
    raw = reader.read_regular(repo / name, 131072)
    source_sha = hashlib.sha256(raw).hexdigest()
    need(
        source_sha == pins["source_files"].get(name) == context["files"].get(name),
        "bundle_runtime_validator_context",
    )
    spec = importlib.util.spec_from_file_location("p1g_reviewed_root_validator", repo / name)
    validator = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = validator
    exec(compile(raw, str(repo / name), "exec"), validator.__dict__)
    support = sys.modules[__name__]
    role = validator.root_interpreter_pin(support)

    def check(facts):
        validator.check_root_interpreter(
            facts,
            role,
            context_sha=hashlib.sha256(context_raw).hexdigest(),
            pins_sha=hashlib.sha256(pins_raw).hexdigest(),
            source_sha=source_sha,
            revision=os.environ["GITHUB_SHA"],
        )

    def postcheck():
        need(validator.root_interpreter_pin(support) == role, "root_interpreter_changed")

    return check, postcheck
