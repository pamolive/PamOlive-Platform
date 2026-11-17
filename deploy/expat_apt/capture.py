"""Automated public acquisition -> authenticated APT dry run -> UNAPPROVED data only."""

import io
import json
import os
import sys
import tarfile
import time
from pathlib import Path

SQV_DEB = "41553e3ca006ed490692872a3e0009247bcfcee92f180f611559f6e8cd152210"
SQV_URL = "https://deb.debian.org/debian/pool/main/r/rust-sequoia-sqv/sqv_1.5.0-1_amd64.deb"


def need(value, code):
    if not value:
        raise ValueError(code)


def worker_failure_diagnostic(result, codecs):
    # Never inspect partial buffers, timeouts, kills or uncertain completion.
    if not (
        result.ok is False
        and result.spawn_attempted is True
        and type(result.pid) is int
        and result.pid > 0
        and type(result.returncode) is int
        and result.returncode == 42
        and type(result.reason) is str
        and result.reason == "nonzero_exit"
        and result.exception_type is result.cleanup_exception_type is None
        and result.owned_child_reaped is True
        and result.drains_complete is True
        and result.killed_owned_child is False
        and type(result.stdout) is bytes
        and 0 < len(result.stdout) <= 2048
        and type(result.stderr) is bytes
        and result.stderr == b""
    ):
        return None
    try:
        value = codecs.json_data(result.stdout)
        if not (
            type(value) is dict
            and set(value) == {"schema", "state", "code_index", "phase", "kind", "operational_GO"}
            and value["schema"] == "pamolive.expat-C-worker-failure-DATA/1"
            and value["state"] == "REFUSED_OR_UNKNOWN"
            and type(value["code_index"]) is int
            and 0 <= value["code_index"] <= 57
            and type(value["phase"]) is str
            and value["phase"]
            in (
                "UNKNOWN",
                "bootstrap",
                "request",
                "acquire",
                "connect",
                "headers",
                "body",
                "decode",
                "write_output",
            )
            and type(value["kind"]) is str
            and value["kind"] in {"UNKNOWN", "TLS_CERTIFICATE", "TLS", "TIMEOUT", "OS", "CONTRACT"}
            and value["operational_GO"] is False
        ):
            return None
        return value
    except Exception:
        return None


class Network:
    def __init__(self, io_helper, transaction, pins, until, codecs, code_sha):
        self.io, self.t, self.pins, self.until = io_helper, transaction, pins, until
        self.m = codecs
        self.code_sha = code_sha
        self.count, self.total, self.unknown = 0, 0, False
        self.root = transaction.WORK / "network"
        self.root.mkdir(mode=0o700)
        self.proof = transaction.PROOF / "network"
        self.proof.mkdir(mode=0o700)
        self.records = []

    def tool(self):
        p = Path("/usr/local/bin/python3.12")
        raw = self.t.read_regular(p, 64 * 1024**2)
        row = p.lstat()
        need(
            row.st_uid == row.st_gid == 0
            and not row.st_mode & 0o6022
            and raw.startswith(b"\x7fELF"),
            "bootstrap_python_role",
        )
        return self.t.sha(raw), self.t.identity(row)

    def perform(self, op, **fields):
        need(
            not self.unknown and self.count < 1024 and time.monotonic() + 20 < self.until,
            "network_budget_or_UNKNOWN",
        )
        self.count += 1
        folder = self.root / str(self.count)
        folder.mkdir(mode=0o700)
        proof = self.proof / str(self.count)
        proof.mkdir(mode=0o700)
        request_path, destination = folder / "request.json", folder / "body.data"
        work = min(180, self.until - time.monotonic() - 10)
        request = {
            "schema": "pamolive.expat-C-worker/1",
            "op": op,
            "destination": str(destination),
            "until": min(self.until - 10, time.monotonic() + work),
            **fields,
        }
        self.t.write_new(request_path, json.dumps(request).encode())
        self.t.write_new(proof / "intent.json", b'{"state":"PENDING"}')
        worker = self.t.HERE / "network_worker.py"
        worker_raw = self.t.read_regular(worker, 131072)
        need(
            self.t.sha(worker_raw) == self.pins["network_worker.py"],
            "worker_source_pin",
        )
        pin = self.tool()
        need(
            self.t.sha(self.t.read_regular(self.t.HERE / "code-pins.json", 16384)) == self.code_sha,
            "external_worker_code_pin",
        )
        self.t.write_new(
            proof / "tool.json",
            json.dumps(
                {
                    "python_sha256": pin[0],
                    "python_identity": pin[1],
                    "worker_source_sha256": self.pins["network_worker.py"],
                    "code_pins_sha256": self.code_sha,
                }
            ).encode(),
        )
        try:
            result = self.io.run_capped(
                [
                    "/usr/local/bin/python3.12",
                    "-I",
                    "-B",
                    "-S",
                    str(worker),
                    str(request_path),
                    self.code_sha,
                ],
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "HOME": str(folder),
                },
                cwd=str(folder),
                timeout=work + 10,
                work_timeout=work,
                deadline=self.until,
                stdout_cap=16384,
                stderr_cap=16384,
                total_cap=32768,
                owned_session=True,
                on_spawn=lambda pid: self.t.write_new(
                    proof / "pid.json", json.dumps({"pid": pid}).encode()
                ),
            )
            facts = result.facts()
            self.t.write_new(proof / "result.json", json.dumps(facts).encode())
            # Best effort closed DATA projection; the original strict refusal still follows.
            try:
                failure = worker_failure_diagnostic(result, self.m)
                if failure is not None:
                    self.t.write_new(proof / "worker-failure.json", json.dumps(failure).encode())
            except Exception:
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
                and result.killed_owned_child is False
                and result.stderr == b""
                and self.tool() == pin
                and self.t.read_regular(worker, 131072) == worker_raw
                and self.t.sha(self.t.read_regular(self.t.HERE / "code-pins.json", 16384))
                == self.code_sha,
                "worker_unknown",
            )
            packet = self.m.json_data(result.stdout)
            need(
                type(packet) is dict
                and set(packet) == {"schema", "state", "bytes", "sha256"}
                and packet["schema"] == "pamolive.expat-C-worker-result/1"
                and packet["state"] == "COMPLETE"
                and type(packet["bytes"]) is int
                and 0 <= packet["bytes"] <= 128 * 1024**2,
                "worker_packet",
            )
            raw = self.t.read_regular(destination, 128 * 1024**2, allow_empty=True)
            need(
                len(raw) == packet["bytes"] and self.t.sha(raw) == packet["sha256"],
                "worker_bytes",
            )
            self.total += len(raw)
            need(self.total <= 2 * 1024**3, "aggregate_public_bytes")
            self.records.append(
                {
                    "ordinal": self.count,
                    "op": op,
                    "bytes": len(raw),
                    "sha256": self.t.sha(raw),
                    "H1": facts,
                }
            )
            return raw, destination
        except BaseException:
            self.unknown = True
            self.t.write_new(
                proof / "UNKNOWN.json",
                b'{"state":"UNKNOWN","resources_released":false}',
            )
            raise

    def public(self, url, *, cap, sha=None, size=None):
        return self.perform("public", url=url, cap=cap, expected_sha256=sha, expected_bytes=size)

    def registry(self, digest, kind, maximum, size=None):
        return self.perform(
            "registry",
            digest=digest,
            kind=kind,
            cap=maximum,
            expected_sha256=digest[7:],
            expected_bytes=size,
        )[0]


def parent(network, transaction, m, g, codec):
    layout = Path("/c-base")
    blobs = layout / "blobs/sha256"
    blobs.mkdir(mode=0o700, parents=True)

    def save(digest, kind, cap, size=None):
        raw = network.registry(digest, kind, cap, size)
        transaction.write_new(blobs / digest[7:], raw)
        return raw

    index = codec.parse(save(g.BASE, "index", 1024**2), 1024**2)
    chosen = codec.select(index)
    need(chosen["digest"] == g.MANIFEST, "expected_platform_manifest")
    manifest = codec.parse(save(g.MANIFEST, "manifest", 1024**2, chosen["size"]), 1024**2)
    config = codec.descriptor(manifest["config"], codec.CONFIG_TYPES, 1024**2)
    need(config["digest"] == g.CONFIG, "expected_config")
    save(g.CONFIG, "config", 1024**2, config["size"])
    layers = [
        codec.descriptor(r, codec.GZIP_TYPES | codec.RAW_TYPES, 64 * 1024**2)
        for r in manifest["layers"]
    ]
    need(
        len(layers) == 4 and sum(r["size"] for r in layers) <= 256 * 1024**2,
        "parent_layers",
    )
    for row in layers:
        save(row["digest"], "layer", 64 * 1024**2, row["size"])
    value = m.base_inventory(layout)
    g.Gate(m).parent(value)
    return value


def verifier(raw, m, g):
    need(len(raw) == 703756 and g.sha(raw) == SQV_DEB, "SQV_supplier_DEB")
    control, inventory = m.deb(raw, payload=True)
    need(m.package_identity(control) == ("sqv", "1.5.0-1", "amd64"), "SQV_control")
    row = inventory.get("usr/bin/sqv", {})
    need(
        row.get("type") == "file"
        and row.get("mode") == 0o755
        and row.get("uid") == row.get("gid") == 0
        and row.get("sha256") == g.SQV_SHA
        and row.get("size") == 1935072,
        "SQV_payload_map",
    )
    members = m.ar_members(raw)
    name = next(n for n in members if n.startswith("data.tar"))
    result = None
    with m.decompressor(name, members[name]) as stream:
        bounded = m.PhysicalReader(stream, 512 * 1024**2)
        with tarfile.open(fileobj=bounded, mode="r|", tarinfo=m.LimitedTarInfo) as archive:
            for item in archive:
                if m.tar_name(item.name) == "usr/bin/sqv":
                    need(
                        result is None and item.isfile() and item.size == 1935072,
                        "SQV_exact_regular",
                    )
                    result = archive.extractfile(item).read(1935073)
        bounded.drain()
    need(
        type(result) is bytes and len(result) == 1935072 and g.sha(result) == g.SQV_SHA,
        "SQV_exact_bytes",
    )
    return result


def authenticated_index(network, runner, m, g, suite, rule, root):
    signed, _ = network.public(rule["uri"] + "dists/" + suite + "/InRelease", cap=1024**2)
    clear, certs = runner.signature(signed, suite, rule)
    fields = m.one_control(clear)
    g.scalar_fields(fields, ("Origin", "Codename", "Date", "Valid-Until"))
    checks = m.release(
        clear,
        codename=suite,
        max_age_days=rule["max_age_days"],
        valid_until_required=rule["valid_until_required"],
        now=g.datetime.fromtimestamp(time.time(), g.UTC),
    )
    compressed_key = "main/binary-amd64/Packages.xz"
    raw_key = "main/binary-amd64/Packages"
    need(compressed_key in checks and raw_key in checks, "signed_raw_and_XZ_required")
    packed, raw_entry = checks[compressed_key], checks[raw_key]
    need(
        0 < packed["size"] <= 32 * 1024**2 and 0 <= raw_entry["size"] <= m.MAX_INDEX,
        "index_caps",
    )
    cost = len(signed) + len(clear) + packed["size"] + raw_entry["size"]
    need(
        getattr(runner, "metadata_bytes", 0) + cost <= m.MAX_META,
        "metadata_aggregate_before_use",
    )
    runner.metadata_bytes = getattr(runner, "metadata_bytes", 0) + cost
    uri = rule["uri"] + "dists/" + suite + "/main/binary-amd64/by-hash/SHA256/" + packed["sha256"]
    compressed, path = network.public(
        uri, cap=32 * 1024**2, sha=packed["sha256"], size=packed["size"]
    )
    index, _ = network.perform(
        "xz",
        source=str(path),
        expected_sha256=packed["sha256"],
        expected_bytes=packed["size"],
        raw_bytes=raw_entry["size"],
        raw_sha256=raw_entry["sha256"],
    )
    # Full scalar/identity framing check BEFORE APT sees these authenticated bytes.
    count = 0
    for row in m.controls(io.BytesIO(index), maximum=m.MAX_INDEX, max_line=128 * 1024):
        count += 1
        need(count <= 300000, "index_stanza_cap")
        g.scalar_fields(
            row,
            (
                "Package",
                "Version",
                "Architecture",
                "Filename",
                "Size",
                "SHA256",
                "Source",
            ),
        )
        m.package_identity(row)
    runner.verified_releases[suite] = (clear, certs)
    for suffix, raw in (
        (".InRelease", signed),
        (".Release", clear),
        (".Packages", index),
        (".Packages.xz", compressed),
    ):
        runner.t.write_new(root / "metadata" / (suite + suffix), raw)
    return signed, clear, index, certs


def run(args, pins, m, g, io_helper, t, *, deadline):
    need(
        sys.platform == "linux" and os.getuid() == os.geteuid() == 0,
        "disposable_Linux_builder",
    )
    until = deadline
    policy_raw = t.read_regular("/c-authority/policy.json", 1024**2)
    gate = g.Gate(m)
    policy = gate.policy(policy_raw, args.policy_sha)
    t.WORK.mkdir(mode=0o700)
    t.PROOF.mkdir(mode=0o700)
    root = Path("/c-capture")
    root.mkdir(mode=0o700)
    for name in ("metadata", "debs", "authority", "bootstrap"):
        (root / name).mkdir(mode=0o700)
    network = Network(io_helper, t, pins, until, m, args.code_pins_sha)
    codec = t.load("expat_oci_codec", "oci_codec.py", pins["oci_codec.py"])
    base = parent(network, t, m, g, codec)
    runner = t.Runner(io_helper, m, base, until=until)
    fence = t.load("expat_solver_fence", "solver_fence.py", pins["solver_fence.py"])
    native = m.json_data(t.read_regular("/c-fence-native/summary.json", 16384))
    fence.validate_native_summary(native, args.code_pins_sha, pins)
    runner.solver_fence_module = fence
    runner.solver_fence_sha = pins["solver_fence.py"]
    runner.solver_code_sha = args.code_pins_sha
    runner.t = t
    runner.verified_releases = {}
    # Tie the actual interpreter role to the same admitted base after its independent capture.
    py = runner.live("usr/local/bin/python3.12")
    need(g.sha(py) == network.tool()[0], "actual_bootstrap_Python_not_base")
    before = runner.live("var/lib/dpkg/status")
    t.write_new(root / "status-before", before)
    t.write_new(
        t.WORK / "debian-archive-keyring.pgp",
        runner.live("usr/share/keyrings/debian-archive-keyring.pgp"),
    )
    bootstrap, _ = network.public(SQV_URL, cap=703756, sha=SQV_DEB, size=703756)
    t.write_new(root / "verifier.deb", bootstrap)
    verifier_bytes = verifier(bootstrap, m, g)
    t.write_new(root / "bootstrap/sqv.data", verifier_bytes)
    t.write_new(t.WORK / "sqv", verifier_bytes, 0o500)
    runner.verifier_sha = g.SQV_SHA
    out, err = runner.call([str(t.WORK / "sqv"), "--version"], seconds=5, cap=1024)
    need(out == t.VERSION and err == b"", "verifier_runtime_version")
    indices, signed_map = {}, {}
    for suite, rule in policy["repositories"].items():
        signed, _, index, _ = authenticated_index(network, runner, m, g, suite, rule, root)
        signed_map[suite] = signed
        indices[suite] = index
    solver = t.load("expat_solver", "solver.py", pins["solver.py"])
    simulation = solver.configure(runner, g, indices, signed_map, t)
    selected = solver.parse_plan(simulation, indices, gate.status(before), m)
    need(runner.live("var/lib/dpkg/status") == before, "simulation_mutated_status")
    spec = {
        "schema": "pamolive.expat-prepared.spool/1",
        "metadata": {
            s: {
                "inrelease": "metadata/" + s + ".InRelease",
                "index": "metadata/" + s + ".Packages",
            }
            for s in g.REPOSITORIES
        },
        "selection": [],
    }
    for row in selected:
        record = row.pop("record")
        raw, _ = network.public(
            policy["repositories"][row["suite"]]["uri"] + record["Filename"],
            cap=m.MAX_DEB,
            sha=record["SHA256"],
            size=int(record["Size"]),
        )
        t.write_new(root / row["deb"], raw)
        spec["selection"].append(row)
    t.write_new(root / "manifest.json", g.canonical(spec))

    # Reuse normal verified immutable buffers; do not rerun SQV into the same path.
    def verified(raw, suite, _rule):
        need(raw == signed_map[suite], "signed_buffer_changed_after_verification")
        return runner.verified_releases[suite]

    def read(name, cap):
        return t.read_regular(root / name, cap, allow_empty=name.endswith(".Packages"))

    material, debs, releases, _ = gate.capture(
        policy_raw,
        args.policy_sha,
        g.canonical(spec),
        read,
        verified,
        base,
        before,
        int(time.time()),
    )
    gate.freshness(releases, int(time.time()))
    need(
        t.read_regular("/var/lib/dpkg/status", 4 * 1024**2) == before
        and not runner.unknown
        and not network.unknown
        and time.monotonic() < until,
        "capture_changed_state_or_UNKNOWN",
    )
    t.write_new(root / "authority/policy.json", policy_raw)
    t.write_new(root / "authority/material-set.json", g.canonical(material))
    t.write_new(root / "material-set.UNAPPROVED.json", g.canonical(material))
    t.write_new(
        root / "plan.json",
        g.canonical(
            {
                "schema": "pamolive.expat-prepared.unapproved-plan/2",
                "requests": list(g.REQUESTS),
                "transitions": material["transitions"],
                "simulation_stdout_sha256": g.sha(simulation),
                "installed": False,
                "authority": False,
            }
        ),
    )
    t.write_new(
        root / "result.json",
        g.canonical(
            {
                "state": "AUTHENTICATED_UNAPPROVED_NOT_INSTALLED",
                "policy_sha256": args.policy_sha,
                "code_pins_sha256": args.code_pins_sha,
                "material_set_sha256": g.sha(g.canonical(material)),
                "parent": material["parent"],
                "prestate_sha256": g.sha(before),
                "poststate_sha256": g.sha(before),
                "network_frontends": network.count,
                "native_frontends": runner.ordinal,
                "build_verified": False,
                "materials_complete": False,
                "compiler_SDK_generated_state_closed": False,
                "other_builder_boundaries_closed": False,
                "all_OS_descendants_released": False,
            }
        ),
    )
    return 0
