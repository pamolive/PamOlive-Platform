"""Finite synthetic bytes and fake native boundaries; no payload execution."""

import copy
import hashlib
import importlib.util
import io
import json
import lzma
import sys
import tarfile
import unittest
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT / "deploy/expat_apt"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, CODE / file)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


m = module("c_reviewed_materials", "materials.py")
g = module("c_gate", "gate.py")
t = module("c_transaction", "transaction.py")
fence = module("c_solver_fence", "solver_fence.py")
NOW = int(datetime(2026, 11, 16, 12, tzinfo=UTC).timestamp())
CERT = "04B54C3CDCA79751B16BC6B5225629DF75B188BD"


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:") as archive:
        for name, raw in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid = len(raw), 0o644, 0, 0
            archive.addfile(info, io.BytesIO(raw))
    return out.getvalue()


def deb(name, version, control_extra=b""):
    control = f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n".encode() + control_extra
    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar", tar([("control", control)])),
        ("data.tar", tar([("usr/share/synthetic-c/" + name, b"PUBLIC_SYNTHETIC_DATA")])),
    ]
    out = bytearray(b"!<arch>\n")
    for filename, raw in members:
        header = (
            (filename + "/").ljust(16)
            + "0".ljust(12)
            + "0".ljust(6)
            + "0".ljust(6)
            + "100644".ljust(8)
            + str(len(raw)).ljust(10)
            + "`\n"
        ).encode()
        assert len(header) == 60
        out.extend(header + raw + (b"\n" if len(raw) % 2 else b""))
    return bytes(out)


class Fixture:
    def __init__(self):
        self.gate = g.Gate(m)
        self.before = (
            b"Package: inherited-base\nVersion: 1\nArchitecture: amd64\n"
            b"Status: install ok installed\n\n"
        )
        self.policy = {
            "schema": "pamolive.expat-prepared.apt-policy/1",
            "stage": g.STAGE,
            "parent": g.BASE,
            "requests": list(g.REQUESTS),
            "base_supplier_tcb": (
                "Docker-Official-python-Root-pinned-OCI-digest-TLS-bootstrap-not-build-attestation"
            ),
            "repositories": {
                suite: {
                    "uri": uri,
                    "allowed_certificates": [CERT],
                    "required_any_current": [CERT],
                    "max_age_days": 7,
                    "valid_until_required": True,
                }
                for suite, uri in g.REPOSITORIES.items()
            },
            "bootstrap": {
                "verifier_sha256": g.SQV_SHA,
                "verifier_bytes": 1935072,
                "keyring_sha256": g.KEYRING_SHA,
                "supplier_tcb": (
                    "Debian-official-HTTPS-plus-Root-approved-SHA-not-tool-build-attestation"
                ),
            },
            "maintainer_scripts_tcb": (
                "signed-reviewed-Debian-DEBs-root-hooks-no-global-output-proof"
            ),
        }
        self.base = {
            "root_digest": g.BASE,
            "linux_manifest_digest": g.MANIFEST,
            "config_digest": g.CONFIG,
            "layers": [{"digest": "sha256:" + str(n) * 64} for n in range(4)],
            "diff_ids": ["sha256:" + str(n + 4) * 64 for n in range(4)],
            "files": {},
        }
        for name in ("usr", "usr/share", "usr/share/keyrings", "var", "var/lib", "var/lib/dpkg"):
            self.base["files"][name] = {"type": "dir", "mode": 0o755, "uid": 0, "gid": 0}
        self.base["files"]["usr/share/keyrings/debian-archive-keyring.pgp"] = {
            "type": "file",
            "sha256": g.KEYRING_SHA,
        }
        self.base["files"]["var/lib/dpkg/status"] = {"type": "file", "sha256": g.sha(self.before)}
        self.spec = {"schema": "pamolive.expat-prepared.spool/1", "metadata": {}, "selection": []}
        self.blobs, self.releases, self.events = {}, {}, []
        records = []
        for request in g.REQUESTS:
            name, _, version = request.partition("=")
            version = version or "1-1"
            raw = deb(name, version)
            path = "debs/" + g.sha(raw) + ".deb"
            self.blobs[path] = raw
            self.spec["selection"].append(
                {
                    "suite": "trixie",
                    "package": name,
                    "version": version,
                    "architecture": "amd64",
                    "deb": path,
                }
            )
            records.append(
                f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
                f"Filename: pool/main/synthetic/{name}.deb\nSize: {len(raw)}\n"
                f"SHA256: {g.sha(raw)}\n\n"
            )
        for suite in g.REPOSITORIES:
            value = {
                "inrelease": "metadata/" + suite + ".InRelease",
                "index": "metadata/" + suite + ".Packages",
            }
            self.spec["metadata"][suite] = value
            index = "".join(records).encode() if suite == "trixie" else b""
            self.blobs[value["index"]] = index
            self.blobs[value["inrelease"]] = (
                b"-----BEGIN PGP SIGNED MESSAGE-----\n" + suite.encode()
            )
            self.release(suite)

    def release(self, suite, *, date=NOW - 60, expiry=NOW + 3600):
        index = self.blobs[self.spec["metadata"][suite]["index"]]
        self.releases[suite] = (
            f"Origin: Debian\nCodename: {suite}\n"
            f"Date: {format_datetime(datetime.fromtimestamp(date, UTC))}\n"
            f"Valid-Until: {format_datetime(datetime.fromtimestamp(expiry, UTC))}\nSHA256:\n"
            f" {g.sha(index)} {len(index)} main/binary-amd64/Packages\n"
        ).encode()

    def read(self, path, cap):
        self.events.append(("read", path))
        raw = self.blobs[path]
        assert len(raw) <= cap
        return raw

    def signature(self, raw, suite, rule):
        self.events.append(("signature", suite))
        assert raw == self.blobs[self.spec["metadata"][suite]["inrelease"]]
        return self.releases[suite], (CERT,)

    def capture(self, **kwargs):
        policy = g.canonical(self.policy)
        return self.gate.capture(
            policy,
            g.sha(policy),
            g.canonical(self.spec),
            self.read,
            kwargs.pop("signature", self.signature),
            self.base,
            self.before,
            kwargs.pop("now", NOW),
            **kwargs,
        )


class BoundaryTests(unittest.TestCase):
    def test_01_real_codecs_bind_fourteen_arguments_not_fourteen_global_authorities(self):
        f = Fixture()
        material, debs, releases, files = f.capture()
        self.assertEqual(len(material["requests"]), 14)
        self.assertEqual(len(debs), 14)
        self.assertEqual(len(releases), 3)
        self.assertEqual(len(files), 20)
        self.assertEqual(material["operation"], "install-with-exact-reviewed-transitions")
        for field in (
            "build_verified",
            "materials_complete",
            "other_builder_boundaries_closed",
            "cryptographic_build_attestation_verified",
            "compiler_SDK_generated_state_closed",
        ):
            self.assertIs(material[field], False)

    def test_02_policy_pin_is_external_and_legacy_eight_or_upgrade_shape_is_refused(self):
        f = Fixture()
        raw = g.canonical(f.policy)
        for expected in (None, "", "f" * 64):
            with self.assertRaises(ValueError):
                f.gate.policy(raw, expected)
        for field, value in (
            ("requests", list(g.REQUESTS[:8])),
            ("parent", "sha256:" + "f" * 64),
            ("upgrade", True),
            ("approved", True),
        ):
            value = g.canonical(f.policy | {field: value})
            with self.assertRaises(ValueError):
                f.gate.policy(value, g.sha(value))

    def test_03_wrong_parent_or_base_keyring_cannot_reach_crypto_or_DEB(self):
        for field, value in (("root_digest", "sha256:" + "f" * 64), ("config_digest", g.MANIFEST)):
            f = Fixture()
            f.base[field] = value
            with self.assertRaises(ValueError):
                f.capture()
            self.assertEqual(f.events, [])
        f = Fixture()
        f.base["files"]["usr/share/keyrings/debian-archive-keyring.pgp"]["sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            f.capture()
        self.assertEqual(f.events, [])

    def test_04_actual_prestate_must_be_exact_base_not_an_observed_replacement(self):
        f = Fixture()
        f.before += b"PRIVATE_UNKNOWN"
        with self.assertRaisesRegex(ValueError, "prestate"):
            f.capture()
        self.assertEqual(f.events, [])

    def test_05_signature_failure_and_non_authority_certificates_precede_index_use(self):
        for certs in (("F" * 40,), (CERT, CERT), (), (CERT, "F" * 40)):
            f = Fixture()

            def signature(raw, suite, rule):
                return f.releases[suite], certs

            with self.assertRaises(ValueError):
                f.capture(signature=signature)
            self.assertFalse(
                any(path.endswith(".Packages") for kind, path in f.events if kind == "read")
            )
        f = Fixture()
        with self.assertRaisesRegex(ValueError, "native UNKNOWN"):
            f.capture(signature=lambda *args: (_ for _ in ()).throw(ValueError("native UNKNOWN")))

    def test_06_signed_index_corruption_never_reaches_the_DEB_parser(self):
        f = Fixture()
        f.blobs[f.spec["metadata"]["trixie"]["index"]] += b"corruption"
        with patch.object(m, "deb", side_effect=AssertionError("DEB parser forbidden")):
            with self.assertRaisesRegex(ValueError, "index_binding"):
                f.capture()

    def test_07_signed_record_hash_and_size_pass_before_any_TAR_parse(self):
        f = Fixture()
        name = min(f.spec["selection"], key=lambda row: row["package"])["deb"]
        f.blobs[name] = f.blobs[name][:-1] + b"!"
        with patch.object(m, "deb", side_effect=AssertionError("TAR parse forbidden")):
            with self.assertRaisesRegex(ValueError, "signed_record"):
                f.capture()

    def test_08_external_approval_is_required_not_candidate_boolean(self):
        f = Fixture()
        material, *_ = f.capture()
        raw = g.canonical(material)
        for digest in (None, "f" * 64):
            with self.assertRaises(ValueError):
                f.gate.approval(raw, digest, material["policy_sha256"])
        bad = g.canonical(material | {"approved": True})
        with self.assertRaises(ValueError):
            f.gate.approval(bad, g.sha(bad), material["policy_sha256"])
        approved = f.gate.approval(raw, g.sha(raw), material["policy_sha256"])
        self.assertEqual(f.gate.admit(approved, g.sha(raw)), raw)

    def test_09_unreviewed_DEB_is_refused_before_its_TAR_even_with_valid_repo(self):
        f = Fixture()
        material, *_ = f.capture()
        material["packages"][0]["sha256"] = "f" * 64
        with patch.object(m, "deb", side_effect=AssertionError("TAR parse forbidden")):
            with self.assertRaisesRegex(ValueError, "external_material_set"):
                f.capture(approved=material)

    def test_10_unique_records_packages_paths_and_architectures_are_not_repaired(self):
        for mutation in ("duplicate", "path", "arch"):
            f = Fixture()
            if mutation == "duplicate":
                f.spec["selection"].append(copy.deepcopy(f.spec["selection"][0]))
            elif mutation == "path":
                f.spec["selection"][0]["deb"] = "debs/../outside.deb"
            else:
                f.spec["selection"][0]["architecture"] = "arm64"
            with self.assertRaises(ValueError):
                f.capture()
        f = Fixture()
        path = f.spec["metadata"]["trixie"]["index"]
        f.blobs[path] += f.blobs[path].split(b"\n\n", 1)[0] + b"\n\n"
        f.release("trixie")
        with self.assertRaisesRegex(ValueError, "selected_record"):
            f.capture()

    def test_11_all_signed_metadata_authentication_precedes_first_payload_parse(self):
        f = Fixture()
        real = m.deb

        def parse(raw, **kwargs):
            self.assertEqual(len([row for row in f.events if row[0] == "signature"]), 3)
            return real(raw, **kwargs)

        with (
            patch.object(m, "deb", parse),
            patch.object(m, "signer_policy", side_effect=AssertionError("old authority forbidden")),
        ):
            f.capture()

    def test_12_index_scalar_folding_case_aliases_and_false_status_are_rejected(self):
        for field in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256"):
            for suffix in (
                "\n CONTINUED",
                "\nvErSiOn: 99" if field == "Version" else "\n" + field.swapcase() + ": BAD",
            ):
                with self.subTest(field=field, suffix=suffix):
                    f = Fixture()
                    path = f.spec["metadata"]["trixie"]["index"]
                    lines = f.blobs[path].decode().splitlines()
                    pos = next(n for n, line in enumerate(lines) if line.startswith(field + ":"))
                    lines[pos] += suffix
                    f.blobs[path] = ("\n".join(lines) + "\n").encode()
                    f.release("trixie")
                    with self.assertRaises(ValueError):
                        f.capture()

    def test_13_expired_future_or_other_suite_release_and_delayed_use_refuse(self):
        for change in ("expired", "future", "suite"):
            f = Fixture()
            if change == "expired":
                f.release("trixie", expiry=NOW - 1)
            elif change == "future":
                f.release("trixie", date=NOW + 1)
            else:
                f.releases["trixie"] = f.releases["trixie"].replace(
                    b"Codename: trixie\n", b"Codename: bookworm\n"
                )
            with self.assertRaises(ValueError):
                f.capture()
        f = Fixture()
        _, _, releases, _ = f.capture()
        with self.assertRaises(ValueError):
            f.gate.freshness(releases, NOW + 3601)

    def test_14_scalar_status_refuses_ambiguity_and_records_reviewed_transition(self):
        for text in (
            (
                b"Package: p\nVersion: 1\n VERSION: 2\nArchitecture: amd64\n"
                b"Status: install ok installed\n"
            ),
            (
                b"Package: p\nVersion: 1\nversion: 2\nArchitecture: amd64\n"
                b"Status: install ok installed\n"
            ),
            b"Package: p\nVersion: 1\nArchitecture: amd64\nStatus: install ok triggers-pending\n",
        ):
            with self.assertRaises(ValueError):
                g.Gate(m).status(text)
        f = Fixture()
        f.before += (
            b"Package: binutils\nVersion: 0\nArchitecture: amd64\nStatus: install ok installed\n\n"
        )
        f.base["files"]["var/lib/dpkg/status"]["sha256"] = g.sha(f.before)
        material, _, _, _ = f.capture()
        transition = next(row for row in material["transitions"] if row["package"] == "binutils")
        self.assertEqual(transition["before"]["version"], "0")
        self.assertEqual(transition["after"]["version"], "1-1")

    def test_15_real_ar_TAR_codecs_refuse_wrong_control_before_admission(self):
        f = Fixture()
        row = f.spec["selection"][0]
        raw = deb("different", row["version"])
        old = row["deb"]
        row["deb"] = "debs/" + g.sha(raw) + ".deb"
        f.blobs[row["deb"]] = raw
        index_name = f.spec["metadata"]["trixie"]["index"]
        f.blobs[index_name] = (
            f.blobs[index_name]
            .replace(g.sha(f.blobs[old]).encode(), g.sha(raw).encode())
            .replace(str(len(f.blobs[old])).encode(), str(len(raw)).encode())
        )
        f.release("trixie")
        with self.assertRaisesRegex(ValueError, "control_identity"):
            f.capture()

    def test_16_codec_inverse_lineage_and_h1_have_expected_source_pins(self):
        self.assertEqual(
            hashlib.sha256(
                (CODE / "materials.py")
                .read_bytes()
                .replace(
                    b"from datetime import UTC, datetime",
                    b"from datetime import datetime, timezone",
                )
                .replace(b"datetime.now(UTC)", b"datetime.now(timezone.utc)")
            ).hexdigest(),
            "309c800a096c25f7ee113c572928e2db47f57181bbb0628e95653cbab070080c",
        )
        self.assertEqual(
            hashlib.sha256((CODE / "bounded_io.py").read_bytes()).hexdigest(),
            "72b778ad6e441744e8bd9ac84ba7f47b1f6b577b7885a2e0daf3b4584cc0150a",
        )


class DriverTests(unittest.TestCase):
    def apply_model(self, *, failure=None, after_change=False, approved_sha=None, swap=False):
        f = Fixture()
        material, debs, releases, _ = f.capture()
        digest = g.sha(g.canonical(material)) if approved_sha is None else approved_sha
        raw_after = b"".join(
            (
                f"Package: {name}\nVersion: {row['version']}\nArchitecture: {row['architecture']}\n"
                f"Status: {row['status']}\n\n"
            ).encode()
            for name, row in material["expected_after_state"].items()
        )
        if after_change:
            raw_after = raw_after.replace(b"Version: 1\n", b"Version: 2\n", 1)
        stored, calls, created = {}, [], []
        if swap:
            debs = ((debs[0][0], debs[0][1] + b"CORRUPT"), *debs[1:])

        class MemoryPath(PurePosixPath):
            def mkdir(self, **kwargs):
                created.append(str(self))

        def read(path, maximum):
            name = str(path)
            raw = raw_after if name == "/var/lib/dpkg/status" else stored[name]
            self.assertLessEqual(len(raw), maximum)
            return raw

        def call(argv, **kwargs):
            calls.append((argv, kwargs))
            if failure == len(calls):
                raise ValueError("synthetic_client_UNKNOWN")
            return b"uninterpreted public APT output", b""

        runner = SimpleNamespace(live=lambda name: f.before, call=call)
        with (
            patch.object(t, "WORK", MemoryPath("/expat-apt-work")),
            patch.object(t, "PROOF", MemoryPath("/expat-apt-proof")),
            patch.object(t, "write_new", lambda path, raw, *args: stored.update({str(path): raw})),
            patch.object(t, "read_regular", read),
            patch.object(t.time, "time", return_value=NOW),
        ):
            result = t.apply(runner, f.gate, material, debs, releases, approved_sha=digest)
        return result, calls, created

    def test_17_real_apply_function_has_one_offline_install_and_no_update_upgrade(self):
        result, calls, _ = self.apply_model()
        self.assertEqual(len(calls), 2)
        self.assertIn("--simulate", calls[0][0])
        self.assertIn("--assume-yes", calls[1][0])
        for argv, kwargs in calls:
            self.assertEqual(argv[0], "/usr/bin/apt-get")
            self.assertNotIn("update", argv)
            self.assertNotIn("upgrade", argv)
            self.assertNotIn("--no-upgrade", argv)
            for option in (
                "--no-download",
                "--no-remove",
                "--no-install-recommends",
            ):
                self.assertIn(option, argv)
            self.assertEqual(kwargs["env"]["APT_CONFIG"], "/expat-apt-work/apt.conf")
            self.assertFalse(any(name.lower().endswith("proxy") for name in kwargs["env"]))
            self.assertTrue(
                all(
                    path.startswith("/expat-apt-work/material-")
                    for path in argv[argv.index("install") + 1 :]
                )
            )
        self.assertTrue(result["boundary_package_state_verified"])
        self.assertFalse(result["materials_complete"])
        self.assertFalse(result["compiler_SDK_generated_state_closed"])

    def test_18_real_apply_missing_approval_or_swapped_bytes_cannot_reach_a_client(self):
        for kwargs in ({"approved_sha": "f" * 64}, {"swap": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.apply_model(**kwargs)

    def test_19_simulation_failure_prevents_install_and_poststate_drift_refuses(self):
        for kwargs in ({"failure": 1}, {"failure": 2}, {"after_change": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.apply_model(**kwargs)

    def test_20_APT_CONFIG_is_read_first_and_never_loads_host_parts_or_sources(self):
        config = t.apt_configuration().decode()
        for value in (
            'Dir::Etc::parts "/expat-apt-work/empty-config";',
            'Dir::Etc::main "/dev/null";',
            'Dir::Etc::sourcelist "/dev/null";',
            'Dir::Etc::sourceparts "/expat-apt-work/empty-sources";',
            'APT::Get::Download "false";',
            'APT::Get::AllowUnauthenticated "false";',
        ):
            self.assertIn(value, config)
        self.assertNotIn("--allow-unauthenticated", config)
        self.assertNotIn("--force", config)

    def test_21_real_runner_Pending_PID_and_unknown_stay_sticky_under_fake_process(self):
        f = Fixture()
        writes, events = {}, []
        runner = t.Runner(None, m, f.base, until=1000)
        runner.tool_pin = lambda path: ("a" * 64, (1,))

        def invoke(argv, **kwargs):
            events.append("spawn")
            self.assertTrue(any(path.endswith("-intent.json") for path in writes))
            kwargs["on_spawn"](123)
            self.assertTrue(any(path.endswith("-pid.json") for path in writes))
            return SimpleNamespace(ok=False, facts=lambda: {"returncode": 9})

        runner.io = SimpleNamespace(run_capped=invoke)
        with (
            patch.object(t.time, "monotonic", return_value=100),
            patch.object(t, "write_new", lambda path, raw: writes.update({str(path): raw})),
        ):
            with self.assertRaises(ValueError):
                runner.call(["/usr/bin/apt-get"], seconds=30)
            self.assertTrue(runner.unknown)
            with self.assertRaises(ValueError):
                runner.call(["/usr/bin/apt-get"], seconds=30)
        self.assertEqual(events, ["spawn"])
        self.assertTrue(any(path.endswith("UNKNOWN.json") for path in writes))

    def test_22_signature_plaintext_is_not_read_after_client_UNKNOWN(self):
        f = Fixture()
        runner = t.Runner(None, m, f.base, until=1000)
        runner.call = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("UNKNOWN"))
        with (
            patch.object(t, "write_new"),
            patch.object(t.Path, "exists", return_value=False),
            patch.object(t.Path, "is_symlink", return_value=False),
            patch.object(t, "read_regular", side_effect=AssertionError("plaintext forbidden")),
        ):
            with self.assertRaisesRegex(ValueError, "UNKNOWN"):
                runner.signature(b"signed", "trixie", {})

    def test_23_crypto_success_still_requires_full_output_and_empty_stderr(self):
        f = Fixture()
        for output in (
            (b"FREE TEXT\n", b"warning"),
            (b"FREE TEXT\n", b""),
            (CERT.encode(), b""),
            (CERT.encode() + b"\r\n", b""),
        ):
            runner = t.Runner(None, m, f.base, until=1000)
            runner.call = lambda *args, **kwargs: output
            with (
                patch.object(t, "write_new"),
                patch.object(t.Path, "exists", return_value=False),
                patch.object(t.Path, "is_symlink", return_value=False),
                patch.object(t, "read_regular", side_effect=AssertionError("plaintext forbidden")),
            ):
                with self.assertRaises(ValueError):
                    runner.signature(b"signed", "trixie", {})

    def test_24_cli_and_source_do_not_run_native_or_accept_an_approval_boolean(self):
        source = (CODE / "transaction.py").read_text()
        self.assertIn('if __name__ == "__main__":', source)
        self.assertIn('sys.platform == "linux"', source)
        self.assertIn('args.disposable_buildkit_ack == "expat-prepared-only-v1"', source)
        self.assertIn("args.approved_material_set_sha", source)
        self.assertNotIn("allow_unattested", source)
        self.assertNotIn("extractall", source)


class IntegrationDataTests(unittest.TestCase):
    def test_25_external_code_pin_file_matches_exact_modules(self):
        pins = m.json_data((CODE / "code-pins.json").read_bytes())
        self.assertEqual(
            set(pins),
            {
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
            },
        )
        for name, digest in pins.items():
            self.assertEqual(g.sha((CODE / name).read_bytes()), digest)

    def test_26_uncommissioned_policy_cannot_authorize_itself_with_its_own_digest(self):
        raw = (CODE / "policy.uncommissioned.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "certificate_policy"):
            g.Gate(m).policy(raw, g.sha(raw))
        f = Fixture()
        duplicated = g.canonical(f.policy).replace(
            b'"stage":"expat-prepared"',
            b'"stage":"expat-prepared","stage":"expat-prepared"',
        )
        with self.assertRaises(ValueError):
            f.gate.policy(duplicated, g.sha(duplicated))


solver = module("c_solver", "solver.py")
worker = module("c_network_worker", "network_worker.py")
cap = module("c_capture", "capture.py")
oci = module("c_oci_codec", "oci_codec.py")


class AcquisitionTests(unittest.TestCase):
    def simulated(self, f, old=None):
        return b"Reading package lists...\n" + b"".join(
            (
                "Inst "
                + row["package"]
                + (" [0]" if row["package"] == old else "")
                + " ("
                + row["version"]
                + " Debian:13/stable [amd64])\n"
                + "Conf "
                + row["package"]
                + " ("
                + row["version"]
                + " Debian:13/stable [amd64])\n"
            ).encode()
            for row in f.spec["selection"]
        )

    def indices(self, f):
        return {suite: f.blobs[value["index"]] for suite, value in f.spec["metadata"].items()}

    def test_27_real_plan_parser_binds_dependency_transition_to_signed_record(self):
        f = Fixture()
        before = f.gate.status(f.before)
        before["binutils"] = {
            "version": "0",
            "architecture": "amd64",
            "status": "install ok installed",
        }
        rows = solver.parse_plan(self.simulated(f, "binutils"), self.indices(f), before, m)
        self.assertEqual(len(rows), 14)
        self.assertEqual({r["package"] for r in rows}, {r["package"] for r in f.spec["selection"]})
        self.assertTrue(all(g.sha(f.blobs[r["deb"]]) == r["record"]["SHA256"] for r in rows))

    def test_28_real_plan_parser_rejects_removal_mismatch_duplicates_and_ambiguous_bytes(self):
        f = Fixture()
        raw = self.simulated(f)
        before = f.gate.status(f.before)
        for invalid in (
            raw + b"Remv inherited-base [1]\n",
            raw + raw,
            raw.replace(b"Conf binutils", b"UNRECOGNIZED binutils"),
            raw.replace(b"Inst binutils (", b"Inst binutils [WRONG] ("),
            raw.replace(b"Inst binutils (1-1", b"Inst binutils (99-9"),
        ):
            with self.subTest(invalid=invalid[-50:]), self.assertRaises(ValueError):
                solver.parse_plan(invalid, self.indices(f), before, m)
        indices = self.indices(f)
        indices["trixie-updates"] = indices["trixie"].replace(b"SHA256: ", b"SHA256: f", 1)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            solver.parse_plan(raw, indices, before, m)

    def test_29_all_requests_already_satisfied_is_a_real_noop_not_fourteen_DEBs(self):
        f = Fixture()
        for row in f.spec["selection"]:
            f.before += (
                f"Package: {row['package']}\nVersion: {row['version']}\n"
                "Architecture: amd64\nStatus: install ok installed\n\n"
            ).encode()
        f.base["files"]["var/lib/dpkg/status"]["sha256"] = g.sha(f.before)
        f.spec["selection"] = []
        material, debs, _, _ = f.capture()
        self.assertEqual((material["transitions"], debs), ([], ()))
        self.assertEqual(
            solver.parse_plan(
                b"0 upgraded, 0 newly installed.\n", self.indices(f), f.gate.status(f.before), m
            ),
            [],
        )

    def test_30_signature_refusal_prevents_index_GET_decode_and_solver(self):
        f = Fixture()
        calls = []
        net = SimpleNamespace(public=lambda url, **kw: (calls.append(url) or (b"signed", None)))
        runner = SimpleNamespace(signature=lambda *a: (_ for _ in ()).throw(ValueError("BAD_SIG")))
        with self.assertRaisesRegex(ValueError, "BAD_SIG"):
            cap.authenticated_index(
                net, runner, m, g, "trixie", f.policy["repositories"]["trixie"], None
            )
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith("/InRelease"))

    def test_31_worker_origin_and_registry_redirect_never_forward_Bearer(self):
        self.assertEqual(
            worker.public_url("https://deb.debian.org/debian/pool/main/p/p.deb"),
            ("deb.debian.org", "/debian/pool/main/p/p.deb"),
        )
        for url in (
            "http://deb.debian.org/debian/pool/p.deb",
            "https://user@deb.debian.org/debian/pool/p.deb",
            "https://127.0.0.1/debian/pool/p.deb",
            "https://deb.debian.org/debian/pool/p.deb?secret=x",
            "https://deb.debian.org/debian/pool/../p.deb",
        ):
            with self.assertRaises(ValueError):
                worker.public_url(url)
        raw = b"PUBLIC"
        digest = g.sha(raw)
        calls = []
        redirect = (
            "https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/"
            "blobs/sha256/" + digest[:2] + "/" + digest + "/data?OPAQUE=not-logged"
        )

        def fetch(host, path, headers, maximum, until):
            calls.append((host, path, dict(headers)))
            if host == oci.AUTH:
                return 200, None, json.dumps({"token": "x" * 24}).encode(), None
            if host == oci.REGISTRY:
                return 307, redirect, b"", None
            self.assertEqual(headers, {})
            return 200, None, raw, None

        req = {
            "op": "registry",
            "kind": "layer",
            "cap": 100,
            "digest": "sha256:" + digest,
            "expected_sha256": digest,
            "expected_bytes": len(raw),
        }
        with patch.object(worker, "fetch", fetch):
            self.assertEqual(worker.acquire(req, 100, oci), raw)
        self.assertIn("Authorization", calls[1][2])
        self.assertEqual(calls[2][2], {})
        self.assertEqual(len(calls), 3)

    def test_32_real_fetch_checks_headers_bytes_and_absolute_slow_drip_deadline(self):
        class Response:
            status = 200

            def getheaders(self):
                return self.rows

            def getheader(self, name, default=None):
                return dict(self.rows).get(name, default)

            def read(self, n):
                return b"X"

        response = Response()
        response.rows = [("Content-Length", "1"), ("Content-Length", "1")]
        connection = SimpleNamespace(
            request=lambda *a, **kw: None, getresponse=lambda: response, close=lambda: None
        )
        ctx = SimpleNamespace(check_hostname=True, verify_mode=worker.ssl.CERT_REQUIRED)
        with (
            patch.object(worker.ssl, "create_default_context", return_value=ctx),
            patch.object(worker.http.client, "HTTPSConnection", return_value=connection),
        ):
            with self.assertRaisesRegex(ValueError, "duplicate_HTTP_header"):
                worker.fetch("deb.debian.org", "/fixed", {}, 4, 10**9)
            response.rows = []
            with patch.object(worker.time, "monotonic", side_effect=[0, 1, 2, 11]):
                with self.assertRaisesRegex(ValueError, "deadline"):
                    worker.fetch("deb.debian.org", "/fixed", {}, 100, 10)
            with patch.object(worker.time, "monotonic", return_value=0):
                with self.assertRaisesRegex(ValueError, "body_cap"):
                    worker.fetch("deb.debian.org", "/fixed", {}, 4, 10)

    def test_33_decode_checks_compressed_and_raw_bindings_with_no_native_process(self):
        raw = b"PUBLIC_PACKAGES_DATA\n"
        packed = lzma.compress(raw)
        writes = {}

        class MP(PurePosixPath):
            pass

        request = {
            "schema": "pamolive.expat-C-worker/1",
            "op": "xz",
            "until": 100,
            "source": "/expat-apt-work/network/1/body.data",
            "destination": "/expat-apt-work/network/2/body.data",
            "expected_sha256": g.sha(packed),
            "expected_bytes": len(packed),
            "raw_sha256": g.sha(raw),
            "raw_bytes": len(raw),
        }

        def read(path, cap):
            return (
                g.canonical(request)
                if str(path) == "/expat-apt-work/network/2/request.json"
                else packed
            )

        fake = SimpleNamespace(read_regular=read, write_new=lambda p, r: writes.update({str(p): r}))

        def load(name):
            return fake if name == "transaction.py" else m if name == "materials.py" else oci

        with (
            patch.object(worker, "loaded", load),
            patch.object(worker, "Path", MP),
            patch.object(worker.sys, "platform", "linux"),
            patch.object(worker.os, "geteuid", return_value=0, create=True),
            patch.object(
                worker.sys, "argv", ["worker", "/expat-apt-work/network/2/request.json", "fixed"]
            ),
            patch.object(worker.time, "monotonic", return_value=0),
            patch("sys.stdout", io.StringIO()),
        ):
            self.assertEqual(worker.main(), 0)
            self.assertEqual(writes["/expat-apt-work/network/2/body.data"], raw)
            writes.clear()
            request["expected_sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "compressed_signed_binding"):
                worker.main()
            self.assertEqual(writes, {})
            request["expected_sha256"] = g.sha(packed)
            request["raw_sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "raw_signed_binding"):
                worker.main()
            self.assertEqual(writes, {})

    def test_34_real_solver_configuration_cannot_update_or_install_target_packages(self):
        f = Fixture()
        writes = {}
        calls = []

        class MP(PurePosixPath):
            def mkdir(self, **kwargs):
                pass

        fake = SimpleNamespace(
            WORK=MP("/expat-apt-work"),
            apt_configuration=t.apt_configuration,
            write_new=lambda p, r, *a: writes.update({str(p): r}),
        )
        runner = SimpleNamespace(
            simulate=lambda argv, **kwargs: (calls.append((argv, kwargs)) or (b"plan", b""))
        )
        solver.configure(runner, g, self.indices(f), {s: b"SIGNED" for s in g.REPOSITORIES}, fake)
        self.assertEqual(len(calls), 1)
        argv, options = calls[0]
        self.assertIn("--simulate", argv)
        self.assertNotIn("--no-download", argv)
        self.assertIn(b'APT::Get::Download "true";', writes["/expat-apt-work/solver.conf"])
        self.assertEqual(g.sha(writes["/expat-apt-work/solver.conf"]), fence.SOLVER_CONFIG_SHA)
        self.assertNotIn("update", argv)
        self.assertNotIn("upgrade", argv)
        self.assertEqual(argv[-14:], list(g.REQUESTS))
        self.assertFalse(any("trusted=yes" in raw.decode() for raw in writes.values()))
        self.assertTrue(all(s + "_InRelease" in " ".join(writes) for s in g.REPOSITORIES))

    def test_35_changed_approved_transition_or_old_contract_is_refused(self):
        f = Fixture()
        material, _, _, _ = f.capture()
        raw = g.canonical(material)
        wrong = copy.deepcopy(material)
        wrong["transitions"][0]["after"]["version"] = "UNAPPROVED"
        with self.assertRaisesRegex(ValueError, "external_material_set_pin"):
            f.gate.admit(wrong, g.sha(raw))
        old = copy.deepcopy(material)
        old["schema"] = "pamolive.expat-prepared.material-set/1"
        oldraw = g.canonical(old)
        with self.assertRaisesRegex(ValueError, "scope"):
            f.gate.approval(oldraw, g.sha(oldraw), g.sha(g.canonical(f.policy)))

    def test_36_network_worker_unknown_stays_sticky_and_precedes_no_second_process(self):
        writes = {}
        events = []

        class MP(PurePosixPath):
            def mkdir(self, **kwargs):
                pass

        fake = SimpleNamespace(
            WORK=MP("/work"),
            PROOF=MP("/proof"),
            HERE=MP("/code"),
            write_new=lambda p, r, *a: writes.update({str(p): r}),
            read_regular=lambda p, *a, **k: b"SOURCE",
            sha=g.sha,
        )

        def run(argv, **kwargs):
            events.append("spawn")
            self.assertIn("/proof/network/1/intent.json", writes)
            kwargs["on_spawn"](123)
            return SimpleNamespace(ok=False, facts=lambda: {"returncode": None})

        net = cap.Network(
            SimpleNamespace(run_capped=run),
            fake,
            {"network_worker.py": g.sha(b"SOURCE")},
            1000,
            m,
            g.sha(b"SOURCE"),
        )
        net.tool = lambda: ("fixed", (1,))
        with patch.object(cap.time, "monotonic", return_value=0):
            with self.assertRaises(ValueError):
                net.public("https://deb.debian.org/fixed", cap=1)
            self.assertTrue(net.unknown)
            with self.assertRaises(ValueError):
                net.public("https://deb.debian.org/fixed", cap=1)
        self.assertEqual(events, ["spawn"])
        self.assertIn("/proof/network/1/pid.json", writes)
        self.assertIn("/proof/network/1/UNKNOWN.json", writes)

    def test_37_real_capture_pipeline_composes_auth_solver_fetch_and_no_status_mutation(self):
        f = Fixture()
        source_pins = {
            "solver.py": "x",
            "oci_codec.py": "x",
            "solver_fence.py": "b" * 64,
            "native_fence_tests.py": "c" * 64,
        }
        native = positive_native_summary("a" * 64, source_pins)
        stored = {"/c-fence-native/summary.json": g.canonical(native)}
        events = []
        raw_indices = self.indices(f)
        packed = {suite: lzma.compress(raw) for suite, raw in raw_indices.items()}
        for suite, raw in raw_indices.items():
            f.releases[suite] += (
                f" {g.sha(packed[suite])} {len(packed[suite])} main/binary-amd64/Packages.xz\n"
            ).encode()
        bootstrap = b"PUBLIC_VERIFIER_DEB"
        py = b"\x7fELF_FAKE_NATIVE_BOUNDARY"

        class MP(PurePosixPath):
            def mkdir(self, **kwargs):
                pass

        def write(path, raw, *args):
            name = str(path)
            self.assertNotIn(name, stored)
            stored[name] = raw

        def read(path, limit, **kwargs):
            name = str(path)
            value = (
                g.canonical(f.policy)
                if name == "/c-authority/policy.json"
                else f.before
                if name == "/var/lib/dpkg/status"
                else stored[name]
            )
            self.assertLessEqual(len(value), limit)
            return value

        test = self

        class FakeRunner:
            def __init__(self, *args, **kwargs):
                self.ordinal = 0
                self.unknown = False

            def live(self, name):
                return (
                    f.before
                    if name == "var/lib/dpkg/status"
                    else py
                    if name.endswith("python3.12")
                    else b"KEYRING"
                )

            def call(self, argv, **kwargs):
                self.ordinal += 1
                if argv[-1] == "--version":
                    return t.VERSION, b""
                events.append("solver")
                test.assertEqual(argv[1], "--simulate")
                test.assertEqual(sum(e.startswith("signature:") for e in events), 3)
                return test.simulated(f), b""

            simulate = call

            def signature(self, raw, suite, rule):
                self.ordinal += 1
                events.append("signature:" + suite)
                return f.releases[suite], (CERT,)

        class FakeNetwork:
            def __init__(self, *args):
                self.count = 0
                self.unknown = False

            def tool(self):
                return g.sha(py), (1,)

            def public(self, url, **kwargs):
                self.count += 1
                if url == cap.SQV_URL:
                    return bootstrap, MP("/synthetic/bootstrap")
                if "/dists/" in url:
                    suite = url.split("/dists/")[1].split("/")[0]
                    if url.endswith("/InRelease"):
                        return f.blobs[f.spec["metadata"][suite]["inrelease"]], MP(
                            "/synthetic/signed"
                        )
                    test.assertIn("signature:" + suite, events)
                    return packed[suite], MP("/synthetic/" + suite)
                test.assertIn("solver", events)
                events.append("DEB")
                row = next(
                    row
                    for row in f.spec["selection"]
                    if url.endswith("/" + row["package"] + ".deb")
                )
                return f.blobs[row["deb"]], MP("/synthetic/DEB")

            def perform(self, op, **kwargs):
                self.count += 1
                test.assertEqual(op, "xz")
                suite = str(kwargs["source"]).split("/")[-1]
                test.assertEqual(kwargs["expected_sha256"], g.sha(packed[suite]))
                return raw_indices[suite], MP("/synthetic/raw")

        proxy = SimpleNamespace(
            WORK=MP("/expat-apt-work"),
            PROOF=MP("/proof"),
            read_regular=read,
            write_new=write,
            Runner=FakeRunner,
            VERSION=t.VERSION,
            apt_configuration=t.apt_configuration,
            load=lambda name, *args: fence
            if name == "expat_solver_fence"
            else solver
            if "solver" in name
            else oci,
        )
        args = SimpleNamespace(policy_sha=g.sha(g.canonical(f.policy)), code_pins_sha="a" * 64)
        with (
            patch.object(cap, "Path", MP),
            patch.object(cap, "Network", FakeNetwork),
            patch.object(cap, "parent", return_value=f.base),
            patch.object(cap, "verifier", return_value=py),
            patch.object(cap.sys, "platform", "linux"),
            patch.object(cap.os, "getuid", return_value=0, create=True),
            patch.object(cap.os, "geteuid", return_value=0, create=True),
            patch.object(cap.time, "time", return_value=NOW),
            patch.object(cap.time, "monotonic", return_value=0),
        ):
            self.assertEqual(
                cap.run(args, source_pins, m, g, None, proxy, deadline=1800),
                0,
            )
        result = m.json_data(stored["/c-capture/result.json"])
        material = m.json_data(stored["/c-capture/material-set.UNAPPROVED.json"])
        self.assertEqual(result["state"], "AUTHENTICATED_UNAPPROVED_NOT_INSTALLED")
        self.assertEqual(result["prestate_sha256"], result["poststate_sha256"])
        self.assertFalse(result["materials_complete"])
        self.assertEqual(len(material["packages"]), 14)
        self.assertEqual(events.count("solver"), 1)
        self.assertEqual(events.count("DEB"), 14)

    def test_38_new_job_gate_never_treats_exported_UNKNOWN_as_capture_success(self):
        path = ROOT / "qualification/expat_apt_C/check_result.py"
        spec = importlib.util.spec_from_file_location("c_check_result", path)
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        f = Fixture()
        material, _, _, _ = f.capture()
        mr = g.canonical(material)
        code = "a" * 64
        policy = g.sha(g.canonical(f.policy))
        result = {
            "state": "AUTHENTICATED_UNAPPROVED_NOT_INSTALLED",
            "code_pins_sha256": code,
            "policy_sha256": policy,
            "material_set_sha256": g.sha(mr),
            "prestate_sha256": g.sha(f.before),
            "poststate_sha256": g.sha(f.before),
            "build_verified": False,
            "materials_complete": False,
        }
        rr = g.canonical(result)
        facts = {
            "spawn_attempted": True,
            "pid": 123,
            "returncode": 0,
            "reason": None,
            "exception_type": None,
            "cleanup_exception_type": None,
            "owned_child_reaped": True,
            "drains_complete": True,
            "killed_owned_child": False,
        }
        packet = {
            "schema": "pamolive.expat-C-supervisor/1",
            "state": "DRIVER_NORMAL_DATA_ONLY",
            "resources_released": False,
            "all_OS_descendants_released": False,
            "build_verified": False,
            "materials_complete": False,
            "code_pins_sha256": code,
            "H1": facts,
            "result_sha256": g.sha(rr),
        }
        self.assertFalse(
            checker.validate(g.canonical(packet), rr, mr, f.before, code, policy)["authority"]
        )
        for field, value in (
            ("returncode", False),
            ("returncode", 42),
            ("drains_complete", False),
            ("owned_child_reaped", False),
            ("exception_type", "OSError"),
        ):
            wrong = copy.deepcopy(packet)
            wrong["H1"][field] = value
            with self.assertRaises(ValueError):
                checker.validate(g.canonical(wrong), rr, mr, f.before, code, policy)
        wrong = copy.deepcopy(packet)
        wrong["state"] = "REFUSED_OR_UNKNOWN"
        with self.assertRaises(ValueError):
            checker.validate(g.canonical(wrong), rr, mr, f.before, code, policy)

    def test_39_worker_protocol_rejects_unknown_fields_bool_budgets_and_foreign_output_before_IO(
        self,
    ):
        root = "/expat-apt-work/network/1/"
        base = {
            "schema": "pamolive.expat-C-worker/1",
            "op": "public",
            "until": 100,
            "destination": root + "body.data",
            "url": "https://deb.debian.org/debian/pool/p.deb",
            "cap": 100,
            "expected_sha256": None,
            "expected_bytes": None,
        }
        with patch.object(worker, "Path", PurePosixPath):
            worker.request_shape(base, root + "request.json")
            for fields in (
                {"extra": True},
                {"cap": True},
                {"expected_bytes": False},
                {"destination": "/foreign/body.data"},
                {"until": True},
            ):
                wrong = {**base, **fields}
                with self.assertRaises(ValueError):
                    worker.request_shape(wrong, root + "request.json")

    def test_40_only_exact_admitted_DEB_can_replace_the_APT_tool_role(self):
        raw = b"\x7fELF_REVIEWED_APT_REPLACEMENT"
        expected = {
            "type": "file",
            "sha256": g.sha(raw),
            "size": len(raw),
            "uid": 0,
            "gid": 0,
            "mode": 0o755,
        }
        row = SimpleNamespace(
            st_mode=0o100755,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_dev=1,
            st_ino=2,
            st_size=len(raw),
            st_mtime_ns=3,
            st_ctime_ns=4,
        )
        runner = t.Runner(None, m, {}, until=1000)
        with (
            patch.object(t, "read_regular", return_value=raw),
            patch.object(t.Path, "lstat", return_value=row),
        ):
            self.assertEqual(runner.replacement_pin("/usr/bin/apt-get", expected)[0], g.sha(raw))
            for wrong in (
                {**expected, "sha256": "f" * 64},
                {**expected, "mode": 0o4755},
                {**expected, "uid": 1000},
                {**expected, "type": "symlink"},
            ):
                with self.assertRaises(ValueError):
                    runner.replacement_pin("/usr/bin/apt-get", wrong)
            with self.assertRaises(ValueError):
                runner.replacement_pin("/foreign/tool", expected)

    def test_41_aggregate_signed_index_budget_is_checked_before_GET_and_solver(self):
        f = Fixture()
        index = f.blobs[f.spec["metadata"]["trixie"]["index"]]
        clear = f.releases["trixie"].replace(
            (str(len(index)) + " main/binary-amd64/Packages\n").encode(),
            (str(10 * 1024**2) + " main/binary-amd64/Packages\n").encode(),
        )
        clear += (" " + "a" * 64 + " 1048576 main/binary-amd64/Packages.xz\n").encode()
        calls = []
        net = SimpleNamespace(public=lambda url, **kwargs: (calls.append(url) or (b"SIGNED", None)))
        runner = SimpleNamespace(
            signature=lambda *a: (clear, (CERT,)), metadata_bytes=250 * 1024**2
        )
        with patch.object(cap.time, "time", return_value=NOW):
            with self.assertRaisesRegex(ValueError, "metadata_aggregate_before_use"):
                cap.authenticated_index(
                    net, runner, m, g, "trixie", f.policy["repositories"]["trixie"], None
                )
        self.assertEqual(len(calls), 1)


class WorkerFailureDiagnosticTests(unittest.TestCase):
    def completed_refusal(self, **changes):
        packet = worker.failure_packet(ValueError("HTTP_non200"), "headers")
        fields = dict(
            ok=False,
            spawn_attempted=True,
            pid=123,
            returncode=42,
            reason="nonzero_exit",
            exception_type=None,
            cleanup_exception_type=None,
            owned_child_reaped=True,
            drains_complete=True,
            killed_owned_child=False,
            stdout=json.dumps(packet).encode(),
            stderr=b"",
        )
        fields.update(changes)
        return SimpleNamespace(**fields)

    def test_42_closed_error_code_phase_and_kind_never_render_exception_text(self):
        class Private(ValueError):
            def __str__(self):
                raise AssertionError("must_not_render_exception")

        for error in (
            Private("PRIVATE_TEXT"),
            ValueError("PRIVATE_TEXT"),
            ValueError("HTTP_non200", "PRIVATE_TEXT"),
            RuntimeError("PRIVATE_TEXT"),
        ):
            packet = worker.failure_packet(error, "PRIVATE_PHASE")
            self.assertEqual(packet["code_index"], 0)
            self.assertEqual(packet["phase"], "UNKNOWN")
            self.assertEqual(packet["kind"], "UNKNOWN")
            self.assertNotIn("PRIVATE", json.dumps(packet))
            self.assertFalse(packet["operational_GO"])
        packet = worker.failure_packet(ValueError("HTTP_non200"), "headers")
        self.assertEqual(worker.FAILURE_CODES[packet["code_index"] - 1], "HTTP_non200")
        self.assertEqual(packet["kind"], "CONTRACT")

    def test_43_actual_reviewed_codec_class_can_publish_only_known_code(self):
        with patch.object(worker, "_codec_error", oci.CapsuleError):
            packet = worker.failure_packet(
                oci.CapsuleError("redirect_origin_unapproved"), "acquire"
            )
            self.assertEqual(
                worker.FAILURE_CODES[packet["code_index"] - 1],
                "redirect_origin_unapproved",
            )
            self.assertEqual(packet["kind"], "CONTRACT")
            unknown = worker.failure_packet(oci.CapsuleError("PRIVATE_TEXT"), "acquire")
            self.assertEqual(unknown["code_index"], 0)

    def test_44_parent_projects_only_complete_normal42_not_partial_or_uncertain_buffers(
        self,
    ):
        valid = self.completed_refusal()
        self.assertEqual(cap.worker_failure_diagnostic(valid, m), json.loads(valid.stdout))
        for changes in (
            {"ok": True},
            {"spawn_attempted": 1},
            {"pid": True},
            {"returncode": 0},
            {"returncode": True},
            {"reason": None},
            {"exception_type": "PRIVATE"},
            {"cleanup_exception_type": "PRIVATE"},
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"killed_owned_child": True},
            {"stdout": bytearray(valid.stdout)},
            {"stdout": b"x" * 2049},
            {"stderr": b"PRIVATE"},
        ):
            with self.subTest(changes=tuple(changes)):
                self.assertIsNone(
                    cap.worker_failure_diagnostic(self.completed_refusal(**changes), m)
                )

    def test_45_arbitrary_fields_bool_aliases_and_indices_refuse_without_echo(self):
        packet = json.loads(self.completed_refusal().stdout)
        for key, value in (
            ("extra", "PRIVATE"),
            ("schema", "PRIVATE"),
            ("state", "COMPLETE"),
            ("code_index", True),
            ("code_index", 58),
            ("code_index", -1),
            ("phase", "PRIVATE"),
            ("kind", "PRIVATE"),
            ("operational_GO", 0),
        ):
            altered = dict(packet, **{key: value})
            self.assertIsNone(
                cap.worker_failure_diagnostic(
                    self.completed_refusal(stdout=json.dumps(altered).encode()), m
                )
            )
        for raw in (b"PRIVATE", b"{}", b'{"schema":1,"schema":2}', b'{"x":NaN}'):
            self.assertIsNone(cap.worker_failure_diagnostic(self.completed_refusal(stdout=raw), m))

    def test_46_literal_tables_are_finite_and_match_parent_integer_bound(self):
        import ast

        self.assertEqual(len(worker.FAILURE_CODES), 57)
        self.assertEqual(len(set(worker.FAILURE_CODES)), 57)
        self.assertEqual(len(worker.FAILURE_PHASES), 9)
        tree = ast.parse((CODE / "capture.py").read_bytes())
        function = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "worker_failure_diagnostic"
        )
        self.assertIn("<= 57", ast.unparse(function))

    def test_47_projection_remains_best_effort_before_original_fatal_guard(self):
        import ast

        tree = ast.parse((CODE / "capture.py").read_bytes())
        network = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Network")
        function = next(
            n for n in network.body if isinstance(n, ast.FunctionDef) and n.name == "perform"
        )
        text = ast.unparse(function)
        self.assertLess(
            text.index("worker_failure_diagnostic(result"),
            text.index("'worker_unknown'"),
        )
        self.assertIn("self.unknown = True", text)
        self.assertIn("except Exception:", text)
        self.assertIn("result.returncode == 0", text)
        self.assertIn("raise", text)

    def test_48_real_network_wrapper_keeps_original_refusal_when_projection_write_fails(
        self,
    ):
        for fail_write in (False, True):
            writes = {}
            calls = []

            class MP(PurePosixPath):
                def mkdir(self, **kwargs):
                    pass

            def write(path, raw, *args):
                if fail_write and str(path).endswith("worker-failure.json"):
                    raise OSError("PRIVATE_WRITE_ERROR")
                writes[str(path)] = raw

            result = self.completed_refusal()
            result.facts = lambda: {"returncode": 42}

            def run(argv, **kwargs):
                calls.append(argv)
                kwargs["on_spawn"](123)
                return result

            fake = SimpleNamespace(
                WORK=MP("/work"),
                PROOF=MP("/proof"),
                HERE=MP("/code"),
                write_new=write,
                read_regular=lambda *a, **k: b"SOURCE",
                sha=g.sha,
            )
            net = cap.Network(
                SimpleNamespace(run_capped=run),
                fake,
                {"network_worker.py": g.sha(b"SOURCE")},
                1000,
                m,
                g.sha(b"SOURCE"),
            )
            net.tool = lambda: ("fixed", (1,))
            with patch.object(cap.time, "monotonic", return_value=0):
                with self.assertRaisesRegex(ValueError, "^worker_unknown$"):
                    net.public("https://deb.debian.org/fixed", cap=1)
                self.assertTrue(net.unknown)
                with self.assertRaises(ValueError):
                    net.public("https://deb.debian.org/fixed", cap=1)
            self.assertEqual(len(calls), 1)
            self.assertIn("/proof/network/1/UNKNOWN.json", writes)
            self.assertEqual("/proof/network/1/worker-failure.json" in writes, not fail_write)
            self.assertNotIn("PRIVATE", json.dumps({p: r.decode() for p, r in writes.items()}))


class AptSimulationDiagnosticTests(unittest.TestCase):
    def result(self, **changes):
        fields = dict(
            ok=False,
            spawn_attempted=True,
            pid=123,
            returncode=100,
            reason="nonzero_exit",
            exception_type=None,
            cleanup_exception_type=None,
            owned_child_reaped=True,
            drains_complete=True,
            killed_owned_child=False,
            stdout=b"Reading package lists...\n",
            stderr=t.APT_ARCHIVES_ERROR + b"\n",
        )
        fields.update(changes)
        return SimpleNamespace(**fields, facts=lambda: {"returncode": fields["returncode"]})

    def packet(self, **changes):
        return t.apt_failure_diagnostic(self.result(**changes), "a" * 64, "a" * 64)

    def test_49_full_stdout_progress_does_not_hide_complete_stderr_error(self):
        packet = self.packet(stdout=b"PUBLIC_PROGRESS\n" * 200)
        self.assertTrue(packet["normal_rc100"])
        self.assertEqual(packet["state"], "REFUSED")
        self.assertTrue(packet["archives_missing_message_observed"])
        self.assertEqual(packet["exported_lines"][0]["stream"], "stderr")
        self.assertEqual(packet["exported_lines"][0]["class"], "archives_missing_no_download")
        self.assertEqual(packet["omitted_lines"], 200)
        self.assertTrue(packet["input_valid"])

    def test_50_priority_and_output_omissions_are_not_input_truncation(self):
        packet = self.packet(
            stdout=b"E: PUBLIC_OTHER\n" * 100,
            stderr=b"W: PUBLIC_WARNING\n" * 100 + t.APT_ARCHIVES_ERROR + b"\n",
        )
        self.assertEqual(len(packet["exported_lines"]), 32)
        self.assertEqual(packet["exported_lines"][0]["class"], "archives_missing_no_download")
        self.assertEqual(packet["omitted_message_lines"], 169)
        self.assertEqual(packet["invalid_lines"], 0)
        self.assertTrue(packet["input_valid"])
        self.assertTrue(packet["archives_missing_message_observed"])
        # Even the 40th error must be scanned, not prefix-truncated by export cap.
        late = self.packet(stderr=b"E: PUBLIC_OTHER\n" * 39 + t.APT_ARCHIVES_ERROR + b"\n")
        self.assertTrue(late["archives_missing_message_observed"])
        self.assertIn("archives_missing_no_download", [r["class"] for r in late["exported_lines"]])

    def test_51_canary_text_unknown_error_and_exception_never_leave_as_raw(self):
        secret = b"PRIVATE_CANARY_PATH_URL_AND_TOKEN"
        packet = self.packet(stderr=b"E: " + secret + b"\n")
        self.assertEqual(packet["exported_lines"][0]["class"], "apt_error_other")
        self.assertEqual(packet["exported_lines"][0]["sha256"], g.sha(b"E: " + secret))
        self.assertNotIn(secret.decode(), json.dumps(packet))
        self.assertFalse(packet["archives_missing_message_observed"])
        unknown = self.packet(exception_type=secret.decode())
        self.assertEqual(unknown["state"], "UNKNOWN")
        self.assertEqual(unknown["exported_lines"], [])
        self.assertNotIn(secret.decode(), json.dumps(unknown))

    def test_52_rc0_rc1_bool_signal_and_uncertain_lifecycle_never_classify100(self):
        for changes in (
            {"ok": True},
            {"ok": 0},
            {"returncode": 0},
            {"returncode": 1},
            {"returncode": True},
            {"returncode": -15},
            {"returncode": None},
            {"spawn_attempted": 1},
            {"pid": True},
            {"pid": 0},
            {"reason": "timeout"},
            {"reason": None},
            {"exception_type": "PRIVATE"},
            {"cleanup_exception_type": "PRIVATE"},
            {"owned_child_reaped": False},
            {"owned_child_reaped": 1},
            {"drains_complete": False},
            {"killed_owned_child": True},
        ):
            with self.subTest(fields=tuple(changes)):
                packet = self.packet(**changes)
                self.assertFalse(packet["normal_rc100"])
                self.assertEqual(packet["state"], "UNKNOWN")
                self.assertEqual(packet["exported_lines"], [])
                self.assertFalse(packet["archives_missing_message_observed"])

    def test_53_invalid_entire_input_cannot_match_valid_prefix_or_other_stream(self):
        for raw in (
            t.APT_ARCHIVES_ERROR,
            t.APT_ARCHIVES_ERROR + b"\r\n",
            t.APT_ARCHIVES_ERROR + b"\x00\n",
            t.APT_ARCHIVES_ERROR + b"\xff\n",
            t.APT_ARCHIVES_ERROR + b" " * 4097 + b"\n",
        ):
            for stream in ("stderr", "stdout"):
                with self.subTest(stream=stream, raw_length=len(raw)):
                    packet = self.packet(**{stream: raw})
                    self.assertEqual(packet["state"], "UNKNOWN")
                    self.assertFalse(packet["input_valid"])
                    self.assertFalse(packet["archives_missing_message_observed"])
                    self.assertEqual(packet["exported_lines"], [])
        packet = self.packet(stdout=b"\xff\n")
        self.assertEqual(packet["encoding_invalid_streams"], 1)
        self.assertEqual(packet["invalid_lines"], 0)

    def test_54_input_caps_types_and_tool_changes_remain_unknown(self):
        for changes in (
            {"stdout": b"x" * (1024**2 + 1)},
            {"stderr": b"x" * 262145},
            {"stdout": bytearray(b"PUBLIC\n")},
            {"stderr": None},
        ):
            packet = self.packet(**changes)
            self.assertEqual(packet["state"], "UNKNOWN")
            self.assertGreater(packet["unbounded_streams"], 0)
        for after in (None, "b" * 64, False):
            packet = t.apt_failure_diagnostic(self.result(), "a" * 64, after)
            self.assertEqual(packet["state"], "UNKNOWN")
            self.assertFalse(packet["tool_stable"])
            self.assertFalse(packet["archives_missing_message_observed"])

    def test_55_envelope_stays_bounded_and_authority_flags_always_false(self):
        packet = self.packet(stdout=b"E: X\n" * 200000)
        self.assertTrue(packet["input_valid"])
        self.assertEqual(len(packet["exported_lines"]), 32)
        self.assertLessEqual(len(json.dumps(packet).encode()), 16384)
        for name in (
            "operational_GO",
            "build_verified",
            "materials_complete",
            "all_OS_descendants_released",
        ):
            self.assertIs(packet[name], False)
        none = self.packet(stdout=b"", stderr=b"")
        self.assertFalse(none["archives_missing_message_observed"])
        self.assertEqual(none["exported_lines"], [])

    def run_failure(self, *, result=None, fail_write=False, after=None, role="apt_simulate"):
        writes, events = {}, []
        result = result or self.result()

        def run(argv, **kwargs):
            events.append(("spawn", tuple(argv), kwargs))
            kwargs["on_spawn"](123)
            return result

        def tool(path):
            events.append(("tool", path))
            if len([e for e in events if e[0] == "tool"]) == 1:
                return "a" * 64, (1,)
            if after == "RAISE":
                raise ValueError("PRIVATE_TOOL_ERROR")
            if after == "IDENTITY":
                return "a" * 64, (2,)
            return after or "a" * 64, (1,)

        def write(path, raw, *args):
            events.append(("write", str(path)))
            if fail_write and str(path).endswith("-apt-diagnostic.json"):
                raise OSError("PRIVATE_WRITE_ERROR")
            writes[str(path)] = raw

        runner = t.Runner(SimpleNamespace(run_capped=run), m, {}, until=1000)
        runner.tool_pin = tool
        env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "/expat-apt-work",
            "APT_CONFIG": "/expat-apt-work/solver.conf",
            "DEBIAN_FRONTEND": "noninteractive",
        }
        with (
            patch.object(t, "write_new", write),
            patch.object(t, "PROOF", PurePosixPath("/expat-apt-proof")),
            patch.object(t.time, "monotonic", return_value=0),
        ):
            with self.assertRaisesRegex(ValueError, "^client_failed_or_UNKNOWN$"):
                runner.call(
                    list(t.APT_SIMULATE_ARGV),
                    seconds=90,
                    cap=1024**2,
                    env=env,
                    diagnostic_role=role,
                )
            self.assertTrue(runner.unknown)
            self.assertEqual(runner.records, [])
            with self.assertRaisesRegex(ValueError, "^client_budget_or_UNKNOWN$"):
                runner.call(
                    list(t.APT_SIMULATE_ARGV),
                    seconds=90,
                    cap=1024**2,
                    env=env,
                    diagnostic_role=role,
                )
        return writes, events

    def test_56_real_runner_failure_diagnoses_before_original_refusal_without_extra_spawn(self):
        writes, events = self.run_failure()
        packet = json.loads(writes["/expat-apt-proof/command-1-apt-diagnostic.json"])
        self.assertEqual(packet["state"], "REFUSED")
        self.assertTrue(packet["archives_missing_message_observed"])
        self.assertIn("/expat-apt-proof/command-1-UNKNOWN.json", writes)
        self.assertEqual(len([e for e in events if e[0] == "spawn"]), 1)
        self.assertEqual(len([e for e in events if e[0] == "tool"]), 2)
        spawn = next(e for e in events if e[0] == "spawn")
        self.assertEqual(spawn[2]["work_timeout"], 90)
        self.assertEqual(spawn[2]["timeout"], 100)
        self.assertEqual(spawn[2]["stdout_cap"], 1024**2)
        self.assertEqual(spawn[2]["stderr_cap"], 262144)

    def test_57_projection_write_failure_and_tool_failure_preserve_primary_unknown(self):
        writes, _ = self.run_failure(fail_write=True)
        self.assertNotIn("/expat-apt-proof/command-1-apt-diagnostic.json", writes)
        self.assertIn("/expat-apt-proof/command-1-UNKNOWN.json", writes)
        for after in ("RAISE", "IDENTITY", "b" * 64):
            writes, _ = self.run_failure(after=after)
            packet = json.loads(writes["/expat-apt-proof/command-1-apt-diagnostic.json"])
            self.assertEqual(packet["state"], "UNKNOWN")
            self.assertFalse(packet["tool_stable"])
            self.assertFalse(packet["archives_missing_message_observed"])
            self.assertNotIn("PRIVATE", json.dumps(packet))
        with patch.object(
            t, "apt_failure_diagnostic", side_effect=RuntimeError("PRIVATE_CALLBACK")
        ):
            writes, _ = self.run_failure()
        self.assertIn("/expat-apt-proof/command-1-UNKNOWN.json", writes)

    def test_58_closed_role_rejects_other_argv_env_budgets_before_tool_or_spawn(self):
        self.assertEqual(tuple(t.APT_SIMULATE_ARGV[6:]), g.REQUESTS)
        base = dict(
            argv=list(t.APT_SIMULATE_ARGV),
            seconds=90,
            cap=1024**2,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "HOME": "/expat-apt-work",
                "APT_CONFIG": "/expat-apt-work/solver.conf",
                "DEBIAN_FRONTEND": "noninteractive",
            },
            diagnostic_role="apt_simulate",
        )
        for changes in (
            {"diagnostic_role": True},
            {"diagnostic_role": "PRIVATE"},
            {"argv": ["/usr/bin/apt-get", "install", "private"]},
            {"argv": list(t.APT_SIMULATE_ARGV) + ["--fix-missing"]},
            {"env": {**base["env"], "PRIVATE": "SECRET"}},
            {"seconds": 91},
            {"seconds": True},
            {"cap": 1024**2 + 1},
            {"post_expected": {}},
        ):
            runner = t.Runner(None, m, {}, until=1000)
            runner.tool_pin = lambda _: self.fail("tool must not be read")
            with self.assertRaisesRegex(ValueError, "^apt_diagnostic_role$"):
                runner.call(**{**base, **changes})
            self.assertEqual(runner.ordinal, 0)

    def test_59_real_solver_failure_stops_before_plan_and_material_payloads(self):
        solver = module("c_diagnostic_solver", "solver.py")
        events = []

        class MP(PurePosixPath):
            def mkdir(self, **kwargs):
                events.append(("mkdir", str(self)))

        def call(argv, **kwargs):
            self.assertEqual(tuple(argv), fence.APT_ARGV)
            self.assertNotIn("diagnostic_role", kwargs)
            self.assertEqual(kwargs["seconds"], 90)
            self.assertEqual(kwargs["cap"], 1024**2)
            raise ValueError("client_failed_or_UNKNOWN")

        tx = SimpleNamespace(
            WORK=MP("/expat-apt-work"),
            apt_configuration=t.apt_configuration,
            write_new=lambda p, raw, *a: events.append(("write", str(p))),
        )
        runner = SimpleNamespace(simulate=call)
        with patch.object(
            solver, "parse_plan", side_effect=AssertionError("no plan after failure")
        ):
            with self.assertRaisesRegex(ValueError, "^client_failed_or_UNKNOWN$"):
                simulation = solver.configure(
                    runner,
                    g,
                    {s: b"PUBLIC" for s in g.REPOSITORIES},
                    {s: b"PUBLIC" for s in g.REPOSITORIES},
                    tx,
                )
                solver.parse_plan(simulation, {}, {}, m)
        self.assertFalse(any(p.endswith(".deb") for _, p in events))

    def test_60_legacy_calls_do_not_project_or_postcheck_nonzero_as_success(self):
        writes, events = self.run_failure(role=None)
        self.assertFalse(any(p.endswith("-apt-diagnostic.json") for p in writes))
        self.assertEqual(len([e for e in events if e[0] == "tool"]), 1)

    def test_61_success_keeps_old_postcheck_and_returns_buffers_without_diagnostic(self):
        writes = {}
        result = self.result(ok=True, returncode=0, reason=None, stderr=b"")

        def run(argv, **kwargs):
            kwargs["on_spawn"](123)
            return result

        runner = t.Runner(SimpleNamespace(run_capped=run), m, {}, until=1000)
        runner.tool_pin = lambda _: ("a" * 64, (1,))
        with (
            patch.object(t.time, "monotonic", return_value=0),
            patch.object(t, "write_new", lambda p, b: writes.update({str(p): b})),
            patch.object(
                t, "apt_failure_diagnostic", side_effect=AssertionError("no success diagnostic")
            ),
        ):
            self.assertEqual(runner.call(["/usr/bin/apt-get"], seconds=30), (result.stdout, b""))
        self.assertFalse(runner.unknown)
        self.assertEqual(len(runner.records), 1)
        self.assertFalse(any(p.endswith("-apt-diagnostic.json") for p in writes))


if __name__ == "__main__":
    unittest.main()


def positive_native_summary(code_sha, pins):
    facts = {
        "spawn_attempted": True,
        "pid": 321,
        "returncode": 0,
        "reason": None,
        "exception_type": None,
        "killed_owned_child": False,
        "owned_child_reaped": True,
        "drains_complete": True,
        "cleanup_exception_type": None,
        "stdout_bytes": 200,
        "stderr_bytes": 0,
    }
    return {
        "schema": "pamolive.expat-solver-fence-native-DATA/1",
        "state": "COMPLETE_DATA_ONLY",
        "code_pins_sha256": code_sha,
        "helper_sha256": pins["solver_fence.py"],
        "native_source_sha256": pins["native_fence_tests.py"],
        "filter_sha256": fence.filter_sha(),
        "cases": ["syscalls", "exec"],
        "H1": [dict(facts), dict(facts)],
        "build_verified": False,
        "materials_complete": False,
        "all_OS_descendants_released": False,
        "operational_GO": False,
    }
