"""Synthetic ELF/package/backport evidence; no Linux code, DB or network runs."""

import copy
import json
import lzma
import struct
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import krb5_inventory as inv


def synthetic_elf(soname, *, symbol="synthetic_export", version="SYNTHETIC_1", tail=b""):
    strings = b"\0" + soname.encode() + b"\0" + symbol.encode() + b"\0" + version.encode() + b"\0"
    symname = strings.index(symbol.encode())
    vername = strings.index(version.encode())
    chunks = [b"", strings, bytes(24) + struct.pack("<IBBHQQ", symname, 18, 0, 1, 0, 10),
              struct.pack("<qQqQ", 14, 1, 0, 0),
              struct.pack("<HHHHIIIII", 1, 0, 2, 1, 0, 20, 0, vername, 0),
              struct.pack("<HH", 0, 2)]
    offset = 64 + 64 * len(chunks)
    sections = []
    for index, chunk in enumerate(chunks):
        kind = [0, 3, 11, 6, 0x6FFFFFFD, 0x6FFFFFFF][index]
        link = 1 if index in (2, 3, 4) else 2 if index == 5 else 0
        sections.append(struct.pack("<IIQQQQIIQQ", 0, kind, 0, 0, offset,
                                    len(chunk), link, 0, 1, 24 if index == 2 else 0))
        offset += len(chunk)
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01" + bytes(10),
                         3, 62, 1, 0, 0, 64, 0, 64, 56, 0, 64, len(chunks), 0)
    return header + b"".join(sections) + b"".join(chunks) + tail


def regression():
    result = {"schema": "pamolive.krb5-asn1-regression.v1", "patch_sha256": inv.PATCH,
              "source_original_sha256": inv.DECODER_SOURCE["before"],
              "source_patched_sha256": inv.DECODER_SOURCE["after"]}
    for phase in ("before", "after"):
        cases = {name: {"status": "passed", "decoder_success": name in ("empty", "long_valid"),
                        "live_allocations_after_cleanup": 0, "allocation_attempts": 0,
                        "malloc_calls": 0, "calloc_calls": 0, "realloc_calls": 0,
                        "failure_points": 0} for name in (
            "empty", "long_valid", "bad_tag", "truncated", "allocation_failure", "partial_cleanup")}
        cases["long_valid"].update(decoded_count=256, decoded_value=7,
            realloc_calls=256 if phase == "before" else 0,
            calloc_calls=1 if phase == "before" else 2,
            allocation_attempts=257 if phase == "before" else 2)
        cases["allocation_failure"]["failure_points"] = 257 if phase == "before" else 2
        result[phase] = {"schema": "pamolive.krb5-asn1-regression.v1", "verified": True,
            "patch_sha256": inv.PATCH, "upstream_make_check_replaced": False,
            "source_file_sha256": inv.DECODER_SOURCE[phase],
            "harness_sha256": inv.digest(b"harness"),
            "executable_sha256": "3" * 64, "objects": [
                {"name": "asn1_encode.o", "sha256": "4" * 64},
                {"name": "asn1_k_encode.o", "sha256": "5" * 64}],
            "case_count": 6, "element_count": 256, "cases": cases,
            "phase": "baseline" if phase == "before" else "patched"}
    return result


class EvidenceNameTests(TestCase):
    def test_exact_debian_descriptor_revision_is_supported(self):
        name = "krb5_1.21.3-5+deb13u1.dsc"
        self.assertEqual(inv.evidence_name(name), name)

    def test_adding_plus_does_not_admit_paths_unicode_or_unbounded_names(self):
        for name in ("../krb5+revision.dsc", "a/b+dsc", "a\\b+dsc", "/a+dsc", "..",
                     ".hidden", "+revision.dsc", "a+é.dsc", "a+\0.dsc", "a+\n.dsc",
                     "a" * 102, None, 1):
            with self.subTest(name=name), self.assertRaisesRegex(inv.Krb5Error, "evidence_name"):
                inv.evidence_name(name)


class Krb5InventoryTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pamolive-krb5-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.patch = b"Synthetic test patch. Not a real security correction."
        self.override = patch.object(inv, "PATCH", inv.digest(self.patch))
        self.override.start()
        self.addCleanup(self.override.stop)
        self.install(inv.BASE_VERSION)
        previous = inv.baseline(root=self.root)
        self.install(inv.VERSION, tail=b"synthetic patched bytes")
        self.write("baseline.json", previous)
        self.write("upstream.patch", self.patch)
        asn1 = regression()
        self.write("asn1.json", asn1)
        self.write("before.json", asn1["before"])
        self.write("after.json", asn1["after"])
        self.write("harness.c", b"harness")
        self.write("wrapper.sh", b"synthetic wrapper")
        self.write("debian-build.log", b"synthetic successful Debian build/test output")
        self.write("debian-tests.json", {"schema": "pamolive.krb5-debian-tests.v1",
            "status": "passed", "tests_enabled": True, "exit_code": 0, "jobs": 1,
            "command": "dpkg-buildpackage -B -us -uc -j1",
            "log_sha256": inv.digest((self.folder / "debian-build.log").read_bytes())})
        self.write("gpgv.status", b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" 0 0 0\n")
        source_lines = "\n".join(f" {sha} 100 {name}" for name, sha in inv.SOURCES.items())
        dsc = ("Format: 3.0 (quilt)\nChecksums-Sha256:\n" + source_lines + "\n").encode()
        self.dsc_name = f"krb5_{inv.BASE_VERSION}.dsc"
        self.write(self.dsc_name, dsc)
        record = ("Package: krb5\nVersion: " + inv.BASE_VERSION + "\nChecksums-Sha256:\n" +
                  source_lines + f"\n {inv.digest(dsc)} {len(dsc)} krb5_{inv.BASE_VERSION}.dsc\n")
        self.write("source-record.txt", record.encode())
        index = lzma.compress((record + "\n").encode())
        self.write("Sources.xz", index)
        release = (f"SHA256:\n {inv.digest(index)} {len(index)} main/source/Sources.xz\n").encode()
        self.write("Release", release)
        self.write("InRelease", b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" +
                   release + b"-----BEGIN PGP SIGNATURE-----\nsynthetic-only\n")
        self.write("keyring.gpg", b"Synthetic keyring; no cryptographic verification in unit tests")
        self.provenance = {"schema": inv.PROVENANCE_SCHEMA, "base_version": inv.BASE_VERSION,
            "version": inv.VERSION, "upstream_commit": inv.COMMIT, "patch_sha256": inv.PATCH,
            "sources": inv.SOURCES, "build": {"jobs": 1, "tests_enabled": True},
            "test_outputs": {"debian": "debian-tests.json", "asn1": "asn1.json",
                "before": "before.json", "after": "after.json", "harness": "harness.c",
                "wrapper": "wrapper.sh"},
            "apt_chain": {"status_file": "gpgv.status", "signer_fingerprints": ["A" * 40],
                "inrelease_file": "InRelease", "release_file": "Release",
                "index_file": "Sources.xz",
                "source_record_file": "source-record.txt", "keyring_file": "keyring.gpg",
                "index_release_path": "main/source/Sources.xz", "dsc_file": self.dsc_name},
            "evidence": {name: inv.digest((self.folder / name).read_bytes()) for name in (
                "baseline.json", "upstream.patch", "asn1.json", "debian-tests.json",
                "gpgv.status", "InRelease", "Release", "Sources.xz", "source-record.txt",
                "keyring.gpg", self.dsc_name, "before.json", "after.json", "harness.c",
                "wrapper.sh", "debian-build.log")}}
        self.write("provenance.json", self.provenance)

    @property
    def folder(self):
        return self.root / inv.PREFIX.lstrip("/")

    def write(self, name, value):
        self.folder.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, bytes) else (inv.canonical(value) + "\n").encode()
        (self.folder / name).write_bytes(raw)

    def install(self, version, tail=b""):
        folder = self.root / "usr/lib/x86_64-linux-gnu"
        folder.mkdir(parents=True, exist_ok=True)
        status = []
        for package, (filename, soname) in inv.LIBRARIES.items():
            (folder / filename).write_bytes(synthetic_elf(soname, tail=tail))
            status.append(f"Package: {package}\nStatus: install ok installed\nArchitecture: amd64\n"
                          f"Version: {version}\n")
        path = self.root / "var/lib/dpkg/status"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(status))

    def manifest(self):
        return inv.inventory(root=self.root)

    def add_capability_skip(self):
        test_patch = b"Synthetic test-only compatibility patch"
        override = patch.object(inv, "TEST_COMPAT_PATCH", inv.digest(test_patch))
        override.start()
        self.addCleanup(override.stop)
        self.write("test-keyring-compat.patch", test_patch)
        self.write("keyctl-probe.py", b"synthetic probe source; never executed")
        self.write("keyctl-probe.json", {"schema": "pamolive.krb5-keyring-probe.v1",
            "exit_code": 1, "errno": "EPERM", "stderr_sha256": inv.KEYRING_STDERR,
            "probe_script_sha256": inv.digest((self.folder / "keyctl-probe.py").read_bytes()),
            "command": inv.KEYRING_COMMAND, "seccomp_mode": 2, "network": "none",
            "supported": False})
        text = "".join("*** Skipping: " + name + ": keyring support not built\n"
                       for name in inv.KEYRING_TESTS).encode()
        self.write("baseline-build.log", text)
        self.write("debian-build.log", text)
        tests = json.loads((self.folder / "debian-tests.json").read_text())
        tests.update(status="passed_with_capability_skips", log_sha256=inv.digest(text),
            test_python="/usr/bin/python3",
            capability_skips=[{"capability": "kernel_keyring", "reason": "docker_seccomp_eperm",
                "probe_file": "keyctl-probe.json", "probe_script_file": "keyctl-probe.py",
                "test_patch_file": "test-keyring-compat.patch", "tests": list(inv.KEYRING_TESTS),
                "historical_test_message": "keyring support not built",
                "phase_logs": {"baseline": "baseline-build.log", "patched": "debian-build.log"},
                "phase_counts": {phase: dict.fromkeys(inv.KEYRING_TESTS, 1)
                                 for phase in ("baseline", "patched")}, "count": 4}])
        self.write("debian-tests.json", tests)
        for name in ("test-keyring-compat.patch", "keyctl-probe.py", "keyctl-probe.json",
                     "baseline-build.log", "debian-build.log", "debian-tests.json"):
            self.provenance["evidence"][name] = inv.digest((self.folder / name).read_bytes())
        self.write("provenance.json", self.provenance)
        return tests

    def test_complete_synthetic_backport_checks_real_elf_bytes_and_evidence(self):
        value = self.manifest()
        self.assertEqual(len(value["libraries"]), 4)
        self.assertEqual(value["packages"], dict.fromkeys(inv.LIBRARIES, inv.VERSION))
        self.assertEqual(len(inv.archive_conditions(value)), 22)

    def test_export_and_version_changes_modify_computed_abi(self):
        before = inv.elf_abi(synthetic_elf("synthetic.so.1"))
        for kwargs in ({"symbol": "other_export"}, {"version": "SYNTHETIC_2"}):
            self.assertNotEqual(before["abi_sha256"], inv.elf_abi(
                synthetic_elf("synthetic.so.1", **kwargs))["abi_sha256"])
        self.assertEqual(before, inv.elf_abi(synthetic_elf("synthetic.so.1", tail=b"changed code")))

    def test_malformed_or_other_architecture_elf_is_refused(self):
        data = bytearray(synthetic_elf("synthetic.so.1"))
        for changed in (b"not ELF", bytes(data[:90]), bytes(data[:18] + b"\xb7\x00" + data[20:])):
            with self.subTest(size=len(changed)), self.assertRaises(inv.Krb5Error):
                inv.elf_abi(changed)

    def test_missing_changed_wrong_version_or_extra_package_record_refused(self):
        path = self.root / "var/lib/dpkg/status"
        original = path.read_text()
        for changed in (original.replace(inv.VERSION, inv.BASE_VERSION, 1),
                        original + "\n" + original, original.split("\n\n", 1)[1]):
            path.write_text(changed)
            with self.subTest(), self.assertRaises(inv.Krb5Error):
                self.manifest()
        path.write_text(original)

    def test_same_patch_metadata_with_changed_bytes_is_refused(self):
        self.write("upstream.patch", b"tampered")
        with self.assertRaisesRegex(inv.Krb5Error, "evidence_changed"):
            self.manifest()

    def test_source_commit_version_and_serial_build_profile_fail_closed(self):
        original = self.manifest()
        for key, value in (("sources", {}), ("upstream_commit", "0" * 40),
                           ("version", "1.22.3"), ("build", {"jobs": 12, "tests_enabled": True})):
            manifest = copy.deepcopy(original)
            manifest["provenance"][key] = value
            with self.subTest(key=key), self.assertRaises(inv.Krb5Error):
                inv.validate_manifest(manifest)

    def test_changed_abi_and_unchanged_patched_library_are_refused(self):
        original = self.manifest()
        for key, value in (("abi_sha256", "a" * 64), ("soname", "other.so.1")):
            manifest = copy.deepcopy(original)
            manifest["libraries"][0][key] = value
            with self.subTest(key=key), self.assertRaises(inv.Krb5Error):
                inv.validate_manifest(manifest)
        original["libraries"] = [{**item, "version": inv.VERSION}
                                 for item in original["baseline"]["libraries"]]
        with self.assertRaisesRegex(inv.Krb5Error, "patched_library_unchanged"):
            inv.validate_manifest(original)

    def test_failed_missing_or_false_allocation_regression_cannot_attest_fix(self):
        original = regression()
        mutations = [lambda v: v["after"]["cases"].pop("truncated"),
                     lambda v: v["after"]["cases"]["long_valid"].update(realloc_calls=256),
                     lambda v: v["after"]["cases"]["long_valid"].update(decoded_value=8),
                     lambda v: v["after"]["cases"]["partial_cleanup"].update(
                         live_allocations_after_cleanup=1),
                     lambda v: v["before"]["cases"]["long_valid"].update(realloc_calls=0)]
        for change in mutations:
            value = copy.deepcopy(original)
            change(value)
            with self.subTest(), self.assertRaises(inv.Krb5Error):
                inv.validate_regression(value)

    def test_failed_signature_even_beside_validsig_is_refused(self):
        self.write("gpgv.status", ("[GNUPG:] VALIDSIG " + "A" * 40 +
                                 "\n[GNUPG:] BADSIG synthetic\n").encode())
        self.provenance["evidence"]["gpgv.status"] = inv.digest(
            (self.folder / "gpgv.status").read_bytes())
        self.write("provenance.json", self.provenance)
        with self.assertRaisesRegex(inv.Krb5Error, "apt_signature_failed"):
            self.manifest()

    def test_duplicate_keys_path_escape_and_arbitrary_evidence_rejected(self):
        self.write("duplicate.json", b'{"x":1,"x":2}')
        with self.assertRaisesRegex(inv.Krb5Error, "duplicate_json_key"):
            inv.read_json(self.folder / "duplicate.json")
        for path in ("/../escape", "/usr//escape", "relative", "C:\\escape"):
            with self.subTest(path=path), self.assertRaises(inv.Krb5Error):
                inv.local(self.root, path)
        with self.assertRaises(inv.Krb5Error):
            inv.evidence_name("../elsewhere")

    def test_source_chain_links_are_checked_not_only_declared_status(self):
        files = {name: (self.folder / name).read_bytes() for name in self.provenance["evidence"]}
        for target in ("Release", "Sources.xz", "source-record.txt", self.dsc_name):
            changed = dict(files)
            changed[target] += b"tampered"
            with self.subTest(target=target), self.assertRaises(inv.Krb5Error):
                inv.validate_chain(self.provenance, changed)

    def test_debian_test_result_binds_command_parallelism_and_exact_log(self):
        original = self.manifest()
        for key, value in (("log_sha256", "0" * 64), ("jobs", 12),
                           ("tests_enabled", False), ("command", "dpkg-buildpackage -d")):
            changed = copy.deepcopy(original)
            changed["debian_tests"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                    inv.Krb5Error, "debian_tests_failed"):
                inv.validate_manifest(changed)

    def test_capability_skip_is_explicit_hash_bound_and_counted_from_both_logs(self):
        self.add_capability_skip()
        manifest = self.manifest()
        self.assertEqual(manifest["debian_tests"]["status"], "passed_with_capability_skips")
        self.assertEqual(len(inv.archive_conditions(manifest)), 26)

    def test_capability_skip_cannot_be_disguised_as_all_tests_passed(self):
        tests = self.add_capability_skip()
        tests["status"] = "passed"
        with self.assertRaisesRegex(inv.Krb5Error, "undocumented_capability_skips"):
            inv.validate_debian_tests(tests, self.provenance)

    def test_wrong_error_probe_profile_or_script_hash_cannot_justify_skip(self):
        tests = self.add_capability_skip()
        files = {name: (self.folder / name).read_bytes() for name in self.provenance["evidence"]}
        for field, value in (("exit_code", 2), ("errno", "EACCES"), ("seccomp_mode", 0),
                             ("stderr_sha256", "0" * 64), ("probe_script_sha256", "1" * 64)):
            changed = dict(files)
            probe = json.loads(changed["keyctl-probe.json"])
            probe[field] = value
            changed["keyctl-probe.json"] = json.dumps(probe).encode()
            with self.subTest(field=field), self.assertRaisesRegex(
                    inv.Krb5Error, "capability_probe"):
                inv.validate_capability_files(tests, self.provenance, changed)

    def test_other_tests_unknown_patch_or_claimed_counts_fail_closed(self):
        tests = self.add_capability_skip()
        for field, value in (("tests", ["all tests"]), ("reason", "network unavailable"),
                             ("count", 99)):
            changed = copy.deepcopy(tests)
            changed["capability_skips"][0][field] = value
            with self.subTest(field=field), self.assertRaises(inv.Krb5Error):
                inv.validate_debian_tests(changed, self.provenance)
        changed = copy.deepcopy(self.provenance)
        changed["evidence"]["test-keyring-compat.patch"] = "0" * 64
        with self.assertRaisesRegex(inv.Krb5Error, "capability_evidence"):
            inv.validate_debian_tests(tests, changed)
        files = {name: (self.folder / name).read_bytes() for name in self.provenance["evidence"]}
        files["baseline-build.log"] = b"no actual skip recorded"
        with self.assertRaisesRegex(inv.Krb5Error, "capability_log_counts"):
            inv.validate_capability_files(tests, self.provenance, files)

    def test_cli_fixed_root_output_exclusive_and_static_errors(self):
        output = self.root / "report.json"
        value = self.manifest()
        with patch.object(inv, "inventory", return_value=value):
            self.assertEqual(inv.main(["--capture", "--output", str(output)]), 0)
            self.assertEqual(inv.main(["--capture", "--output", str(output)]), 1)
        self.assertEqual(json.loads(output.read_text()), value)
        with self.assertRaises(SystemExit):
            inv.main(["--capture", "--root", str(self.root), "--output", str(output)])
