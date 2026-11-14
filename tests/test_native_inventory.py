"""Adverse native inventory tests: no Docker, ELF execution or network."""

import copy
import io
import json
import os
import struct
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import native_inventory as native

ROOT = Path(__file__).resolve().parents[1]


def elf(search="/opt/pamolive-freerdp/lib", needed="libc.so.6"):
    table = b"\0" + needed.encode() + b"\0" + search.encode() + b"\0"
    data = bytearray(512 + len(table))
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0,
                     b"\x7fELF\x02\x01" + b"\0" * 10, 3, 62, 1, 0,
                     64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 4096)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 176, 0x4000B0, 0, 80, 80, 8)
    entries = ((5, 0x400200), (10, len(table)), (1, 1), (29, len(needed) + 2), (0, 0))
    for i, item in enumerate(entries):
        struct.pack_into("<qQ", data, 176 + i * 16, *item)
    data[512:] = table
    return bytes(data)


class NativeInventoryTests(TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="pamolive-native-unit-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.paths = []
        for name, prefix in native.PREFIXES.items():
            folder = prefix + ("/share/pamolive-freerdp" if name == "freerdp"
                               else "/share/pamolive")
            version, digest = native.SOURCES[name]
            self.write(folder + "/version.txt", version)
            self.write(folder + "/source-sha256.txt", digest)
            if name == "freerdp":
                self.write(folder + "/signer-fingerprint.txt", native.SIGNER)
                self.write(folder + "/signature.status", "[GNUPG:] VALIDSIG " + native.SIGNER)
                self.write(folder + "/build-options.txt", "\n".join(
                    f"{k}:BOOL={v}" for k, v in native.OPTIONS.items()))
                self.write(folder + "/rpath-policy.txt", prefix + "/lib")
                self.write(folder + "/rpath-tool.txt", "patchelf 0.18.0")
                self.write(folder + "/compile-policy.json", json.dumps({
                    "schema": "pamolive.native-compile-policy.v1", "verified": True,
                    "compile_commands_sha256": "a" * 64, "compilation_commands": 100,
                    "link_command_files": 10, "prohibited_flag_prefixes": ["-flto", "-mavx"],
                    "allowed_march": ["-march=x86-64"],
                    "excluded_configuration_probe_roots": native.CONFIGURATION_PROBES,
                }))
                suffixes = ("/lib/libfreerdp3.so.3", "/lib/libfreerdp-client3.so.3",
                            "/lib/libwinpr3.so.3")
            else:
                self.write(folder + "/build-options.txt", " ".join(native.GUAC_FLAGS))
                self.write(folder + "/freerdp-version.txt", native.SOURCES["freerdp"][0])
                self.write(folder + "/guacd-deny-rdp-redirection.patch",
                           (ROOT / "deploy/guacd-deny-rdp-redirection.patch").read_bytes())
                self.write(folder + "/guacd-freerdp3-gdi-lifecycle.patch", (
                    ROOT / "deploy/guacd-freerdp3-gdi-lifecycle.patch").read_bytes())
                self.write(folder + "/gdi-upstream-commit.txt", native.COMPAT_UPSTREAM_COMMIT)
                suffixes = ("/sbin/guacd", "/lib/libguac-client-rdp.so",
                            "/lib/libguac-client-ssh.so")
            for suffix in suffixes:
                self.paths.append(self.write(prefix + suffix, elf()))
        self.write("/usr/lib/x86_64-linux-gnu/libc.so.6", b"system-library")
        self.write("/var/lib/dpkg/status", "Package: libc6\nStatus: install ok installed\n")

    def write(self, path, value):
        path = self.root / path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())
        return path

    def probe(self, path):
        return [{"soname": "libc.so.6", "path": "/usr/lib/x86_64-linux-gnu/libc.so.6"}]

    def versions(self):
        return {"freerdp": "3.33.1", "winpr": "3.33.1", "guacd": "1.6.0",
                "freerdp_build_options": dict(native.RUNTIME_OPTIONS)}

    def inventory(self):
        return native.inventory(root=self.root, link_probe=self.probe, version_probe=self.versions)

    def test_capture_and_verify_every_native_file(self):
        manifest = self.inventory()
        result = native.verify(manifest, root=self.root, link_probe=self.probe,
                               version_probe=self.versions)
        self.assertTrue(result["verified"])
        self.assertFalse(result["live_link_probe"])
        self.assertEqual(len(result["inventory"]["files"]), 6)

    def test_changed_binary_fails_existing_manifest(self):
        manifest = self.inventory()
        self.paths[0].write_bytes(self.paths[0].read_bytes() + b"changed")
        with self.assertRaisesRegex(native.InventoryError, "inventory_changed"):
            native.verify(manifest, root=self.root, link_probe=self.probe,
                          version_probe=self.versions)

    def test_omitted_or_additional_binary_fails(self):
        manifest = self.inventory()
        bad = copy.deepcopy(manifest)
        bad["files"].pop()
        with self.assertRaisesRegex(native.InventoryError, "inventory_changed"):
            native.verify(bad, root=self.root, link_probe=self.probe, version_probe=self.versions)
        self.write("/opt/pamolive-freerdp/lib/extra.so", elf())
        with self.assertRaisesRegex(native.InventoryError, "inventory_changed"):
            native.verify(manifest, root=self.root, link_probe=self.probe,
                          version_probe=self.versions)

    def test_wrong_version_hash_signer_and_build_options_fail(self):
        folder = "/opt/pamolive-freerdp/share/pamolive-freerdp/"
        for name, value in (("version.txt", "3.15.0"), ("source-sha256.txt", "0" * 64),
                            ("signer-fingerprint.txt", "0" * 40),
                            ("signature.status", "[GNUPG:] BADSIG other"),
                            ("build-options.txt", "WITH_OPENSSL:BOOL=OFF")):
            path = self.root / (folder + name).lstrip("/")
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_text(value)
                with self.assertRaises(native.InventoryError):
                    self.inventory()
                path.write_bytes(original)

    def test_missing_required_consumer_fails(self):
        self.paths[-1].unlink()
        with self.assertRaisesRegex(native.InventoryError, "required_consumer_missing"):
            self.inventory()

    def test_guacd_requires_both_reviewed_patch_bytes_and_pinned_upstream_commit(self):
        folder = "opt/pamolive-guac/share/pamolive/"
        for filename, value, code in (
                ("guacd-deny-rdp-redirection.patch", b"changed", "patch_identity"),
                ("guacd-freerdp3-gdi-lifecycle.patch", b"changed", "compat_patch_identity"),
                ("gdi-upstream-commit.txt", b"0" * 40, "compat_patch_upstream")):
            path = self.root / (folder + filename)
            original = path.read_bytes()
            path.write_bytes(value)
            with self.subTest(filename=filename), self.assertRaisesRegex(
                    native.InventoryError, code):
                self.inventory()
            path.write_bytes(original)

    def test_real_version_disagrees_with_source_metadata_fails(self):
        with self.assertRaisesRegex(native.InventoryError, "runtime_version_mismatch"):
            native.inventory(root=self.root, link_probe=self.probe, version_probe=lambda: {
                "freerdp": "3.15.0", "winpr": "3.15.0", "guacd": "1.6.0"})

    def test_uninitialized_string_and_duplicate_cmake_security_flags_fail(self):
        path = self.root / "opt/pamolive-freerdp/share/pamolive-freerdp/build-options.txt"
        original = path.read_text()
        for value in (original.replace("WITH_SIMD:BOOL", "WITH_SIMD:UNINITIALIZED"),
                      original.replace("WITH_SIMD:BOOL", "WITH_SIMD:STRING"),
                      original + "\nWITH_SIMD:BOOL=OFF"):
            with self.subTest(value=value[-40:]):
                path.write_text(value)
                with self.assertRaises(native.InventoryError):
                    self.inventory()
        path.write_text(original)

    def test_only_known_dependent_cmake_internal_type_is_accepted(self):
        path = self.root / "opt/pamolive-freerdp/share/pamolive-freerdp/build-options.txt"
        original = path.read_text()
        path.write_text(original.replace("WITH_CLIENT_SDL:BOOL", "WITH_CLIENT_SDL:INTERNAL"))
        self.inventory()
        path.write_text(original.replace("WITH_SIMD:BOOL", "WITH_SIMD:INTERNAL"))
        with self.assertRaisesRegex(native.InventoryError, "build_option_type"):
            self.inventory()

    def test_runtime_build_flags_override_claimed_cache_values(self):
        flags = self.versions()
        flags["freerdp_build_options"]["WITH_FFMPEG"] = "ON"
        with self.assertRaisesRegex(native.InventoryError, "runtime_version_mismatch"):
            native.inventory(root=self.root, link_probe=self.probe, version_probe=lambda: flags)

    def test_rpath_transformation_must_be_real_bounded_tool_and_allowed_prefix(self):
        folder = "opt/pamolive-freerdp/share/pamolive-freerdp/"
        for filename, content in (("rpath-tool.txt", "fake tool"),
                                  ("rpath-policy.txt", "/tmp")):
            path = self.root / (folder + filename)
            original = path.read_text()
            path.write_text(content)
            with self.assertRaises(native.InventoryError):
                self.inventory()
            path.write_text(original)

    def test_compile_policy_requires_commands_hash_counts_and_exact_restrictions(self):
        path = self.root / "opt/pamolive-freerdp/share/pamolive-freerdp/compile-policy.json"
        original = json.loads(path.read_text())
        for key, bad in (("verified", False), ("compile_commands_sha256", "invalid"),
                         ("compilation_commands", 0), ("link_command_files", True),
                         ("prohibited_flag_prefixes", []), ("allowed_march", ["-march=native"])):
            with self.subTest(key=key):
                path.write_text(json.dumps({**original, key: bad}))
                with self.assertRaises(native.InventoryError):
                    self.inventory()
        path.write_text(json.dumps(original))

    def test_compile_policy_rejects_any_additional_or_rewritten_probe_exclusion(self):
        path = self.root / "opt/pamolive-freerdp/share/pamolive-freerdp/compile-policy.json"
        original = json.loads(path.read_text())
        for bad in (native.CONFIGURATION_PROBES + ["build/libfreerdp"], ["build/*"],
                    ["build/CMakeFiles/../libfreerdp"], ["/opt/pamolive-freerdp/lib"], []):
            with self.subTest(exclusion=bad):
                path.write_text(json.dumps({**original, "excluded_configuration_probe_roots": bad}))
                with self.assertRaisesRegex(native.InventoryError, "compile_policy_exclusions"):
                    self.inventory()
        path.write_text(json.dumps(original))

    def test_native_library_misattributed_to_guacd_fails(self):
        self.write("/opt/pamolive-guac/lib/libfreerdp3.so.3", elf())
        def misplaced(path):
            return self.probe(path) + [{"soname": "libfreerdp3.so.3",
                                       "path": "/opt/pamolive-guac/lib/libfreerdp3.so.3"}]
        with self.assertRaisesRegex(native.InventoryError, "native_link_component"):
            native.inventory(root=self.root, link_probe=misplaced, version_probe=self.versions)

    def test_legacy_freerdp_debian_package_fails(self):
        self.write("/var/lib/dpkg/status",
                   "Package: libfreerdp3-3\nStatus: install ok installed\n")
        with self.assertRaisesRegex(native.InventoryError, "legacy_package"):
            self.inventory()

    def test_native_soname_loaded_from_system_path_fails(self):
        self.write("/usr/lib/x86_64-linux-gnu/libfreerdp3.so.3", b"old-library")
        def malicious(path):
            return self.probe(path) + [{"soname": "libfreerdp3.so.3",
                                       "path": "/usr/lib/x86_64-linux-gnu/libfreerdp3.so.3"}]
        with self.assertRaisesRegex(native.InventoryError, "native_link_outside_manifest"):
            native.inventory(root=self.root, link_probe=malicious, version_probe=self.versions)

    def test_unresolved_needed_and_arbitrary_system_path_fail(self):
        self.write("/tmp/libc.so.6", b"injected")
        with self.assertRaisesRegex(native.InventoryError, "unexpected_system_link"):
            native.inventory(root=self.root, version_probe=self.versions, link_probe=lambda _: [
                {"soname": "libc.so.6", "path": "/tmp/libc.so.6"}])
        with self.assertRaisesRegex(native.InventoryError, "needed_not_resolved"):
            native.inventory(root=self.root, version_probe=self.versions, link_probe=lambda _: [
                {"soname": "other.so", "path": "/usr/lib/x86_64-linux-gnu/libc.so.6"}])

    def test_rpath_injection_relative_empty_and_origin_fail(self):
        for value in ("/tmp", "$ORIGIN", "relative", "/opt/pamolive-freerdp/lib:"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    native.InventoryError, "elf_search_path"):
                native.elf_dynamic(elf(value))

    def test_truncated_wrong_architecture_and_needed_path_fail(self):
        for value in (b"\x7fELF", elf()[:100], elf(needed="/tmp/injected.so")):
            with self.subTest(size=len(value)), self.assertRaises(native.InventoryError):
                native.elf_dynamic(value)

    def test_ldd_parser_refuses_missing_duplicate_and_unexpected_output(self):
        for value in ("libc.so.6 => not found", "statically linked", "malicious output",
                      "libc.so.6 => /lib/libc.so.6 (0xabc)\n" * 2):
            with self.subTest(value=value), self.assertRaises(native.InventoryError):
                native.parse_ldd(value)
        result = native.parse_ldd("linux-vdso.so.1 (0xabc)\n"
                                  "libc.so.6 => /lib/libc.so.6 (0xabc)\n"
                                  "/lib64/ld-linux-x86-64.so.2 (0xabc)")
        self.assertEqual(len(result), 2)

    def test_manifest_duplicate_keys_rejected(self):
        with self.assertRaisesRegex(native.InventoryError, "duplicate_json_key"):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=native._pairs)

    def test_cli_reserves_output_before_any_probe_and_never_overwrites(self):
        output = self.root / "output.json"
        output.write_text("preserve")
        with patch.object(native, "inventory") as capture, redirect_stdout(io.StringIO()):
            self.assertEqual(native.main(["--capture", "--output", str(output)]), 1)
        capture.assert_not_called()
        self.assertEqual(output.read_text(), "preserve")

    def test_cli_refuses_runtime_loader_environment_before_probe(self):
        output = self.root / "output.json"
        with patch.dict(os.environ, {"LD_LIBRARY_PATH": "/tmp"}), patch.object(
                native, "inventory") as capture, redirect_stdout(io.StringIO()):
            self.assertEqual(native.main(["--capture", "--output", str(output)]), 1)
        capture.assert_not_called()
