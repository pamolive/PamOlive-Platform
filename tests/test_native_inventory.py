"""Adverse native inventory tests: no Docker, ELF execution or network."""

import copy
import io
import json
import os
import stat
import struct
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
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
                self.write(folder + "/freerdp-jansson-compat.patch", (
                    ROOT / "deploy/freerdp-jansson-compat.patch").read_bytes())
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
                self.paths.append(self.write(prefix + suffix, elf(needed=(
                    "libjansson.so.4" if "libwinpr3" in suffix else "libc.so.6"))))
        self.write("/usr/lib/x86_64-linux-gnu/libc.so.6", b"system-library")
        self.write("/usr/lib/x86_64-linux-gnu/libjansson.so.4", b"system-jansson")
        self.write("/var/lib/dpkg/status", "Package: libc6\nStatus: install ok installed\n\n"
                   "Package: libjansson4\nStatus: install ok installed\nVersion: 2.14-2+b3\n")

    def write(self, path, value):
        path = self.root / path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())
        return path

    def probe(self, path):
        return [{"soname": name, "path": "/usr/lib/x86_64-linux-gnu/" + name}
                for name in ("libc.so.6", "libjansson.so.4")]

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

    def test_cjson_installed_needed_and_transitive_are_refused(self):
        status = self.root / "var/lib/dpkg/status"
        original = status.read_text()
        status.write_text(original + "\nPackage: libcjson1\nStatus: install ok installed\n")
        with self.assertRaisesRegex(native.InventoryError, "cjson_package"):
            self.inventory()
        status.write_text(original)
        self.paths[0].write_bytes(elf(needed="libcjson.so.1"))
        with self.assertRaisesRegex(native.InventoryError, "cjson_needed"):
            self.inventory()
        self.paths[0].write_bytes(elf())
        with self.assertRaisesRegex(native.InventoryError, "cjson_resolved"):
            native.inventory(root=self.root, version_probe=self.versions, link_probe=lambda p:
                self.probe(p) + [{"soname": "libcjson_utils.so.1", "path": "/tmp/no-open"}])

    def test_jansson_package_version_backend_and_patch_are_required(self):
        p = self.root / "var/lib/dpkg/status"
        original = p.read_text()
        for old, new, code in (("2.14-2+b3", "0.19+ds-1", "jansson_version"),
                               ("libjansson4", "other", "jansson_package_missing")):
            p.write_text(original.replace(old, new))
            with self.assertRaisesRegex(native.InventoryError, code):
                self.inventory()
        p.write_text(original)
        self.paths[2].write_bytes(elf())
        with self.assertRaisesRegex(native.InventoryError, "jansson_needed"):
            self.inventory()
        self.paths[2].write_bytes(elf(needed="libjansson.so.4"))
        self.write("/opt/pamolive-freerdp/share/pamolive-freerdp/"
                   "freerdp-jansson-compat.patch", "bad")
        with self.assertRaisesRegex(native.InventoryError, "json_patch_identity"):
            self.inventory()


class GCCMemoryFS:
    """Memory-only Linux metadata/FDs. Never opens a PC ELF or foreign FD."""

    def __init__(self):
        self.nodes, self.links, self.data = {}, {}, {}
        self.fds, self.closed, self.opened = {}, [], []
        self.on_read = None
        self.bad_fd = False
        self.growing = False
        for path in (
            "/",
            "/usr",
            "/usr/lib",
            native.GCC_DIRS[1],
            "/var",
            "/var/lib",
            "/var/lib/dpkg",
        ):
            self.add(path, stat.S_IFDIR | 0o755)
        self.add("/lib", stat.S_IFLNK | 0o777)
        self.links["/lib"] = "usr/lib"
        self.target = native.GCC_DIRS[1] + "/libstdc++.so.6.0.33"
        for directory in native.GCC_DIRS:
            path = directory + "/libstdc++.so.6"
            self.add(path, stat.S_IFLNK | 0o777)
            self.links[path] = "libstdc++.so.6.0.33"
        raw = bytearray(64)
        raw[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", raw, 16, 3, 62)
        self.add(self.target, stat.S_IFREG | 0o644, bytes(raw))
        self.status_path = "/var/lib/dpkg/status"
        self.status = "\n\n".join(
            "Package: "
            + name
            + "\nVersion: 14.2.0-19\nArchitecture: amd64\nStatus: install ok installed\n"
            "Description: PRIVATE_CANARY_NOT_PROJECTED\n"
            for name in native.GCC_PACKAGES
        ).encode()
        self.add(self.status_path, stat.S_IFREG | 0o644, self.status)

    def key(self, path):
        return str(path).replace("\\", "/")

    def add(self, path, mode, data=b""):
        self.nodes[path] = SimpleNamespace(
            st_dev=1,
            st_ino=len(self.nodes) + 1,
            st_mode=mode,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=len(data),
            st_mtime_ns=100,
            st_ctime_ns=200,
        )
        self.data[path] = data

    def lstat(self, path):
        path = self.key(path)
        if path not in self.nodes:
            raise FileNotFoundError()
        return self.nodes[path]

    def readlink(self, path):
        return self.links[self.key(path)]

    def open(self, path, flags, *args):
        path = self.key(path)
        if (
            flags
            != self.api.O_RDONLY | self.api.O_NOFOLLOW | self.api.O_NONBLOCK | self.api.O_CLOEXEC
        ):
            raise AssertionError("unexpected_open_flags")
        self.opened.append(path)
        fd = 50 + len(self.opened)
        self.fds[fd] = [path, 0]
        return fd

    def fstat(self, fd):
        row = self.nodes[self.fds[fd][0]]
        return SimpleNamespace(**(vars(row) | {"st_ino": 999})) if self.bad_fd else row

    def read(self, fd, size):
        path, offset = self.fds[fd]
        raw = b"G" * size if self.growing else self.data[path][offset : offset + size]
        self.fds[fd][1] += len(raw)
        if self.on_read:
            self.on_read(path, raw)
        return raw

    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("foreign_fd_close")
        self.closed.append(fd)
        del self.fds[fd]

    def patch(self):
        self.api = SimpleNamespace(
            name="posix",
            lstat=self.lstat,
            readlink=self.readlink,
            open=self.open,
            fstat=self.fstat,
            read=self.read,
            close=self.close,
            O_RDONLY=0,
            O_NOFOLLOW=0x20000,
            O_NONBLOCK=0x800,
            O_CLOEXEC=0x80000,
        )
        return patch.object(native, "os", self.api)


class GCCProviderDataTests(TestCase):
    def report(self, paths=None):
        paths = paths or [
            native.GCC_DIRS[0] + "/libstdc++.so.6",
            native.GCC_DIRS[1] + "/libstdc++.so.6",
        ]
        return {
            "schema": native.SCHEMA,
            "verified": True,
            "live_link_probe": True,
            "inventory": {
                "files": [
                    {
                        "path": "/opt/pamolive-freerdp/lib/consumer" + str(i),
                        "resolved": [{"soname": "libstdc++.so.6", "path": path}],
                    }
                    for i, path in enumerate(paths)
                ]
            },
        }

    def capture(self, fs, report=None):
        report = self.report() if report is None else report
        raw = (json.dumps(report, indent=2) + "\n").encode()
        with (
            fs.patch(),
            patch.object(native, "probe") as probe,
            patch.object(native, "runtime_versions") as versions,
        ):
            value = native.gcc_provider_data(report, raw)
        probe.assert_not_called()
        versions.assert_not_called()
        self.assertFalse(fs.fds)
        return value

    def test_one_provider_many_existing_routes_and_no_additional_probes(self):
        fs = GCCMemoryFS()
        value = self.capture(fs)
        self.assertEqual(len(value["routes"]), 2)
        self.assertEqual(
            value["provider"]["sha256"], native.hashlib.sha256(fs.data[fs.target]).hexdigest()
        )
        self.assertEqual(value["provider"]["machine"], 62)
        self.assertEqual(value["provider"]["ELF_class"], 64)
        self.assertEqual(fs.opened, [fs.target, fs.status_path])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(value))
        for key in (
            "ABI_proved",
            "PBDS_instantiations_proved",
            "precompiled_config_proved",
            "CVE_closed",
            "operational_GO",
        ):
            self.assertIs(value[key], False)

    def test_missing_route_wrong_path_and_unverified_report_refuse_before_read(self):
        for mutate in (
            lambda r: r.update(verified=False),
            lambda r: r.update(live_link_probe=False),
            lambda r: r["inventory"]["files"][0]["resolved"][0].update(path="/private/CANARY"),
            lambda r: [row.update(resolved=[]) for row in r["inventory"]["files"]],
            lambda r: r["inventory"]["files"][0].update(path="/opt/pamolive-freerdp-foreign/x"),
        ):
            fs, report = GCCMemoryFS(), self.report()
            mutate(report)
            with self.assertRaises(native.InventoryError):
                self.capture(fs, report)
            self.assertEqual(fs.opened, [])

    def test_native_report_buffer_must_be_the_exact_serialization(self):
        fs = GCCMemoryFS()
        with (
            fs.patch(),
            self.assertRaisesRegex(native.InventoryError, "gcc_verified_inventory_required"),
        ):
            native.gcc_provider_data(self.report(), b"other report")
        self.assertEqual(fs.opened, [])

    def test_unknown_usrmerge_leaf_escape_and_multiple_provider_refuse(self):
        for mode in ("root", "leaf", "two"):
            fs = GCCMemoryFS()
            if mode == "root":
                fs.links["/lib"] = "../PRIVATE_CANARY"
            elif mode == "leaf":
                fs.links[native.GCC_DIRS[0] + "/libstdc++.so.6"] = "../../PRIVATE_CANARY"
            else:
                fs.nodes["/lib"].st_mode = stat.S_IFDIR | 0o755
                fs.add(native.GCC_DIRS[0], stat.S_IFDIR | 0o755)
            with self.subTest(mode=mode), self.assertRaises(native.InventoryError):
                self.capture(fs)
            self.assertEqual(fs.opened, [])

    def test_elf_class_machine_and_type_refuse(self):
        for offset, byte in ((4, 1), (5, 2), (16, 2), (18, 3)):
            fs = GCCMemoryFS()
            raw = bytearray(fs.data[fs.target])
            raw[offset] = byte
            fs.data[fs.target] = bytes(raw)
            with (
                self.subTest(offset=offset),
                self.assertRaisesRegex(native.InventoryError, "gcc_elf_platform"),
            ):
                self.capture(fs)
            self.assertFalse(fs.fds)

    def test_foreign_fd_identity_is_refused_and_owned_fd_closed(self):
        fs = GCCMemoryFS()
        fs.bad_fd = True
        with self.assertRaisesRegex(native.InventoryError, "gcc_open_identity"):
            self.capture(fs)
        self.assertEqual(len(fs.closed), 1)

    def test_same_fd_internal_growth_probe_is_bounded(self):
        fs = GCCMemoryFS()
        fs.growing = True
        with fs.patch(), self.assertRaisesRegex(native.InventoryError, "gcc_read_budget"):
            native._gcc_read(Path("/"), fs.target, 64, {})
        self.assertFalse(fs.fds)

    def test_short_read_and_alias_change_never_admit(self):
        fs = GCCMemoryFS()
        fs.data[fs.target] = b"\x7fELF"
        with self.assertRaisesRegex(native.InventoryError, "gcc_read_size"):
            self.capture(fs)
        fs = GCCMemoryFS()

        def mutate(path, raw):
            if path == fs.target and not raw:
                fs.links[native.GCC_DIRS[0] + "/libstdc++.so.6"] = "libstdc++.so.6.0.34"

        fs.on_read = mutate
        with self.assertRaisesRegex(native.InventoryError, "gcc_path_changed"):
            self.capture(fs)
        self.assertFalse(fs.fds)

    def test_mode_nlink_boolean_parent_alias_and_size_refuse(self):
        for key, value, path in [
            ("st_mode", stat.S_IFREG | 0o666, "target"),
            ("st_nlink", True, "target"),
            ("st_uid", 1000, "target"),
            ("st_size", 16 * 1024**2 + 1, "target"),
            ("st_mode", stat.S_IFLNK | 0o777, "/usr"),
        ]:
            fs = GCCMemoryFS()
            setattr(fs.nodes[fs.target if path == "target" else path], key, value)
            if path == "/usr":
                fs.links[path] = "/PRIVATE_CANARY"
            with self.subTest(key=key, value=value), self.assertRaises(native.InventoryError):
                self.capture(fs)

    def test_four_status_rows_only_and_duplicates_state_framing_refuse(self):
        raw = GCCMemoryFS().status
        rows = native._gcc_status(raw + b"\n\nPackage: unrelated\nDescription: PRIVATE_CANARY\n")
        self.assertEqual([row["Package"] for row in rows], list(native.GCC_PACKAGES))
        self.assertNotIn("Description", json.dumps(rows))
        for bad in (
            raw + b"\n\n" + raw,
            raw.replace(b"Architecture: amd64", b"Architecture: arm64"),
            raw.replace(b"Status: install ok installed", b"Status: deinstall ok installed"),
            raw.replace(b"Version: 14.2.0-19", b"Version: \nVersion: other"),
            raw.replace(b"\n", b"\r\n"),
            raw.split(b"\n\n", 1)[0],
        ):
            with self.assertRaises(native.InventoryError):
                native._gcc_status(bad)

    def test_without_option_old_main_and_candidate_emit_identical_bytes(self):
        import ast
        from contextlib import redirect_stdout

        old_path = ROOT / "tests/fixtures/native_inventory_940_main.DATA.txt"
        with old_path.open("rb") as handle:
            old_raw = handle.read(8193)
        self.assertLessEqual(len(old_raw), 8192)
        self.assertEqual(
            native.hashlib.sha256(old_raw).hexdigest(),
            "d2a9cceb14e17d313a8ef22509c017661a4201039758398feebeef02b4376d4d",
        )
        nodes = ast.parse(old_raw).body
        self.assertEqual(len(nodes), 1)
        old_main = nodes[0]
        self.assertIsInstance(old_main, ast.FunctionDef)
        self.assertEqual(old_main.name, "main")
        report = self.report()
        scope = dict(vars(native)) | {"verify": lambda value: report}
        exec(compile(ast.Module(body=[old_main], type_ignores=[]), "<old-main>", "exec"), scope)
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            manifest = directory / "manifest.json"
            manifest.write_text("{}")
            with (
                patch.dict(os.environ, {"LD_LIBRARY_PATH": native.LIBRARY_PATH, "LD_PRELOAD": ""}),
                patch.object(native, "verify", return_value=report),
                patch.object(native, "gcc_provider_data") as extra,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    scope["main"](
                        ["--manifest", str(manifest), "--output", str(directory / "old")]
                    ),
                    0,
                )
                self.assertEqual(
                    native.main(["--manifest", str(manifest), "--output", str(directory / "new")]),
                    0,
                )
            extra.assert_not_called()
            self.assertEqual((directory / "old").read_bytes(), (directory / "new").read_bytes())

    def test_capture_option_is_rejected_before_creating_outputs(self):
        with patch.object(native.os, "open") as opened, redirect_stdout(io.StringIO()):
            self.assertEqual(
                native.main(
                    ["--capture", "--output", "unused", "--gcc-provider-output", "unused2"]
                ),
                1,
            )
        opened.assert_not_called()

    def test_optional_path_uses_one_verified_report_and_same_exact_buffer(self):
        report = self.report()
        captured = []
        expected = (json.dumps(report, indent=2) + "\n").encode()

        def capture(value, raw):
            self.assertIs(value, report)
            self.assertEqual(raw, expected)
            captured.append(raw)
            return {"native_report_sha256": native.hashlib.sha256(raw).hexdigest()}

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            manifest = directory / "manifest.json"
            manifest.write_text("{}")
            with (
                patch.dict(os.environ, {"LD_LIBRARY_PATH": native.LIBRARY_PATH, "LD_PRELOAD": ""}),
                patch.object(native, "verify", return_value=report) as verify,
                patch.object(native, "gcc_provider_data", side_effect=capture),
                patch.object(native, "write_gcc_provider") as write,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    native.main(
                        [
                            "--manifest",
                            str(manifest),
                            "--output",
                            str(directory / "native"),
                            "--gcc-provider-output",
                            str(directory / "sidecar"),
                        ]
                    ),
                    0,
                )
            verify.assert_called_once_with({})
            self.assertEqual(len(captured), 1)
            self.assertEqual((directory / "native").read_bytes(), expected)
            self.assertEqual(
                write.call_args.args[1]["native_report_sha256"],
                native.hashlib.sha256(expected).hexdigest(),
            )

    def test_failed_sidecar_never_emits_verified_success_or_calls_writer(self):
        report = self.report()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            manifest = directory / "manifest.json"
            manifest.write_text("{}")
            public = io.StringIO()
            with (
                patch.dict(os.environ, {"LD_LIBRARY_PATH": native.LIBRARY_PATH, "LD_PRELOAD": ""}),
                patch.object(native, "verify", return_value=report),
                patch.object(
                    native,
                    "gcc_provider_data",
                    side_effect=native.InventoryError("gcc_provider_path"),
                ),
                patch.object(native, "write_gcc_provider") as writer,
                redirect_stdout(public),
            ):
                result = native.main(
                    [
                        "--manifest",
                        str(manifest),
                        "--output",
                        str(directory / "native"),
                        "--gcc-provider-output",
                        str(directory / "sidecar"),
                    ]
                )
            self.assertEqual(result, 1)
            writer.assert_not_called()
            self.assertEqual(
                json.loads(public.getvalue()), {"verified": False, "error": "gcc_provider_path"}
            )
            self.assertEqual((directory / "native").read_bytes(), b"")
            self.assertFalse((directory / "sidecar").exists())

    def test_sidecar_output_budget_collision_and_shortwrite_are_closed(self):
        with (
            patch.object(native.os, "open") as opened,
            self.assertRaisesRegex(native.InventoryError, "gcc_output_budget"),
        ):
            native.write_gcc_provider("unused", {"oversize": "X" * 32768})
        opened.assert_not_called()

        class Stream(io.BytesIO):
            def fileno(self):
                return 8

            def write(self, value):
                return len(value) - 1

        api = SimpleNamespace(
            open=lambda *args: 8,
            fdopen=lambda *args: Stream(),
            close=lambda fd: None,
            O_WRONLY=1,
            O_CREAT=2,
            O_EXCL=4,
            O_NOFOLLOW=8,
        )
        with (
            patch.object(native, "os", api),
            self.assertRaisesRegex(native.InventoryError, "gcc_output_short_write"),
        ):
            native.write_gcc_provider("unused", {"small": True})

        def exists(*args):
            raise FileExistsError()

        api.open = exists
        with patch.object(native, "os", api), self.assertRaises(FileExistsError):
            native.write_gcc_provider("unused", {"small": True})


class GCCStatusScalarFramingTests(TestCase):
    def check_scalar(self, field, value, extra, kind):
        raw = GCCMemoryFS().status
        if kind == "continuation":
            replacement = f"{field}: {value}\n {extra}"
        else:
            replacement = f"{field}: {value}\n{field.swapcase()}: {extra}"
        changed = raw.replace(f"{field}: {value}".encode(), replacement.encode(), 1)
        self.assertNotEqual(changed, raw)
        with self.assertRaisesRegex(
            native.InventoryError, "^gcc_package_(scalar_(continuation|alias)|duplicate)$"
        ):
            native._gcc_status(changed)
        # Non-projected Description remains a legitimate folded field.
        description = raw.replace(
            b"Description: PRIVATE_CANARY_NOT_PROJECTED\n",
            b"Description: PRIVATE_CANARY_NOT_PROJECTED\n extra_description_text\n",
            1,
        )
        self.assertEqual(native._gcc_status(description), native._gcc_status(raw))

    def test_package_continuation_refuses(self):
        self.check_scalar("Package", "gcc-14-base", "foreign-package", "continuation")

    def test_package_case_alias_refuses(self):
        self.check_scalar("Package", "gcc-14-base", "foreign-package", "casefold_duplicate")

    def test_version_continuation_refuses(self):
        self.check_scalar("Version", "14.2.0-19", "99.0-1", "continuation")

    def test_version_case_alias_refuses(self):
        self.check_scalar("Version", "14.2.0-19", "99.0-1", "casefold_duplicate")

    def test_architecture_continuation_refuses(self):
        self.check_scalar("Architecture", "amd64", "arm64", "continuation")

    def test_architecture_case_alias_refuses(self):
        self.check_scalar("Architecture", "amd64", "arm64", "casefold_duplicate")

    def test_status_continuation_refuses(self):
        self.check_scalar(
            "Status", "install ok installed", "deinstall ok installed", "continuation"
        )

    def test_status_case_alias_refuses(self):
        self.check_scalar(
            "Status", "install ok installed", "deinstall ok installed", "casefold_duplicate"
        )
