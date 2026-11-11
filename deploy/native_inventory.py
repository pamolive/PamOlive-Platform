"""Offline native inventory for trusted, digest-identified Linux qualification images.

This invokes system ldd only on reviewed installation prefixes, never uploads.
Build metadata consistency is not cryptographic proof of compilation.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from itertools import islice
from pathlib import Path

SCHEMA = "pamolive.native-inventory.v1"
PREFIXES = {"freerdp": "/opt/pamolive-freerdp", "guacd": "/opt/pamolive-guac"}
LIBRARY_PATH = ":".join(path + "/lib" for path in PREFIXES.values())
SOURCES = {
    "freerdp": ("3.33.1", "4431bbf04d370545cfe2924b9d9f116b95c90c64ff156b2550bbaf82d34e7124"),
    "guacd": ("1.6.0", "8bc45675da96d7b6f39728160181e3d4ff3c08f460f6d26de5805b642bf13f2b"),
}
SIGNER = "7703B333420E0AEF995EB4B3A49454A3FC909FD5"
PATCH_SHA = "e907f097d83aeefc891b851cd48248e63cde20383922ecf691c4f1341b15fe5c"
COMPAT_PATCH_SHA = "22abebc3df34da38a96bd476b7387754c97eefc51477112a7ad812dd08a3cb05"
COMPAT_UPSTREAM_COMMIT = "ab36756b596520ae2a94cd4d25e406e0b5aa820b"
OPTIONS = {"WITH_OPENSSL": "ON", "WITH_CAIRO": "ON", **dict.fromkeys((
    "WITH_MBEDTLS", "WITH_FFMPEG", "WITH_SWSCALE", "WITH_OPENH264", "WITH_X11",
    "WITH_WAYLAND", "WITH_SERVER", "WITH_CLIENT_SDL", "WITH_ALSA", "WITH_PULSE",
    "WITH_CUPS", "WITH_PCSC", "WITH_DEBUG_ALL", "WITH_DEBUG_NLA",
    "WITH_DEBUG_TRANSPORT", "WITH_FUSE", "WITH_EMBEDDED_CLI_IN_RDP_FILES",
    "CHANNEL_URBDRC", "CMAKE_INTERPROCEDURAL_OPTIMIZATION", "WITH_SIMD"), "OFF")}
RUNTIME_OPTIONS = {key: value for key, value in OPTIONS.items() if key.startswith("WITH_")}
# CMakeDependentOption changes this cache entry to INTERNAL when WITH_CLIENT=OFF.
# It is also checked against the effective variable compiled into the library.
INTERNAL_OPTIONS = {"WITH_CLIENT_SDL"}
CONFIGURATION_PROBES = ["build/CMakeFiles/_CMakeLTOTest-C",
                        "build/CMakeFiles/_CMakeLTOTest-CXX"]
GUAC_FLAGS = ("--with-rdp", "--with-ssh", *(
    "--without-" + name for name in ("vnc", "telnet", "websockets", "pulse", "vorbis",
                                     "libavcodec", "libavformat", "libavutil", "libswscale")))
MAX_FILE = 64 * 1024 * 1024


class InventoryError(ValueError):
    """Bounded failure code, without credentials or raw subprocess output."""


def require(condition, code):
    if not condition:
        raise InventoryError(code)


def local(root, path):
    require(isinstance(path, str) and path.startswith("/") and "\\" not in path,
            "invalid_path")
    require(".." not in path.split("/") and "//" not in path, "invalid_path")
    result = (root / path.lstrip("/")).resolve(strict=True)
    require(result.is_relative_to(root), "path_escape")
    return result


def relative(root, path):
    return "/" + path.relative_to(root).as_posix()


def read_small(path, limit=1024 * 1024):
    require(path.stat().st_size <= limit, "file_budget")
    return path.read_text(encoding="utf-8").strip()


def components(root):
    result = []
    for name, prefix in PREFIXES.items():
        folder = prefix + ("/share/pamolive-freerdp" if name == "freerdp" else "/share/pamolive")
        version = read_small(local(root, folder + "/version.txt"))
        digest = read_small(local(root, folder + "/source-sha256.txt"))
        require((version, digest) == SOURCES[name], "source_identity")
        options = read_small(local(root, folder + "/build-options.txt"))
        item = {"name": name, "prefix": prefix, "version": version, "source_sha256": digest}
        if name == "freerdp":
            fingerprint = read_small(local(root, folder + "/signer-fingerprint.txt"))
            require(fingerprint == SIGNER, "source_signer")
            status = read_small(local(root, folder + "/signature.status"))
            signatures = [line.split() for line in status.splitlines()
                          if line.startswith("[GNUPG:] VALIDSIG ")]
            require(any(len(parts) >= 3 and (parts[2] == SIGNER or parts[-1] == SIGNER)
                        for parts in signatures), "source_signature_status")
            parsed = {}
            for key, kind, value in re.findall(
                    r"^([A-Z0-9_]+):([^=\n]+)=([^\n]*)$", options, re.M):
                if key in OPTIONS:
                    require(key not in parsed, "duplicate_build_option")
                    require(kind == "BOOL" or kind == "INTERNAL" and key in INTERNAL_OPTIONS,
                            "build_option_type")
                    parsed[key] = value
            require(all(parsed.get(k) == v for k, v in OPTIONS.items()), "build_options")
            rpath = read_small(local(root, folder + "/rpath-policy.txt"))
            tool = read_small(local(root, folder + "/rpath-tool.txt"))
            require(rpath == prefix + "/lib", "rpath_transformation")
            require(re.fullmatch(r"patchelf \d+(?:\.\d+){1,3}", tool) is not None,
                    "rpath_tool")
            compilation = json.loads(read_small(local(root, folder + "/compile-policy.json")),
                                     object_pairs_hook=_pairs)
            require(isinstance(compilation, dict) and compilation.get("schema") ==
                    "pamolive.native-compile-policy.v1" and compilation.get("verified") is True,
                    "compile_policy")
            require(re.fullmatch(r"[0-9a-f]{64}", str(compilation.get(
                "compile_commands_sha256", ""))) is not None, "compile_policy_digest")
            require(all(type(compilation.get(key)) is int and 0 < compilation[key] <= 100000
                        for key in ("compilation_commands", "link_command_files")),
                    "compile_policy_counts")
            require(compilation.get("prohibited_flag_prefixes") == ["-flto", "-mavx"] and
                    compilation.get("allowed_march") == ["-march=x86-64"], "compile_policy_flags")
            require(compilation.get("excluded_configuration_probe_roots") ==
                    CONFIGURATION_PROBES, "compile_policy_exclusions")
            item.update(signer_fingerprint=fingerprint,
                        build_options={k: parsed[k] for k in OPTIONS},
                        transformations=[{"tool": tool, "operation": "--set-rpath",
                                          "value": rpath}],
                        compile_policy={key: compilation[key] for key in (
                            "schema", "verified", "compile_commands_sha256",
                            "compilation_commands", "link_command_files",
                            "prohibited_flag_prefixes", "allowed_march",
                            "excluded_configuration_probe_roots")})
        else:
            flags = options.split()
            require(all(flag in flags for flag in GUAC_FLAGS), "build_options")
            require(not any(flag.startswith("--with-") and flag not in GUAC_FLAGS
                            for flag in flags), "build_options")
            patch = local(root, folder + "/guacd-deny-rdp-redirection.patch").read_bytes()
            require(hashlib.sha256(patch).hexdigest() == PATCH_SHA, "patch_identity")
            compatibility = local(root, folder + "/guacd-freerdp3-gdi-lifecycle.patch").read_bytes()
            require(hashlib.sha256(compatibility).hexdigest() == COMPAT_PATCH_SHA,
                    "compat_patch_identity")
            commit = read_small(local(root, folder + "/gdi-upstream-commit.txt"))
            require(commit == COMPAT_UPSTREAM_COMMIT, "compat_patch_upstream")
            linked = read_small(local(root, folder + "/freerdp-version.txt"))
            require(linked == SOURCES["freerdp"][0], "build_link_version")
            item.update(build_options=sorted(GUAC_FLAGS), patch_sha256=PATCH_SHA,
                        compat_patch_sha256=COMPAT_PATCH_SHA,
                        compat_upstream_commit=COMPAT_UPSTREAM_COMMIT)
        result.append(item)
    return result


def elf_dynamic(data):
    """Parse bounded ELF64 LE/amd64 dynamic search paths without executing ELF."""
    require(64 <= len(data) <= MAX_FILE and data[:6] == b"\x7fELF\x02\x01", "elf_platform")
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        require(header[2] == 62 and header[9] == 56 and header[10] <= 128, "elf_headers")
        segments = [struct.unpack_from("<IIQQQQQQ", data, header[5] + n * 56)
                    for n in range(header[10])]
        require(all(p[2] + p[5] <= len(data) for p in segments), "elf_segment_bounds")
        dynamic = [p for p in segments if p[0] == 2]
        require(len(dynamic) == 1 and dynamic[0][5] <= 65536, "elf_dynamic")
        p = dynamic[0]
        entries = []
        for offset in range(p[2], p[2] + p[5], 16):
            tag, value = struct.unpack_from("<qQ", data, offset)
            if tag == 0:
                break
            entries.append((tag, value))
        else:
            raise InventoryError("elf_dynamic_terminator")
        addresses = [v for tag, v in entries if tag == 5]
        sizes = [v for tag, v in entries if tag == 10]
        require(len(addresses) == len(sizes) == 1, "elf_strings")
        address, size = addresses[0], sizes[0]
        loads = [p for p in segments if p[0] == 1 and p[3] <= address
                 and address + size <= p[3] + p[5]]
        require(len(loads) == 1 and size <= MAX_FILE, "elf_strings_bounds")
        start = loads[0][2] + address - loads[0][3]
        table = data[start:start + size]
        result = {"needed": [], "rpath": [], "runpath": []}
        for tag, offset in entries:
            if tag not in (1, 15, 29):
                continue
            end = table.find(b"\0", offset)
            require(0 <= offset < len(table) and end >= offset, "elf_string")
            value = table[offset:end].decode("ascii")
            require(value and len(value) <= 4096, "elf_string")
            field = {1: "needed", 15: "rpath", 29: "runpath"}[tag]
            if tag == 1:
                require("/" not in value and "\\" not in value, "elf_needed_path")
                result[field].append(value)
            else:
                paths = value.split(":")
                require(all(x in LIBRARY_PATH.split(":") for x in paths), "elf_search_path")
                result[field].extend(paths)
        return result
    except (struct.error, UnicodeError) as exc:
        raise InventoryError("elf_malformed") from exc


def parse_ldd(text):
    require(isinstance(text, str) and len(text) <= 131072, "link_output_budget")
    links = []
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"linux-vdso\.so\.\d+ \(0x[0-9a-f]+\)", line):
            continue
        match = re.fullmatch(r"([^\s/]+) => (/[^\s]+) \(0x[0-9a-f]+\)", line)
        if match:
            links.append({"soname": match[1], "path": match[2]})
            continue
        match = re.fullmatch(r"(/[^\s]+) \(0x[0-9a-f]+\)", line)
        require(match is not None, "link_unresolved_or_unexpected")
        links.append({"soname": Path(match[1]).name, "path": match[1]})
    require(bool(links), "link_empty")
    require(len({x["soname"] for x in links}) == len(links), "link_duplicate")
    return links


def probe(path):
    result = subprocess.run(
        ["/usr/bin/ldd", str(path)], capture_output=True, text=True, timeout=15, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
             "LD_LIBRARY_PATH": LIBRARY_PATH, "LD_PRELOAD": ""},
    )
    require(result.returncode == 0 and not result.stderr, "link_probe_failed")
    return parse_ldd(result.stdout)


def runtime_versions():
    """Query public version APIs in a bounded child, without starting a daemon."""
    code = r"""
import ctypes, json, re, sys
versions = {}
for name, path in [('freerdp', '/opt/pamolive-freerdp/lib/libfreerdp3.so.3'),
                   ('winpr', '/opt/pamolive-freerdp/lib/libwinpr3.so.3')]:
    library = ctypes.CDLL(path)
    function = getattr(library, name + '_get_version')
    function.argtypes = [ctypes.POINTER(ctypes.c_int)] * 3
    function.restype = None
    parts = [ctypes.c_int() for _ in range(3)]
    function(*(ctypes.byref(part) for part in parts))
    versions[name] = '.'.join(str(part.value) for part in parts)
    if name == 'freerdp':
        function = library.freerdp_get_build_config
        function.argtypes = []
        function.restype = ctypes.c_char_p
        raw = function()
        assert raw is not None and len(raw) <= 65536
        parsed = dict(re.findall(r'\b(WITH_[A-Z0-9_]+)=(ON|OFF)\b', raw.decode('ascii')))
        keys = json.loads(sys.argv[1])
        versions['freerdp_build_options'] = {key: parsed.get(key) for key in keys}
print(json.dumps(versions))
"""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "LD_LIBRARY_PATH": LIBRARY_PATH, "LD_PRELOAD": ""}
    result = subprocess.run([sys.executable, "-I", "-c", code,
                             json.dumps(sorted(RUNTIME_OPTIONS))], capture_output=True,
                            text=True, timeout=15, check=False, env=env)
    require(result.returncode == 0 and not result.stderr and len(result.stdout) < 8192,
            "version_probe_failed")
    versions = json.loads(result.stdout)
    result = subprocess.run(["/opt/pamolive-guac/sbin/guacd", "-v"], capture_output=True,
                            text=True, timeout=10, check=False, env=env)
    require(result.returncode == 0 and len(result.stdout + result.stderr) < 1024,
            "version_probe_failed")
    require(re.fullmatch(r"Guacamole proxy daemon \(guacd\) version 1\.6\.0\s*",
                         result.stdout + result.stderr) is not None, "guacd_runtime_version")
    versions["guacd"] = "1.6.0"
    return versions


def inventory(*, root=Path("/"), link_probe=probe, version_probe=runtime_versions):
    """Capture reviewed metadata, every installed native ELF and its real links.

    A different root and injected probe exist for isolated unit tests only. The
    CLI always inspects the current container root and invokes the real loader.
    """
    root = root.resolve(strict=True)
    declared = components(root)
    files, aliases = {}, {}
    for name, prefix in PREFIXES.items():
        directory = local(root, prefix)
        require(relative(root, directory) == prefix, "prefix_alias")
        paths = list(islice(directory.rglob("*"), 8193))
        require(len(paths) <= 8192, "tree_budget")
        for path in paths:
            if not path.is_file():
                continue
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(directory), "native_symlink_escape")
            with resolved.open("rb") as stream:
                magic = stream.read(4)
            if magic != b"\x7fELF":
                continue
            canonical = relative(root, resolved)
            aliases[relative(root, path)] = canonical
            if canonical in files:
                continue
            require(resolved.stat().st_size <= MAX_FILE, "elf_size")
            data = resolved.read_bytes()
            files[canonical] = {"path": canonical, "component": name,
                                "sha256": hashlib.sha256(data).hexdigest(),
                                **elf_dynamic(data)}
    require(1 <= len(files) <= 256, "files_budget")
    required = [PREFIXES["guacd"] + suffix for suffix in (
        "/sbin/guacd", "/lib/libguac-client-rdp.so", "/lib/libguac-client-ssh.so")]
    require(all(path in aliases for path in required), "required_consumer_missing")
    for stem in ("libfreerdp3.so", "libfreerdp-client3.so", "libwinpr3.so"):
        require(any(Path(path).name.startswith(stem) and
                    path.startswith(PREFIXES["freerdp"] + "/lib/") for path in aliases),
                "required_library_missing")
    status = read_small(local(root, "/var/lib/dpkg/status"), 4 * 1024 * 1024)
    for paragraph in status.split("\n\n"):
        if "Status: install ok installed" not in paragraph.splitlines():
            continue
        package = next((line[9:] for line in paragraph.splitlines()
                        if line.startswith("Package: ")), "")
        require(not package.startswith(("libfreerdp", "libwinpr", "freerdp3")), "legacy_package")
    for path, item in sorted(files.items()):
        links = link_probe(local(root, path))
        for link in links:
            canonical = relative(root, local(root, link["path"]))
            native = link["soname"].startswith(("libfreerdp", "libwinpr", "libguac"))
            if native:
                require(canonical in files, "native_link_outside_manifest")
                expected = "freerdp" if link["soname"].startswith(
                    ("libfreerdp", "libwinpr")) else "guacd"
                require(files[canonical]["component"] == expected, "native_link_component")
            else:
                require(canonical in files or canonical.startswith((
                    "/usr/lib/x86_64-linux-gnu/", "/usr/lib64/", "/lib/x86_64-linux-gnu/",
                    "/lib64/")), "unexpected_system_link")
        require(set(item["needed"]).issubset({link["soname"] for link in links}),
                "needed_not_resolved")
        item["resolved"] = sorted(links, key=lambda link: link["soname"])
    versions = version_probe()
    require(versions == {"freerdp": SOURCES["freerdp"][0], "winpr": SOURCES["freerdp"][0],
                         "guacd": SOURCES["guacd"][0],
                         "freerdp_build_options": RUNTIME_OPTIONS}, "runtime_version_mismatch")
    return {"schema": SCHEMA, "components": declared, "runtime_versions": versions,
            "files": [files[path] for path in sorted(files)],
            "aliases": aliases, "library_path": LIBRARY_PATH}


def verify(manifest, *, root=Path("/"), link_probe=probe, version_probe=runtime_versions):
    require(isinstance(manifest, dict) and manifest.get("schema") == SCHEMA, "manifest_schema")
    actual = inventory(root=root, link_probe=link_probe, version_probe=version_probe)
    require(manifest == actual, "inventory_changed")
    return {"schema": SCHEMA, "verified": True, "live_link_probe": link_probe is probe,
            "inventory": actual,
            "limitations": ["Build metadata is not cryptographic proof of compilation.",
                            "System libraries require their own OS vulnerability scan."]}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--manifest", default="/opt/pamolive-native-manifest.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o444 if args.capture else 0o600)
        require(os.environ.get("LD_LIBRARY_PATH") == LIBRARY_PATH, "runtime_library_path")
        require(not os.environ.get("LD_PRELOAD"), "runtime_preload")
        if args.capture:
            report = inventory()
        else:
            raw = read_small(Path(args.manifest))
            report = verify(json.loads(raw, object_pairs_hook=_pairs))
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            json.dump(report, stream, indent=2)
            stream.write("\n")
    except (InventoryError, OSError, ValueError, subprocess.SubprocessError, RecursionError) as exc:
        if fd is not None:
            os.close(fd)
        code = str(exc) if isinstance(exc, InventoryError) else "verification_failed"
        print(json.dumps({"verified": False, "error": code}))
        return 1
    print(json.dumps({"captured" if args.capture else "verified": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
