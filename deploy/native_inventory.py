"""Offline native inventory for trusted, digest-identified Linux qualification images.

This invokes system ldd only on reviewed installation prefixes, never uploads.
Build metadata consistency is not cryptographic proof of compilation.
"""

import argparse
import hashlib
import json
import os
import re
import stat
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
JSON_PATCH_SHA = "7a3694d19f3fda9ea248905e1adf3b2048e911510420240f5c71a6aec2842500"
JANSSON_VERSION = "2.14-2+b3"
OPTIONS = {"WITH_JSONC_REQUIRED": "OFF", "WITH_CJSON_REQUIRED": "OFF",
           "WITH_JANSSON_REQUIRED": "ON", "WITH_JSON_DISABLED": "OFF",
           "WITH_OPENSSL": "ON", "WITH_CAIRO": "ON", "WITH_KRB5": "ON", **dict.fromkeys((
    "WITH_MBEDTLS", "WITH_FFMPEG", "WITH_SWSCALE", "WITH_OPENH264", "WITH_X11",
    "WITH_WAYLAND", "WITH_SERVER", "WITH_CLIENT_SDL", "WITH_ALSA", "WITH_PULSE",
    "WITH_CUPS", "WITH_PCSC", "WITH_DEBUG_ALL", "WITH_DEBUG_NLA",
    "WITH_DEBUG_TRANSPORT", "WITH_FUSE", "WITH_EMBEDDED_CLI_IN_RDP_FILES",
    "CHANNEL_URBDRC", "CMAKE_INTERPROCEDURAL_OPTIMIZATION", "WITH_SIMD"), "OFF")}
RUNTIME_OPTIONS = {key: value for key, value in OPTIONS.items() if key.startswith("WITH_")}
# CMakeDependentOption changes this cache entry to INTERNAL when WITH_CLIENT=OFF.
# It is also checked against the effective variable compiled into the library.
INTERNAL_OPTIONS = {"WITH_CLIENT_SDL", "WITH_CJSON_REQUIRED", "WITH_JSONC_REQUIRED"}
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
            patch = local(root, folder + "/freerdp-jansson-compat.patch")
            require(patch.stat().st_size <= 65536, "json_patch_budget")
            require(hashlib.sha256(patch.read_bytes()).hexdigest() == JSON_PATCH_SHA,
                    "json_patch_identity")
            item["json_backend_patch_sha256"] = JSON_PATCH_SHA
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


def elf_dynamic(data, *, observe_needed=False):
    """Parse bounded ELF64 LE/amd64 dynamic search paths without executing ELF."""
    require(64 <= len(data) <= MAX_FILE and data[:6] == b"\x7fELF\x02\x01", "elf_platform")
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        require(header[2] == 62 and header[9] == 56 and header[10] <= 128, "elf_headers")
        if observe_needed:
            require(header[10] > 0 and 64 <= header[5] <= len(data) - header[10] * 56,
                    "elf_observation_headers")
        segments = [struct.unpack_from("<IIQQQQQQ", data, header[5] + n * 56)
                    for n in range(header[10])]
        require(all(p[2] + p[5] <= len(data) for p in segments), "elf_segment_bounds")
        dynamic = [p for p in segments if p[0] == 2]
        if observe_needed and not dynamic:
            return None
        require(len(dynamic) == 1 and dynamic[0][5] <= 65536, "elf_dynamic")
        p = dynamic[0]
        if observe_needed:
            require(16 <= p[5] and p[5] % 16 == 0, "elf_observation_dynamic")
            mappings = [segment for segment in segments if segment[0] == 1
                        and segment[3] <= p[3] and p[3] + p[5] <= segment[3] + segment[5]]
            require(len(mappings) == 1 and p[2] == mappings[0][2] + p[3] - mappings[0][3],
                    "elf_dynamic_mapping")
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
        result = {"needed": [], "rpath": [], "runpath": []}
        for tag, offset in entries:
            if tag not in (1, 15, 29):
                continue
            if observe_needed and tag != 1:
                continue
            limit = 256 if observe_needed else 4096
            require(offset < size, "elf_string")
            begin = start + offset
            end = data.find(b"\0", begin, min(start + size, begin + limit + 1))
            require(end > begin, "elf_string")
            value = data[begin:end].decode("ascii")
            field = {1: "needed", 15: "rpath", 29: "runpath"}[tag]
            if tag == 1:
                if observe_needed:
                    require(re.fullmatch(r"[A-Za-z0-9_+.-]+", value) is not None
                            and value not in (".", "..") and len(result["needed"]) < 128,
                            "elf_needed_observation")
                else:
                    require("/" not in value and "\\" not in value, "elf_needed_path")
                result[field].append(value)
            else:
                paths = value.split(":")
                require(all(x in LIBRARY_PATH.split(":") for x in paths), "elf_search_path")
                result[field].extend(paths)
        return result
    except (struct.error, UnicodeError) as exc:
        raise InventoryError("elf_malformed") from exc


def observe_elf_needed(data):
    """Report direct dynamic linkage without applying the live loader policy."""
    if len(data) < 64:
        return {"status": "unparsed"}
    if (data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\x3e\0"
            or data[16:18] not in (b"\x02\0", b"\x03\0")):
        return {"status": "unsupported"}
    try:
        dynamic = elf_dynamic(data, observe_needed=True)
    except InventoryError:
        return {"status": "unparsed"}
    if dynamic is None:
        return {"status": "no_dynamic_segment"}
    return {"status": "observed", "needed": dynamic["needed"]}


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
    json_package = False
    for paragraph in status.split("\n\n"):
        if "Status: install ok installed" not in paragraph.splitlines():
            continue
        package = next((line[9:] for line in paragraph.splitlines()
                        if line.startswith("Package: ")), "")
        require(not package.startswith(("libfreerdp", "libwinpr", "freerdp3")), "legacy_package")
        require(not package.startswith(("libcjson", "cjson")), "cjson_package")
        if package == "libjansson4":
            require("Version: " + JANSSON_VERSION in paragraph.splitlines(), "jansson_version")
            json_package = True
    require(json_package, "jansson_package_missing")
    for path, item in sorted(files.items()):
        require(not any(name.lower().startswith("libcjson") for name in item["needed"]),
                "cjson_needed")
        if Path(path).name.startswith("libwinpr3.so"):
            require("libjansson.so.4" in item["needed"], "jansson_needed")
        links = link_probe(local(root, path))
        for link in links:
            require(not link["soname"].lower().startswith("libcjson"), "cjson_resolved")
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


GCC_PACKAGES = ("gcc-14-base", "libatomic1", "libgcc-s1", "libstdc++6")
GCC_DIRS = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu")
GCC_TARGET = r"libstdc\+\+\.so\.6\.0\.[0-9]{1,4}"


def _gcc_identity(info):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    result = {key.removeprefix("st_"): getattr(info, key) for key in fields}
    require(all(type(value) is int for value in result.values()), "gcc_identity_type")
    require(info.st_uid == 0 and info.st_nlink >= 1, "gcc_owner_or_links")
    return result


def _gcc_snapshot(root, logical, snapshots):
    info = os.lstat(root / logical.lstrip("/"))
    row = {"identity": _gcc_identity(info)}
    if stat.S_ISLNK(info.st_mode):
        row["target"] = os.readlink(root / logical.lstrip("/"))
    else:
        require(info.st_mode & 0o6022 == 0, "gcc_writable_or_special_mode")
    require(logical not in snapshots or snapshots[logical] == row, "gcc_path_changed")
    snapshots[logical] = row
    return info, row


def _gcc_read(root, logical, cap, snapshots):
    info, _ = _gcc_snapshot(root, logical, snapshots)
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap, "gcc_file_type_or_budget")
    fd = os.open(root / logical.lstrip("/"),
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(_gcc_identity(os.fstat(fd)) == _gcc_identity(info), "gcc_open_identity")
        chunks, count = [], 0
        while True:
            request = min(65536, cap + 1 - count)
            raw = os.read(fd, request)
            require(type(raw) is bytes and len(raw) <= request, "gcc_read_contract")
            count += len(raw)
            require(count <= cap, "gcc_read_budget")
            if not raw:
                break
            chunks.append(raw)
        require(count == info.st_size, "gcc_read_size")
        require(_gcc_identity(os.fstat(fd)) == _gcc_identity(info), "gcc_fd_changed")
        _gcc_snapshot(root, logical, snapshots)
        return b"".join(chunks), _gcc_identity(info)
    finally:
        os.close(fd)


def _gcc_status(raw):
    text = raw.decode("utf-8", "strict")
    require("\r" not in text and "\0" not in text, "gcc_status_framing")
    paragraphs = text.split("\n\n")
    require(len(paragraphs) <= 8192, "gcc_status_count")
    selected = {}
    scalars = {key.lower(): key for key in ("Package", "Version", "Architecture", "Status")}
    for paragraph in paragraphs:
        lines = paragraph.splitlines()
        packages = []
        for line in lines:
            if line.startswith((" ", "\t")):
                continue
            key, sep, value = line.partition(":")
            if sep and key.lower() == "package":
                packages.append(value.lstrip(" \t"))
        if not any(package in GCC_PACKAGES for package in packages):
            continue
        require(len(packages) == 1 and packages[0] not in selected, "gcc_package_duplicate")
        fields = {}
        previous = None
        for line in lines:
            if not line:
                continue
            if line.startswith((" ", "\t")):
                require(previous not in scalars.values(), "gcc_package_scalar_continuation")
                continue
            key, sep, value = line.partition(": ")
            require(sep and re.fullmatch(r"[A-Za-z0-9-]+", key) and key not in fields,
                    "gcc_package_field")
            require(key.lower() not in scalars or key == scalars[key.lower()],
                    "gcc_package_scalar_alias")
            fields[key] = value
            previous = key
        require(fields.get("Package") == packages[0] and fields.get("Architecture") == "amd64"
                and fields.get("Status") == "install ok installed"
                and re.fullmatch(r"[0-9A-Za-z.+:~_-]{1,128}", fields.get("Version", "")),
                "gcc_package_state")
        selected[packages[0]] = {key: fields[key] for key in (
            "Package", "Version", "Architecture", "Status")}
    require(set(selected) == set(GCC_PACKAGES), "gcc_package_closure")
    return [selected[name] for name in GCC_PACKAGES]


def gcc_provider_data(report, native_bytes, *, root=Path("/")):
    """Only extra file reads: no probe/process, ABI inference or image admission."""
    require(os.name == "posix", "gcc_linux_only")
    require(type(report) is dict and report.get("schema") == SCHEMA
            and report.get("verified") is True and report.get("live_link_probe") is True
            and type(native_bytes) is bytes
            and native_bytes == (json.dumps(report, indent=2) + "\n").encode("utf-8"),
            "gcc_verified_inventory_required")
    require(type(report.get("inventory")) is dict, "gcc_inventory_type")
    files = report.get("inventory", {}).get("files")
    require(type(files) is list and 1 <= len(files) <= 256, "gcc_inventory_files")
    routes = []
    for item in files:
        require(type(item) is dict, "gcc_inventory_item")
        consumer = item.get("path", "")
        require(type(consumer) is str and len(consumer) <= 512
                and consumer.startswith(tuple(prefix + "/" for prefix in PREFIXES.values()))
                and not any(part in {"", ".", ".."} for part in consumer[1:].split("/"))
                and all(32 < ord(char) < 127 and char != "\\" for char in consumer),
                "gcc_consumer_path")
        links = item.get("resolved")
        require(type(links) is list and len(links) <= 1024, "gcc_resolved_count")
        for link in links:
            require(type(link) is dict, "gcc_resolved_item")
            if link.get("soname") != "libstdc++.so.6":
                continue
            path = link.get("path")
            require(type(path) is str and any(
                path == directory + "/libstdc++.so.6"
                or re.fullmatch(re.escape(directory) + "/" + GCC_TARGET, path)
                for directory in GCC_DIRS), "gcc_provider_path")
            routes.append({"consumer": consumer, "reported_path": path})
    require(1 <= len(routes) <= 256 and len({r["consumer"] for r in routes}) == len(routes),
            "gcc_routes")
    root, snapshots = Path(root), {}
    for logical in ("/", "/usr", "/usr/lib", GCC_DIRS[1], "/var", "/var/lib", "/var/lib/dpkg"):
        info, _ = _gcc_snapshot(root, logical, snapshots)
        require(stat.S_ISDIR(info.st_mode), "gcc_parent_directory")
    lib, lib_row = _gcc_snapshot(root, "/lib", snapshots)
    merged = stat.S_ISLNK(lib.st_mode)
    require((merged and lib_row["target"] == "usr/lib") or stat.S_ISDIR(lib.st_mode),
            "gcc_lib_root")
    if not merged:
        info, _ = _gcc_snapshot(root, GCC_DIRS[0], snapshots)
        require(stat.S_ISDIR(info.st_mode), "gcc_parent_directory")
    aliases, targets = [], set()
    for directory in GCC_DIRS:
        logical = directory + "/libstdc++.so.6"
        try:
            info, row = _gcc_snapshot(root, logical, snapshots)
        except FileNotFoundError:
            require(not any(r["reported_path"].startswith(directory + "/") for r in routes),
                    "gcc_reported_alias_missing")
            aliases.append({"path": logical, "present": False})
            continue
        require(stat.S_ISLNK(info.st_mode) and re.fullmatch(GCC_TARGET, row["target"]),
                "gcc_provider_alias")
        canonical = (GCC_DIRS[1] if merged and directory == GCC_DIRS[0] else directory)
        target = canonical + "/" + row["target"]
        targets.add(target)
        aliases.append({"path": logical, "present": True, **row, "canonical_target": target})
    require(len(targets) == 1, "gcc_multiple_providers")
    target = next(iter(targets))
    for route in routes:
        directory = route["reported_path"].rsplit("/", 1)[0]
        alias = next(row for row in aliases if row["path"].startswith(directory + "/"))
        require(alias["present"] and (route["reported_path"].endswith("/libstdc++.so.6")
                or route["reported_path"].rsplit("/", 1)[1] == target.rsplit("/", 1)[1]),
                "gcc_route_binding")
    raw, identity = _gcc_read(root, target, 16 * 1024**2, snapshots)
    require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<HH", raw, 16) == (3, 62), "gcc_elf_platform")
    status, status_identity = _gcc_read(root, "/var/lib/dpkg/status", 4 * 1024**2, snapshots)
    packages = _gcc_status(status)
    for logical in list(snapshots):
        _gcc_snapshot(root, logical, snapshots)
    for alias in aliases:
        if not alias["present"]:
            try:
                os.lstat(root / alias["path"].lstrip("/"))
            except FileNotFoundError:
                pass
            else:
                raise InventoryError("gcc_absent_alias_changed")
    return {"schema": "pamolive.gcc-provider-data/1",
            "native_report_sha256": hashlib.sha256(native_bytes).hexdigest(),
            "routes": sorted(routes, key=lambda row: row["consumer"]), "aliases": aliases,
            "provider": {"path": target, "identity": identity, "bytes": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest(), "ELF_class": 64,
                         "endian": "little", "machine": 62, "type": 3},
            "status": {"path": "/var/lib/dpkg/status", "identity": status_identity,
                       "sha256": hashlib.sha256(status).hexdigest(), "packages": packages},
            "ABI_proved": False, "PBDS_instantiations_proved": False,
            "precompiled_config_proved": False, "CVE_closed": False, "operational_GO": False}


def write_gcc_provider(path, value):
    raw = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    require(len(raw) <= 32768, "gcc_output_budget")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = None
            require(stream.write(raw) == len(raw), "gcc_output_short_write")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd is not None:
            os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--manifest", default="/opt/pamolive-native-manifest.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--gcc-provider-output")
    args = parser.parse_args(argv)
    fd = None
    try:
        require(not (args.capture and args.gcc_provider_output), "gcc_capture_not_supported")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o444 if args.capture else 0o600)
        require(os.environ.get("LD_LIBRARY_PATH") == LIBRARY_PATH, "runtime_library_path")
        require(not os.environ.get("LD_PRELOAD"), "runtime_preload")
        if args.capture:
            report = inventory()
        else:
            raw = read_small(Path(args.manifest))
            report = verify(json.loads(raw, object_pairs_hook=_pairs))
        if args.gcc_provider_output:
            native_bytes = (json.dumps(report, indent=2) + "\n").encode("utf-8")
            extra = gcc_provider_data(report, native_bytes)
            with os.fdopen(fd, "wb") as stream:
                fd = None
                require(stream.write(native_bytes) == len(native_bytes), "gcc_native_short_write")
            write_gcc_provider(args.gcc_provider_output, extra)
        else:
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
