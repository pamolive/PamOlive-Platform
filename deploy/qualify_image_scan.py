"""Fail-closed, offline policy gate for exact qualified-image Grype artifacts.

This verifies evidence consistency; it never invokes Docker, downloads data, or
claims that scanner coverage is exhaustive. Policy exceptions need independent
review and executable archive conditions, not a global scanner ignore list.
"""

import argparse
import base64
import fnmatch
import gzip
import hashlib
import json
import os
import re
import tarfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

try:
    from deploy import build_recipe, krb5_inventory, qualified_image
except ModuleNotFoundError:
    import build_recipe
    import krb5_inventory
    import qualified_image

SCHEMA = "pamolive.image-scan-policy.v1"
TOOL_VERSION = "0.121.3"
TOOL_SHA256 = "e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85"
EXPECTED_CONTROL = {("freerdp", "3.15.0", "CVE-2026-45700"),
                    ("guacamole-server", "1.5.5", "CVE-2024-35164")}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
MAX_JSON = 32 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
DISPOSITIONS = {"untriaged", "not_reachable", "fixed_by_backport",
                "not_affected_build", "code_not_present"}
ELF_SET_SCHEMA = "pamolive.elf-set.v1"
GCC_VERSION = "14.2.0-19"
GCC_PACKAGES = {"gcc-14-base", "libatomic1", "libgcc-s1", "libstdc++6"}
GCC_LIBRARY = "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33"
GCC_LIBRARY_SHA = "972bb2a18b71140dab0240f8a1f68ab3fb1d56bcd4c4f824a91b70888faf5a00"
GCC_COMMITS = {"not_affected_build": "200183d4ab5d57575f3dfebc6af3baf649910b9e",
               "code_not_present": "aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6"}
GCC_SOURCES = {
    "icu": {"version": "76.1-4", "archives": {
        "icu_76.1.orig.tar.gz": "dfacb46bfe4747410472ce3e1144bf28a102feeaa4e3875bac9b4c6cf30f4f3e",
        "icu_76.1-4.debian.tar.xz":
            "5f9ff8b3a8e89a01b52c84bfebd35e7825ac561669d24e5a3d5f25d158e4f412"}},
    "apt": {"version": "3.0.4", "archives": {
        "apt_3.0.4.tar.xz": "e853aec49afbe520ebcd4dbcbc98e1c55262c6bf1c119cf43e6aec69752443c6"}},
    "harfbuzz": {"version": "10.2.0-1+deb13u1", "archives": {
        "harfbuzz_10.2.0.orig.tar.xz":
            "620e3468faec2ea8685d32c46a58469b850ef63040b3565cde05959825b48227",
        "harfbuzz_10.2.0-1+deb13u1.debian.tar.xz":
            "7694792ba03256931cbd068b9100d5bcca1d63496434af3c30b56babddd01d90"}},
}


class ScanPolicyError(ValueError):
    """A bounded failure code, without raw scanner/configuration contents."""


class BoundedTarInfo(tarfile.TarInfo):
    """Reject oversized extended metadata before tarfile reads its payload."""

    @classmethod
    def frombuf(cls, buf, encoding, errors):
        return cls._frombuf(buf, encoding, errors)

    @classmethod
    def _frombuf(cls, buf, encoding, errors, **kwargs):
        # Newer patched CPython tarfile bypasses public frombuf internally.
        # Cover both entry points; Python 3.12's original parser has no _frombuf.
        parent = super()
        item = (parent._frombuf(buf, encoding, errors, **kwargs)
                if hasattr(parent, "_frombuf") else parent.frombuf(buf, encoding, errors))
        metadata = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                    tarfile.GNUTYPE_LONGLINK, tarfile.SOLARIS_XHDTYPE}
        require(item.type != tarfile.GNUTYPE_SPARSE, "archive_sparse_unsupported")
        require(item.type not in metadata or 0 <= item.size <= 65536,
                "archive_extended_metadata_budget")
        return item

    def _unsupported_sparse(self, *args, **kwargs):
        raise ScanPolicyError("archive_sparse_unsupported")

    # PAX sparse maps can otherwise allocate before a returned member is checked.
    _proc_gnusparse_00 = _unsupported_sparse
    _proc_gnusparse_01 = _unsupported_sparse
    _proc_gnusparse_10 = _unsupported_sparse


class ArchiveFacts(tuple):
    """Preserve the existing (names, files) interface, with an optional sentinel."""

    def __new__(cls, names, files, elf_set=None, *, entries=None, contents=None, captured=None,
                layer_digests=None):
        value = super().__new__(cls, (names, files))
        value.elf_set = elf_set
        value.entries = entries
        value.contents = contents
        value.captured = captured
        value.layer_digests = layer_digests
        return value

    def __getnewargs__(self):
        return self[0], self[1], self.elf_set


def require(condition, code):
    if not condition:
        raise ScanPolicyError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def hash_file(path, maximum=2 * 1024**3):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            "artifact_file")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def bounded(value, depth=0, nodes=None):
    nodes = nodes if nodes is not None else [0]
    nodes[0] += 1
    require(depth <= 40 and nodes[0] <= 500000, "json_structure_budget")
    if isinstance(value, dict):
        for item in value.values():
            bounded(item, depth + 1, nodes)
    elif isinstance(value, list):
        for item in value:
            bounded(item, depth + 1, nodes)
    elif isinstance(value, str):
        require(len(value) <= 2 * 1024 * 1024 and "\x00" not in value, "json_string_budget")


def read_json(path, maximum=MAX_JSON):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "json_file")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "json_byte_budget")
    value = json.loads(raw, object_pairs_hook=pairs)
    bounded(value)
    return value


def instant(value):
    require(isinstance(value, str) and len(value) <= 40, "timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "timestamp_timezone")
    return result.astimezone(UTC)


def validate_report(report, *, expected_from, now):
    require(isinstance(report, dict) and not report.get("error") and not report.get("errors"),
            "scanner_error")
    descriptor = report.get("descriptor", {})
    require(not descriptor.get("error") and not descriptor.get("errors") and
            not report.get("source", {}).get("error"), "scanner_error")
    require(descriptor.get("name") == "grype" and descriptor.get("version") == TOOL_VERSION,
            "scanner_identity")
    scan_time = instant(descriptor.get("timestamp"))
    require(timedelta(minutes=-5) <= now - scan_time <= timedelta(hours=24), "stale_scan")
    config = descriptor.get("configuration", {})
    require(config.get("from") == [expected_from], "scan_source_mode")
    for name in ("ignore", "exclude", "vex-documents", "vex-add"):
        require(config.get(name) == [], "scanner_filter_" + name)
    for name in ("only-fixed", "only-notfixed"):
        require(config.get(name) is False, "scanner_filter_" + name)
    require(config.get("ignore-wontfix") in ("", False) and
            config.get("match-upstream-kernel-headers") is True and
            config.get("include-matcher-suppressions") is True, "scanner_hidden_suppression")
    require(config.get("match", {}).get("stock", {}).get("using-cpes") is True,
            "cpe_matching_disabled")
    require(config.get("externalSources", {}).get("enable") is False, "external_enrichment")
    db_config = config.get("db", {})
    require(db_config.get("auto-update") is False and db_config.get("validate-age") is True
            and db_config.get("validate-by-hash-on-start") is True, "database_validation")
    status = descriptor.get("db", {}).get("status", {})
    require(status.get("valid") is True and re.fullmatch(r"v6\.\d+\.\d+", str(
        status.get("schemaVersion"))) is not None, "database_status")
    built = instant(status.get("built"))
    require(timedelta(minutes=-5) <= now - built <= timedelta(hours=48)
            and built <= scan_time + timedelta(minutes=5), "stale_database")
    matches = report.get("matches")
    require(isinstance(matches, list) and len(matches) <= 50000, "matches_budget")
    # Grype's pinned JSON presenter uses omitempty for an empty ignored list.
    # Explicit null/invalid types still fail; strict config was checked above.
    ignored = report.get("ignoredMatches", [])
    require(isinstance(ignored, list) and len(ignored) <= 50000, "ignored_matches_missing")
    for match in matches:
        require(isinstance(match, dict) and isinstance(match.get("artifact"), dict)
                and isinstance(match.get("vulnerability"), dict), "match_object")
        vulnerability = match["vulnerability"]
        require(vulnerability.get("severity") in SEVERITIES, "unknown_severity")
        require(isinstance(vulnerability.get("id"), str) and
                1 <= len(vulnerability["id"]) <= 100, "vulnerability_identity")
        fix = vulnerability.get("fix", {})
        require(fix.get("state") in ("fixed", "not-fixed", "wont-fix", "unknown") and
                isinstance(fix.get("versions"), list), "fix_metadata")
    return {"schema": status["schemaVersion"], "built": status["built"]}


def high_groups(report, scope):
    groups = {}
    distro = report.get("distro", {})
    for match in report["matches"]:
        vulnerability, artifact = match["vulnerability"], match["artifact"]
        if vulnerability["severity"] != "High":
            continue
        upstreams = artifact.get("upstreams") or [{"name": artifact.get("name")}]
        require(len(upstreams) == 1 and isinstance(upstreams[0].get("name"), str),
                "ambiguous_package_source")
        finding = {"scope": scope, "source_package": upstreams[0]["name"],
                   "vulnerability_id": vulnerability["id"], "severity": "High",
                   "fix_state": vulnerability["fix"]["state"],
                   "namespace": vulnerability.get("namespace", ""),
                   "data_source": vulnerability.get("dataSource", ""),
                   "distro": {key: distro.get(key, "") for key in ("name", "version")}}
        key = canonical(finding)
        group = groups.setdefault(key, {**finding, "packages": []})
        package = {key: artifact.get(key, "") for key in ("name", "version", "type", "purl")}
        require(all(isinstance(value, str) for value in package.values()), "package_identity")
        if package not in group["packages"]:
            group["packages"].append(package)
    result = {}
    for group in groups.values():
        group["packages"].sort(key=canonical)
        result[fingerprint(group)] = group
    return result


def checked_path(value):
    require(isinstance(value, str) and 1 <= len(value) <= 512 and "\\" not in value,
            "condition_path")
    path = PurePosixPath(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == value,
            "condition_path")
    return value


def elf_set_summary(entries):
    rows = [entries[path] for path in sorted(entries)]
    require(1 <= len(rows) <= 5000, "elf_set_count")
    elf_count = sum(row["type"] == "elf" for row in rows)
    require(elf_count > 0, "elf_set_empty")
    return {"schema": ELF_SET_SCHEMA, "count": len(rows), "elf_count": elf_count,
            "alias_count": len(rows) - elf_count,
            "sha256": hashlib.sha256(canonical({"schema": ELF_SET_SCHEMA,
                                                "entries": rows}).encode()).hexdigest()}


def docker_manifest(outer, *, require_config=False):
    """Validate layer names before TAR lookup, including duplicate/link rejection."""
    # TarFile caches metadata while iterating; bound it BEFORE getmembers or
    # tar_metadata can materialize an attacker-sized list of outer entries.
    for count, _ in enumerate(outer, 1):
        require(count <= 2048, "archive_metadata_budget")
    manifest = json_bytes(qualified_image.tar_metadata(outer, "manifest.json", 262144))
    require(isinstance(manifest, list) and len(manifest) == 1 and
            isinstance(manifest[0], dict), "archive_manifest")
    item = manifest[0]
    layers = item.get("Layers")
    require(isinstance(layers, list) and 1 <= len(layers) <= 128 and
            all(isinstance(name, str) for name in layers) and
            len(set(layers)) == len(layers), "layer_budget")
    config = item.get("Config")
    require(not require_config or isinstance(config, str), "archive_configuration_missing")
    for name in ([config] if config is not None else []) + layers:
        require(isinstance(name, str) and 0 < len(name) <= 512 and
                "\\" not in name and "\0" not in name and
                not PurePosixPath(name).is_absolute() and
                str(PurePosixPath(name)) == name and
                ".." not in PurePosixPath(name).parts, "archive_member_path")
        matches = [member for member in outer.getmembers() if member.name == name]
        require(len(matches) == 1 and matches[0].isfile() and
                0 < matches[0].size <= 2 * 1024**3, "archive_member_identity")
    require(config not in layers and config != "manifest.json" and
            "manifest.json" not in layers, "archive_member_identity")
    return item


def image_diff_ids(config_bytes, layer_count):
    config = json_bytes(config_bytes)
    require(isinstance(config, dict) and config.get("os") == "linux" and
            config.get("architecture") == "amd64", "archive_configuration_platform")
    rootfs = config.get("rootfs")
    require(isinstance(rootfs, dict) and set(rootfs) == {"type", "diff_ids"} and
            rootfs["type"] == "layers", "archive_rootfs")
    diff_ids = rootfs["diff_ids"]
    require(isinstance(diff_ids, list) and len(diff_ids) == layer_count and
            all(isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value)
                for value in diff_ids) and len(set(diff_ids)) == len(diff_ids),
            "archive_diff_ids")
    return diff_ids


class LayerReader:
    """Hash uncompressed TAR bytes, including padding, under a shared hard budget."""

    def __init__(self, stream, budget):
        self.stream = stream
        self.budget = budget
        self.digest = hashlib.sha256()

    def read(self, size):
        require(type(size) is int and 0 <= size <= 1024**2, "layer_read_budget")
        data = self.stream.read(size)
        self.budget[0] += len(data)
        require(self.budget[0] <= 4 * 1024**3, "layer_stream_budget")
        self.digest.update(data)
        return data


def archive_facts(archive, conditions, *, read_paths=(), expected_diff_ids=None):
    """Stream final file/ELF/link identities, without extraction or following links."""
    requested = {checked_path(item["path"]) for item in conditions
                 if item.get("kind") in ("elf", "file_sha256")}
    require(isinstance(read_paths, (list, tuple, set)) and len(read_paths) <= 32,
            "archive_read_paths")
    read_paths = {checked_path(name) for name in read_paths}
    requested |= read_paths
    capture_set = bool(read_paths) or any(item.get("kind") == "elf_set" for item in conditions)
    names, elves, entries = set(), {}, {}
    captured = {}
    # Hardlinks retain bytes even after their original path is removed. Track
    # immutable content snapshots and link groups, never filesystem links.
    contents, link_groups, next_group = {}, {}, 0
    hardlink_dependencies = {}
    ancestors = {str(parent) for path in requested for parent in PurePosixPath(path).parents}
    non_directories = set()

    def masks_current_dependency(path):
        return any(dependency == path or dependency.startswith(path.rstrip("/") + "/")
                   for dependencies in hardlink_dependencies.values()
                   for dependency in dependencies)

    def invalidate(path, *, preserve=()):
        for mapping in (elves, entries, captured):
            for existing in list(mapping):
                if existing not in preserve and (existing == path or existing.startswith(
                        path.rstrip("/") + "/")):
                    del mapping[existing]
                    hardlink_dependencies.pop(existing, None)
        for existing in list(contents):
            if existing not in preserve and (existing == path or existing.startswith(
                    path.rstrip("/") + "/")):
                group = contents.pop(existing)["group"]
                link_groups[group].discard(existing)
                if not link_groups[group]:
                    del link_groups[group]

    total = count = 0
    stream_budget, layer_digests = [0], []
    with tarfile.open(archive, mode="r:", tarinfo=BoundedTarInfo) as outer:
        manifest = docker_manifest(outer)
        layers = manifest["Layers"]
        if "Config" in manifest:
            actual_diff_ids = image_diff_ids(qualified_image.tar_metadata(
                outer, manifest["Config"], 2 * 1024**2), len(layers))
            require(expected_diff_ids is None or expected_diff_ids == actual_diff_ids,
                    "archive_configuration_changed")
            expected_diff_ids = actual_diff_ids
        require(expected_diff_ids is None or len(expected_diff_ids) == len(layers),
                "archive_diff_ids")
        for layer_index, layer in enumerate(layers):
            touched = set()
            hardlink_dependencies = {}
            with outer.extractfile(layer) as stream:
                magic = stream.read(2)
                stream.seek(0)
                decoded = (gzip.GzipFile(fileobj=stream, mode="rb")
                           if magic == b"\x1f\x8b" else stream)
                reader = LayerReader(decoded, stream_budget)
                with tarfile.open(fileobj=reader, mode="r|", tarinfo=BoundedTarInfo) as inner:
                    for member in inner:
                        require(member.sparse is None, "archive_sparse_unsupported")
                        count += 1
                        total += member.size
                        require(0 <= member.size and count <= 100000 and total <= 4 * 1024**3,
                                "layer_content_budget")
                        require("\\" not in member.name and
                                ".." not in PurePosixPath(member.name).parts, "layer_path")
                        normalized = str(PurePosixPath(member.name)).lstrip("/")
                        name = checked_path("/" if normalized == "." else "/" + normalized)
                        names.add(name)
                        pure = PurePosixPath(name)
                        blocked = any(str(parent) in non_directories for parent in pure.parents)
                        # We do not emulate writes through directory symlinks. Such
                        # archives cannot establish a complete final-ELF sentinel.
                        require(not capture_set or not blocked, "elf_set_ambiguous_ancestor")
                        if pure.name.startswith(".wh."):
                            target = str(pure.parent) if pure.name == ".wh..wh..opq" else str(
                                pure.with_name(pure.name[4:]))
                            # A NEW link cannot read a lower-layer target which
                            # this layer masks. Whiteouts apply before link creation
                            # regardless of TAR order. Old links retain their inode.
                            require(not capture_set or not masks_current_dependency(target),
                                    "elf_set_hardlink_whiteout")
                            # OCI whiteouts hide LOWER layers, independent of TAR
                            # order. New files from this same layer must survive.
                            invalidate(target, preserve=touched)
                            non_directories = {path for path in non_directories
                                if path in touched or not (path == target or path.startswith(
                                    target.rstrip("/") + "/"))}
                            continue
                        touched.add(name)
                        if member.isdir():
                            elves.pop(name, None)
                            entries.pop(name, None)
                            captured.pop(name, None)
                            if name in contents:
                                require(not masks_current_dependency(name),
                                        "elf_set_hardlink_replacement")
                                group = contents.pop(name)["group"]
                                link_groups[group].discard(name)
                                if not link_groups[group]:
                                    del link_groups[group]
                            non_directories.discard(name)
                            continue
                        if capture_set and member.isfile() and name in contents:
                            require(len(link_groups[contents[name]["group"]]) == 1,
                                    "elf_set_hardlink_replacement")
                        require(not capture_set or not masks_current_dependency(name),
                                "elf_set_hardlink_replacement")
                        invalidate(name)
                        if capture_set or name in ancestors:
                            non_directories.add(name)
                        if blocked:
                            continue
                        if capture_set and (member.issym() or member.islnk()):
                            require(isinstance(member.linkname, str) and
                                    0 < len(member.linkname) <= 4096 and
                                    "\x00" not in member.linkname and "\\" not in member.linkname,
                                    "elf_set_link")
                            entries[name] = {"path": name, "type": "symlink" if member.issym()
                                             else "hardlink", "target": member.linkname}
                            if member.islnk():
                                require(".." not in PurePosixPath(member.linkname).parts,
                                        "elf_set_hardlink_target")
                                target = checked_path("/" + str(PurePosixPath(
                                    member.linkname)).lstrip("/"))
                                require(target in contents, "elf_set_hardlink_target")
                                record = dict(contents[target])
                                contents[name] = record
                                hardlink_dependencies[name] = (set(hardlink_dependencies.get(
                                    target, ())) if target in touched else {target})
                                link_groups[record["group"]].add(name)
                                entries[name].update({key: record[key]
                                                      for key in ("sha256", "class", "machine")})
                        elif member.isfile() and (capture_set or name in requested):
                            data = inner.extractfile(member)
                            header = data.read(64)
                            is_elf = header[:4] == b"\x7fELF"
                            if capture_set or name in requested or is_elf:
                                require(member.size <= 64 * 1024**2, "elf_budget")
                                sha = hashlib.sha256(header)
                                parts = [header] if name in read_paths else None
                                while block := data.read(1024 * 1024):
                                    sha.update(block)
                                    if parts is not None:
                                        parts.append(block)
                                if parts is not None:
                                    captured[name] = b"".join(parts)
                                    require(sum(map(len, captured.values())) <= 128 * 1024**2,
                                            "archive_read_budget")
                                elf_class = ({1: 32, 2: 64}.get(header[4]) if
                                             is_elf and len(header) >= 6 else None)
                                machine = None
                                if name in requested or (capture_set and is_elf):
                                    elves[name] = {"sha256": sha.hexdigest(), "class": elf_class}
                                if capture_set and is_elf:
                                    require(len(header) >= 20 and elf_class in (32, 64) and
                                            header[5] in (1, 2), "elf_set_header")
                                    machine = int.from_bytes(header[18:20],
                                        "little" if header[5] == 1 else "big")
                                    entries[name] = {"path": name, "type": "elf",
                                        "class": elf_class, "machine": machine,
                                        "sha256": sha.hexdigest()}
                                if capture_set:
                                    next_group += 1
                                    contents[name] = {"group": next_group,
                                        "sha256": sha.hexdigest(), "class": elf_class,
                                        "machine": machine}
                                    link_groups[next_group] = {name}
                        require(not capture_set or len(entries) <= 5000, "elf_set_count")
                while reader.read(1024**2):
                    pass
                if decoded is not stream:
                    decoded.close()
                digest = "sha256:" + reader.digest.hexdigest()
                require(expected_diff_ids is None or digest == expected_diff_ids[layer_index],
                        "archive_layer_digest_changed")
                layer_digests.append(digest)
    return ArchiveFacts(names, elves, elf_set_summary(entries) if capture_set else None,
                        entries=entries if capture_set else None,
                        contents={name: {key: item[key] for key in ("sha256", "class", "machine")}
                                  for name, item in contents.items()} if capture_set else None,
                        captured=captured, layer_digests=layer_digests)




def conditions_hold(conditions, facts):
    require(isinstance(conditions, list) and 1 <= len(conditions) <= 32, "conditions_missing")
    names, elves = facts
    for item in conditions:
        kind = item.get("kind")
        if kind == "absent_basename_glob":
            pattern = item.get("pattern")
            require(isinstance(pattern, str) and 1 <= len(pattern) <= 128 and
                    "/" not in pattern and "\\" not in pattern, "condition_pattern")
            if any(fnmatch.fnmatchcase(PurePosixPath(name).name, pattern) for name in names):
                return False
        elif kind == "absent_path_suffix":
            suffix = checked_path(item.get("suffix"))
            if any(name.endswith(suffix) for name in names):
                return False
        elif kind == "elf":
            path = checked_path(item.get("path"))
            require(item.get("class") in (32, 64) and SHA.fullmatch(str(item.get("sha256"))),
                    "condition_elf")
            if elves.get(path) != {"class": item["class"], "sha256": item["sha256"]}:
                return False
        elif kind == "file_sha256":
            path = checked_path(item.get("path"))
            require(SHA.fullmatch(str(item.get("sha256"))), "condition_file")
            if elves.get(path, {}).get("sha256") != item["sha256"]:
                return False
        elif kind == "elf_set":
            require(set(item) == {"kind", "schema", "sha256", "count", "elf_count", "alias_count"}
                    and item.get("schema") == ELF_SET_SCHEMA and
                    SHA.fullmatch(str(item.get("sha256"))) and all(type(item.get(key)) is int
                    for key in ("count", "elf_count", "alias_count")) and
                    1 <= item["count"] <= 5000 and 1 <= item["elf_count"] <= item["count"] and
                    item["alias_count"] >= 0 and item["elf_count"] + item["alias_count"] ==
                    item["count"], "condition_elf_set")
            if getattr(facts, "elf_set", None) != {key: value for key, value in item.items()
                                                  if key != "kind"}:
                return False
        else:
            raise ScanPolicyError("unknown_condition")
    return True


def json_bytes(raw, maximum=2 * 1024**2):
    require(isinstance(raw, bytes) and len(raw) <= maximum, "archive_json_budget")
    value = json.loads(raw, object_pairs_hook=pairs)
    bounded(value)
    return value


def source_coverage(recipe, facts):
    """Exact COPY source bytes and a closed map of generated client assets."""
    roots = {"config", "deploy", "docs", "examples", "integrations", "platform_core",
             "platform_modules", "templates", "tests", "third_party"}
    root_files = {"requirements.lock", "requirements-bootstrap.lock",
                  "requirements-python-runtime-linux.lock", "manage.py",
                  "pyproject.toml", "README.md", "LICENSE", ".env.example"}
    not_copied = {"deploy/check_image_scan_ci.sh"}
    expected = {"/app/" + name: value for name, value in recipe["files"].items()
                if name not in not_copied and (PurePosixPath(name).parts[0] in roots or
                                               name in root_files)}
    expected.update(recipe["generated_assets"])
    require(isinstance(facts.contents, dict) and isinstance(facts.entries, dict),
            "source_archive_capture_missing")
    actual = {name: value["sha256"] for name, value in facts.contents.items()
              if name.startswith("/app/")}
    require(not any(name.startswith("/app/") and item["type"] != "elf"
                    for name, item in facts.entries.items()), "source_archive_alias")
    require(actual == expected, "source_archive_changed")
    return {"source_files": len(expected) - len(recipe["generated_assets"]),
            "generated_assets": dict(recipe["generated_assets"])}


def verify_archive_backport(archive, recipe, repo):
    """Read current proof bytes as data; never execute an image-provided tool."""
    build_recipe.verify(recipe, repo)
    before = hash_file(archive)
    with tarfile.open(archive, mode="r:", tarinfo=BoundedTarInfo) as outer:
        image_config = qualified_image.tar_metadata(outer, docker_manifest(
            outer, require_config=True)["Config"],
                                                    2 * 1024**2)
    first = archive_facts(archive, [], read_paths=[krb5_inventory.MANIFEST_PATH])
    require(krb5_inventory.MANIFEST_PATH in first.captured, "backport_manifest_missing")
    raw_manifest = first.captured[krb5_inventory.MANIFEST_PATH]
    manifest = krb5_inventory.validate_manifest(json_bytes(raw_manifest))
    provenance = manifest["provenance"]
    rules = recipe["backport"]
    require(manifest["baseline"] == rules["baseline"] and
            sorted(provenance["evidence"]) == rules["proof_names"] and
            provenance["test_outputs"] == rules["test_outputs"] and
            provenance["apt_chain"] == rules["apt_chain"] and
            all(provenance["evidence"].get(name) == sha
                for name, sha in rules["fixed_evidence"].items()), "backport_recipe_changed")
    prefix = krb5_inventory.PREFIX + "/"
    names = {krb5_inventory.MANIFEST_PATH, prefix + "provenance.json", "/var/lib/dpkg/status"}
    names.update(prefix + krb5_inventory.evidence_name(name) for name in provenance["evidence"])
    names.update(item["path"] for item in manifest["libraries"])
    facts = archive_facts(archive, [], read_paths=sorted(names))
    require(names == set(facts.captured) and facts.captured[krb5_inventory.MANIFEST_PATH] ==
            raw_manifest and hash_file(archive) == before, "backport_archive_changed")
    raw_provenance = facts.captured[prefix + "provenance.json"]
    require(json_bytes(raw_provenance) == provenance and
            hashlib.sha256(raw_provenance).hexdigest() == manifest["provenance_sha256"],
            "backport_provenance_changed")
    files = {name: facts.captured[prefix + name] for name in provenance["evidence"]}
    require(all(hashlib.sha256(raw).hexdigest() == provenance["evidence"][name]
                for name, raw in files.items()), "backport_evidence_changed")
    require(json_bytes(files["baseline.json"]) == manifest["baseline"], "backport_baseline_changed")
    outputs = provenance["test_outputs"]
    require(json_bytes(files[outputs["asn1"]]) == manifest["asn1"] and
            json_bytes(files[outputs["debian"]]) == manifest["debian_tests"] and
            all(json_bytes(files[outputs[phase]]) == manifest["asn1"][phase]
                for phase in ("before", "after")) and all(
            manifest["asn1"][phase]["harness_sha256"] == provenance["evidence"][outputs["harness"]]
                for phase in ("before", "after")), "backport_test_binding")
    krb5_inventory.validate_chain(provenance, files)
    krb5_inventory.validate_debian_tests(manifest["debian_tests"], provenance)
    krb5_inventory.validate_capability_files(manifest["debian_tests"], provenance, files)
    for name in ("baseline-build.log", "debian-build.log"):
        require(name in files, "backport_log_missing")
        text = files[name].decode("utf8")
        require(not re.search(r"(?m)^(?:FAIL:|FAILED\b|make(?:\[\d+\])?: \*\*\*|"
                              r"Tests failed|[1-9][0-9]* tests failed)", text),
                "backport_log_failure")
        require("destest: 171 tests passed successfully" in text and
                "create-stamp debian/debhelper-build-stamp" in text,
                "backport_log_incomplete")
    require("dpkg-buildpackage: info: binary-only upload (no source included)" in
            files["debian-build.log"].decode("utf8"), "backport_package_log_incomplete")
    installed = {}
    status = facts.captured["/var/lib/dpkg/status"].decode().replace("\r\n", "\n")
    for paragraph in status.split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if ": " in line and not line.startswith((" ", "\t")):
                key, value = line.split(": ", 1)
                require(key not in fields, "backport_dpkg_duplicate")
                fields[key] = value
        name = fields.get("Package")
        if name in krb5_inventory.LIBRARIES:
            require(name not in installed and fields.get("Status") == "install ok installed" and
                    fields.get("Architecture") == "amd64", "backport_dpkg_identity")
            installed[name] = fields.get("Version")
    require(installed == manifest["packages"], "backport_dpkg_changed")
    for item in manifest["libraries"]:
        data = facts.captured[item["path"]]
        abi = krb5_inventory.elf_abi(data)
        require(hashlib.sha256(data).hexdigest() == item["sha256"] and
                all(item[key] == value for key, value in abi.items()), "backport_elf_changed")
    coverage = source_coverage(recipe, facts)
    build_recipe.verify(recipe, repo)
    return facts, {"schema": "pamolive.archive-backport-verification.v1", "verified": True,
        "archive_sha256": before, "recipe_content_sha256": build_recipe.sha(
            build_recipe.canonical(recipe).encode()),
        "image_config_id": "sha256:" + hashlib.sha256(image_config).hexdigest(),
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "layer_diff_ids": facts.layer_digests,
        "conditions": krb5_inventory.archive_conditions(manifest), "elf_set": facts.elf_set,
        "libraries": manifest["libraries"], "source_coverage": coverage,
        "debian_test_status": manifest["debian_tests"]["status"],
        "cryptographic_build_attestation_verified": False, "build_verified": False,
        "trust_basis": "reviewed verifier/workflow/runner; gpgv status is a build claim",
        "compilation_proof": False}


def recipe_artifact(entry, *, proofs, repo, archive, cache):
    proof = entry.get("build_recipe")
    require(isinstance(proof, dict) and proof in proofs, "build_recipe_evidence")
    require(archive is not None, "build_recipe_archive_required")
    key = proof["sha256"]
    if key not in cache:
        recipe = build_recipe.read_json(repo / proof["path"])
        require(hash_file(repo / proof["path"], 2 * 1024**2) == key, "build_recipe_changed")
        facts, report = verify_archive_backport(archive, recipe, repo)
        cache[key] = (recipe, facts, report)
    # Offline consistency is deliberately not a build authority. No trusted
    # materials/attestation verifier exists yet; even supplied True flags or a
    # populated cache cannot authorize this experimental policy path.
    raise ScanPolicyError("recipe_build_authority_unavailable")


def elf_delta(recipe, facts):
    """Only four verified C output hashes may differ; aliases stay byte-exact."""
    reference = {item["path"]: item for item in recipe["elf_reference"]}
    current = facts.entries
    require(isinstance(current, dict) and set(reference) == set(current), "gcc_delta_paths")
    permitted = {"/usr/lib/x86_64-linux-gnu/" + name
                 for name, _ in krb5_inventory.LIBRARIES.values()}
    for path, original in reference.items():
        actual = current[path]
        if path in permitted:
            require({key: value for key, value in original.items() if key != "sha256"} ==
                    {key: value for key, value in actual.items() if key != "sha256"},
                    "gcc_delta_kerberos_type")
        else:
            require(original == actual, "gcc_delta_unreviewed_change")
    return True


def gcc_conditions(entry, finding, *, proofs, repo):
    """Two finite reviewed GCC justifications; never a package-wide waiver."""
    disposition = entry["disposition"]
    cve = "CVE-2026-95619" if disposition == "not_affected_build" else "CVE-2026-102010"
    require(finding.get("scope") == "os" and finding.get("source_package") == "gcc-14" and
            finding.get("vulnerability_id") == cve and finding.get("distro", {}).get("name") ==
            "debian" and finding.get("packages") and all(item.get("name") in
            GCC_PACKAGES and item.get("version") == GCC_VERSION and
            item.get("type") == "deb" for item in finding["packages"]), "gcc_finding_scope")
    proof = entry.get("gcc_evidence")
    require(isinstance(proof, dict) and proof in proofs, "gcc_evidence_missing")
    evidence = read_json(repo / proof["path"], 2 * 1024**2)
    require(evidence.get("schema") == "pamolive.gcc-finding-evidence.v1" and
            evidence.get("source_version") == GCC_VERSION and
            evidence.get("vulnerability_id") == cve and
            evidence.get("upstream_commit") == GCC_COMMITS[disposition], "gcc_evidence_identity")
    upstream = "https://github.com/gcc-mirror/gcc/commit/" + GCC_COMMITS[disposition]
    require(any(value in (upstream, upstream + ".patch") for value in entry["vendor_evidence"]),
            "gcc_primary_evidence")
    if disposition == "not_affected_build":
        require(evidence.get("justification") == "posix_memalign_implementation" and
                evidence.get("platform") == "linux/amd64" and evidence.get("function") ==
                {"name": "_ZnwmSt11align_val_t", "size": 125,
                 "allocation_backend": "posix_memalign"} and evidence.get("library") ==
                {"path": GCC_LIBRARY, "class": 64, "sha256": GCC_LIBRARY_SHA},
                "gcc_build_proof")
        return [{"kind": "elf", "path": GCC_LIBRARY, "class": 64, "sha256": GCC_LIBRARY_SHA}]
    require(evidence.get("justification") == "gnu_pbds_binary_heap_erase_if_not_instantiated" and
            evidence.get("template") == "__gnu_pbds::priority_queue<binary_heap_tag>::erase_if" and
            evidence.get("sources") == GCC_SOURCES and evidence.get("reviewed_files") == 7112 and
            type(evidence.get("affected_type_uses")) is int and
            evidence["affected_type_uses"] == 0, "gcc_source_proof")
    consumers = evidence.get("consumers")
    require(isinstance(consumers, list) and len(consumers) == 27 and
            len({item.get("path") for item in consumers}) == 27 and
            Counter(item.get("source_package") for item in consumers) ==
            {"icu": 6, "apt": 20, "harfbuzz": 1},
            "gcc_consumer_set")
    conditions = []
    for item in consumers:
        path = checked_path(item.get("path"))
        require(path.startswith(("/usr/bin/", "/usr/lib/")) and item.get("class") == 64 and
                SHA.fullmatch(str(item.get("sha256"))), "gcc_consumer_identity")
        conditions.append({"kind": "elf", "path": path, "class": 64, "sha256": item["sha256"]})
    sentinel = evidence.get("elf_set")
    require(isinstance(sentinel, dict) and set(sentinel) ==
            {"schema", "sha256", "count", "elf_count", "alias_count"}, "gcc_elf_set_missing")
    marker = ({"kind": "elf_recipe_delta", "sha256": entry["build_recipe"]["sha256"]}
              if "build_recipe" in entry else {**sentinel, "kind": "elf_set"})
    conditions.extend([marker,
                       {"kind": "absent_basename_glob", "pattern": "erase_fn_imps.hpp"}])
    return conditions


def reviewed_exception(entry, finding, *, facts, repo, now, archive=None, artifact_cache=None):
    require(entry.get("fingerprint") == fingerprint(entry.get("finding")), "policy_fingerprint")
    require(entry["finding"] == finding, "policy_finding_changed")
    if entry.get("disposition") == "untriaged":
        return False
    require(entry.get("disposition") in DISPOSITIONS - {"untriaged"},
            "unknown_disposition")
    analyst, reviewers = entry.get("analyst"), entry.get("reviewers")
    require(isinstance(analyst, str) and analyst.strip() and isinstance(reviewers, list)
            and len(set(reviewers)) >= 2 and analyst not in reviewers and
            all(isinstance(item, str) and item.strip() for item in reviewers), "independent_review")
    require(isinstance(entry.get("analysis"), str) and len(entry["analysis"].strip()) >= 80,
            "exposure_analysis_missing")
    reviewed, expires = instant(entry.get("reviewed_at")), instant(entry.get("expires"))
    require(reviewed <= now + timedelta(minutes=5) and
            now < expires <= reviewed + timedelta(days=30),
            "review_expired")
    vendor = entry.get("vendor_evidence")
    require(isinstance(vendor, list) and bool(vendor), "vendor_evidence_missing")
    for value in vendor:
        url = urlsplit(value)
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and not url.fragment and url.port in (None, 443), "vendor_evidence_url")
    proofs = entry.get("local_evidence")
    require(isinstance(proofs, list) and 1 <= len(proofs) <= 8, "local_evidence_missing")
    for proof in proofs:
        name = proof.get("path")
        require(isinstance(name, str) and not PurePosixPath(name).is_absolute() and
                ".." not in PurePosixPath(name).parts and "\\" not in name and
                name.startswith(("docs/", "deploy/", ".github/qualification/")), "proof_path")
        candidate = repo / name
        require(not candidate.is_symlink(), "proof_symlink")
        path = candidate.resolve(strict=True)
        require(path.is_relative_to(repo) and hash_file(path, 2 * 1024 * 1024) ==
                proof.get("sha256"), "proof_changed")
    if entry["disposition"] == "fixed_by_backport":
        require(finding.get("scope") == "os" and finding.get("source_package") == "krb5" and
                finding.get("vulnerability_id") == "CVE-2026-119079" and
                finding.get("distro", {}).get("name") == "debian" and
                finding.get("packages") and all(item.get("name") in krb5_inventory.LIBRARIES and
                item.get("version") == krb5_inventory.VERSION and item.get("type") == "deb"
                for item in finding["packages"]), "backport_finding_scope")
        if "build_recipe" not in entry:
            # Immutable-subject mode retains the original strict 26 byte identities.
            proof = entry.get("backport_inventory")
            require(isinstance(proof, dict) and proof in proofs, "backport_inventory_missing")
            manifest = krb5_inventory.validate_manifest(read_json(repo / proof["path"]))
            require(entry.get("conditions") == krb5_inventory.archive_conditions(manifest),
                    "backport_archive_binding")
            return conditions_hold(entry["conditions"], facts)
        require(entry.get("conditions") == [{"kind": "backport_recipe",
                "sha256": entry.get("build_recipe", {}).get("sha256")}],
                "backport_archive_binding")
        recipe_artifact(entry, proofs=proofs, repo=repo, archive=archive,
                        cache=artifact_cache if artifact_cache is not None else {})
        return True
    elif entry["disposition"] in ("not_affected_build", "code_not_present"):
        expected = gcc_conditions(entry, finding, proofs=proofs, repo=repo)
        require(sorted(entry.get("conditions", []), key=canonical) ==
                sorted(expected, key=canonical), "gcc_archive_binding")
        if entry["disposition"] == "code_not_present" and "build_recipe" in entry:
            recipe, current, _ = recipe_artifact(entry, proofs=proofs, repo=repo, archive=archive,
                cache=artifact_cache if artifact_cache is not None else {})
            evidence = read_json(repo / entry["gcc_evidence"]["path"], 2 * 1024**2)
            reference = {item["path"]: item for item in recipe["elf_reference"]}
            require(elf_set_summary(reference) == evidence["elf_set"], "gcc_recipe_reference")
            elf_delta(recipe, current)
            return conditions_hold([item for item in expected
                                    if item["kind"] != "elf_recipe_delta"], current)
    return conditions_hold(entry.get("conditions"), facts)


def check_positive(report):
    found = {(item["artifact"].get("name"), item["artifact"].get("version"),
              item["vulnerability"]["id"]) for item in report["matches"]}
    require(EXPECTED_CONTROL <= found, "positive_control_not_detected")


def check_fixture(fixture):
    expected = {("freerdp", "3.15.0", "pkg:generic/freerdp@3.15.0",
                 "cpe:2.3:a:freerdp:freerdp:3.15.0:*:*:*:*:*:*:*"),
                ("guacamole-server", "1.5.5", "pkg:generic/guacamole-server@1.5.5",
                 "cpe:2.3:a:apache:guacamole:1.5.5:*:*:*:*:*:*:*")}
    components = fixture.get("components")
    require(fixture.get("bomFormat") == "CycloneDX" and fixture.get("specVersion") == "1.4"
            and isinstance(components, list) and len(components) == 2,
            "positive_fixture_schema")
    require({tuple(item.get(key) for key in ("name", "version", "purl", "cpe"))
             for item in components} == expected, "positive_fixture_components")
    require(fixture.get("metadata", {}).get("properties") == [
        {"name": "pamolive:synthetic-positive-control", "value": "true; not an installed image"}],
        "positive_fixture_identity")


def qualify(os_report, compiled_report, positive_report, compiled_sbom, policy, *,
            config_id, config_bytes, facts, repo, now=None, archive=None):
    """Pure policy evaluation after files/archive identities have been checked."""
    now = now or datetime.now(UTC)
    require(policy.get("schema") == SCHEMA and policy.get("version") == 1, "policy_version")
    databases = [validate_report(report, expected_from=source, now=now) for report, source in (
        (os_report, "docker-archive"), (compiled_report, "sbom"), (positive_report, "sbom"))]
    require(databases[0] == databases[1] == databases[2], "database_mismatch")
    check_positive(positive_report)
    target = os_report.get("source", {}).get("target")
    require(os_report.get("source", {}).get("type") == "image" and isinstance(target, dict)
            and target.get("imageID") == config_id and target.get("os") == "linux"
            and target.get("architecture") == "amd64", "os_image_identity")
    require(base64.b64decode(target.get("config", ""), validate=True) == config_bytes,
            "os_configuration_bytes")
    for report in (compiled_report, positive_report):
        require(report.get("source", {}).get("type") == "sbom-file", "sbom_source")
    properties = compiled_sbom.get("metadata", {}).get("properties", [])
    require(len({item["name"] for item in properties}) == len(properties), "duplicate_property")
    props = {item["name"]: item["value"] for item in properties}
    require(props.get("pamolive:sbom:image-digest-kind") == "image_config" and
            props.get("pamolive:sbom:image-digest") == config_id, "sbom_image_identity")
    expected_cpes = {"cpe:2.3:a:freerdp:freerdp:3.33.1:*:*:*:*:*:*:*",
                     "cpe:2.3:a:apache:guacamole:1.6.0:*:*:*:*:*:*:*"}
    require(expected_cpes <= {item.get("cpe") for item in compiled_sbom.get("components", [])},
            "compiled_inventory_missing")
    entries = policy.get("findings")
    require(isinstance(entries, list) and len(entries) <= 1000, "policy_findings")
    indexed = {}
    for entry in entries:
        key = entry.get("fingerprint")
        require(key == fingerprint(entry.get("finding")) and key not in indexed,
                "policy_fingerprint")
        require(entry.get("disposition") in DISPOSITIONS,
                "unknown_disposition")
        indexed[key] = entry
    blockers, groups = [], {}
    summaries = {}
    for scope, report in (("os", os_report), ("compiled", compiled_report)):
        summaries[scope] = {"severities": dict(Counter(
            item["vulnerability"]["severity"] for item in report["matches"])),
            "matches": len(report["matches"]),
            "ignored_matches": len(report.get("ignoredMatches", []))}
        if report.get("ignoredMatches", []):
            blockers.append({"code": "unreviewed_suppressed_matches", "scope": scope,
                             "count": len(report["ignoredMatches"])})
        for item in report["matches"]:
            vulnerability = item["vulnerability"]
            if vulnerability["severity"] == "Critical":
                blockers.append({"code": "critical", "scope": scope,
                                 "id": vulnerability["id"]})
            elif vulnerability["severity"] == "High" and (
                    vulnerability["fix"]["state"] == "fixed" or
                    vulnerability["fix"]["versions"]):
                blockers.append({"code": "high_fix_available", "scope": scope,
                                 "id": vulnerability["id"]})
        groups.update(high_groups(report, scope))
    artifact_cache = {}
    for key, finding in groups.items():
        entry = indexed.get(key)
        if entry is None or not reviewed_exception(entry, finding, facts=facts, repo=repo, now=now,
                                                   archive=archive, artifact_cache=artifact_cache):
            blockers.append({"code": "untriaged_high", "fingerprint": key, "finding": finding})
    require(all(item[2]["image_config_id"] == config_id for item in artifact_cache.values()),
            "recipe_image_config_changed")
    return {"schema": "pamolive.image-scan-result.v1", "passed": not blockers,
            "all_findings_clear": all(not report["matches"] and not report.get("ignoredMatches", [])
                                      for report in (
                os_report, compiled_report)), "config_id": config_id,
            "scanner_version": TOOL_VERSION, "database": databases[0], "summary": summaries,
            "high_finding_groups": len(groups), "blockers": blockers,
            "coverage": "OS archive plus declared compiled/application SBOM; not exhaustive SCA",
            "decisions": [{"fingerprint": key, "disposition": indexed[key]["disposition"]}
                          for key in groups if key in indexed],
            "elf_set": getattr(facts, "elf_set", None),
            "layer_diff_ids": getattr(facts, "layer_digests", None),
            "artifact_qualifications": [item[2] for item in artifact_cache.values()],
            "cryptographic_build_attestation_verified": False, "build_verified": False}


def referenced(policy_path, item):
    name = item.get("file")
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name), "reference_path")
    path = policy_path.parent / name
    require(hash_file(path, 1024 * 1024) == item.get("sha256"), "reference_hash")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "revision", "os-report", "compiled-sbom", "compiled-report",
                 "positive-report", "scanner-archive", "policy", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        policy_path = Path(args.policy).resolve(strict=True)
        require(policy_path.parent.name == "qualification" and
                policy_path.parent.parent.name == ".github", "policy_location")
        repo = policy_path.parent.parent.parent.resolve(strict=True)
        policy = read_json(policy_path, 1024 * 1024)
        tool_path = referenced(policy_path, policy["scanner_pin"])
        tool = read_json(tool_path, 65536)
        require(tool.get("schema") == "pamolive.grype-release-pin.v1" and
                tool.get("version") == TOOL_VERSION and tool.get("archive_sha256") == TOOL_SHA256,
                "scanner_pin")
        require(hash_file(args.scanner_archive, 128 * 1024 * 1024) == TOOL_SHA256,
                "scanner_archive_hash")
        control_path = referenced(policy_path, policy["positive_control"])
        check_fixture(read_json(control_path))
        bundle = Path(args.bundle).resolve(strict=True)
        # Read duplicate keys ourselves before reusing the existing read-only verifier.
        metadata = read_json(bundle / qualified_image.METADATA, 8192)
        archive = bundle / qualified_image.ARCHIVE
        require(hash_file(archive) == metadata.get("archive_sha256"), "archive_checksum")
        with tarfile.open(archive, mode="r:", tarinfo=BoundedTarInfo) as outer:
            manifest = docker_manifest(outer, require_config=True)
            config = qualified_image.tar_metadata(outer, manifest["Config"], 2 * 1024 * 1024)
        require(metadata == qualified_image.verify_bundle(bundle, args.revision), "bundle_identity")
        conditions = [condition for entry in policy["findings"]
                      if entry.get("disposition") in DISPOSITIONS - {"untriaged"}
                      for condition in entry.get("conditions", [])]
        facts = archive_facts(archive, conditions)
        os_report, compiled, positive, sbom = (read_json(path) for path in (
            args.os_report, args.compiled_report, args.positive_report, args.compiled_sbom))
        compiled_target = compiled["source"]["target"]
        positive_target = positive["source"]["target"]
        require(compiled_target == "/combined.cdx.json" or Path(compiled_target).resolve() ==
                Path(args.compiled_sbom).resolve(), "compiled_sbom_source")
        require(positive_target == "/control.cdx.json" or Path(positive_target).resolve() ==
                control_path.resolve(), "positive_control_source")
        result = qualify(os_report, compiled, positive, sbom, policy,
                         config_id=metadata["image_id"], config_bytes=config, facts=facts,
                         repo=repo, archive=archive)
        require(hash_file(archive) == metadata["archive_sha256"], "archive_changed_during_scan")
        result["input_sha256"] = {name: hash_file(path) for name, path in (
            ("qualified_image", bundle / qualified_image.METADATA), ("archive", archive),
            ("os_report", args.os_report), ("compiled_report", args.compiled_report),
            ("positive_report", args.positive_report), ("compiled_sbom", args.compiled_sbom),
            ("positive_fixture", control_path), ("policy", policy_path),
            ("scanner_pin", tool_path))}
        result["source_targets"] = {"compiled": compiled_target, "positive": positive_target,
                                    "binding": "fixed read-only CI mounts or identical host paths"}
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(canonical(result) + "\n")
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError,
            tarfile.TarError, EOFError) as exc:
        if fd is not None:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(canonical({"passed": False, "error": str(exc) if isinstance(
                    exc, ScanPolicyError) else "qualification_failed"}) + "\n")
        print(json.dumps({"passed": False, "error": str(exc) if isinstance(
            exc, ScanPolicyError) else "qualification_failed"}))
        return 1
    print(json.dumps({"passed": result["passed"], "high_groups": result["high_finding_groups"],
                      "blockers": len(result["blockers"]), "all_findings_clear":
                      result["all_findings_clear"]}))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
