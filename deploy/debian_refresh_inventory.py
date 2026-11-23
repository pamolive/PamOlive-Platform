"""Bind the qualified official Debian packages to the installed runtime and image."""

import argparse
import json
import os
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

from qualification.debian_138_refresh import verify_refresh as refresh

SCHEMA = "pamolive.debian-refresh-runtime/1"
RECEIPT = "/usr/share/pamolive/debian-refresh/debian-138-refresh.json"
DPKG_STATUS = "/var/lib/dpkg/status"
ELF_PATHS = frozenset(path for paths in refresh.NATIVE_FILES.values() for path in paths)
RUNTIME_PACKAGES = frozenset(refresh.NATIVE_FILES) | {"libc-bin"}
KRB5_ALIASES = {
    refresh.LIB + soname: refresh.NATIVE_FILES[package][0]
    for soname, package in (
        ("libkrb5.so.3", "libkrb5-3"),
        ("libk5crypto.so.3", "libk5crypto3"),
        ("libkrb5support.so.0", "libkrb5support0"),
        ("libgssapi_krb5.so.2", "libgssapi-krb5-2"),
    )
}
LEGACY_PREFIX = "/usr/share/pamolive/krb5-backport"
MAX_STATUS = 8 * refresh.MIB
MAX_RECEIPT = 128 * 1024
REPORT_FIELDS = {
    "schema", "architecture", "receipt_sha256", "packages", "installed_elf_sha256"
}
IMAGE_FIELDS = {"image_config_id", "archive_sha256", "revision"}


class InventoryError(ValueError):
    """The installed official Debian package evidence does not match."""


def need(condition, code):
    if not condition:
        raise InventoryError(code)


def expected_packages(sdk):
    return frozenset(refresh.PACKAGES) if sdk else RUNTIME_PACKAGES


def validate_report(value, *, archive=False, sdk=False):
    """Validate the closed report before combining it with other image evidence."""
    need(not (archive and sdk), "archive_sdk_mode")
    fields = REPORT_FIELDS | IMAGE_FIELDS if archive else REPORT_FIELDS
    need(type(value) is dict and set(value) == fields, "report_fields")
    need(value["schema"] == SCHEMA and value["architecture"] == "amd64", "report_identity")
    need(refresh.is_sha(value["receipt_sha256"]), "report_receipt_hash")
    paths = value["installed_elf_sha256"]
    need(type(paths) is dict and set(paths) == ELF_PATHS
         and all(refresh.is_sha(sha) for sha in paths.values()), "report_elf")
    names, packages = sorted(expected_packages(sdk)), value["packages"]
    need(type(packages) is list and len(packages) == len(names), "report_packages")
    for name, row in zip(names, packages, strict=True):
        source, version, suite, _ = refresh.PACKAGES[name]
        need(type(row) is dict and set(row) == set(refresh.PACKAGE_FIELDS)
             and (row["package"], row["source"], row["version"], row["suite"])
             == (name, source, version, suite), "report_package_identity")
        need(refresh.is_sha(row["archive_sha256"]) and type(row["archive_bytes"]) is int
             and 0 < row["archive_bytes"] <= 16 * refresh.MIB, "report_archive")
    if archive:
        from deploy import qualified_image

        need(type(value["image_config_id"]) is str
             and qualified_image.DIGEST.fullmatch(value["image_config_id"])
             and type(value["revision"]) is str
             and qualified_image.REVISION.fullmatch(value["revision"])
             and refresh.is_sha(value["archive_sha256"]), "report_image_identity")
    return value


def verify_status(raw, *, sdk=False):
    need(0 < len(raw) <= MAX_STATUS, "status_size")
    selected, allowed = set(), expected_packages(sdk)
    for row in refresh.controls(raw):
        name = row.get("Package")
        if name not in refresh.PACKAGES:
            continue
        need(name in allowed and name not in selected, "status_package_overlap")
        source, version, _, _ = refresh.PACKAGES[name]
        need(row.get("Status") == "install ok installed"
             and row.get("Architecture") == "amd64" and row.get("Version") == version
             and row.get("Source") in (source, f"{source} ({version})"), "status_identity")
        selected.add(name)
    need(selected == allowed, "status_missing")


def verified_report(raw, status, files, *, sdk=False):
    need(0 < len(raw) <= MAX_RECEIPT, "receipt_size")
    receipt = refresh.validate_receipt(json.loads(raw, object_pairs_hook=refresh.unique_dict))
    verify_status(status, sdk=sdk)
    need(files == receipt["installed_elf_sha256"], "installed_elf_changed")
    need(refresh.materials_sha256(receipt["selection"], files) == refresh.REVIEWED_MATERIALS_SHA256,
         "unreviewed_debian_materials")
    return validate_report({
        "schema": SCHEMA,
        "architecture": "amd64",
        "receipt_sha256": refresh.sha(raw),
        "packages": [row for row in receipt["selection"]["packages"]
                     if row["package"] in expected_packages(sdk)],
        "installed_elf_sha256": files,
    }, sdk=sdk)


def verify_alias_target(target, canonical):
    need(target in (canonical, PurePosixPath(canonical).name), "kerberos_alias")


def inspect_root(root, *, sdk=False):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), "runtime_root")
    root = root.resolve(strict=True)
    need(not os.path.lexists(root / LEGACY_PREFIX.lstrip("/")), "legacy_backport")
    raw = refresh.read_regular(root / RECEIPT.lstrip("/"), MAX_RECEIPT, installed=True)
    status = refresh.read_regular(root / DPKG_STATUS.lstrip("/"), MAX_STATUS, installed=True)
    files = {}
    for name in sorted(ELF_PATHS):
        data = refresh.read_regular(
            root / name.lstrip("/"), 8 * refresh.MIB, installed=True
        )
        need(len(data) >= 20 and data[:6] == b"\x7fELF\x02\x01"
             and data[18:20] == b"\x3e\x00", "installed_elf_platform")
        files[name] = refresh.sha(data)
    for alias, canonical in KRB5_ALIASES.items():
        verify_alias_target(os.readlink(root / alias.lstrip("/")), canonical)
    return verified_report(raw, status, files, sdk=sdk)


def file_identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_size, info.st_mtime_ns,
    )


def inspect_bundle(directory, revision):
    from deploy import qualified_image
    from deploy import qualify_image_scan as archive_reader

    directory = Path(directory)
    metadata = qualified_image.verify_bundle(directory, revision)
    path = directory / qualified_image.ARCHIVE
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode)
         and 0 < before.st_size <= qualified_image.MAX_ARCHIVE_SIZE, "archive_file")
    identity = file_identity(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        need(file_identity(opened) == identity, "archive_changed")
        with tarfile.open(fileobj=stream, mode="r:",
                          tarinfo=archive_reader.BoundedTarInfo) as outer:
            manifest = archive_reader.docker_manifest(outer, require_config=True)
            config = qualified_image.tar_metadata(outer, manifest["Config"], 2 * refresh.MIB)
        need("sha256:" + refresh.sha(config) == metadata["image_id"], "archive_image_id")
        stream.seek(0)
        facts = archive_reader.archive_facts(
            None, [{"kind": "elf_set"}], read_paths=(RECEIPT, DPKG_STATUS), archive_stream=stream
        )
        need(set(facts.captured) == {RECEIPT, DPKG_STATUS}, "archive_evidence")
        need(all(name != LEGACY_PREFIX and not name.startswith(LEGACY_PREFIX + "/")
                 for name in facts[0]), "legacy_backport")
        files = {}
        for name in sorted(ELF_PATHS):
            entry = facts.entries.get(name, {})
            need(entry.get("type") == "elf" and entry.get("class") == 64
                 and entry.get("machine") == 62, "archive_elf_identity")
            files[name] = entry["sha256"]
        for alias, canonical in KRB5_ALIASES.items():
            entry = facts.entries.get(alias, {})
            need(entry.get("type") == "symlink", "kerberos_alias")
            verify_alias_target(entry.get("target"), canonical)
        archive_sha = qualified_image.archive_hash(None, archive_stream=stream)
        after_fd, after_path = os.fstat(stream.fileno()), path.lstat()
        need(archive_sha == metadata["archive_sha256"]
             and file_identity(after_fd) == file_identity(after_path) == identity
             and after_fd.st_ctime_ns == opened.st_ctime_ns
             and after_path.st_ctime_ns == before.st_ctime_ns, "archive_changed")
    report = verified_report(facts.captured[RECEIPT], facts.captured[DPKG_STATUS], files)
    return validate_report({
        **report,
        "image_config_id": metadata["image_id"],
        "archive_sha256": archive_sha,
        "revision": metadata["revision"],
    }, archive=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--root", type=Path)
    source.add_argument("--bundle", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--sdk", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if (args.bundle is not None) != (args.revision is not None) or (args.bundle and args.sdk):
        parser.error("--revision is required with --bundle and --sdk is only valid with --root")
    try:
        if args.bundle is not None:
            report = inspect_bundle(args.bundle, args.revision)
        else:
            report = inspect_root(args.root, sdk=args.sdk)
        with args.output.open("x", encoding="ascii") as stream:
            json.dump(report, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            stream.write("\n")
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, RecursionError):
        print("Official Debian refresh inventory refused.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
