"""Bind qualified Debian and local backport packages to the runtime and image."""

import argparse
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

from qualification.debian_138_refresh import verify_refresh as refresh

SCHEMA = "pamolive.debian-refresh-runtime/1"
SCHEMA_V2 = "pamolive.debian-refresh-runtime/2"
SCHEMA_V3 = "pamolive.debian-refresh-runtime/3"
BACKPORT_SUITE = "pamolive-trixie"
KERBEROS_SUITE = BACKPORT_SUITE
RECEIPT_FIELDS = {"krb5": "kerberos_receipt_sha256", "openssl": "openssl_receipt_sha256"}
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
    """The installed package evidence does not match."""


def need(condition, code):
    if not condition:
        raise InventoryError(code)


def expected_packages(sdk):
    return frozenset(refresh.PACKAGES) if sdk else RUNTIME_PACKAGES


def _backport_modules(kerberos_backport, openssl_backport):
    need(not openssl_backport or kerberos_backport, "openssl_requires_kerberos")
    modules = {}
    if kerberos_backport:
        from deploy import krb5_trixie_materials

        modules["krb5"] = krb5_trixie_materials
    if openssl_backport:
        from deploy import openssl_trixie_materials

        modules["openssl"] = openssl_trixie_materials
    return modules


def _schema(modules):
    if "openssl" in modules:
        return SCHEMA_V3
    return SCHEMA_V2 if "krb5" in modules else SCHEMA


def _openssl_paths(modules):
    if "openssl" in modules:
        return frozenset().union(*modules["openssl"].ELF_BY_PACKAGE.values())
    return frozenset()


def _package_profiles(sdk, modules):
    profiles = {}
    for name in expected_packages(sdk):
        source, version, suite, _ = refresh.PACKAGES[name]
        if source in modules:
            version, suite = modules[source].VERSION, BACKPORT_SUITE
        profiles[name] = (source, version, suite)
    if "openssl" in modules:
        openssl = modules["openssl"]
        names = openssl.RUNTIME_PACKAGES
        if sdk:
            names += openssl.SDK_PACKAGES
        profiles.update(dict.fromkeys(names, ("openssl", openssl.VERSION, BACKPORT_SUITE)))
    return profiles


def validate_report(value, *, archive=False, sdk=False):
    """Validate the closed report before combining it with other image evidence."""
    schema = value.get("schema") if type(value) is dict else None
    modules = _backport_modules(schema in (SCHEMA_V2, SCHEMA_V3), schema == SCHEMA_V3)
    receipts = {source: module.load_reviewed() for source, module in modules.items()}
    return _validate_report(value, modules, receipts, archive=archive, sdk=sdk)


def _validate_report(value, modules, receipts, *, archive=False, sdk=False):
    need(not (archive and sdk), "archive_sdk_mode")
    fields = REPORT_FIELDS | {RECEIPT_FIELDS[source] for source in modules}
    if archive:
        fields |= IMAGE_FIELDS
    need(type(value) is dict and set(value) == fields, "report_fields")
    need(
        value["schema"] == _schema(modules) and value["architecture"] == "amd64", "report_identity",
    )
    need(refresh.is_sha(value["receipt_sha256"]), "report_receipt_hash")
    paths = value["installed_elf_sha256"]
    openssl_paths = _openssl_paths(modules)
    need(type(paths) is dict and set(paths) == ELF_PATHS | openssl_paths
         and all(refresh.is_sha(sha) for sha in paths.values()), "report_elf")
    if "openssl" in receipts:
        installed_openssl_paths = set(receipts["openssl"]["installed_elf_sha256"])
        need(installed_openssl_paths == openssl_paths, "report_openssl_elf")
    for source, module in modules.items():
        receipt_field = RECEIPT_FIELDS[source]
        label = receipt_field.removesuffix("_receipt_sha256")
        need(value[receipt_field] == module.SHA256, f"report_{label}_receipt_hash")
        installed = receipts[source]["installed_elf_sha256"]
        need(all(paths[path] == sha for path, sha in installed.items()), f"report_{label}_elf")
    profiles = _package_profiles(sdk, modules)
    names, packages = sorted(profiles), value["packages"]
    need(type(packages) is list and len(packages) == len(names), "report_packages")
    for name, row in zip(names, packages, strict=True):
        source, version, suite = profiles[name]
        need(type(row) is dict and set(row) == set(refresh.PACKAGE_FIELDS)
             and (row["package"], row["source"], row["version"], row["suite"])
             == (name, source, version, suite), "report_package_identity")
        need(refresh.is_sha(row["archive_sha256"]) and type(row["archive_bytes"]) is int
             and 0 < row["archive_bytes"] <= 16 * refresh.MIB, "report_archive")
        if source in receipts:
            expected = receipts[source]["packages"][name]
            label = RECEIPT_FIELDS[source].removesuffix("_receipt_sha256")
            need(
                row["archive_sha256"] == expected["sha256"]
                and row["archive_bytes"] == expected["bytes"],
                f"report_{label}_archive",
            )
    if archive:
        from deploy import qualified_image

        need(type(value["image_config_id"]) is str
             and qualified_image.DIGEST.fullmatch(value["image_config_id"])
             and type(value["revision"]) is str
             and qualified_image.REVISION.fullmatch(value["revision"])
             and refresh.is_sha(value["archive_sha256"]), "report_image_identity")
    return value


def verify_status(raw, *, sdk=False, kerberos_backport=False, openssl_backport=False):
    modules = _backport_modules(kerberos_backport, openssl_backport)
    _verify_status(raw, sdk, modules)


def _verify_status(raw, sdk, modules):
    need(0 < len(raw) <= MAX_STATUS, "status_size")
    selected, profiles = set(), _package_profiles(sdk, modules)
    known = _package_profiles(True, modules)
    for row in refresh.controls(raw):
        name = row.get("Package")
        if name not in known:
            continue
        need(name in profiles and name not in selected, "status_package_overlap")
        source, version, _ = profiles[name]
        source_matches = row.get("Source") in (source, f"{source} ({version})")
        if name == source == "openssl" and "Source" not in row:
            source_matches = True
        need(row.get("Status") == "install ok installed"
             and row.get("Architecture") == "amd64" and row.get("Version") == version
             and source_matches, "status_identity")
        selected.add(name)
    need(selected == profiles.keys(), "status_missing")


def verified_report(raw, status, files, *, sdk=False, kerberos_raw=None, openssl_raw=None):
    modules = _backport_modules(kerberos_raw is not None, openssl_raw is not None)
    need(0 < len(raw) <= MAX_RECEIPT, "receipt_size")
    receipt = refresh.validate_receipt(json.loads(raw, object_pairs_hook=refresh.unique_dict))
    official_files = receipt["installed_elf_sha256"]
    installed_files = dict(official_files)
    receipts = {}
    for source, module in modules.items():
        backport_raw = kerberos_raw if source == "krb5" else openssl_raw
        label = RECEIPT_FIELDS[source].removesuffix("_receipt_sha256")
        need(0 < len(backport_raw) <= MAX_RECEIPT and refresh.sha(backport_raw) == module.SHA256,
             f"{label}_receipt_hash")
        receipts[source] = module.parse(backport_raw)
        installed_files.update(receipts[source]["installed_elf_sha256"])
    _verify_status(status, sdk, modules)
    need(files == installed_files, "installed_elf_changed")
    need(refresh.materials_sha256(receipt["selection"], official_files)
         == refresh.REVIEWED_MATERIALS_SHA256, "unreviewed_debian_materials")
    official_packages = {row["package"]: row for row in receipt["selection"]["packages"]}
    packages = []
    for name, (source, version, suite) in sorted(_package_profiles(sdk, modules).items()):
        if source in receipts:
            record = receipts[source]["packages"][name]
            packages.append({
                "package": name, "source": source, "version": version, "suite": suite,
                "archive_sha256": record["sha256"], "archive_bytes": record["bytes"],
            })
        else:
            packages.append(dict(official_packages[name]))
    report = {
        "schema": _schema(modules),
        "architecture": "amd64",
        "receipt_sha256": refresh.sha(raw),
        "packages": packages,
        "installed_elf_sha256": files,
        **{RECEIPT_FIELDS[source]: module.SHA256 for source, module in modules.items()},
    }
    return _validate_report(report, modules, receipts, sdk=sdk)


def verify_alias_target(target, canonical):
    need(target in (canonical, PurePosixPath(canonical).name), "kerberos_alias")


def inspect_root(root, *, sdk=False, kerberos_backport=False, openssl_backport=False):
    modules = _backport_modules(kerberos_backport, openssl_backport)
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), "runtime_root")
    root = root.resolve(strict=True)
    need(not os.path.lexists(root / LEGACY_PREFIX.lstrip("/")), "legacy_backport")
    raw = refresh.read_regular(root / RECEIPT.lstrip("/"), MAX_RECEIPT, installed=True)
    status = refresh.read_regular(root / DPKG_STATUS.lstrip("/"), MAX_STATUS, installed=True)
    receipts = {
        source: refresh.read_regular(
            root / str(module.PATH).lstrip("/"), MAX_RECEIPT, installed=True,
        )
        for source, module in modules.items()
    }
    files = {}
    for name in sorted(ELF_PATHS | _openssl_paths(modules)):
        data = refresh.read_regular(
            root / name.lstrip("/"), 8 * refresh.MIB, installed=True
        )
        need(len(data) >= 20 and data[:6] == b"\x7fELF\x02\x01"
             and data[18:20] == b"\x3e\x00", "installed_elf_platform")
        files[name] = refresh.sha(data)
    for alias, canonical in KRB5_ALIASES.items():
        verify_alias_target(os.readlink(root / alias.lstrip("/")), canonical)
    return verified_report(raw, status, files, sdk=sdk,
                           kerberos_raw=receipts.get("krb5"), openssl_raw=receipts.get("openssl"))


def file_identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_size, info.st_mtime_ns,
    )


def inspect_bundle(directory, revision, *, kerberos_backport=False, openssl_backport=False):
    from deploy import qualified_image
    from deploy import qualify_image_scan as archive_reader

    modules = _backport_modules(kerberos_backport, openssl_backport)
    backport_paths = {source: str(module.PATH) for source, module in modules.items()}
    receipt_paths = {RECEIPT, DPKG_STATUS, *backport_paths.values()}
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
            None, [{"kind": "elf_set"}], read_paths=receipt_paths, archive_stream=stream
        )
        need(set(facts.captured) == receipt_paths, "archive_evidence")
        need(all(name != LEGACY_PREFIX and not name.startswith(LEGACY_PREFIX + "/")
                 for name in facts[0]), "legacy_backport")
        files = {}
        for name in sorted(ELF_PATHS | _openssl_paths(modules)):
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
    report = verified_report(
        facts.captured[RECEIPT], facts.captured[DPKG_STATUS], files,
        kerberos_raw=facts.captured.get(backport_paths.get("krb5")),
        openssl_raw=facts.captured.get(backport_paths.get("openssl")),
    )
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
    parser.add_argument("--kerberos-backport", action="store_true")
    parser.add_argument("--openssl-backport", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if (args.bundle is not None) != (args.revision is not None) or (args.bundle and args.sdk):
        parser.error("--revision is required with --bundle and --sdk is only valid with --root")
    if args.openssl_backport and not args.kerberos_backport:
        parser.error("--openssl-backport requires --kerberos-backport")
    try:
        if args.bundle is not None:
            report = inspect_bundle(
                args.bundle, args.revision, kerberos_backport=args.kerberos_backport,
                openssl_backport=args.openssl_backport,
            )
        else:
            report = inspect_root(
                args.root, sdk=args.sdk, kerberos_backport=args.kerberos_backport,
                openssl_backport=args.openssl_backport,
            )
        with args.output.open("x", encoding="ascii") as stream:
            json.dump(report, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            stream.write("\n")
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, RecursionError) as error:
        if args.openssl_backport:
            message = "Debian, Kerberos and OpenSSL refresh inventory refused."
        elif args.kerberos_backport:
            message = "Debian and Kerberos refresh inventory refused."
        else:
            message = "Official Debian refresh inventory refused."
        code = "invalid_evidence"
        if isinstance(error, PermissionError):
            code = "filesystem_permission"
        elif isinstance(error, FileNotFoundError):
            code = "missing_evidence"
        elif isinstance(error, (InventoryError, refresh.Refused)) and len(error.args) == 1:
            label = error.args[0]
            if isinstance(label, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", label, re.ASCII):
                code = label
        print(f"{message} [{code}]", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
