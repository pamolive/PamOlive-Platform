"""Verify the ACL consumer packages and bindings in the exact release archive."""

import argparse
import hashlib
import os
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from deploy import acl_runtime_inventory as acl
from deploy import qualified_image
from deploy import qualify_image_scan as gate
from qualification.debian_138_refresh.verify_refresh import controls

SCHEMA = "pamolive.acl-runtime-inventory/2"
QUALIFICATION = "deploy/acl-rebuild/consumer-qualification.json"
INSTALLED_QUALIFICATION = "/usr/share/pamolive/acl-consumers/qualification.json"
QUALIFICATION_LIMIT = 16384
PACKAGE_PATHS = {
    "coreutils": ("/usr/bin/cp", "/usr/bin/install", "/usr/bin/mv"),
    "sed": ("/usr/bin/sed",),
    "tar": ("/usr/bin/tar",),
}
CONSUMERS = {path for paths in PACKAGE_PATHS.values() for path in paths}
FD_ONLY = {"/usr/sbin/useradd", "/usr/sbin/usermod"}
ALL_CONSUMERS = CONSUMERS | FD_ONLY
LIBRARY_ALIAS = str(PurePosixPath(acl.LIBRARY).with_name(acl.SONAME))
MANAGED = (acl.LIBRARY, *sorted(ALL_CONSUMERS))
READ_PATHS = (*MANAGED, INSTALLED_QUALIFICATION, acl.STATUS)
ATTRIBUTES = (*MANAGED, INSTALLED_QUALIFICATION)


def validate_qualification(qualification):
    acl.need(set(qualification) == {"schema", "architecture", "qualification", "packages"}
             and qualification["schema"] == "pamolive.acl-consumer-packages/1"
             and qualification["architecture"] == "amd64", "acl_consumer_qualification_schema")
    source = qualification["qualification"]
    acl.need(set(source) == {"revision", "run_id", "artifact_id", "artifact_sha256"}
             and qualified_image.REVISION.fullmatch(source["revision"])
             and qualified_image.HASH.fullmatch(source["artifact_sha256"])
             and all(type(source[key]) is int and 0 < source[key] < 2**63
                     for key in ("run_id", "artifact_id")), "acl_consumer_qualification_identity")
    packages = qualification["packages"]
    acl.need(set(packages) == set(PACKAGE_PATHS), "acl_consumer_package_scope")
    for name, paths in PACKAGE_PATHS.items():
        package = packages[name]
        acl.need(set(package) == {"version", "deb_sha256", "deb_bytes", "binaries"}
                 and 0 < len(package["version"]) <= 40
                 and package["version"].endswith("+pamolive1")
                 and qualified_image.HASH.fullmatch(package["deb_sha256"])
                 and type(package["deb_bytes"]) is int and 0 < package["deb_bytes"] <= 8 * 1024**2
                 and set(package["binaries"]) == set(paths), "acl_consumer_package_identity")
        for binary in package["binaries"].values():
            acl.need(set(binary) == {"sha256", "descriptor_imports"}
                     and qualified_image.HASH.fullmatch(binary["sha256"]),
                     "acl_consumer_binary_record")
            symbols = binary["descriptor_imports"]
            acl.need(isinstance(symbols, list) and 0 < len(symbols) <= 4
                     and symbols == sorted(set(symbols)) and all(symbol in {
                         "acl_delete_def_file_at@ACL_1.3", "acl_extended_file_at@ACL_1.3",
                         "acl_get_file_at@ACL_1.3", "acl_set_file_at@ACL_1.3",
                         "acl_get_fd@ACL_1.0", "acl_set_fd@ACL_1.0",
                     } for symbol in symbols), "acl_consumer_descriptor_symbols")
    return packages


def require_installed(facts, packages):
    installed = {}
    for row in controls(facts.captured[acl.STATUS]):
        name = row["Package"]
        if row["Status"] != "install ok installed":
            continue
        acl.need(name not in acl.EXCLUDED_PACKAGES, "acl_consumer_sdk_installed")
        if name in packages or name == "libacl1":
            acl.need(name not in installed, "acl_consumer_package_duplicate")
            installed[name] = row
    for name, package in packages.items():
        row = installed.get(name, {})
        source = row.get("Source", name)
        acl.need(row.get("Version") == package["version"] and row.get("Architecture") == "amd64"
                 and source in {name, f"{name} ({package['version']})"},
                 "acl_consumer_installed_identity")
    library = installed.get("libacl1", {})
    acl.need(library.get("Version") == acl.VERSION and library.get("Architecture") == "amd64"
             and library.get("Source") in {"acl", f"acl ({acl.VERSION})"},
             "acl_consumer_library_identity")


def inspect_consumers(facts, packages, target):
    expected = {path: binary for package in packages.values()
                for path, binary in package["binaries"].items()}
    for observation in facts.elf_linkage.values():
        acl.need(observation["status"] in {"observed", "no_dynamic_segment"},
                 "acl_consumer_linkage_incomplete")
    direct = {path for path, item in facts.entries.items() if item.get("class") is not None
              and acl.SONAME in facts.elf_linkage[item["sha256"]].get("needed", [])}
    acl.need(direct == ALL_CONSUMERS, "acl_consumer_dependency_scope")
    for path in MANAGED:
        item = facts.entries.get(path, {})
        attrs = facts.attributes.get(path)
        mode = 0o644 if path == acl.LIBRARY else 0o755
        acl.need(item.get("type") == "elf" and item.get("class") == 64
                 and item.get("machine") == 62 and attrs == {
                     "uid": 0, "gid": 0, "mode": mode, "has_capability": False},
                 "acl_consumer_elf_attributes")
    library = facts.captured[acl.LIBRARY]
    acl.need(hashlib.sha256(library).hexdigest() == acl.ELF_SHA256, "acl_consumer_library")
    acl.need(facts.entries.get(LIBRARY_ALIAS) == {
        "path": LIBRARY_ALIAS, "type": "symlink", "target": PurePosixPath(acl.LIBRARY).name,
    }, "acl_consumer_library_alias")
    library_text = acl.readelf(library, target)
    acl.need(f"Library soname: [{acl.SONAME}]" in library_text, "acl_consumer_library_soname")
    _, exports = acl.acl_symbols(library_text)
    observed = {}
    for path in sorted(direct):
        data = facts.captured[path]
        checksum = hashlib.sha256(data).hexdigest()
        imports, _ = acl.acl_symbols(acl.readelf(data, target))
        acl.need(bool(imports) and imports <= exports
                 and not acl.LEGACY.intersection(symbol.split("@", 1)[0] for symbol in imports),
                 "acl_consumer_legacy_import")
        if path in FD_ONLY:
            acl.need(imports == {"perm_copy_fd@ACL_1.1"}, "acl_consumer_unexpected_fd_user")
        else:
            pin = expected[path]
            acl.need(checksum == pin["sha256"] and set(pin["descriptor_imports"]) <= imports,
                     "acl_consumer_elf_identity")
        observed[path] = {"sha256": checksum, "imports": sorted(imports)}
    return observed


def measure(facts, qualification_bytes, metadata, target):
    qualification = gate.json_bytes(qualification_bytes, maximum=QUALIFICATION_LIMIT)
    packages = validate_qualification(qualification)
    acl.need(facts.captured.get(INSTALLED_QUALIFICATION) == qualification_bytes
             and facts.attributes.get(INSTALLED_QUALIFICATION) == {
                 "uid": 0, "gid": 0, "mode": 0o444, "has_capability": False},
             "acl_consumer_installed_qualification")
    for name in facts.contents.keys() | facts.entries.keys():
        path = PurePosixPath(name)
        acl.need(path.name not in acl.TOOLS and name not in acl.SDK_FILES
                 and path.name != "libacl.so", "acl_consumer_runtime_only")
        if path.name.startswith("libacl.so."):
            acl.need(name in {acl.LIBRARY, LIBRARY_ALIAS}, "acl_consumer_duplicate_library")
    require_installed(facts, packages)
    observed = inspect_consumers(facts, packages, target)
    return {
        "schema": SCHEMA,
        "architecture": "amd64",
        "revision": metadata["revision"],
        "image_config_id": metadata["image_id"],
        "archive_sha256": metadata["archive_sha256"],
        "qualification_sha256": hashlib.sha256(qualification_bytes).hexdigest(),
        "qualification": qualification["qualification"],
        "packages": packages,
        "consumers": observed,
    }


def inspect_facts(facts, metadata, *, repo=None):
    repo = Path(__file__).resolve().parents[1] if repo is None else repo
    qualification = repo / QUALIFICATION
    acl.need(qualification.is_file() and not qualification.is_symlink()
             and 0 < qualification.stat().st_size <= QUALIFICATION_LIMIT,
             "acl_consumer_qualification_file")
    with TemporaryDirectory(prefix="pamolive-acl-consumers-") as temporary:
        return measure(facts, qualification.read_bytes(), metadata, Path(temporary) / "elf")


def inspect_bundle(bundle, revision):
    metadata = qualified_image.verify_bundle(bundle, revision)
    archive = bundle / qualified_image.ARCHIVE
    _, facts = gate.bound_archive_facts(archive, metadata, [], read_paths=READ_PATHS,
                                      attribute_paths=ATTRIBUTES, observe_elf_linkage=True)
    return inspect_facts(facts, metadata)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inspect_bundle(args.bundle, args.revision)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            stream.write(gate.canonical(report) + "\n")
    except acl.InventoryError as exc:
        raise SystemExit(f"ACL consumer verification refused ({exc}).") from None
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        raise SystemExit("ACL consumer verification refused.") from None


if __name__ == "__main__":
    main()
