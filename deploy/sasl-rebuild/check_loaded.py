"""Verify the installed SASL libraries and their native consumers without connecting."""

import json
import os
import subprocess
import sys
import sysconfig
from importlib.machinery import ExtensionFileLoader
from pathlib import Path

SCHEMA = "pamolive.sasl-runtime/1"
VERSION = "2.1.28+dfsg1-12~pamolive13u1"
SYSTEM = Path("/usr/lib/x86_64-linux-gnu")
CORE = SYSTEM / "libsasl2.so.2"
DB = SYSTEM / "sasl2/libsasldb.so.2"
LDAP = SYSTEM / "libldap.so.2"
PQ = SYSTEM / "libpq.so.5"
PACKAGES = {
    "libsasl2-2": (CORE, "f915d8cd6cb9e2ba4f69a9a5c9df3f7a355bf3fdef793be75408705bb513599b"),
    "libsasl2-modules-db": (DB, "58ecbb6b49dfa9452023a47c615aa43973fe91734a08b46210308aa86be736ea"),
}


def driver_checks():
    # The direct entry point also supports Python's isolated mode (-I).
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parents[2]))
    try:
        from deploy import check_database_driver
    finally:
        sys.path.pop(0)
    return check_database_driver


def check_packages(checks):
    result = subprocess.check_output(
        [
            "/usr/bin/dpkg-query", "-W",
            "-f=${Package}|${source:Package}|${Version}|${Architecture}|${Status}\n",
            "libsasl2-*",
        ],
        timeout=5,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).decode("ascii")
    expected = {
        f"{name}|cyrus-sasl2|{VERSION}|amd64|install ok installed" for name in PACKAGES
    }
    rows = result.splitlines()
    checks.require(
        {row for row in rows if row.split("|", 1)[0] in PACKAGES} == expected,
        "sasl_package_identity",
    )
    forbidden = {"libsasl2-dev", "libsasl2-modules"}
    checks.require(
        not any(
            row.split("|", 1)[0] in forbidden and row.endswith(" installed") for row in rows
        ),
        "unqualified_sasl_package",
    )
    for directory in (SYSTEM / "sasl2", Path("/usr/lib/sasl2")):
        checks.require(not any(directory.glob("libdigestmd5*")), "digestmd5_plugin_present")

    libraries = {}
    for package, (soname, expected_hash) in PACKAGES.items():
        path = checks.trusted_file(soname, prefix=soname.parent)
        owner = checks.dpkg_owner(path)
        checks.require(
            owner["package"].partition(":")[0] == package and owner["version"] == VERSION,
            "sasl_library_owner",
        )
        checks.require(checks.digest(path) == expected_hash, "sasl_library_sha256")
        libraries[soname.name] = {"path": str(path), "sha256": expected_hash, "package": package}
    return libraries


def assert_dependency(checks, path, soname):
    checks.require(path.stat().st_size <= checks.MAX_FILE, "file_budget")
    dynamic = checks.elf_dynamic(path.read_bytes())
    checks.require(soname in dynamic["needed"], "native_dependency_missing")


def check_mappings(checks, paths):
    expected = {path.name.split(".", 1)[0]: path for path in paths}
    identities = {prefix: path.stat() for prefix, path in expected.items()}
    mapped = set()
    for line in checks.read_maps(Path("/proc/self/maps")).splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        raw_path, deleted, _ = fields[5].partition(" (deleted)")
        path = Path(raw_path)
        prefix = path.name.split(".", 1)[0].split("-", 1)[0]
        checks.require(prefix != "libdigestmd5", "digestmd5_plugin_mapped")
        if prefix not in expected:
            continue
        info = identities[prefix]
        device = tuple(int(part, 16) for part in fields[3].split(":"))
        checks.require(
            not deleted
            and path.resolve(strict=True) == expected[prefix]
            and device == (os.major(info.st_dev), os.minor(info.st_dev))
            and int(fields[4]) == info.st_ino,
            "native_mapping_identity",
        )
        if "x" in fields[1]:
            mapped.add(expected[prefix])
    return mapped


def collect(checks):
    checks.require(sys.platform == "linux" and os.uname().machine == "x86_64", "linux_amd64")
    checks.require(os.getuid() == os.geteuid() == 1000, "runtime_uid")
    checks.require(os.environ.get("PSYCOPG_IMPL") == "c", "driver_environment")
    checks.require(
        os.environ.get("LD_LIBRARY_PATH") == checks.LIBRARY_PATH
        and not any(os.environ.get(name) for name in ("LD_PRELOAD", "LD_AUDIT", "SASL_PATH")),
        "loader_environment",
    )
    libraries = check_packages(checks)
    core = Path(libraries[CORE.name]["path"])
    db = Path(libraries[DB.name]["path"])
    ldap = checks.trusted_file(LDAP, prefix=SYSTEM)
    pq = checks.trusted_file(PQ, prefix=SYSTEM)
    platlib = Path(sysconfig.get_path("platlib"))

    import _ldap
    from psycopg import pq as driver_pq
    from psycopg_c import _psycopg
    from psycopg_c import pq as c_pq

    checks.require(driver_pq.__impl__ == "c" and driver_pq.PGconn is c_pq.PGconn, "driver_fallback")
    extensions = {}
    for module in (_ldap, _psycopg, c_pq):
        checks.require(isinstance(module.__loader__, ExtensionFileLoader), "native_extension")
        path, dynamic = checks.validate_extension(Path(module.__file__), platlib)
        needed = LDAP.name if module is _ldap else PQ.name
        checks.require(needed in dynamic["needed"], "extension_dependency_missing")
        extensions[module.__name__] = path
    assert_dependency(checks, pq, LDAP.name)
    assert_dependency(checks, ldap, CORE.name)

    required = {core, ldap, pq, *extensions.values()}
    mapped = check_mappings(checks, required | {db})
    checks.require(required <= mapped, "native_mapping_missing")
    for library in libraries.values():
        library["mapped"] = Path(library["path"]) in mapped
    return {
        "schema": SCHEMA,
        "verified": True,
        "architecture": "amd64",
        "version": VERSION,
        "libraries": libraries,
        "native_extensions": {name: str(path) for name, path in extensions.items()},
        "libldap": str(ldap),
        "libpq": str(pq),
        "digestmd5_plugin_absent": True,
    }


def main():
    try:
        checks = driver_checks()
        try:
            report = collect(checks)
        except checks.DriverError as exc:
            report = {"schema": SCHEMA, "verified": False, "error": str(exc)}
    except Exception:
        report = {"schema": SCHEMA, "verified": False, "error": "sasl_verification_failed"}
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
