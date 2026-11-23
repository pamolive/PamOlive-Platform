"""Record the SASL ABI and exercise the runtime libraries on synthetic values."""

import ctypes
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

BASELINE = "2.1.28+dfsg1-9"
CANDIDATE = "2.1.28+dfsg1-12~pamolive13u1"
LIBDIR = Path("/usr/lib/x86_64-linux-gnu")
CORE = LIBDIR / "libsasl2.so.2"
DB = LIBDIR / "sasl2" / "libsasldb.so.2"
LDAP = LIBDIR / "libldap.so.2"
PQ = LIBDIR / "libpq.so.5"
PACKAGES = ("libsasl2-2", "libsasl2-modules-db")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def run(*args):
    return subprocess.check_output(
        args, text=True, encoding="ascii", timeout=10, env={"LC_ALL": "C"},
    )


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def package_version(name):
    result = run("dpkg-query", "-W", "-f=${Status}\t${Architecture}\t${Version}", name)
    status, architecture, version = result.split("\t")
    require((status, architecture) == ("install ok installed", "amd64"), "package_identity")
    return version


def dynamic(path):
    return run("readelf", "--wide", "--dynamic", str(path))


def exports(path):
    names = set()
    for line in run("readelf", "--wide", "--dyn-syms", str(path)).splitlines():
        fields = line.split()
        if len(fields) < 8 or not re.fullmatch(r"\d+:", fields[0]):
            continue
        _, _, _, kind, binding, visibility, index, name = fields[:8]
        if (
            kind in {"FUNC", "IFUNC"}
            and binding in {"GLOBAL", "WEAK"}
            and visibility in {"DEFAULT", "PROTECTED"}
            and index != "UND"
        ):
            names.add(name)
    require(0 < len(names) <= 256, "export_count")
    return sorted(names)


def bind(library, name, return_type, *types):
    function = getattr(library, name)
    function.restype = return_type
    function.argtypes = types
    return function


def exercise():
    pointer, string, integer = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
    ref = ctypes.POINTER(pointer)
    ldap = ctypes.CDLL(str(LDAP))
    pq = ctypes.CDLL(str(PQ))
    sasl = ctypes.CDLL(str(CORE))
    init = bind(sasl, "sasl_client_init", integer, pointer)
    new = bind(
        sasl, "sasl_client_new", integer, string, string, string, string,
        pointer, ctypes.c_uint, ref,
    )
    dispose = bind(sasl, "sasl_dispose", None, ref)
    done = bind(sasl, "sasl_done", None)
    connection = pointer()
    require(init(None) == 0, "sasl_initialization")
    try:
        result = new(
            b"ldap", b"directory.example.invalid", None, None, None, 0, ctypes.byref(connection),
        )
        require(result == 0 and connection.value, "sasl_client_context")
    finally:
        if connection.value:
            dispose(ctypes.byref(connection))
        done()

    initialize = bind(ldap, "ldap_initialize", integer, ref, string)
    unbind = bind(ldap, "ldap_unbind_ext_s", integer, pointer, pointer, pointer)
    session = pointer()
    result = initialize(ctypes.byref(session), b"ldap://127.0.0.1:9")
    require(result == 0 and session.value, "ldap_context")
    require(unbind(session, None, None) == 0, "ldap_context_close")

    parse = bind(pq, "PQconninfoParse", pointer, string, ctypes.POINTER(string))
    free = bind(pq, "PQconninfoFree", None, pointer)
    options = parse(b"host=127.0.0.1 dbname=synthetic sslmode=verify-full", None)
    require(options, "libpq_conninfo")
    free(options)

    mapped = set()
    for line in Path("/proc/self/maps").read_text(encoding="ascii").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        mapped.add(Path(fields[5]))
    require({lib.resolve(strict=True) for lib in (CORE, LDAP, PQ)} <= mapped, "loaded_libraries")


def runtime(version):
    require(version in {BASELINE, CANDIDATE}, "unrecognized_version")
    require(all(package_version(name) == version for name in PACKAGES), "package_version")
    require(not list(LIBDIR.glob("sasl2/libdigestmd5*")), "digestmd5_present")
    require(f"Library soname: [{CORE.name}]" in dynamic(CORE), "sasl_soname")
    require(f"Library soname: [{DB.name}]" in dynamic(DB), "sasldb_soname")
    require(f"Shared library: [{CORE.name}]" in dynamic(LDAP), "ldap_sasl_link")
    require(f"Shared library: [{LDAP.name}]" in dynamic(PQ), "libpq_ldap_link")
    exercise()
    return {
        "version": version,
        "core_sha256": sha(CORE),
        "db_sha256": sha(DB),
        "exports": exports(CORE),
        "client_initialization": True,
        "digestmd5_plugin_absent": True,
    }


def compare(root):
    baseline = json.loads((root / "baseline.json").read_bytes())
    candidate = json.loads((root / "candidate.json").read_bytes())
    versions = (baseline["version"], candidate["version"])
    require(versions == (BASELINE, CANDIDATE), "compared_versions")
    for item in (baseline, candidate):
        require(
            item["client_initialization"] is True and item["digestmd5_plugin_absent"] is True,
            "runtime_profile",
        )
    require(set(baseline["exports"]) <= set(candidate["exports"]), "missing_legacy_exports")
    return {
        "schema": "pamolive.sasl-trixie-qualification/1",
        "architecture": "amd64",
        "version": CANDIDATE,
        "core_sha256": candidate["core_sha256"],
        "db_sha256": candidate["db_sha256"],
        "preserved_exports": len(baseline["exports"]),
        "package_sha256": {name: sha(root / f"{name}.deb") for name in PACKAGES},
        "buildinfo_sha256": sha(root / "buildinfo"),
        "client_initialization": True,
        "digestmd5_plugin_absent": True,
    }


if __name__ == "__main__":
    _, action, value = sys.argv
    if action == "runtime":
        report = runtime(value)
    elif action == "compare":
        report = compare(Path(value))
    else:
        raise SystemExit("Unrecognized qualification action")
    print(json.dumps(report, sort_keys=True))
