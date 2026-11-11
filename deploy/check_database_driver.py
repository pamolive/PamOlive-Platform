"""Offline check of a trusted Linux runtime's C database driver; never connects."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import ssl
import subprocess
import sys
import sysconfig
from pathlib import Path

try:
    from deploy.native_inventory import LIBRARY_PATH, elf_dynamic, probe
    from deploy.native_inventory import InventoryError as InventoryError
except ModuleNotFoundError:
    from native_inventory import LIBRARY_PATH, elf_dynamic, probe
    from native_inventory import InventoryError as InventoryError

VERSION = "3.2.10"
SCHEMA = "pamolive.database-driver-runtime/1"
SYSTEM = Path("/usr/lib/x86_64-linux-gnu")
MAX_FILE = 64 * 1024 * 1024
MAX_MAPS = 4 * 1024 * 1024


class DriverError(ValueError):
    """Static code only; never raw exception/subprocess output."""


def require(condition, code):
    if not condition:
        raise DriverError(code)


def digest(path):
    require(path.is_file() and path.stat().st_size <= MAX_FILE, "file_budget")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def trusted_file(path, *, prefix):
    resolved = path.resolve(strict=True)
    require(resolved.is_relative_to(prefix.resolve(strict=True)), "dependency_outside_system")
    require(resolved.is_file(), "dependency_not_file")
    for node in (resolved, *resolved.parents):
        info = node.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "untrusted_file_permissions")
    return resolved


def validate_versions(core, extension, impl, runtime, build):
    require(core == extension == VERSION, "driver_version_mismatch")
    require(impl == "c", "driver_fallback")
    require(
        type(runtime) is int and type(build) is int and runtime >= 170000 and build >= 170000,
        "libpq_version",
    )
    require(runtime // 10000 == build // 10000, "libpq_build_runtime_major_mismatch")


def reject_binary_packages(folders):
    for folder in folders:
        require(folder.is_dir(), "package_directory_missing")
        entries = list(folder.iterdir())
        require(len(entries) <= 10000, "package_directory_budget")
        for path in entries:
            name = path.name.lower().replace("-", "_")
            require(
                not name.startswith("psycopg_binary")
                and not ("psycopg" in name and name.endswith(".libs")),
                "vendored_driver_present",
            )


def dpkg_owner(path):
    result = subprocess.run(
        ["/usr/bin/dpkg-query", "-S", str(path)],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    require(
        result.returncode == 0 and not result.stderr and len(result.stdout) <= 16384,
        "dependency_not_owned_by_dpkg",
    )
    rows = result.stdout.splitlines()
    require(len(rows) == 1, "dependency_owner_ambiguous")
    package, separator, owned = rows[0].partition(": ")
    require(
        separator
        and owned == str(path)
        and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::amd64)?", package),
        "dependency_owner_invalid",
    )
    version = subprocess.run(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}",
            package,
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    fields = version.stdout.split("\t")
    require(
        version.returncode == 0
        and not version.stderr
        and len(version.stdout) <= 2048
        and len(fields) == 3
        and fields[0] == package
        and fields[2].strip() == "ii"
        and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", fields[1]),
        "dependency_package_not_installed",
    )
    return dict(package=package, version=fields[1])


def loaded_libpq(maps, expected):
    require(isinstance(maps, str) and len(maps) <= MAX_MAPS, "maps_budget")
    paths = set()
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and "libpq" in Path(fields[5]).name:
            require(not fields[5].endswith(" (deleted)"), "loaded_library_deleted")
            paths.add(Path(fields[5]).resolve(strict=True))
    require(paths == {expected.resolve(strict=True)}, "loaded_libpq_mismatch")
    return digest(next(iter(paths)))


def read_maps(path):
    # procfs st_size is normally zero, so bound the read itself instead.
    with path.open("rb") as stream:
        raw = stream.read(MAX_MAPS + 1)
    require(len(raw) <= MAX_MAPS, "maps_budget")
    return raw.decode("utf-8")


def cryptography_openssl_version():
    from cryptography.hazmat.backends import default_backend

    return default_backend().openssl_version_text()


def extension_paths(distribution):
    require(distribution.files is not None, "driver_metadata_missing")
    files = list(distribution.files)
    require(len(files) <= 1000, "driver_metadata_budget")
    paths = []
    for item in files:
        text = str(item).replace("\\", "/")
        require(not text.startswith("/") and ".." not in text.split("/"), "driver_metadata_path")
        require(
            not any(part.endswith(".libs") for part in text.split("/")), "vendored_driver_present"
        )
        if text.startswith("psycopg_c/") and text.endswith(".so"):
            paths.append(Path(distribution.locate_file(item)))
    require(
        len(paths) == 2 and {p.name.split(".")[0] for p in paths} == {"_psycopg", "pq"},
        "driver_extension_inventory",
    )
    return paths


def validate_extension(path, package_root):
    require(not path.is_symlink(), "driver_extension_symlink")
    path = trusted_file(path, prefix=package_root)
    require(path.stat().st_size <= MAX_FILE, "file_budget")
    dynamic = elf_dynamic(path.read_bytes())
    require(not dynamic["rpath"] and not dynamic["runpath"], "driver_search_path")
    return path, dynamic


def collect():
    require(sys.platform == "linux", "linux_runtime_required")
    require(os.environ.get("PSYCOPG_IMPL") == "c", "driver_environment")
    require(
        not os.environ.get("LD_PRELOAD") and os.environ.get("LD_LIBRARY_PATH") == LIBRARY_PATH,
        "loader_environment",
    )
    folders = {Path(sysconfig.get_path(key)) for key in ("purelib", "platlib")}
    folders.update(
        Path(p) for p in sys.path if p and Path(p).name in {"site-packages", "dist-packages"}
    )
    require(0 < len(folders) <= 16, "package_search_budget")
    reject_binary_packages(folders)
    # Imports only after physical package/environment checks. No connection is opened.
    import psycopg
    import psycopg_c
    from psycopg import pq

    distribution = importlib.metadata.distribution("psycopg-c")
    require(
        importlib.metadata.version("psycopg") == psycopg.__version__
        and distribution.version == psycopg_c.__version__,
        "driver_metadata_version",
    )
    validate_versions(
        psycopg.__version__, psycopg_c.__version__, pq.__impl__, pq.version(), pq.__build_version__
    )
    extensions, libraries = [], {}
    package_root = Path(distribution.locate_file("psycopg_c")).resolve(strict=True)
    require(
        any(package_root.is_relative_to(p.resolve(strict=True)) for p in folders),
        "driver_package_outside_installation",
    )
    for path in extension_paths(distribution):
        path, dynamic = validate_extension(path, package_root)
        module = importlib.import_module("psycopg_c." + path.name.split(".")[0])
        require(
            Path(module.__file__).resolve(strict=True) == path, "driver_loaded_extension_mismatch"
        )
        links = probe(path)
        require(len(links) <= 64, "dependency_budget")
        for link in links:
            resolved = trusted_file(Path(link["path"]), prefix=SYSTEM)
            record = dict(path=str(resolved), sha256=digest(resolved), **dpkg_owner(resolved))
            previous = libraries.setdefault(link["soname"], record)
            require(previous == record, "dependency_resolution_changed")
        extensions.append(dict(path=str(path), sha256=digest(path), needed=dynamic["needed"]))
    require("libpq.so.5" in libraries, "libpq_not_resolved")
    require(libraries["libpq.so.5"]["package"].split(":")[0] == "libpq5", "libpq_wrong_package")
    maps = Path("/proc/self/maps")
    actual_hash = loaded_libpq(read_maps(maps), Path(libraries["libpq.so.5"]["path"]))
    require(actual_hash == libraries["libpq.so.5"]["sha256"], "loaded_libpq_hash_mismatch")
    return dict(
        schema=SCHEMA,
        verified=True,
        driver_version=VERSION,
        implementation=pq.__impl__,
        libpq_runtime_version=pq.version(),
        libpq_build_version=pq.__build_version__,
        extensions=extensions,
        system_libraries=libraries,
        python_ssl_version=ssl.OPENSSL_VERSION,
        cryptography_openssl_version=cryptography_openssl_version(),
        coverage=[
            "psycopg C extensions and their system ldd dependency closure",
            "OpenSSL public version inventory; not complete native vulnerability coverage",
        ],
        database_connection_tested=False,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        report = collect()
        raw = json.dumps(report, sort_keys=True, indent=2)
        require(len(raw) <= 1024 * 1024, "report_budget")
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(raw + "\n")
    except Exception as error:
        # Any unexpected probe/import failure is a refusal, never a traceback
        # containing environment or raw subprocess details. BaseException is
        # deliberately not caught (interrupts still interrupt qualification).
        if fd is not None:
            os.close(fd)
        code = str(error) if isinstance(error, DriverError) else "driver_verification_failed"
        print(json.dumps(dict(verified=False, error=code)))
        return 1
    print(json.dumps(dict(verified=True)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
