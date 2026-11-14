"""Bounded public Python input acquisition and per-build native wheel inventory.

This is byte verification, never an authority or a build attestation. Acquisition
does not import, extract, or execute any acquired Python code or backend.
"""

import argparse
import email.parser
import gzip
import hashlib
import io
import json
import platform
import re
import ssl
import stat
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

MAX_JSON = 262144
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
CHUNK = 65536
SCHEMA = "pamolive.python-materials.v1"
TARGET = {
    "implementation": "cpython",
    "python": "3.12.16",
    "abi": "cp312",
    "os": "linux",
    "arch": "x86_64",
    "glibc": "2.41",
}
RUNTIME = {
    "asgiref": "3.13.0",
    "asyncssh": "2.24.1",
    "bcrypt": "5.0.0",
    "cbor2": "6.2.1",
    "cffi": "2.1.1",
    "click": "8.5.1",
    "cryptography": "50.0.2",
    "dj-database-url": "3.1.2",
    "django": "5.2.19",
    "gunicorn": "23.0.0",
    "h11": "0.16.0",
    "packaging": "26.3",
    "psycopg": "3.2.10",
    "pyasn1": "0.6.5",
    "pyasn1-modules": "0.4.2",
    "pycparser": "3.12",
    "pyjwt": "2.15.1",
    "pyopenssl": "26.4.0",
    "pyotp": "2.9.0",
    "sqlparse": "0.6.1",
    "typing-extensions": "4.16.0",
    "tzdata": "2026.6",
    "uvicorn": "0.54.0",
    "webauthn": "3.0.1",
    "websockets": "17.4",
    "whitenoise": "6.11.0",
}
BUILD = {"setuptools": "84.2.1", "wheel": "0.48.0", "packaging": "26.3"}
SOURCES = {"psycopg-c": "3.2.10", "python-ldap": "3.4.8"}
EXPECTED = RUNTIME | BUILD | SOURCES | {"pip": "26.3", "pillow": "13.0.0"}
LOCKS = {
    "runtime": "requirements-python-runtime-linux.lock",
    "build-tools": "requirements-python-build-tools-linux.lock",
    "sources": "requirements-python-native-sources-linux.lock",
    "native-test": "requirements-python-native-test-linux.lock",
    "bootstrap": "requirements-bootstrap.lock",
}
SO_PATHS = {
    "psycopg-c": {
        "psycopg_c/_psycopg.cpython-312-x86_64-linux-gnu.so",
        "psycopg_c/pq.cpython-312-x86_64-linux-gnu.so",
    },
    "python-ldap": {"_ldap.cpython-312-x86_64-linux-gnu.so"},
}
SOURCE_PATHS = {
    "psycopg-c": {
        "PKG-INFO",
        "psycopg_c.egg-info/PKG-INFO",
        "build_backend/cython_backend.py",
        "psycopg_c/_psycopg.c",
        "psycopg_c/pq.c",
        "psycopg_c/types/numutils.c",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
    },
    "python-ldap": {
        "PKG-INFO",
        "Lib/python_ldap.egg-info/PKG-INFO",
        "Lib/ldap/pkginfo.py",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
    }
    | {
        "Modules/" + filename
        for filename in (
            "LDAPObject.c",
            "LDAPObject.h",
            "berval.c",
            "berval.h",
            "common.c",
            "common.h",
            "constants.c",
            "constants.h",
            "constants_generated.h",
            "functions.c",
            "functions.h",
            "ldapcontrol.c",
            "ldapcontrol.h",
            "ldapmodule.c",
            "message.c",
            "message.h",
            "options.c",
            "options.h",
        )
    },
}


class MaterialsError(ValueError):
    """An input or generated artifact failed the closed byte contract."""


def require(condition, code):
    if not condition:
        raise MaterialsError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, limit=MAX_FILE):
    path = Path(path)
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
        "file_type_or_budget",
    )
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file_budget")
    return data


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def safe_path(value, basename=False):
    require(type(value) is str and 0 < len(value) <= 240, "path")
    require(re.fullmatch(r"[A-Za-z0-9_./+-]+", value) is not None, "path")
    parts = PurePosixPath(value).parts
    require(
        not value.startswith("/") and all(p not in ("", ".", "..") for p in value.split("/")),
        "path",
    )
    require(not basename or len(parts) == 1, "filename")
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "sha256")


def valid_url(url, filename):
    require(type(url) is str and len(url) <= 1024, "url")
    require(all(33 <= ord(char) <= 126 for char in url), "url_characters")
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise MaterialsError("url") from exc
    require(parsed.scheme == "https" and parsed.netloc == "files.pythonhosted.org", "url_origin")
    require(not parsed.query and not parsed.fragment and "%" not in url, "url_components")
    require(
        parsed.path.startswith("/packages/") and parsed.path.rsplit("/", 1)[-1] == filename,
        "url_filename",
    )
    safe_path(parsed.path[1:])


def compatible_wheel(filename):
    parts = filename[:-4].split("-")
    require(len(parts) == 5, "wheel_tags")
    interpreter, abi, platforms = parts[-3:]
    if abi == "none":
        require(interpreter in ("py3", "py2.py3") and platforms == "any", "wheel_tags")
        return
    require(
        (interpreter == "cp312" and abi == "cp312")
        or (abi == "abi3" and interpreter in {f"cp3{n}" for n in range(2, 13)}),
        "wheel_tags",
    )
    for tag in platforms.split("."):
        if tag in (
            "linux_x86_64",
            "manylinux1_x86_64",
            "manylinux2010_x86_64",
            "manylinux2014_x86_64",
        ):
            continue
        match = re.fullmatch(r"manylinux_2_([0-9]{1,2})_x86_64", tag)
        require(match is not None and 5 <= int(match[1]) <= 41, "wheel_platform")


def roles_for(name):
    return sorted(
        (["runtime"] if name in RUNTIME else [])
        + (["build-tools"] if name in BUILD else [])
        + (["sources"] if name in SOURCES else [])
        + (["bootstrap"] if name == "pip" else [])
        + (["native-test"] if name == "pillow" else [])
    )


def validate_manifest(manifest):
    require(
        type(manifest) is dict
        and set(manifest)
        == {"schema", "target", "build_verified", "attestation_verified", "materials"},
        "manifest_fields",
    )
    require(manifest["schema"] == SCHEMA and manifest["target"] == TARGET, "manifest_target")
    require(
        manifest["build_verified"] is False and manifest["attestation_verified"] is False,
        "unsupported_attestation",
    )
    rows = manifest["materials"]
    require(type(rows) is list and len(rows) == 32, "material_count")
    names, filenames, total = set(), set(), 0
    for row in rows:
        require(
            type(row) is dict
            and set(row)
            == {
                "name",
                "version",
                "filename",
                "url",
                "sha256",
                "size",
                "kind",
                "roles",
                "source_files",
            },
            "material_fields",
        )
        name = row["name"]
        require(type(name) is str and name in EXPECTED and name not in names, "material_name")
        names.add(name)
        require(
            row["version"] == EXPECTED[name] and row["roles"] == roles_for(name),
            "material_version_or_roles",
        )
        filename = safe_path(row["filename"], basename=True)
        require(filename not in filenames, "duplicate_filename")
        filenames.add(filename)
        require(type(row["size"]) is int and 0 < row["size"] <= MAX_FILE, "material_size")
        total += row["size"]
        digest(row["sha256"])
        valid_url(row["url"], filename)
        prefix = name.replace("-", "_") + "-" + row["version"]
        if name in SOURCES:
            require(row["kind"] == "sdist" and filename == prefix + ".tar.gz", "sdist_filename")
            require(
                type(row["source_files"]) is dict
                and set(row["source_files"]) == SOURCE_PATHS[name],
                "source_inventory",
            )
            for path, value in row["source_files"].items():
                safe_path(path)
                digest(value)
        else:
            require(
                row["kind"] == "wheel"
                and filename.startswith(prefix + "-")
                and filename.endswith(".whl"),
                "wheel_filename",
            )
            compatible_wheel(filename)
            require(row["source_files"] == {}, "unexpected_source_inventory")
    require(names == set(EXPECTED) and total <= MAX_TOTAL, "materials_budget_or_set")
    return manifest


def load_manifest(path):
    raw = regular(path, MAX_JSON)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(MaterialsError("json_constant")),
        )
        return validate_manifest(value), sha(raw)
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaterialsError("invalid_json") from exc


def lock_bytes(rows):
    return (
        "".join(
            f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}\n"
            for r in sorted(rows, key=lambda r: r["name"])
        )
    ).encode("ascii")


def check_locks(manifest, directory):
    for role, filename in LOCKS.items():
        raw = regular(Path(directory) / filename, MAX_JSON)
        # Existing bootstrap commentary remains unchanged. All data lines exact.
        lines = (
            b"\n".join(
                line
                for line in raw.replace(b"\r\n", b"\n").splitlines()
                if line and not line.startswith(b"#")
            )
            + b"\n"
        )
        require(
            lines == lock_bytes([r for r in manifest["materials"] if role in r["roles"]]),
            "lock_manifest_mismatch",
        )


def check_target():
    require(
        sys.implementation.name == "cpython"
        and platform.python_version() == TARGET["python"]
        and sys.platform == "linux"
        and platform.machine() == "x86_64"
        and platform.libc_ver() == ("glibc", "2.41"),
        "builder_target",
    )
    require(not sysconfig_flag("Py_GIL_DISABLED") and not sysconfig_flag("Py_DEBUG"), "builder_abi")


def sysconfig_flag(name):
    import sysconfig

    return sysconfig.get_config_var(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise MaterialsError("redirect_forbidden")


def https_opener():
    context = ssl.create_default_context()
    require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "tls_verification")
    # Ignore ambient HTTP(S)_PROXY and credentials; do not add an auth handler.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect()
    )


def download(row, destination, opener):
    safe_path(row["filename"], basename=True)
    valid_url(row["url"], row["filename"])
    directory = Path(destination)
    require(directory.is_dir() and not directory.is_symlink(), "download_directory")
    target = directory / row["filename"]
    require(not target.exists() and not target.is_symlink(), "download_exists")
    created, started = False, time.monotonic()
    request = urllib.request.Request(
        row["url"], headers={"Accept-Encoding": "identity", "User-Agent": "PamOlive-materials/1"}
    )
    try:
        with opener.open(request, timeout=30) as response:
            require(
                response.status == 200 and response.geturl() == row["url"],
                "http_status_or_redirect",
            )
            require(
                response.headers.get("Content-Encoding", "identity") == "identity", "http_encoding"
            )
            length = response.headers.get("Content-Length")
            require(length is None or length == str(row["size"]), "http_size")
            h, count = hashlib.sha256(), 0
            with target.open("xb") as stream:
                created = True
                while True:
                    require(time.monotonic() - started <= 300, "download_deadline")
                    block = response.read(min(CHUNK, row["size"] - count + 1))
                    if not block:
                        break
                    count += len(block)
                    require(count <= row["size"], "download_size")
                    h.update(block)
                    stream.write(block)
            require(count == row["size"] and h.hexdigest() == row["sha256"], "download_integrity")
    except Exception:
        if created and target.is_file() and not target.is_symlink():
            target.unlink()
        raise


def verify_file(path, row):
    data = regular(path)
    require(len(data) == row["size"] and sha(data) == row["sha256"], "input_integrity")
    return data


def source_inventory(path, row):
    verified_bytes = verify_file(path, row)
    found, seen, total = {}, set(), 0
    prefix = row["filename"][:-7] + "/"
    try:
        # Bound decompression before tarfile can consume PAX/GNU metadata.
        with gzip.GzipFile(fileobj=io.BytesIO(verified_bytes), mode="rb") as compressed:
            payload = compressed.read(MAX_TOTAL + 1)
        require(len(payload) <= MAX_TOTAL, "source_expansion_budget")
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for index, member in enumerate(archive):
                require(index < 2048, "source_member_count")
                safe_path(member.name.rstrip("/"))
                require(
                    member.name not in seen
                    and (
                        member.name.startswith(prefix)
                        or (member.isdir() and member.name == prefix[:-1])
                    ),
                    "source_member",
                )
                seen.add(member.name)
                require(member.isdir() or member.isfile(), "source_member_type")
                total += member.size
                require(
                    0 <= member.size <= MAX_FILE and total <= MAX_TOTAL, "source_expansion_budget"
                )
                relative = member.name[len(prefix) :]
                require(not relative.endswith(".pyx"), "unexpected_cython_source")
                if relative in row["source_files"]:
                    require(member.isfile(), "source_file_type")
                    data = archive.extractfile(member).read(member.size + 1)
                    require(len(data) == member.size, "source_truncated")
                    found[relative] = sha(data)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise MaterialsError("source_archive") from exc
    require(found == row["source_files"], "source_inventory_mismatch")
    return found


def acquire(manifest, output, opener=None):
    validate_manifest(manifest)
    output = Path(output)
    output.mkdir()  # Fresh exclusive directory; no untrusted preexisting paths.
    for role in (*LOCKS, "runtime-inputs"):
        (output / role).mkdir()
    opener = opener or https_opener()
    started = time.monotonic()
    for row in manifest["materials"]:
        require(time.monotonic() - started <= 1800, "acquisition_deadline")
        primary = output / row["roles"][0]
        download(row, primary, opener)
        verified_bytes = verify_file(primary / row["filename"], row)
        if row["kind"] == "sdist":
            source_inventory(primary / row["filename"], row)
        elif "build-tools" not in row["roles"] or "runtime" in row["roles"]:
            inspect_upstream(primary / row["filename"], verified_bytes=verified_bytes)
        for role in row["roles"][1:]:
            with (output / role / row["filename"]).open("xb") as stream:
                stream.write(verified_bytes)
        if "runtime" in row["roles"] or "bootstrap" in row["roles"]:
            with (output / "runtime-inputs" / row["filename"]).open("xb") as stream:
                stream.write(verified_bytes)


def wheel_members(archive):
    members = archive.infolist()
    require(len(members) <= 4096, "wheel_member_count")
    seen, total = set(), 0
    for item in members:
        safe_path(item.filename.rstrip("/"))
        mode = stat.S_IFMT(item.external_attr >> 16)
        require(
            item.filename not in seen and mode in (0, stat.S_IFREG, stat.S_IFDIR), "wheel_member"
        )
        require(
            not item.filename.endswith((".pth", ".pyc")),
            "unexpected_wheel_pth_or_pyc_requires_review",
        )
        seen.add(item.filename)
        total += item.file_size
        require(0 <= item.file_size <= MAX_FILE and total <= MAX_TOTAL, "wheel_expansion_budget")
    return members, seen


def inspect_upstream(path, *, verified_bytes=None):
    data = regular(path) if verified_bytes is None else verified_bytes
    require(type(data) is bytes and len(data) <= MAX_FILE, "wheel_buffer_budget")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            wheel_members(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise MaterialsError("upstream_wheel_archive") from exc


def wheel_inventory(path, name, version, *, verified_bytes=None):
    expected = name.replace("-", "_") + "-" + version
    require(path.name == expected + "-cp312-cp312-linux_x86_64.whl", "derived_filename")
    data = regular(path) if verified_bytes is None else verified_bytes
    require(type(data) is bytes and len(data) <= MAX_FILE, "wheel_buffer_budget")
    extensions = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members, seen = wheel_members(archive)
            for item in members:
                if item.filename.endswith(".so"):
                    require(item.filename in SO_PATHS[name], "wheel_extension_path")
                    data = archive.read(item)
                    require(
                        len(data) >= 64
                        and data[:7] == b"\x7fELF\x02\x01\x01"
                        and data[16:20] == b"\x03\x00\x3e\x00",
                        "wheel_extension_elf",
                    )
                    extensions[item.filename] = {"sha256": sha(data), "size": len(data)}
            require(set(extensions) == SO_PATHS[name], "wheel_extension_set")
            metadata_name = expected + ".dist-info/METADATA"
            wheel_name = expected + ".dist-info/WHEEL"
            require(metadata_name in seen and wheel_name in seen, "wheel_metadata_missing")
            require(
                archive.getinfo(metadata_name).file_size <= MAX_JSON
                and archive.getinfo(wheel_name).file_size <= MAX_JSON,
                "wheel_metadata_budget",
            )
            metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_name))
            norm = re.sub(r"[-_.]+", "-", metadata.get("Name", "")).lower()
            require(
                norm == name
                and metadata.get_all("Name") == [metadata["Name"]]
                and metadata.get_all("Version") == [version],
                "wheel_identity",
            )
            wheel = email.parser.BytesParser().parsebytes(archive.read(wheel_name))
            require(
                wheel.get_all("Tag") == ["cp312-cp312-linux_x86_64"]
                and wheel.get_all("Root-Is-Purelib") == ["false"],
                "wheel_abi",
            )
    except (zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        raise MaterialsError("wheel_archive") from exc
    return extensions


def capture_derived(manifest, manifest_sha, inputs, wheels, output):
    validate_manifest(manifest)
    digest(manifest_sha)
    inputs, wheels, output = Path(inputs), Path(wheels), Path(output)
    require(wheels.is_dir() and not wheels.is_symlink() and output != wheels, "derived_directory")
    require(
        inputs.is_dir()
        and not inputs.is_symlink()
        and (inputs / "sources").is_dir()
        and not (inputs / "sources").is_symlink(),
        "source_directory",
    )
    source_rows = [r for r in manifest["materials"] if r["name"] in SOURCES]
    require(
        {p.name for p in (inputs / "sources").iterdir()} == {r["filename"] for r in source_rows},
        "source_set",
    )
    paths = list(wheels.iterdir())
    require(len(paths) == 2, "derived_count")
    records, lock = [], []
    for row in source_rows:
        source_files = source_inventory(inputs / "sources" / row["filename"], row)
        prefix = row["name"].replace("-", "_") + "-" + row["version"]
        path = wheels / (prefix + "-cp312-cp312-linux_x86_64.whl")
        data = regular(path)
        extensions = wheel_inventory(path, row["name"], row["version"], verified_bytes=data)
        wheel_hash = sha(data)
        lock.append({"name": row["name"], "version": row["version"], "sha256": wheel_hash})
        records.append(
            {
                "name": row["name"],
                "version": row["version"],
                "source_filename": row["filename"],
                "source_sha256": row["sha256"],
                "source_files": source_files,
                "wheel_filename": path.name,
                "wheel_sha256": wheel_hash,
                "wheel_size": len(data),
                "extensions": extensions,
            }
        )
    output.mkdir()
    (output / "requirements-python-derived-linux.lock").write_bytes(lock_bytes(lock))
    report = {
        "schema": "pamolive.python-derived-wheels.v1",
        "target": TARGET,
        "input_manifest_sha256": manifest_sha,
        "build_verified": False,
        "attestation_verified": False,
        "materials": records,
    }
    (output / "derived-manifest.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("acquire", "capture-derived", "check-locks"))
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--locks", default=".")
    parser.add_argument("--output")
    parser.add_argument("--inputs")
    parser.add_argument("--wheels")
    args = parser.parse_args(argv)
    try:
        manifest, manifest_sha = load_manifest(args.manifest)
        check_locks(manifest, args.locks)
        if args.command == "acquire":
            require(args.output is not None, "output_required")
            check_target()
            acquire(manifest, args.output)
        elif args.command == "capture-derived":
            require(all((args.inputs, args.wheels, args.output)), "derived_arguments")
            check_target()
            capture_derived(manifest, manifest_sha, args.inputs, args.wheels, args.output)
    except (MaterialsError, OSError, ValueError) as exc:
        print(f"python-materials: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
