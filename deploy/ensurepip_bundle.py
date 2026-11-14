"""Apply the reviewed local ensurepip overlay without executing bundled code."""

import argparse
import email.parser
import hashlib
import io
import json
import os
import stat
import sys
import sysconfig
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

BASE_REFERENCE = (
    "python:3.12.16-slim-trixie@sha256:"
    "5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)
MODULE = "usr/local/lib/python3.12/ensurepip"
ROOT_NAMES = frozenset({"__init__.py", "__main__.py", "_uninstall.py", "_bundled", "__pycache__"})
SYSCONFIG_PATH = "usr/local/lib/python3.12/_sysconfigdata__linux_x86_64-linux-gnu.py"
SYSCONFIG_SHA256 = "ff048f75a99504e073c8a9b7e9da146763fcde6960d2291c19ca2b72cde9eb69"
API_SHA256 = {
    "__main__.py": "ee735f518d0fc4dfec81f7aa3da1e052372ed4202c0da4eddd2587840beaecd7",
    "_uninstall.py": "3a6e95d01c45e2e47c05df3c81073b895c97c1eb0e5b90ab175d6d9263fc81f2",
}
SOURCE_SIZE = 9445
SOURCE_SHA256 = "90f6c76cd9ef7ed6daa198bb9ef771139683487f1b061211be7aa511831b2028"
PATCHED_SIZE = 9443
PATCHED_SHA256 = "5946b1d405e3650a310f4a85b1a48bdf4182f03397e069ff34f9fd7a1422217a"
OLD_NAME = "pip-25.0.1-py3-none-any.whl"
OLD_SIZE = 1841526
OLD_SHA256 = "c46efd13b6aa8279f33f2864459c8ce587ea6a1a59ee20de055868d8f7688f7f"
NEW_NAME = "pip-26.3-py3-none-any.whl"
NEW_SIZE = 1950951
NEW_SHA256 = "f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13"
METADATA_SHA256 = "ad63a8564cd158c8de9e6a912e92776b4abc56cfa2d8286ef4c35bfb9cb9e439"
BEFORE = b'_PIP_VERSION = "25.0.1"'
AFTER = b'_PIP_VERSION = "26.3"'
PROOF = Path("/usr/share/pamolive/python-materials/ensurepip-bundle.json")


class BundleError(ValueError):
    """Static error codes; no file contents or arbitrary exception messages."""


def require(value, code):
    if not value:
        raise BundleError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def no_alias(path, *, directory=False):
    path = Path(path).absolute()
    for parent in reversed(path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), "parent_alias_or_type")
    info = path.lstat()
    if directory:
        require(stat.S_ISDIR(info.st_mode), "directory_alias_or_type")
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "file_alias_or_type")
    return info


def regular(path, maximum):
    info = no_alias(path)
    require(0 <= info.st_size <= maximum, "file_budget")
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) == info.st_size and len(data) <= maximum, "file_changed_or_budget")
    return data


def pinned(path, size, checksum):
    data = regular(path, size)
    require(len(data) == size and sha(data) == checksum, "input_pin")
    return data


def check_wheel(data):
    """Read the already hash-checked buffer, never import/execute the wheel."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            require(0 < len(entries) <= 4096, "wheel_members")
            seen, total = set(), 0
            for entry in entries:
                path = PurePosixPath(entry.filename)
                require(
                    0 < len(entry.filename) <= 240
                    and not path.is_absolute()
                    and "\\" not in entry.filename
                    and all(
                        part not in ("", ".", "..")
                        for part in entry.filename.rstrip("/").split("/")
                    )
                    and all(32 < ord(char) < 127 for char in entry.filename)
                    and entry.filename not in seen,
                    "wheel_path",
                )
                seen.add(entry.filename)
                require(
                    stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
                    "wheel_alias_or_type",
                )
                require(not entry.filename.endswith((".pyc", ".pth")), "wheel_unexpected_code")
                total += entry.file_size
                require(
                    0 <= entry.file_size <= 2 * 1024**2 and total <= 16 * 1024**2, "wheel_expansion"
                )
            name = "pip-26.3.dist-info/METADATA"
            wheel_name = "pip-26.3.dist-info/WHEEL"
            require(name in seen and wheel_name in seen, "wheel_metadata_missing")
            require(
                archive.getinfo(name).file_size <= 65536
                and archive.getinfo(wheel_name).file_size <= 4096,
                "wheel_metadata_budget",
            )
            metadata = archive.read(name)
            require(sha(metadata) == METADATA_SHA256, "wheel_metadata_pin")
            fields = email.parser.BytesParser().parsebytes(metadata)
            require(
                fields.get_all("Name") == ["pip"] and fields.get_all("Version") == ["26.3"],
                "wheel_identity",
            )
            fields = email.parser.BytesParser().parsebytes(archive.read(wheel_name))
            require(
                fields.get_all("Tag") == ["py3-none-any"]
                and fields.get_all("Root-Is-Purelib") == ["true"],
                "wheel_tag",
            )
    except (zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError) as exc:
        raise BundleError("wheel_archive") from exc


def write_new(path, data):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    os.chmod(path, 0o644)


def empty_cache(directory):
    cache = directory / "__pycache__"
    info = no_alias(cache, directory=True)
    require(stat.S_IMODE(info.st_mode) == 0o755, "ensurepip_cache_mode")
    require(not any(cache.iterdir()), "ensurepip_cache_not_empty")


def replace_bundle(root, wheel, *, wheel_pkg_dir):
    require(type(wheel_pkg_dir) is str and wheel_pkg_dir == "", "external_wheel_directory")
    root = Path(root).absolute()
    no_alias(root, directory=True)
    require(
        sha(regular(root / SYSCONFIG_PATH, 128 * 1024)) == SYSCONFIG_SHA256, "sysconfig_source_pin"
    )
    directory = root / MODULE
    no_alias(directory, directory=True)
    require(
        {p.name for p in directory.iterdir()} == ROOT_NAMES,
        "ensurepip_file_set",
    )
    empty_cache(directory)
    unchanged = {name: sha(regular(directory / name, 16384)) for name in API_SHA256}
    require(unchanged == API_SHA256, "api_source_pin")
    bundled = directory / "_bundled"
    no_alias(bundled, directory=True)
    require({p.name for p in bundled.iterdir()} == {OLD_NAME}, "old_bundle_set")
    module = directory / "__init__.py"
    original = pinned(module, SOURCE_SIZE, SOURCE_SHA256)
    require(original.count(BEFORE) == 1 and AFTER not in original, "source_patch_count")
    patched = original.replace(BEFORE, AFTER)
    require(len(patched) == PATCHED_SIZE and sha(patched) == PATCHED_SHA256, "post_pin")
    old = bundled / OLD_NAME
    pinned(old, OLD_SIZE, OLD_SHA256)
    wheel = Path(wheel)
    require(wheel.name == NEW_NAME, "new_wheel_name")
    replacement = pinned(wheel, NEW_SIZE, NEW_SHA256)
    check_wheel(replacement)
    # All input refusals above precede any write. A later filesystem failure
    # aborts the Docker RUN; no partial layer or success proof is exported.
    new = bundled / NEW_NAME
    write_new(new, replacement)
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".pamolive-ensurepip-", dir=directory)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(patched)
        os.chmod(temporary, 0o644)
        # Refuse an intervening substitution before changing/removing inputs.
        pinned(module, SOURCE_SIZE, SOURCE_SHA256)
        pinned(old, OLD_SIZE, OLD_SHA256)
        os.replace(temporary, module)
        temporary = None
        pinned(old, OLD_SIZE, OLD_SHA256)
        old.unlink()  # The one exact, prevalidated obsolete wheel only.
    finally:
        if temporary is not None:
            temporary.unlink()
    pinned(module, PATCHED_SIZE, PATCHED_SHA256)
    pinned(new, NEW_SIZE, NEW_SHA256)
    require({p.name for p in bundled.iterdir()} == {NEW_NAME}, "final_bundle_set")
    require(
        {name: sha(regular(directory / name, 16384)) for name in unchanged} == unchanged,
        "unchanged_api_files",
    )
    require(
        {p.name for p in directory.iterdir()} == ROOT_NAMES,
        "final_ensurepip_file_set",
    )
    empty_cache(directory)
    return {
        "schema": "pamolive.ensurepip-bundle-overlay.v1",
        "recipe_base_reference": BASE_REFERENCE,
        "module_path": "/" + MODULE + "/__init__.py",
        "source_before": {"sha256": SOURCE_SHA256, "size": SOURCE_SIZE},
        "local_overlay_after": {"sha256": PATCHED_SHA256, "size": PATCHED_SIZE},
        "removed_wheel": {"filename": OLD_NAME, "sha256": OLD_SHA256, "size": OLD_SIZE},
        "added_wheel": {
            "filename": NEW_NAME,
            "sha256": NEW_SHA256,
            "size": NEW_SIZE,
            "metadata_sha256": METADATA_SHA256,
        },
        "unchanged_api_files": unchanged,
        "wheel_pkg_dir": wheel_pkg_dir,
        "sysconfigdata_sha256": SYSCONFIG_SHA256,
        "retained_cache_directory": {
            "path": "/" + MODULE + "/__pycache__",
            "mode": "0755",
            "empty": True,
        },
        "build_verified": False,
        "attestation_verified": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True)
    args = parser.parse_args(argv)
    try:
        require(
            sys.platform == "linux"
            and sys.implementation.name == "cpython"
            and sys.version_info[:3] == (3, 12, 16)
            and os.geteuid() == 0,
            "interpreter_profile",
        )
        no_alias(PROOF.parent, directory=True)
        require(not PROOF.exists() and not PROOF.is_symlink(), "proof_exists")
        report = replace_bundle(
            Path("/"), args.wheel, wheel_pkg_dir=sysconfig.get_config_var("WHEEL_PKG_DIR")
        )
        write_new(PROOF, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    except (BundleError, OSError, ValueError) as exc:
        code = str(exc) if isinstance(exc, BundleError) else "overlay_failed"
        print("ensurepip-bundle: " + code, file=sys.stderr)
        return 1
    print("ensurepip-bundle: reviewed local overlay applied; no build authority asserted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
