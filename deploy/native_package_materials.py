"""Reject rebuilt native archives which differ from their reviewed bytes."""

import hashlib
import stat


def verify_archives(directory, version, names, packages, *, scope, versioned=True):
    if not (directory.is_absolute() and directory.is_dir() and not directory.is_symlink()):
        raise ValueError(f"{scope}_package_directory")
    for name in names:
        expected = packages[name]
        package = directory / (f"{name}_{version}_amd64.deb" if versioned else f"{name}.deb")
        info = package.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected["bytes"]:
            raise ValueError(f"{scope}_package_identity")
        with package.open("rb") as stream:
            data = stream.read(expected["bytes"] + 1)
        if hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError(f"{scope}_package_digest")
