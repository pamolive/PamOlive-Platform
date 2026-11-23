"""Verify the qualified util-linux archives and an offline privilege inventory."""

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from deploy.native_package_materials import verify_archives

PATH = "/usr/share/pamolive/util-linux-trixie/qualification.json"
SHA256 = "3f3f7f7cf518fa613a836699b4f74d753e2b5f0be04e44c45463aa4a78a6ad8c"
VERSION = "2.41.5-0+deb13u1+pamolive1"
RUNTIME_PACKAGES = (
    "bsdutils", "libblkid1", "liblastlog2-2", "libmount1", "libsmartcols1",
    "libuuid1", "login", "mount", "util-linux",
)
PACKAGE_VERSIONS = {
    **dict.fromkeys(RUNTIME_PACKAGES, VERSION),
    "bsdutils": "1:" + VERSION,
    "login": "1:4.16.0-2+really" + VERSION,
}
LIBDIR = "/usr/lib/x86_64-linux-gnu/"
LIBRARIES = {
    "libblkid1": ("libblkid.so.1", "libblkid.so.1.1.0"),
    "liblastlog2-2": ("liblastlog2.so.2", "liblastlog2.so.2.0.0"),
    "libmount1": ("libmount.so.1", "libmount.so.1.1.0"),
    "libsmartcols1": ("libsmartcols.so.1", "libsmartcols.so.1.1.0"),
    "libuuid1": ("libuuid.so.1", "libuuid.so.1.3.0"),
}
ALIASES = {LIBDIR + alias: LIBDIR + path for alias, path in LIBRARIES.values()}
SPECIAL_MODE_PATHS = ("/usr/bin/mount", "/usr/bin/newgrp", "/usr/bin/su", "/usr/bin/umount")
SPECIAL_FILE_METADATA = {"mode": 0o4755, "uid": 0, "gid": 0, "has_capability": False}
ELF_BY_PACKAGE = {
    **{name: (LIBDIR + path,) for name, (_, path) in LIBRARIES.items()},
    "mount": ("/usr/bin/mount",),
    "util-linux": ("/usr/bin/findmnt", "/usr/bin/nsenter", "/usr/bin/unshare"),
}
REVIEWED = Path(__file__).resolve().with_name("util-linux-trixie-backport") / "qualification.json"
MAX_RECEIPT = 16 * 1024


def parse(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT
            or hashlib.sha256(raw).hexdigest() != SHA256):
        raise ValueError("unreviewed_util_linux_materials")
    return json.loads(raw)


def load_reviewed():
    with REVIEWED.open("rb") as stream:
        return parse(stream.read(MAX_RECEIPT + 1))


def verify_packages(directory):
    verify_archives(
        directory, VERSION, RUNTIME_PACKAGES, load_reviewed()["packages"],
        scope="util_linux", versioned=False,
    )


def raise_walk_error(error):
    raise error


def has_capability(path):
    return "security.capability" in os.listxattr(path, follow_symlinks=False)


def privilege_profile(roots):
    """Compare set-ID modes, ownership and file capabilities across installation."""
    profile = {}
    for root in roots:
        for directory, dirnames, filenames in os.walk(root, onerror=raise_walk_error):
            for name in (*dirnames, *filenames):
                path = Path(directory) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                regular = stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                capability = ""
                if regular and has_capability(path):
                    capability = os.getxattr(
                        path, "security.capability", follow_symlinks=False,
                    ).hex()
                if not regular or capability or info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    profile[str(path)] = [info.st_mode, info.st_uid, info.st_gid,
                                          info.st_rdev, capability]
    return profile


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--directory", type=Path)
    action.add_argument("--privilege-profile", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.privilege_profile:
            print(json.dumps(privilege_profile(("/usr", "/etc", "/var")), sort_keys=True))
        else:
            verify_packages(args.directory)
    except (ValueError, OSError):
        print("Qualified util-linux evidence refused.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
