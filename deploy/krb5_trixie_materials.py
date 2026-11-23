"""Verify the rebuilt Kerberos packages against the independently qualified archives."""

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path

PATH = "/usr/share/pamolive/krb5-trixie/qualification.json"
SHA256 = "115ba95dff1152115bfbc03d84eed5c30061c7fe72f97038616cd8f8dc3b65b4"
VERSION = "1.21.3-5+deb13u2+pamolive1"
SDK_PACKAGES = (
    "libkrb5-dev", "krb5-multidev", "libgssrpc4t64", "libkadm5clnt-mit12",
    "libkadm5srv-mit12", "libkdb5-10t64",
)
RUNTIME_PACKAGES = ("libkrb5-3", "libk5crypto3", "libkrb5support0", "libgssapi-krb5-2")
REVIEWED = Path(__file__).resolve().with_name("krb5-trixie-backport") / "qualification.json"
MAX_RECEIPT = 16 * 1024


def parse(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT
            or hashlib.sha256(raw).hexdigest() != SHA256):
        raise ValueError("unreviewed_kerberos_materials")
    return json.loads(raw)


def load_reviewed():
    with REVIEWED.open("rb") as stream:
        return parse(stream.read(MAX_RECEIPT + 1))


def verify_packages(directory, *, sdk=False):
    if not (directory.is_absolute() and directory.is_dir() and not directory.is_symlink()):
        raise ValueError("kerberos_package_directory")
    receipt = load_reviewed()
    names = RUNTIME_PACKAGES + SDK_PACKAGES if sdk else RUNTIME_PACKAGES
    for name in names:
        expected = receipt["packages"][name]
        package = directory / f"{name}_{VERSION}_amd64.deb"
        info = package.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected["bytes"]:
            raise ValueError("kerberos_package_identity")
        with package.open("rb") as stream:
            data = stream.read(expected["bytes"] + 1)
        if hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("kerberos_package_digest")


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--sdk", action="store_true")
    args = parser.parse_args()
    try:
        verify_packages(args.directory, sdk=args.sdk)
    except (ValueError, OSError):
        print("Qualified Kerberos packages refused.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
