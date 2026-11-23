"""Verify the rebuilt OpenSSL packages against the independently qualified archives."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from deploy.native_package_materials import verify_archives

PATH = "/usr/share/pamolive/openssl-trixie/qualification.json"
SHA256 = "b04eb9567f8353f766028862b2482599cb3e2ba95b5060b37c805e758574d6a0"
VERSION = "3.5.9-1~deb13u1+pamolive1"
RUNTIME_PACKAGES = ("libssl3t64", "openssl", "openssl-provider-legacy")
SDK_PACKAGES = ("libssl-dev",)
LIBDIR = "/usr/lib/x86_64-linux-gnu"
ELF_BY_PACKAGE = {
    "libssl3t64": (LIBDIR + "/libcrypto.so.3", LIBDIR + "/libssl.so.3"),
    "openssl": ("/usr/bin/openssl",),
    "openssl-provider-legacy": (LIBDIR + "/ossl-modules/legacy.so",),
}
REVIEWED = Path(__file__).resolve().with_name("openssl-trixie-backport") / "qualification.json"
MAX_RECEIPT = 16 * 1024


def parse(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT
            or hashlib.sha256(raw).hexdigest() != SHA256):
        raise ValueError("unreviewed_openssl_materials")
    return json.loads(raw)


def load_reviewed():
    with REVIEWED.open("rb") as stream:
        return parse(stream.read(MAX_RECEIPT + 1))


def verify_packages(directory, *, sdk=False):
    names = RUNTIME_PACKAGES + SDK_PACKAGES if sdk else RUNTIME_PACKAGES
    verify_archives(directory, VERSION, names, load_reviewed()["packages"], scope="openssl")


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--sdk", action="store_true")
    args = parser.parse_args()
    try:
        verify_packages(args.directory, sdk=args.sdk)
    except (ValueError, OSError):
        print("Qualified OpenSSL packages refused.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
