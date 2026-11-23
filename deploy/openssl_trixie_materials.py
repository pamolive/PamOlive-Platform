"""Verify the rebuilt OpenSSL packages against the independently qualified archives."""

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from deploy.native_package_materials import verify_archives

PATH = "/usr/share/pamolive/openssl-trixie/qualification.json"
RUNTIME_PACKAGES = ("libssl3t64", "openssl", "openssl-provider-legacy")
SDK_PACKAGES = ("libssl-dev",)
LIBDIR = "/usr/lib/x86_64-linux-gnu"
ELF_BY_PACKAGE = {
    "libssl3t64": (LIBDIR + "/libcrypto.so.3", LIBDIR + "/libssl.so.3"),
    "openssl": ("/usr/bin/openssl",),
    "openssl-provider-legacy": (LIBDIR + "/ossl-modules/legacy.so",),
}
DIRECTORY = Path(__file__).resolve().with_name("openssl-trixie-backport")
MAX_RECEIPT = 16 * 1024


@dataclass(frozen=True)
class Materials:
    VERSION: str
    SHA256: str
    filename: str

    PATH = PATH
    RUNTIME_PACKAGES = RUNTIME_PACKAGES
    SDK_PACKAGES = SDK_PACKAGES
    ELF_BY_PACKAGE = ELF_BY_PACKAGE

    def parse(self, raw):
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT
                or hashlib.sha256(raw).hexdigest() != self.SHA256):
            raise ValueError("unreviewed_openssl_materials")
        return json.loads(raw)

    def load_reviewed(self):
        with (DIRECTORY / self.filename).open("rb") as stream:
            return self.parse(stream.read(MAX_RECEIPT + 1))


HISTORICAL = Materials(
    "3.5.9-1~deb13u1+pamolive1",
    "b04eb9567f8353f766028862b2482599cb3e2ba95b5060b37c805e758574d6a0",
    "qualification.json",
)
CURRENT = Materials(
    "3.5.9-1~deb13u1+pamolive2",
    "2b119889a3882af54f1271306467ec01013c87355b7034f4a7ed409c9c1b78a0",
    "qualification-dane.json",
)
VERSION = CURRENT.VERSION
SHA256 = CURRENT.SHA256
parse = CURRENT.parse
load_reviewed = CURRENT.load_reviewed


def select(receipt_sha256):
    for materials in (CURRENT, HISTORICAL):
        if receipt_sha256 == materials.SHA256:
            return materials
    raise ValueError("unreviewed_openssl_materials")


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
