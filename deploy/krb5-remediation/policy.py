"""Finite candidate materials; Root purpose is not product/ABI admission."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import read, record, write_new
from source_model import PRIMARY, PURPOSE, need, sha

HERE = Path(__file__).resolve().parent

PATCH_PLAN_SHA256 = "209cb75a6f42cbbb0e750bf0f0c1c7a8bc446e65d582736c25e80c00dcdcc33c"

MATERIALS = {
    "krb5-1.22.3.tar.gz": (
        8758584,
        "fe90af8441ad9fa9b064b8e53077cefb782a96f8a68276b031dc54af1789ff0b",
    ),
    "krb5-1.22.3.tar.gz.asc": (
        833,
        "818d8e52d8602c6fb2a53b4d456fdb7caf217aab89f917a3a3d014610fcba193",
    ),
    "MIT-C449-keyserver-untrusted.asc": (
        6717,
        "ec0471ac4181d5f063028831411a31cf31bfe94bdcd6c78baf57dadcb24f2167",
    ),
    "krb5_1.22.1-3.dsc": (3397, "b619af9a52f00c4888e1f53f38d5e147e8c518d1c5b0cda120873fa4ebd4ea77"),
    "krb5_1.22.1-3.debian.tar.xz": (
        111476,
        "519ad7537260ebc450a678b38f00c8deaf0e05d848d0e5cfeef1ddb154663ba8",
    ),
}
ROOT_PURPOSE = {
    "schema": "pamolive.Root.krb5-upgrade-bootstrap/1",
    "purpose": PURPOSE,
    "primary": PRIMARY,
    "signer": PRIMARY,
    "key_sha256": MATERIALS["MIT-C449-keyserver-untrusted.asc"][1],
    "tar_sha256": MATERIALS["krb5-1.22.3.tar.gz"][1],
    "asc_sha256": MATERIALS["krb5-1.22.3.tar.gz.asc"][1],
    "Debian_chain": "trusted-builder-debian-archive-keyring-signed-unstable-Sources",
    "packaging_adaptation_sha256": PATCH_PLAN_SHA256,
    "product_admission": False,
    "operational_GO": False,
}


def material(folder, name):
    need(name in MATERIALS, "material_name")
    size, digest = MATERIALS[name]
    raw = read(Path(folder) / name, size)
    need(len(raw) == size and sha(raw) == digest, "material_bytes")
    return raw


def copy_materials(source, target):
    target = Path(target)
    target.mkdir(mode=0o700)
    for name in MATERIALS:
        write_new(target / name, material(source, name), 0o444)
    record(target / "Root-purpose.json", ROOT_PURPOSE)
