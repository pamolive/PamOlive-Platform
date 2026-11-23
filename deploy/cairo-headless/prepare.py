"""Select Cairo's supported headless backends on a pinned Debian source tree."""

import hashlib
import re
import sys
from pathlib import Path

BASE_VERSION = b"1.18.4-1"
REBUILD_VERSION = b"1.18.4-1+pamolive13u1"
SOURCE_DIGESTS = {
    "rules": "c24fb511d466f0fd6effb0038989e3f665a311f97c0ac862e593a8983a4a4817",
    "control": "34ec5cc65b40bebeef63bcc8e2b04c045a5de6fce8190e5ed0f48933255ddf55",
    "libcairo2.symbols": "ebd96ff8225d847c7e6ee29c71f63b6cdb5fb5dca09ae3929a4050589fc83ede",
}
X_SDK = (
    b"libsm-dev", b"libx11-dev", b"libxcb-render0-dev", b"libxcb-shm0-dev",
    b"libxcb1-dev", b"libxext-dev", b"libxrender-dev",
)


def replace_one(data, old, new):
    if data.count(old) != 1:
        raise ValueError("unexpected_cairo_packaging")
    return data.replace(old, new, 1)


def configure_rules(data):
    continuation = b" " + b"\\" + b"\n"
    quartz_flag = b"\t-Dquartz=disabled" + continuation
    flags = b"".join(
        b"\t-D" + backend + b"=disabled" + continuation
        for backend in (b"xlib", b"xcb", b"xlib-xcb")
    )
    # Keep the udeb configuration aligned with the common backend choices.
    current_udeb = b"udeb_configure_flags +=" + continuation
    current_udeb += b"\t$(configure_flags)" + continuation + b"\t-Dxcb=disabled"
    data = replace_one(data, current_udeb, b"udeb_configure_flags += $(configure_flags)")
    return replace_one(data, quartz_flag, quartz_flag + flags)


def sdk_control(data):
    marker = b"\nPackage: libcairo2-dev\n"
    if data.count(marker) != 1:
        raise ValueError("unexpected_cairo_sdk")
    before, _, tail = data.partition(marker)
    sdk, separator, after = tail.partition(b"\n\n")
    if not separator:
        raise ValueError("unexpected_cairo_sdk")
    for dependency in X_SDK:
        sdk = replace_one(sdk, b"         " + dependency + b",\n", b"")
    return before + marker + sdk + separator + after


def headless_symbols(data, allowed):
    removed, retained = [], []
    for row in data.splitlines(keepends=True):
        match = re.match(rb" (cairo_(?:xlib|xcb)_[a-z0-9_]+)@Base ", row)
        if match:
            removed.append(match[1])
        else:
            retained.append(row)
    if sorted(removed) != allowed or len(removed) != 26:
        raise ValueError("unexpected_cairo_symbol_delta")
    return b"".join(retained)


def prepare(root, export_path):
    inputs = {}
    for name, expected in SOURCE_DIGESTS.items():
        raw = (root / "debian" / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("unexpected_cairo_source")
        inputs[name] = raw
    allowed = export_path.read_bytes().splitlines()
    changelog = root / "debian/changelog"
    previous = changelog.read_bytes()
    if not previous.startswith(b"cairo (" + BASE_VERSION + b") "):
        raise ValueError("unexpected_cairo_version")
    prefix = b"cairo (" + REBUILD_VERSION + b") trixie; urgency=medium\n\n"
    prefix += b"  * Use the image, PNG and font backends without X11 clients.\n\n"
    prefix += b" -- PamOlive Build <pamolive-automation@users.noreply.github.com>"
    prefix += b"  Mon, 23 Nov 2026 00:00:00 +0000\n\n"
    changes = {
        "rules": configure_rules(inputs["rules"]),
        "control": sdk_control(inputs["control"]),
        "libcairo2.symbols": headless_symbols(inputs["libcairo2.symbols"], allowed),
        "changelog": prefix + previous,
    }
    for name, data in changes.items():
        (root / "debian" / name).write_bytes(data)


if __name__ == "__main__":
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
