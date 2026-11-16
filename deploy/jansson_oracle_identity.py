"""Public build-stage hashes only; never load a library or execute an oracle."""

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

CASES = {
    "build": (
        "/opt/pamolive-test/winpr-jansson-regression",
        "/opt/pamolive-test/winpr-jansson-regression.json",
    ),
    "runtime": (
        "/opt/pamolive-test/winpr-jansson-regression",
        "/opt/pamolive-test/winpr-jansson-runtime.json",
    ),
    "reference": ("/tmp/json-backend-reference", "/json-reference.jsonl"),
}
PREFIX = "/opt/pamolive-freerdp/lib"
STEMS = ("libfreerdp3.so", "libfreerdp-client3.so", "libwinpr3.so")


def need(value):
    if not value:
        raise ValueError("jansson_oracle_identity")


def _identity(info):
    # Access time may change during a legitimate read. Change time is checked
    # within each stat API below (Windows exposes different ctime semantics).
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
    )


def captured(path, maximum):
    path = Path(path)
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and not before.st_mode & 0o022
        and 0 < before.st_size <= maximum
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        need(_identity(opened) == _identity(before))
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        body = stream.read(maximum + 1)
        after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
        need(
            _identity(after_fd) == _identity(opened)
            and _identity(after_path) == _identity(before)
            and after_fd.st_ctime_ns == opened.st_ctime_ns
            and after_path.st_ctime_ns == before.st_ctime_ns
            and len(body) == before.st_size
        )
    return hashlib.sha256(body).hexdigest()


def snapshot(case, root=Path("/")):
    need(case in CASES)
    directory = root / PREFIX.lstrip("/")
    need(directory.resolve(strict=True) == directory)
    aliases, files = {}, {}
    paths = sorted({path for stem in STEMS for path in directory.glob(stem + "*")})
    need(1 <= len(paths) <= 32)
    for path in paths:
        target = path.resolve(strict=True)
        need(target.parent == directory)
        canonical = "/" + target.relative_to(root).as_posix()
        aliases["/" + path.relative_to(root).as_posix()] = canonical
        if canonical not in files:
            files[canonical] = captured(target, 32 * 1024**2)
    binary, oracle = CASES[case]
    jansson_root = root / "usr/lib/x86_64-linux-gnu"
    jansson = (jansson_root / "libjansson.so.4").resolve(strict=True)
    need(jansson.parent == jansson_root and jansson.name.startswith("libjansson.so."))
    return {
        "schema": "pamolive.jansson-oracle-identity/1",
        "case": case,
        "provider_files": files,
        "aliases": aliases,
        "jansson_files": {
            "/" + jansson.relative_to(root).as_posix(): captured(jansson, 4 * 1024**2)
        },
        "binary_sha256": captured(root / binary.lstrip("/"), 4 * 1024**2),
        "oracle_sha256": captured(root / oracle.lstrip("/"), 32768),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=sorted(CASES))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    value = snapshot(args.case)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
