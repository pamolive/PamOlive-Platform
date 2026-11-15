"""Pinned helper loading; bootstrap reader retains the reviewed R2 FD body."""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAX_WHEEL = 2 * 1024**2
PINS_SHA = "b19e49007f7f3655efdea0a4fc891ecfec89c2944809b5589dd6fd8376611de2"


def need(condition):
    if not condition:
        raise ValueError("vault_installed_refused")


def read_regular(path, cap):
    need(type(cap) is int and 0 <= cap <= MAX_WHEEL)
    path = path.absolute()
    need(all(part not in (".", "..") for part in path.parts))
    for parent in path.parents:
        row = parent.lstat()
        need(stat.S_ISDIR(row.st_mode) and not getattr(row, "st_file_attributes", 0) & 1024)

    def checked(row):
        need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and 0 <= row.st_size <= cap)
        need(not getattr(row, "st_file_attributes", 0) & 1024)
        return (
            row.st_dev,
            row.st_ino,
            row.st_mode,
            row.st_nlink,
            row.st_size,
            row.st_mtime_ns,
        )

    before_path = path.lstat()
    before = checked(before_path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        need(checked(opened) == before)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(cap + 1)
        need(len(raw) == before[4] and len(raw) <= cap)
        after_fd, after_path = os.fstat(descriptor), path.lstat()
        need(checked(after_fd) == before and checked(after_path) == before)
        # Windows lstat/fstat can expose different ctime meanings. Check each
        # API's time before/after; do not equate the two representations.
        need(after_fd.st_ctime_ns == opened.st_ctime_ns)
        need(after_path.st_ctime_ns == before_path.st_ctime_ns)
        return raw
    finally:
        os.close(descriptor)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pins():
    raw = read_regular(ROOT / "helper-pins.json", 65536)
    need(sha(raw) == PINS_SHA)
    return json.loads(raw)


def load(name):
    records = pins()
    need(name in records and name.endswith(".py") and "/" not in name and "\\" not in name)
    path = ROOT / "helpers" / name
    raw = read_regular(path, 1024**2)
    need(len(raw) == records[name]["bytes"] and sha(raw) == records[name]["sha256"])
    module_name = "_vault_installed_helper_" + name[:-3]
    if module_name in sys.modules:
        return sys.modules[module_name]

    class Loader(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            return compile(raw, str(path), "exec", dont_inherit=True)

    spec = importlib.util.spec_from_loader(module_name, Loader(module_name, str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[module_name]
        raise
    return module
