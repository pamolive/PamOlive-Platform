"""Check a reservation-only wheel as data; never import or extract its code."""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import stat
import struct
import zipfile
import zlib
from email import policy
from email.parser import BytesParser
from pathlib import Path

NAME = "pamolive_vault_reservation_runtime"
VERSION = "0.1.0a1"
DIST = f"{NAME}-{VERSION}.dist-info"
SQL = f"{NAME}-{VERSION}.data/data/share/pamolive/vault-reservation/schema.sql"
MODULES = ("__init__", "admission", "asgi", "assembly", "bounded", "ledger", "slot", "transport")
DEPENDENCIES = {
    "cryptography==50.0.2",
    "pamolive-pam-trust-verifier==0.1.0a1",
    "pamolive-vault-contracts==0.1.0a1",
    "uvicorn==0.54.0",
}
MAX_WHEEL = 2 * 1024**2
SUMMARY = "Internal reservation-only Vault runtime; no secret release authority"
GENERATOR = "setuptools (84.2.1)"


def need(condition):
    if not condition:
        raise ValueError("reservation_wheel_refused")


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


def source_files(repository):
    runtime = repository / "components/vault/runtime"
    result = {
        f"pamolive_vault_runtime/{name}.py": read_regular(
            runtime / "pamolive_vault_runtime" / (name + ".py"), MAX_WHEEL
        )
        for name in MODULES
    }
    result[SQL] = read_regular(runtime / "sql/schema.sql", MAX_WHEEL)
    notice = read_regular(repository / "LICENSE", MAX_WHEEL)
    need(read_regular(runtime / "LICENSE", MAX_WHEEL) == notice)
    result[DIST + "/licenses/LICENSE"] = notice
    return result


def one(message, name, expected):
    need(message.get_all(name, []) == [expected])


def validate(raw, repository):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_WHEEL)
    need(len(raw) >= 22 and raw.startswith(b"PK\x03\x04"))
    end = struct.unpack("<4s4H2LH", raw[-22:])
    need(end[0] == b"PK\x05\x06" and end[1:3] == (0, 0) and end[3:5] == (14, 14))
    need(end[7] == 0 and end[6] + end[5] == len(raw) - 22)
    sources = source_files(repository)
    record_name = DIST + "/RECORD"
    expected = set(sources) | {
        DIST + "/METADATA",
        DIST + "/WHEEL",
        DIST + "/top_level.txt",
        record_name,
    }
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        need(len(entries) == len(expected) == 14)
        need({entry.filename for entry in entries} == expected)
        need(archive.comment == b"")
        need(sum(entry.file_size for entry in entries) <= 8 * 1024**2)
        offset = 0
        for entry in sorted(entries, key=lambda value: value.header_offset):
            mode = entry.external_attr >> 16
            need(entry.orig_filename == entry.filename and not entry.extra and not entry.comment)
            need(entry.header_offset == offset and offset + 30 <= len(raw))
            header = struct.unpack_from("<4s5H3I2H", raw, offset)
            need(header[0] == b"PK\x03\x04" and header[2] == entry.flag_bits == 0)
            need(
                header[3] == entry.compress_type
                and header[6:9] == (entry.CRC, entry.compress_size, entry.file_size)
            )
            need(header[10] == 0)
            name_end = offset + 30 + header[9]
            need(raw[offset + 30 : name_end] == entry.filename.encode("ascii"))
            offset = name_end + entry.compress_size
            need(not entry.is_dir() and not entry.flag_bits & 1)
            need(stat.S_IFMT(mode) in (0, stat.S_IFREG) and not mode & 0o7000)
            need(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            need(0 <= entry.file_size <= MAX_WHEEL)
            compressed = raw[name_end:offset]
            if entry.compress_type == zipfile.ZIP_DEFLATED:
                decoder = zlib.decompressobj(-15)
                decoded = decoder.decompress(compressed, entry.file_size + 1)
                need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail)
                need(len(decoded) == entry.file_size)
            else:
                need(len(compressed) == entry.file_size)
        need(offset == end[6])
        files = {entry.filename: archive.read(entry) for entry in entries}
    need(all(files[name] == content for name, content in sources.items()))
    need(files[DIST + "/top_level.txt"] == b"pamolive_vault_runtime\n")
    metadata = BytesParser(policy=policy.compat32).parsebytes(files[DIST + "/METADATA"])
    need(metadata.get_unixfrom() is None and not metadata.defects and not metadata.is_multipart())
    need(
        set(metadata.keys())
        == {
            "Metadata-Version",
            "Name",
            "Version",
            "Summary",
            "Requires-Python",
            "License-Expression",
            "License-File",
            "Requires-Dist",
            "Description-Content-Type",
            "Dynamic",
        }
    )
    one(metadata, "Metadata-Version", "2.4")
    one(metadata, "Name", "pamolive-vault-reservation-runtime")
    one(metadata, "Version", VERSION)
    one(metadata, "Summary", SUMMARY)
    one(metadata, "Requires-Python", ">=3.12")
    one(metadata, "License-Expression", "AGPL-3.0-or-later")
    one(metadata, "License-File", "LICENSE")
    one(metadata, "Description-Content-Type", "text/markdown")
    # Pinned setuptools84.2.1 marks expanded license globs dynamic. The only
    # accepted value still names the single byte-exact notice checked above.
    one(metadata, "Dynamic", "license-file")
    description = read_regular(repository / "components/vault/runtime/README.md", MAX_WHEEL).decode(
        "utf-8"
    )
    need(
        metadata.get_payload(decode=True).decode("utf-8").replace("\r\n", "\n").rstrip("\n")
        == description.replace("\r\n", "\n").rstrip("\n")
    )
    dependencies = metadata.get_all("Requires-Dist", [])
    need(len(dependencies) == len(DEPENDENCIES) and set(dependencies) == DEPENDENCIES)
    need(not metadata.get_all("Provides-Extra"))
    wheel = BytesParser(policy=policy.compat32).parsebytes(files[DIST + "/WHEEL"])
    need(wheel.get_unixfrom() is None and not wheel.defects and not wheel.is_multipart())
    need(wheel.get_payload(decode=True) == b"")
    need(set(wheel.keys()) == {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag"})
    one(wheel, "Wheel-Version", "1.0")
    one(wheel, "Root-Is-Purelib", "true")
    one(wheel, "Tag", "py3-none-any")
    one(wheel, "Generator", GENERATOR)
    rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"), newline="")))
    need(len(rows) == len(files) and all(len(row) == 3 for row in rows))
    need(len({row[0] for row in rows}) == len(rows) and {row[0] for row in rows} == set(files))
    for name, digest, size in rows:
        if name == record_name:
            need(digest == size == "")
        else:
            value = files[name]
            encoded = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=")
            need(digest == "sha256=" + encoded.decode("ascii") and size == str(len(value)))
    return {
        "schema": "pamolive.reservation-wheel-data-check/1",
        "files": len(files),
        "source_modules": len(MODULES),
        "wheel_sha256": hashlib.sha256(raw).hexdigest(),
        "schema_sql_sha256": hashlib.sha256(sources[SQL]).hexdigest(),
        "dependencies": sorted(DEPENDENCIES),
        "sources_schema_notice_RECORD_exact": True,
        "wheel_executed_or_installed": False,
        "build_attestation": False,
        "secret_release_authority": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    result = validate(read_regular(args.wheel, MAX_WHEEL), args.repository.absolute())
    print(json.dumps(result))


if __name__ == "__main__":
    main()
