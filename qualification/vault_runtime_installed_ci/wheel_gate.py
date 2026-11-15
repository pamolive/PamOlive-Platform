"""Three closed internal wheel data gates; no extraction or member execution."""

import io
import stat
import struct
import tomllib
import zipfile
import zlib
from email import policy
from email.parser import BytesParser

from adapter_v2 import CODE
from support import load, need, read_regular, sha

PACKAGES = {
    "runtime": ("pamolive-vault-reservation-runtime", "pamolive_vault_runtime"),
    "verifier": ("pamolive-pam-trust-verifier", "pamolive_pam_trust_verifier"),
    "contracts": ("pamolive-vault-contracts", "pamolive_vault_contracts"),
}
VERSION = "0.1.0a1"


def members(raw, wanted):
    need(type(raw) is bytes and 0 < len(raw) <= 2 * 1024**2)
    need(len(raw) >= 22 and raw.startswith(b"PK\x03\x04"))
    end = struct.unpack("<4s4H2LH", raw[-22:])
    need(end[0] == b"PK\x05\x06" and end[1:3] == (0, 0))
    need(end[3] == end[4] == len(wanted) and end[7] == 0 and end[6] + end[5] == len(raw) - 22)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        need(len(entries) == len(wanted) and {row.filename for row in entries} == wanted)
        need(not archive.comment and sum(row.file_size for row in entries) <= 4 * 1024**2)
        offset = 0
        for row in sorted(entries, key=lambda value: value.header_offset):
            mode = row.external_attr >> 16
            need(row.orig_filename == row.filename and not row.extra and not row.comment)
            need(not row.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG) and not mode & 0o7000)
            need(
                row.flag_bits == 0
                and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            )
            need(
                0 <= row.file_size <= 1024**2
                and row.header_offset == offset
                and offset + 30 <= len(raw)
            )
            header = struct.unpack_from("<4s5H3I2H", raw, offset)
            need(header[0] == b"PK\x03\x04" and header[2] == 0 and header[3] == row.compress_type)
            need(header[6:9] == (row.CRC, row.compress_size, row.file_size) and header[10] == 0)
            name_end = offset + 30 + header[9]
            need(raw[offset + 30 : name_end] == row.filename.encode("ascii"))
            offset = name_end + row.compress_size
            compressed = raw[name_end:offset]
            if row.compress_type == zipfile.ZIP_DEFLATED:
                decoder = zlib.decompressobj(-15)
                value = decoder.decompress(compressed, row.file_size + 1)
                need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail)
                need(len(value) == row.file_size)
            else:
                need(len(compressed) == row.file_size)
        need(offset == end[6])
        result = {}
        for row in entries:
            with archive.open(row) as stream:
                value = stream.read(row.file_size + 1)
            need(len(value) == row.file_size)
            result[row.filename] = value
        return result


def expected(source, kind):
    name, module = PACKAGES[kind]
    stem = name.replace("-", "_")
    info = stem + "-" + VERSION + ".dist-info"
    project = tomllib.loads(read_regular(source / "pyproject.toml", 65536).decode())["project"]
    wanted = {}
    directory = source / module if kind == "runtime" else source / "src" / module
    for path in directory.glob("*.py"):
        wanted[module + "/" + path.name] = read_regular(path, 1024**2)
    need({path.split("/", 1)[1] for path in wanted} == CODE[module])
    for license_name in project["license-files"]:
        wanted[info + "/licenses/" + license_name] = read_regular(source / license_name, 1024**2)
    if kind == "runtime":
        wanted[stem + "-" + VERSION + ".data/data/share/pamolive/vault-reservation/schema.sql"] = (
            read_regular(source / "sql/schema.sql", 65536)
        )
    return name, module, info, project, wanted


def validate(raw, source, kind, *, repository=None):
    name, module, info, project, wanted = expected(source, kind)
    fixed = {info + "/" + part for part in ("METADATA", "WHEEL", "RECORD", "top_level.txt")}
    files = members(raw, set(wanted) | fixed)
    need(all(files[path] == value for path, value in wanted.items()))
    # Maintained, pinned existing ZIP/RECORD checker; new closure/header guards
    # are additional. Never reconfigure its public-verifier-only pure profile.
    load("qualify_installed.py").zip_inventory(raw, name=name, version=VERSION)
    metadata = BytesParser(policy=policy.compat32).parsebytes(files[info + "/METADATA"])
    wheel = BytesParser(policy=policy.compat32).parsebytes(files[info + "/WHEEL"])
    need(metadata.get_unixfrom() is None and not metadata.defects and not metadata.is_multipart())
    need(wheel.get_unixfrom() is None and not wheel.defects and not wheel.is_multipart())
    need(wheel.get_payload(decode=True) == b"")
    headers = {
        "Metadata-Version": "2.4",
        "Name": name,
        "Version": VERSION,
        "Summary": project["description"],
        "Requires-Python": ">=3.12",
        "License-Expression": "AGPL-3.0-or-later",
        "Description-Content-Type": "text/markdown",
        "Dynamic": "license-file",
    }
    dependencies = project.get("dependencies", [])
    need(
        set(metadata.keys())
        == set(headers) | {"License-File"} | ({"Requires-Dist"} if dependencies else set())
    )
    for header, value in headers.items():
        need(metadata.get_all(header, []) == [value])
    need(sorted(metadata.get_all("License-File", [])) == sorted(project["license-files"]))
    need(sorted(metadata.get_all("Requires-Dist", [])) == sorted(dependencies))
    description = read_regular(source / "README.md", 65536).decode()
    need(
        metadata.get_payload(decode=True).decode().replace("\r\n", "\n").rstrip("\n")
        == description.replace("\r\n", "\n").rstrip("\n")
    )
    need(set(wheel.keys()) == {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag"})
    for key, value in {
        "Wheel-Version": "1.0",
        "Generator": "setuptools (84.2.1)",
        "Root-Is-Purelib": "true",
        "Tag": "py3-none-any",
    }.items():
        need(wheel.get_all(key, []) == [value])
    need(files[info + "/top_level.txt"] == (module + "\n").encode())
    if kind == "runtime":
        need(repository is not None)
        load("check_wheel.py").validate(raw, repository)
    return {
        "name": name,
        "module": module,
        "version": VERSION,
        "info": info,
        "wheel_sha256": sha(raw),
        "wheel_bytes": len(raw),
        "files": {
            path: {"sha256": sha(value), "bytes": len(value)}
            for path, value in files.items()
            if path != info + "/RECORD"
        },
        "wheel_RECORD_checked": True,
        "source_notice_metadata_exact": True,
    }
