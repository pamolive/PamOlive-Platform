"""Bounded, private transfer of the exact installed52 build products."""

import os
import struct

import adapter_v2
import schema
import workload_schema
from support import need, read_regular, sha
from wheel_gate import PACKAGES

MAGIC = b"pamolive.vault.verified-wheels/1\n"
HEADER = struct.Struct("!5I")
KINDS = ("verifier", "contracts", "runtime")
MAX_FRAME = schema.MAX_PACKET  # The existing Docker attach cap is 512 KiB.
MAX_DESCRIPTOR = 64 * 1024
FILENAME = "verified-wheels.bin"


def wheel_names():
    return {
        kind: PACKAGES[kind][0].replace("-", "_") + "-0.1.0a1-py3-none-any.whl" for kind in KINDS
    }


def verify(packet, descriptor, wheels, bindings):
    # Use the normal installed52 acceptance, including checks on the final
    # source bytes, installed RECORDs and the guarded child result.
    workload_schema.accept(packet, 0, **bindings)
    need(type(descriptor) is bytes and sha(descriptor) == bindings["expected_input"])
    value = adapter_v2.descriptor(schema.parse(descriptor, MAX_DESCRIPTOR))
    need(value["source_sha256"] == bindings["expected_source"])
    need(value["sql_sha256"] == bindings["expected_sql"])
    need(set(wheels) == set(KINDS))
    rows = {row["name"]: row for row in packet["execution"]["built_wheels"]}
    for kind in KINDS:
        row = rows[PACKAGES[kind][0]]
        raw = wheels[kind]
        need(
            type(raw) is bytes
            and len(raw) == row["wheel_bytes"]
            and sha(raw) == row["wheel_sha256"]
        )


def encode(packet, descriptor, wheels, *, bindings):
    verify(packet, descriptor, wheels, bindings)
    parts = [schema.encode(packet, schema.MAX_PACKET), descriptor, *(wheels[k] for k in KINDS)]
    sizes = [len(part) for part in parts]
    need(len(MAGIC) + HEADER.size + sum(sizes) <= MAX_FRAME)
    return b"".join([MAGIC, HEADER.pack(*sizes), *parts])


def decode(raw, *, bindings):
    offset = len(MAGIC) + HEADER.size
    need(type(raw) is bytes and offset < len(raw) <= MAX_FRAME and raw.startswith(MAGIC))
    sizes = HEADER.unpack_from(raw, len(MAGIC))
    need(all(sizes) and offset + sum(sizes) == len(raw))
    parts = []
    for size in sizes:
        parts.append(raw[offset : offset + size])
        offset += size
    wire_packet, descriptor, *archives = parts
    packet = schema.parse(wire_packet, schema.MAX_PACKET)
    need(wire_packet == schema.encode(packet, schema.MAX_PACKET))
    wheels = dict(zip(KINDS, archives, strict=True))
    verify(packet, descriptor, wheels, bindings)
    return packet, descriptor, {name: wheels[kind] for kind, name in wheel_names().items()}


def from_work(work, packet, *, bindings):
    """Use the same fixed post-check paths in the private builder's tmpfs."""
    descriptor = read_regular(work / "input.json", MAX_DESCRIPTOR)
    wheels = {
        kind: read_regular(work / "built" / kind / name, MAX_FRAME)
        for kind, name in wheel_names().items()
    }
    return encode(packet, descriptor, wheels, bindings=bindings)


def keep_private(work, raw):
    """Create a single owner-only file after the host has received cleanup."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(work / FILENAME, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
