"""Measure the exact image layers before a bounded, offline scanner invocation."""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from pathlib import Path

from deploy import qualified_image

SCRATCH_BYTES = 1024**3
MARGIN_BYTES = 128 * 1024**2
MAX_LAYERS = 128
LAYER = re.compile(r"(?:blobs/sha256/[a-f0-9]{64}|[a-f0-9]{64}/layer\.tar)\Z")


def measure(path):
    archive_sha = qualified_image.archive_hash(path)
    compressed = path.stat().st_size
    # Two copies of expanded layers, the original archive, and a fixed margin.
    # This is a conservative sizing policy, not a guarantee about scanner internals.
    qualified_image.require(compressed + MARGIN_BYTES < SCRATCH_BYTES, "scratch_budget")
    budget = (SCRATCH_BYTES - compressed - MARGIN_BYTES) // 2
    total, rows = 0, []
    with tarfile.open(path, mode="r:") as outer:
        manifest = json.loads(qualified_image.tar_metadata(outer, "manifest.json", 65536))
        qualified_image.require(isinstance(manifest, list) and len(manifest) == 1,
                                "scratch_manifest")
        layers = manifest[0]["Layers"]
        qualified_image.require(isinstance(layers, list) and 0 < len(layers) <= MAX_LAYERS
                                and all(isinstance(name, str) and LAYER.fullmatch(name)
                                        for name in layers)
                                and len(set(layers)) == len(layers), "scratch_layers")
        for name in layers:
            matches = [item for item in outer if item.name == name]
            qualified_image.require(len(matches) == 1 and matches[0].isfile(),
                                    "scratch_layer_type")
            member = matches[0]
            with outer.extractfile(member) as raw, io.BufferedReader(raw) as buffered:
                header = buffered.peek(512)[:512]
                magic = header[:2]
                if magic != b"\x1f\x8b":
                    qualified_image.require(len(header) == 512, "scratch_layer_header")
                    # Accept raw tar or gzip, never estimate an unknown codec by
                    # its compressed length. The scanner still validates content.
                    tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                stream = gzip.GzipFile(fileobj=buffered) if magic == b"\x1f\x8b" else buffered
                expanded = 0
                try:
                    while block := stream.read(min(1024**2, budget - total + 1)):
                        total += len(block)
                        expanded += len(block)
                        qualified_image.require(total <= budget, "scratch_budget")
                finally:
                    if stream is not buffered:
                        stream.close()
            rows.append({"path": name, "stored_bytes": member.size,
                         "expanded_bytes": expanded})
    return {"schema": "pamolive.scanner-scratch.v1", "archive_sha256": archive_sha,
            "archive_bytes": compressed, "expanded_layer_bytes": total, "layers": rows,
            "required_bytes": 2 * total + compressed + MARGIN_BYTES,
            "scratch_limit_bytes": SCRATCH_BYTES, "margin_bytes": MARGIN_BYTES,
            "container_memory_bytes": 1536 * 1024**2, "passed": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        result = measure(args.archive)
        # Bind the report to bytes inspected, including concurrent modifications.
        with args.archive.open("rb") as stream:
            qualified_image.require(hashlib.file_digest(stream, "sha256").hexdigest() ==
                                    result["archive_sha256"], "scratch_archive_changed")
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            json.dump(result, stream, sort_keys=True)
            stream.write("\n")
    except (ValueError, OSError, KeyError, TypeError, EOFError, tarfile.TarError):
        if fd is not None:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"passed": False, "error": "scratch_qualification_failed"}, stream)
        print(json.dumps({"passed": False, "error": "scratch_qualification_failed"}))
        return 1
    print(json.dumps({"passed": True, "required_bytes": result["required_bytes"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
