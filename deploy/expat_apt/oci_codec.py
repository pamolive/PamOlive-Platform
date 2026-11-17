"""Pure OCI descriptor/redirect primitives from the reviewed public 5e capture. No I/O."""

import hashlib
import json
import re
from urllib.parse import urlsplit

PIN = "sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"

REGISTRY = "registry-1.docker.io"

AUTH = "auth.docker.io"

CDN = {
    "production.cloudfront.docker.com",
    "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
}

MAX_TOTAL = 256 * 1024**2

MAX_BLOB = 64 * 1024**2

MAX_JSON = 2 * 1024**2

MAX_INDEX = 1024**2

MAX_RAW = 512 * 1024**2

MAX_RAW_TOTAL = 1024**3

INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}

MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}

CONFIG_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}

GZIP_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}

RAW_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
}


class CapsuleError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise CapsuleError(code)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def checked_digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", value), "invalid_digest")
    return value


def size(value, maximum):
    require(type(value) is int and 0 < value <= maximum, "size_budget")
    return value


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, "json_budget")
    try:
        return json.loads(
            raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "nonfinite_json")
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise CapsuleError("invalid_json") from None


def descriptor(value, types, maximum):
    require(
        type(value) is dict and value.get("mediaType") in types and not value.get("urls"),
        "descriptor_type_or_external_urls",
    )
    return {
        "mediaType": value["mediaType"],
        "digest": checked_digest(value.get("digest")),
        "size": size(value.get("size"), maximum),
    }


def select(index):
    require(
        type(index) is dict
        and index.get("schemaVersion") == 2
        and index.get("mediaType") in INDEX_TYPES,
        "index_schema",
    )
    rows = index.get("manifests")
    require(type(rows) is list and 1 <= len(rows) <= 128, "index_count")
    matches = [
        r
        for r in rows
        if type(r) is dict
        and type(r.get("platform")) is dict
        and r["platform"].get("os") == "linux"
        and r["platform"].get("architecture") == "amd64"
    ]
    require(
        len(matches) == 1 and matches[0]["platform"].get("variant") in (None, "", "v1"),
        "amd64_not_unique",
    )
    return {
        **descriptor(matches[0], MANIFEST_TYPES, MAX_JSON),
        "platform": {"os": "linux", "architecture": "amd64"},
    }


def storage_url(value, expected_digest):
    require(
        type(value) is str and 0 < len(value) <= 16384 and all(33 <= ord(c) <= 126 for c in value),
        "redirect_url",
    )
    parsed = urlsplit(value)
    require(
        parsed.scheme == "https"
        and parsed.netloc == parsed.hostname
        and parsed.hostname in CDN
        and not parsed.fragment,
        "redirect_origin_unapproved",
    )
    require(
        "%" not in parsed.path and ".." not in parsed.path.split("/") and "\\" not in parsed.path,
        "redirect_path",
    )
    require(
        re.fullmatch(
            r"/registry-v2/docker/registry/v2/blobs/sha256/"
            + re.escape(expected_digest[7:9])
            + "/"
            + re.escape(expected_digest[7:])
            + r"/data",
            parsed.path,
        ),
        "redirect_blob_path",
    )
    return parsed.hostname, parsed.path, parsed.path + ("?" + parsed.query if parsed.query else "")
