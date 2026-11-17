"""Finite public HTTPS/XZ worker. Parent H1 covers DNS/TLS/headers/body/decode."""

import hashlib
import http.client
import importlib.util
import json
import os
import re
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

FAILURE_CODES = (
    "HTTP_body_cap",
    "HTTP_encoding",
    "HTTP_length",
    "HTTP_non200",
    "HTTP_short_read",
    "HTTP_transfer_framing",
    "Linux_build_worker",
    "TLS",
    "amd64_not_unique",
    "anonymous_token",
    "auth_redirect",
    "code_pin",
    "compressed_signed_binding",
    "decode_deadline",
    "decode_must_have_signed_binding",
    "decode_request",
    "descriptor_type_or_external_urls",
    "download_cap_type",
    "download_hash",
    "download_size",
    "duplicate_HTTP_header",
    "duplicate_JSON",
    "duplicate_json_key",
    "expected_SHA_type",
    "expected_size_type",
    "fetch_budget",
    "header_budget",
    "index_count",
    "index_schema",
    "invalid_digest",
    "json_budget",
    "metadata_redirect",
    "module_pin",
    "nonfinite_JSON",
    "nonfinite_json",
    "public_URL",
    "public_origin",
    "public_path",
    "public_redirect_forbidden",
    "raw_cap",
    "raw_signed_binding",
    "redirect_blob_path",
    "redirect_origin_unapproved",
    "redirect_path",
    "redirect_url",
    "registry_digest_header",
    "registry_expected_digest",
    "registry_request",
    "registry_shape",
    "second_redirect",
    "size_budget",
    "worker_deadline",
    "worker_deadline_type",
    "worker_fields",
    "worker_output_scope",
    "worker_private_path",
    "worker_schema",
)
FAILURE_PHASES = (
    "UNKNOWN",
    "bootstrap",
    "request",
    "acquire",
    "connect",
    "headers",
    "body",
    "decode",
    "write_output",
)
_phase = "UNKNOWN"
_codec_error = None


def failure_packet(error, phase):
    # This is a closed observation, never a causal or authentication decision.
    code = None
    if type(error) is ValueError or (
        _codec_error is not None and type(error) is _codec_error
    ):
        args = BaseException.args.__get__(error, BaseException)
        if (
            type(args) is tuple
            and len(args) == 1
            and type(args[0]) is str
            and args[0] in FAILURE_CODES
        ):
            code = args[0]
    if type(error) is ssl.SSLCertVerificationError:
        kind = "TLS_CERTIFICATE"
    elif type(error) is ssl.SSLError:
        kind = "TLS"
    elif type(error) is TimeoutError:
        kind = "TIMEOUT"
    elif type(error) is OSError:
        kind = "OS"
    elif code is not None:
        kind = "CONTRACT"
    else:
        kind = "UNKNOWN"
    return {
        "schema": "pamolive.expat-C-worker-failure-DATA/1",
        "state": "REFUSED_OR_UNKNOWN",
        "code_index": FAILURE_CODES.index(code) + 1 if code is not None else 0,
        "phase": phase if type(phase) is str and phase in FAILURE_PHASES else "UNKNOWN",
        "kind": kind,
        "operational_GO": False,
    }


def need(value, code):
    if not value:
        raise ValueError(code)


def pairs(rows):
    result = {}
    for name, value in rows:
        need(name not in result, "duplicate_JSON")
        result[name] = value
    return result


def data(raw):
    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda value: need(False, "nonfinite_JSON"),
    )


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def loaded(name):
    root = Path(__file__).parent
    raw_pins = (root / "code-pins.json").read_bytes()
    need(len(raw_pins) <= 16384 and digest(raw_pins) == sys.argv[2], "code_pin")
    pins = data(raw_pins)
    raw = (root / name).read_bytes()
    need(len(raw) <= 131072 and digest(raw) == pins[name], "module_pin")
    spec = importlib.util.spec_from_file_location("worker_" + name[:-3], root / name)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(root / name), "exec"), module.__dict__)
    return module


def public_url(url):
    need(type(url) is str and len(url) <= 1024, "public_URL")
    p = urlsplit(url)
    need(
        p.scheme == "https"
        and p.netloc == "deb.debian.org"
        and not p.query
        and not p.fragment
        and "%" not in p.path
        and ".." not in p.path.split("/")
        and "\\" not in p.path,
        "public_origin",
    )
    need(
        re.fullmatch(
            r"/(?:debian|debian-security)/(?:pool/[a-zA-Z0-9/+_.~-]+\.deb|"
            r"dists/(?:trixie|trixie-updates|trixie-security)/(?:InRelease|"
            r"main/binary-amd64/by-hash/SHA256/[a-f0-9]{64}))",
            p.path,
        ),
        "public_path",
    )
    return p.hostname, p.path


def fetch(host, path, headers, cap, until):
    global _phase
    _phase = "connect"
    # These globals are private to this worker. Actual aggregate headers <=16KiB below.
    http.client._MAXLINE = 8192
    http.client._MAXHEADERS = 32
    need(time.monotonic() < until and 0 < cap <= 128 * 1024**2, "fetch_budget")
    context = ssl.create_default_context()
    need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "TLS")
    connection = http.client.HTTPSConnection(host, timeout=15, context=context)
    try:
        connection.request(
            "GET", path, headers={"Accept-Encoding": "identity", **headers}
        )
        response = connection.getresponse()
        _phase = "headers"
        rows = response.getheaders()
        need(sum(len(n) + len(v) + 4 for n, v in rows) <= 16384, "header_budget")
        names = [n.lower() for n, _ in rows]
        for n in (
            "content-length",
            "content-encoding",
            "location",
            "docker-content-digest",
            "transfer-encoding",
        ):
            need(names.count(n) <= 1, "duplicate_HTTP_header")
        need(
            response.getheader("Content-Encoding", "identity") == "identity",
            "HTTP_encoding",
        )
        transfer = response.getheader("Transfer-Encoding")
        need(
            transfer is None
            or (transfer == "chunked" and "content-length" not in names),
            "HTTP_transfer_framing",
        )
        if response.status in (301, 302, 303, 307, 308):
            return response.status, response.getheader("Location"), b"", None
        need(response.status == 200, "HTTP_non200")
        declared = response.getheader("Content-Length")
        need(
            declared is None or (declared.isdecimal() and int(declared) <= cap),
            "HTTP_length",
        )
        _phase = "body"
        raw = bytearray()
        while True:
            need(time.monotonic() < until, "worker_deadline")
            block = response.read(min(65536, cap - len(raw) + 1))
            if not block:
                break
            raw.extend(block)
            need(len(raw) <= cap, "HTTP_body_cap")
        need(declared is None or int(declared) == len(raw), "HTTP_short_read")
        return 200, None, bytes(raw), response.getheader("Docker-Content-Digest")
    finally:
        connection.close()


def acquire(request, until, codec):
    cap = request["cap"]
    if request["op"] == "public":
        host, path = public_url(request["url"])
        status, _, raw, _ = fetch(host, path, {}, cap, until)
        need(status == 200, "public_redirect_forbidden")
    else:
        need(
            request["op"] == "registry"
            and request["kind"] in {"index", "manifest", "config", "layer"},
            "registry_request",
        )
        wanted = codec.checked_digest(request["digest"])
        status, _, token_raw, _ = fetch(
            codec.AUTH,
            "/token?service=registry.docker.io&scope=repository:library/python:pull",
            {"Accept": "application/json"},
            32768,
            until,
        )
        need(status == 200, "auth_redirect")
        auth = data(token_raw)
        token = auth.get("token", auth.get("access_token"))
        need(
            type(token) is str
            and 20 <= len(token) <= 16384
            and not any(c.isspace() for c in token)
            and not auth.get("refresh_token")
            and ("access_token" not in auth or auth["access_token"] == token),
            "anonymous_token",
        )
        del auth, token_raw
        endpoint = (
            "manifests/" if request["kind"] in {"index", "manifest"} else "blobs/"
        )
        accept = ",".join(sorted(codec.INDEX_TYPES | codec.MANIFEST_TYPES))
        status, location, raw, header = fetch(
            codec.REGISTRY,
            "/v2/library/python/" + endpoint + wanted,
            {"Authorization": "Bearer " + token, "Accept": accept},
            cap,
            until,
        )
        del token
        if status != 200:
            need(request["kind"] in {"config", "layer"}, "metadata_redirect")
            host, _, path = codec.storage_url(location, wanted)
            status, _, raw, header = fetch(host, path, {}, cap, until)
            need(status == 200, "second_redirect")
        need(header is None or header == wanted, "registry_digest_header")
    need(
        request["expected_sha256"] is None or digest(raw) == request["expected_sha256"],
        "download_hash",
    )
    need(
        request["expected_bytes"] is None or len(raw) == request["expected_bytes"],
        "download_size",
    )
    return raw


def request_shape(request, request_path):
    need(
        type(request) is dict and request.get("schema") == "pamolive.expat-C-worker/1",
        "worker_schema",
    )
    common = {"schema", "op", "destination", "until"}
    fields = {
        "public": {"url", "cap", "expected_sha256", "expected_bytes"},
        "registry": {"digest", "kind", "cap", "expected_sha256", "expected_bytes"},
        "xz": {
            "source",
            "expected_sha256",
            "expected_bytes",
            "raw_bytes",
            "raw_sha256",
        },
    }
    op = request.get("op")
    need(
        type(op) is str and op in fields and set(request) == common | fields[op],
        "worker_fields",
    )
    need(
        type(request["until"]) in (int, float) and request["until"] > 0,
        "worker_deadline_type",
    )
    prefix = r"/expat-apt-work/network/[1-9][0-9]{0,3}/"
    need(
        re.fullmatch(prefix + r"request\.json", str(request_path))
        and request["destination"] == str(Path(request_path).parent / "body.data"),
        "worker_private_path",
    )
    if op == "xz":
        need(
            type(request["source"]) is str
            and re.fullmatch(prefix + r"body\.data", request["source"])
            and type(request["raw_bytes"]) is int
            and 0 <= request["raw_bytes"] <= 128 * 1024**2
            and type(request["raw_sha256"]) is str
            and re.fullmatch(r"[a-f0-9]{64}", request["raw_sha256"]),
            "decode_request",
        )
    else:
        need(
            type(request["cap"]) is int and 0 < request["cap"] <= 128 * 1024**2,
            "download_cap_type",
        )
        if op == "public":
            public_url(request["url"])
        else:
            need(
                type(request["digest"]) is str
                and re.fullmatch(r"sha256:[a-f0-9]{64}", request["digest"])
                and request["kind"] in {"index", "manifest", "config", "layer"},
                "registry_shape",
            )
    need(
        request["expected_sha256"] is None
        or (
            type(request["expected_sha256"]) is str
            and re.fullmatch(r"[a-f0-9]{64}", request["expected_sha256"])
        ),
        "expected_SHA_type",
    )
    need(
        request["expected_bytes"] is None
        or (
            type(request["expected_bytes"]) is int
            and 0 <= request["expected_bytes"] <= 128 * 1024**2
        ),
        "expected_size_type",
    )
    if op == "registry":
        need(
            request["expected_sha256"] == request["digest"][7:],
            "registry_expected_digest",
        )
    if op == "xz":
        need(
            request["expected_sha256"] is not None
            and request["expected_bytes"] is not None,
            "decode_must_have_signed_binding",
        )


def main():
    global _phase, _codec_error
    _phase = "bootstrap"
    need(sys.platform == "linux" and os.geteuid() == 0, "Linux_build_worker")
    transaction = loaded("transaction.py")
    codec = loaded("oci_codec.py")
    _codec_error = getattr(codec, "CapsuleError", None)
    _phase = "request"
    request = data(transaction.read_regular(sys.argv[1], 65536))
    request_shape(request, sys.argv[1])
    until = min(request["until"], time.monotonic() + 180)
    if request["op"] == "xz":
        _phase = "decode"
        m = loaded("materials.py")
        compressed = transaction.read_regular(request["source"], 32 * 1024**2)
        need(
            digest(compressed) == request["expected_sha256"]
            and len(compressed) == request["expected_bytes"],
            "compressed_signed_binding",
        )
        raw = bytearray()
        with m.XZReader(compressed) as stream:
            while block := stream.read(65536):
                need(time.monotonic() < until, "decode_deadline")
                raw.extend(block)
                need(len(raw) <= request["raw_bytes"] <= 128 * 1024**2, "raw_cap")
        raw = bytes(raw)
        need(
            len(raw) == request["raw_bytes"] and digest(raw) == request["raw_sha256"],
            "raw_signed_binding",
        )
    else:
        _phase = "acquire"
        raw = acquire(request, until, codec)
    _phase = "write_output"
    destination = Path(request["destination"])
    need(
        destination.is_absolute() and destination.parent == Path(sys.argv[1]).parent,
        "worker_output_scope",
    )
    transaction.write_new(destination, raw)
    print(
        json.dumps(
            {
                "schema": "pamolive.expat-C-worker-result/1",
                "bytes": len(raw),
                "sha256": digest(raw),
                "state": "COMPLETE",
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        try:
            print(json.dumps(failure_packet(error, _phase)))
        except Exception:
            print('{"state":"REFUSED_OR_UNKNOWN"}')
        raise SystemExit(42) from None
