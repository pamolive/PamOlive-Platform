"""A1 data-only codecs. No process, network, package installation or authority."""

import gzip
import hashlib
import io
import json
import lzma
import re
import stat
import tarfile
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath

BASE = "5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
MAX_DEB = 128 * 1024**2
MAX_SPOOL = 1024**3
MAX_META = 256 * 1024**2
MAX_INDEX = 128 * 1024**2
SHA = re.compile(r"[a-f0-9]{64}\Z")
KEYRING_SHA = "506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017"
OPERATOR_REVIEW_SHA = "87745a6fbe5f36346b05b93630abfc68161aa83da1fe60008a85faa907598b5f"
MAPPING_RELEASE_REVIEW_SHA = (
    "4b758ac18854ee5f19a582bc76fe7f317b60d4d5b9e5db6875142a1e1983bee5"
)
MAPPING_EVIDENCE_SHA = (
    "a64b2b08de46193a316c68a6024dc8771a3cbd5610507e4ff473790a22360ccb"
)
TRIXIE_ARCHIVE = "04B54C3CDCA79751B16BC6B5225629DF75B188BD"
TRIXIE_STABLE = "41587F7DB8C774BCCF131416762F67A0B2C39DE4"
TRIXIE_SECURITY = "5E04A1E3223A19A20706E20F9904613D4CCE68C6"
BOOKWORM_ARCHIVE = "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8"
BOOKWORM_SECURITY = "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"
SIGNER_TO_PRIMARY = {
    "B8E5F13176D2A7A75220028078DBA3BC47EF2265": TRIXIE_ARCHIVE,
    "89C87ACEA5DD6B8E6A7068808E9F831205B4BA95": TRIXIE_SECURITY,
    "4CB50190207B4758A3F73A796ED0E7B82643E131": BOOKWORM_ARCHIVE,
    "B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8": BOOKWORM_SECURITY,
    **{
        value: value
        for value in (
            TRIXIE_ARCHIVE,
            TRIXIE_STABLE,
            TRIXIE_SECURITY,
            BOOKWORM_ARCHIVE,
            BOOKWORM_SECURITY,
        )
    },
}
SUITE_POLICY = {
    "trixie": {
        "required_any_current": [TRIXIE_ARCHIVE, TRIXIE_STABLE],
        "allowed_additional": [BOOKWORM_ARCHIVE],
        "max_age_days": 90,
        "valid_until_required": False,
    },
    "trixie-updates": {
        "required_any_current": [TRIXIE_ARCHIVE],
        "allowed_additional": [BOOKWORM_ARCHIVE],
        "max_age_days": 7,
        "valid_until_required": True,
    },
    "trixie-security": {
        "required_any_current": [TRIXIE_SECURITY],
        "allowed_additional": [BOOKWORM_SECURITY],
        "max_age_days": 7,
        "valid_until_required": True,
    },
}


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def signer_policy(value):
    need(
        set(value)
        == {
            "schema",
            "s0_keyring_sha256",
            "operator_review_sha256",
            "mapping_evidence_sha256",
            "mapping_release_review_sha256",
            "signer_to_primary",
            "suites",
            "state",
            "build_verified",
            "attestation_verified",
        },
        "signer_policy_fields",
    )
    need(
        value["schema"] == "pamolive.apt-a1-signer-policy-candidate.v1"
        and value["state"] == "CANDIDATE_NOT_AUTHORITY"
        and value["build_verified"] is False
        and value["attestation_verified"] is False
        and value["s0_keyring_sha256"] == KEYRING_SHA
        and value["operator_review_sha256"] == OPERATOR_REVIEW_SHA
        and value["mapping_evidence_sha256"] == MAPPING_EVIDENCE_SHA
        and value["mapping_release_review_sha256"] == MAPPING_RELEASE_REVIEW_SHA
        and canonical(value["signer_to_primary"]) == canonical(SIGNER_TO_PRIMARY)
        and canonical(value["suites"]) == canonical(SUITE_POLICY),
        "signer_policy_candidate_scope",
    )
    return value


def signature_scope(policy, suite, signers):
    signer_policy(policy)
    need(suite in SUITE_POLICY and signers, "signature_suite_or_missing_signers")
    need(
        all(s in policy["signer_to_primary"] for s in signers),
        "signature_unknown_signer",
    )
    primaries = {policy["signer_to_primary"][s] for s in signers}
    rule = policy["suites"][suite]
    current = set(rule["required_any_current"])
    need(
        primaries & current and primaries <= current | set(rule["allowed_additional"]),
        "signature_current_authority_or_suite",
    )
    return sorted(primaries)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def json_data(raw):
    need(len(raw) <= 16 * 1024**2, "json_budget")
    try:

        def constant(_):
            raise Refusal("invalid_json_constant")

        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        stack, count = [(value, 0)], 0
        while stack:
            item, depth = stack.pop()
            count += 1
            need(count <= 2000000 and depth <= 24, "json_shape")
            if isinstance(item, dict):
                stack.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                stack.extend((v, depth + 1) for v in item)
            elif isinstance(item, str):
                need(len(item) <= 16384 and "\0" not in item, "json_string")
        return value
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise Refusal("invalid_json") from exc


def relative(name):
    need(
        type(name) is str
        and 0 < len(name) <= 512
        and "\\" not in name
        and "\0" not in name,
        "path",
    )
    need(
        not name.startswith("/")
        and all(p not in ("", ".", "..") for p in name.split("/")),
        "path",
    )
    return name


def tar_name(name):
    if name in ("", ".", "./"):
        return ""
    while name.startswith("./"):
        name = name[2:]
    return relative(name.rstrip("/")) if name.rstrip("/") else ""


def controls(lines, *, maximum=MAX_INDEX, comments=False, max_line=65536):
    """Stream deb822, retain one stanza only. Duplicate fields are never repaired."""
    need(
        type(max_line) is int and max_line in (65536, 128 * 1024), "control_line_limit"
    )
    current, key, used, stanza = {}, None, 0, 0
    for raw in lines:
        need(type(raw) is bytes or type(raw) is str, "control_line_type")
        need(len(raw) <= max_line, "control_budget")
        raw_size = len(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
        used += raw_size
        need(used <= maximum and raw_size <= max_line, "control_budget")
        line = (
            raw.decode("utf-8").rstrip("\r\n")
            if isinstance(raw, bytes)
            else raw.rstrip("\r\n")
        )
        if comments and line.startswith("#"):
            continue
        if not line:
            if current:
                yield current
            current, key, stanza = {}, None, 0
            continue
        stanza += raw_size
        need(stanza <= 1024**2, "control_stanza_budget")
        if line[0] in " \t":
            need(key is not None, "control_continuation")
            current[key] += "\n" + line[1:]
        else:
            key, sep, value = line.partition(":")
            need(
                sep and re.fullmatch(r"[A-Za-z0-9-]+", key) and key not in current,
                "control_field",
            )
            current[key] = value.lstrip(" ")
    if current:
        yield current


def one_control(raw):
    values = list(controls(io.BytesIO(raw), maximum=1024**2))
    need(len(values) == 1, "control_count")
    return values[0]


def release(raw, *, codename, max_age_days, now=None, valid_until_required=None):
    value = one_control(raw)
    need(
        value.get("Origin") == "Debian" and value.get("Codename") == codename,
        "release_identity",
    )
    now = now or datetime.now(UTC)
    issued = parsedate_to_datetime(value["Date"])
    need(
        issued.tzinfo is not None
        and 0 <= (now - issued).total_seconds() <= max_age_days * 86400,
        "release_date",
    )
    if "Valid-Until" in value:
        expiry = parsedate_to_datetime(value["Valid-Until"])
        need(
            expiry.tzinfo is not None and issued < expiry and now < expiry,
            "release_expired",
        )
    else:
        need(
            codename == "trixie" and valid_until_required is not True,
            "release_expiry_missing",
        )
    checks = {}
    for line in value.get("SHA256", "").splitlines():
        row = line.split()
        if not row:
            continue
        need(
            len(row) == 3 and SHA.fullmatch(row[0]) and row[1].isdigit(),
            "release_checksum",
        )
        relative(row[2])
        need(row[2] not in checks, "release_duplicate_checksum")
        checks[row[2]] = {"sha256": row[0], "size": int(row[1])}
    need(checks, "release_checksums_missing")
    return checks


def source_identity(fields):
    value = fields.get("Source", fields["Package"])
    match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([^\s()]+)\))?", value)
    need(match is not None, "source_identity")
    return match[1], match[2] or fields["Version"]


def package_identity(fields):
    need(
        re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", fields.get("Package", "")), "package_name"
    )
    need(
        re.fullmatch(r"[0-9A-Za-z.+:~_-]+", fields.get("Version", "")),
        "package_version",
    )
    need(fields.get("Architecture") in ("amd64", "all"), "package_arch")
    return fields["Package"], fields["Version"], fields["Architecture"]


class LimitedTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buf, encoding, errors):
        return cls._frombuf(buf, encoding, errors)

    @classmethod
    def _frombuf(cls, buf, encoding, errors, **kwargs):
        parent = super()
        item = (
            parent._frombuf(buf, encoding, errors, **kwargs)
            if hasattr(parent, "_frombuf")
            else parent.frombuf(buf, encoding, errors)
        )
        need(item.type != tarfile.GNUTYPE_SPARSE, "sparse_unsupported")
        if item.type in {
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
            tarfile.SOLARIS_XHDTYPE,
        }:
            need(0 <= item.size <= 8192, "extended_metadata_budget")
        return item

    def _unsupported_sparse(self, *args, **kwargs):
        raise Refusal("sparse_unsupported")

    _proc_gnusparse_00 = _unsupported_sparse
    _proc_gnusparse_01 = _unsupported_sparse
    _proc_gnusparse_10 = _unsupported_sparse

    def _apply_pax_info(self, headers, *args, **kwargs):
        need(
            not any(
                key.startswith("GNU.sparse") or key == "SCHILY.realsize"
                for key in headers
            )
            and headers.get("SCHILY.filetype") != "sparse",
            "sparse_unsupported",
        )
        return super()._apply_pax_info(headers, *args, **kwargs)

    def _proc_pax(self, tarfile):
        need(self.size <= 8192, "pax_budget")
        return super()._proc_pax(tarfile)

    def _proc_gnulong(self, tarfile):
        need(self.size <= 8192, "gnu_name_budget")
        return super()._proc_gnulong(tarfile)


class PhysicalReader:
    """Count all expanded bytes, including TAR headers, padding and trailer."""

    def __init__(self, source, maximum):
        self.source, self.maximum, self.used = source, maximum, 0

    def read(self, size):
        need(type(size) is int and 0 <= size <= 1024**2, "raw_read_size")
        raw = self.source.read(min(size, self.maximum - self.used + 1))
        self.used += len(raw)
        need(self.used <= self.maximum, "tar_physical_budget")
        return raw

    def drain(self):
        while self.read(65536):
            pass


def tar_map(stream, *, limit=512 * 1024**2):
    files, deletions, opaque, total = {}, set(), set(), 0
    stream = PhysicalReader(stream, limit)
    with tarfile.open(fileobj=stream, mode="r|", tarinfo=LimitedTarInfo) as archive:
        for count, item in enumerate(archive):
            need(count < 100000 and 0 <= item.size <= MAX_DEB, "tar_budget")
            total += item.size
            need(total <= limit, "tar_budget")
            name = tar_name(item.name)
            if not name:
                need(item.isdir(), "tar_root_type")
                continue
            if PurePosixPath(name).name == ".wh..wh..opq":
                parent = str(PurePosixPath(name).parent)
                opaque.add("" if parent == "." else parent)
                continue
            if PurePosixPath(name).name.startswith(".wh."):
                deletions.add(
                    str(PurePosixPath(name).with_name(PurePosixPath(name).name[4:]))
                )
                continue
            need(name not in files, "tar_duplicate")
            row = {"mode": item.mode, "uid": item.uid, "gid": item.gid}
            if item.isfile():
                reader, h, used = archive.extractfile(item), hashlib.sha256(), 0
                while block := reader.read(65536):
                    used += len(block)
                    need(used <= item.size, "tar_file_budget")
                    h.update(block)
                need(used == item.size, "tar_truncated")
                row.update(type="file", sha256=h.hexdigest(), size=used)
            elif item.isdir():
                row["type"] = "dir"
            elif item.issym() or item.islnk():
                need(
                    0 < len(item.linkname) <= 512
                    and "\0" not in item.linkname
                    and "\\" not in item.linkname,
                    "tar_link",
                )
                row.update(
                    type="symlink" if item.issym() else "hardlink", target=item.linkname
                )
            else:
                raise Refusal("tar_special_type")
            files[name] = row
    stream.drain()
    return files, deletions, opaque


def overlay(previous, current, deletions=(), opaque=()):
    result = dict(previous)
    ancestors = {
        str(parent)
        for name in result
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    for path in list(result):
        if any(path == p or path.startswith(p + "/") for p in deletions) or any(
            not p or path.startswith(p + "/") for p in opaque
        ):
            del result[path]
    # Non-directory replacement removes all lower descendants.
    for path, item in current.items():
        if item["type"] != "dir" and path in ancestors:
            for old in list(result):
                if old.startswith(path + "/"):
                    del result[old]
    result.update(current)
    for path, item in list(result.items()):
        if item["type"] == "hardlink":
            target = resolve(result, item["target"])
            need(target["type"] == "file", "hardlink_target")
            result[path] = {
                **item,
                "type": "file",
                "sha256": target["sha256"],
                "size": target["size"],
            }
    return result


def resolve(files, path, *, with_path=False):
    parts = path.lstrip("/").split("/")
    for _ in range(40):
        normalized = []
        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                need(normalized, "link_escape")
                normalized.pop()
            else:
                normalized.append(part)
        parts = normalized
        for i in range(1, len(parts) + 1):
            key = "/".join(parts[:i])
            item = files.get(key)
            need(item is not None, "base_path_missing")
            if item["type"] in ("symlink", "hardlink"):
                target = item["target"]
                parts = (
                    (
                        []
                        if target.startswith("/") or item["type"] == "hardlink"
                        else parts[: i - 1]
                    )
                    + target.lstrip("/").split("/")
                    + parts[i:]
                )
                break
        else:
            key = "/".join(parts)
            return ("/" + key, files[key]) if with_path else files[key]
    raise Refusal("link_cycle")


def blob(layout, descriptor, *, maximum=MAX_SPOOL):
    digest = descriptor.get("digest", "")
    need(
        re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
        and type(descriptor.get("size")) is int,
        "oci_descriptor",
    )
    path = Path(layout) / "blobs/sha256" / digest[7:]
    need(
        stat.S_ISREG(path.lstat().st_mode)
        and path.lstat().st_nlink == 1
        and not (getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
        and 0 < path.stat().st_size == descriptor["size"] <= maximum,
        "oci_blob_size",
    )
    h = hashlib.sha256()
    with path.open("rb") as f:
        while data := f.read(65536):
            h.update(data)
    need(h.hexdigest() == digest[7:], "oci_blob_digest")
    return path


def base_inventory(layout):
    layout = Path(layout).absolute()
    for path in (layout, layout / "blobs", layout / "blobs/sha256"):
        need(
            stat.S_ISDIR(path.lstat().st_mode)
            and not (getattr(path.lstat(), "st_file_attributes", 0) & 0x400),
            "base_directory_alias",
        )
    root = Path(layout) / "blobs/sha256" / BASE
    need(
        stat.S_ISREG(root.lstat().st_mode)
        and root.lstat().st_nlink == 1
        and not (getattr(root.lstat(), "st_file_attributes", 0) & 0x400)
        and root.stat().st_size <= 1024**2,
        "base_root_blob_missing",
    )
    raw = root.read_bytes()
    need(sha(raw) == BASE, "base_index_digest")
    index = json_data(raw)
    if "manifests" in index:
        choices = [
            d
            for d in index["manifests"]
            if d.get("platform", {}).get("os") == "linux"
            and d["platform"].get("architecture") == "amd64"
            and not d["platform"].get("variant")
        ]
        need(len(choices) == 1, "base_platform_selection")
        manifest_path = blob(layout, choices[0], maximum=1024**2)
        manifest_digest = choices[0]["digest"]
        manifest = json_data(manifest_path.read_bytes())
    else:
        manifest, manifest_digest = index, "sha256:" + BASE
    config_path = blob(layout, manifest["config"], maximum=1024**2)
    config = json_data(config_path.read_bytes())
    need(
        config.get("os") == "linux"
        and config.get("architecture") == "amd64"
        and config.get("rootfs", {}).get("type") == "layers",
        "base_configuration",
    )
    layers, diff_ids = manifest["layers"], config["rootfs"]["diff_ids"]
    need(0 < len(layers) == len(diff_ids) <= 32, "base_layer_count")
    need(
        len({row["digest"] for row in layers}) == len(layers)
        and len(set(diff_ids)) == len(diff_ids),
        "base_duplicate_layer",
    )
    expected_blobs = {BASE, manifest_digest[7:], manifest["config"]["digest"][7:]} | {
        r["digest"][7:] for r in layers
    }
    need(
        {p.name for p in (layout / "blobs/sha256").iterdir()} == expected_blobs,
        "base_blob_set",
    )
    need(
        sum((layout / "blobs/sha256" / name).stat().st_size for name in expected_blobs)
        <= 256 * 1024**2,
        "base_compressed_total",
    )
    files, total = {}, 0
    for descriptor, expected in zip(layers, diff_ids, strict=True):
        path = blob(layout, descriptor, maximum=64 * 1024**2)
        compressed = descriptor["mediaType"].endswith(("+gzip", ".gzip"))
        need(
            compressed or descriptor["mediaType"].endswith("layer.v1.tar"),
            "base_layer_compression",
        )
        h, expanded = hashlib.sha256(), 0
        with gzip.open(path, "rb") if compressed else path.open("rb") as f:
            while data := f.read(65536):
                expanded += len(data)
                total += len(data)
                need(
                    expanded <= 512 * 1024**2 and total <= 1024**3,
                    "base_layer_expansion",
                )
                h.update(data)
        need("sha256:" + h.hexdigest() == expected, "base_diff_id")
        with gzip.open(path, "rb") if compressed else path.open("rb") as f:
            rows, deleted, opaque = tar_map(f)
            files = overlay(files, rows, deleted, opaque)
        blob(layout, descriptor, maximum=64 * 1024**2)
    return {
        "root_digest": "sha256:" + BASE,
        "root_kind": "index" if "manifests" in index else "manifest",
        "linux_manifest_digest": manifest_digest,
        "config_digest": manifest["config"]["digest"],
        "layers": layers,
        "diff_ids": diff_ids,
        "files": files,
    }


def ar_members(raw):
    need(raw.startswith(b"!<arch>\n") and len(raw) <= MAX_DEB, "deb_ar")
    offset, members = 8, {}
    while offset < len(raw):
        need(offset + 60 <= len(raw), "deb_header")
        header = raw[offset : offset + 60]
        need(header[58:] == b"`\n", "deb_header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        need(
            name not in members
            and name
            in {
                "debian-binary",
                "control.tar.xz",
                "control.tar.gz",
                "control.tar",
                "data.tar.xz",
                "data.tar.gz",
                "data.tar",
            },
            "deb_member",
        )
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as exc:
            raise Refusal("deb_size") from exc
        need(0 <= size <= MAX_DEB and offset + 60 + size <= len(raw), "deb_size")
        members[name] = raw[offset + 60 : offset + 60 + size]
        offset += 60 + size + size % 2
    need(
        offset == len(raw)
        and members.get("debian-binary") == b"2.0\n"
        and len(members) == 3,
        "deb_members",
    )
    return members


class XZReader(io.RawIOBase):
    """One XZ stream, bounded decoder dictionary and bounded returned chunks."""

    def __init__(self, data):
        super().__init__()
        self.source = io.BytesIO(data)
        self.decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_XZ, memlimit=64 * 1024**2
        )
        self.finished = False

    def read(self, size):
        need(type(size) is int and 0 <= size <= 1024**2, "xz_read_size")
        result = bytearray()
        while len(result) < size and not self.finished:
            if self.decoder.eof:
                need(
                    not self.decoder.unused_data and not self.source.read(1),
                    "xz_trailing",
                )
                self.finished = True
                break
            block = self.source.read(65536) if self.decoder.needs_input else b""
            need(block or not self.decoder.needs_input, "xz_truncated")
            try:
                result.extend(
                    self.decoder.decompress(block, max_length=size - len(result))
                )
            except lzma.LZMAError as exc:
                raise Refusal("xz_invalid_or_memory") from exc
        return bytes(result)


def decompressor(name, data):
    if name.endswith(".xz"):
        return XZReader(data)
    if name.endswith(".gz"):
        return gzip.GzipFile(fileobj=io.BytesIO(data))
    return io.BytesIO(data)


def deb(raw, *, payload=False):
    members = ar_members(raw)
    control = [n for n in members if n.startswith("control.tar")]
    data = [n for n in members if n.startswith("data.tar")]
    need(len(control) == len(data) == 1, "deb_sections")
    with decompressor(control[0], members[control[0]]) as f:
        physical = PhysicalReader(f, 8 * 1024**2)
        with tarfile.open(
            fileobj=physical, mode="r|", tarinfo=LimitedTarInfo
        ) as archive:
            found, seen, total = None, set(), 0
            for count, entry in enumerate(archive):
                need(count <= 256 and entry.size <= 1024**2, "deb_control_budget")
                name = tar_name(entry.name)
                need(name not in seen, "deb_control_duplicate")
                seen.add(name)
                total += entry.size
                need(
                    total <= 4 * 1024**2 and (entry.isfile() or entry.isdir()),
                    "deb_control_type",
                )
                if name == "control":
                    need(entry.isfile(), "deb_control_type")
                    found = one_control(archive.extractfile(entry).read(entry.size + 1))
            need(found is not None, "deb_control_missing")
        physical.drain()
    package_identity(found)
    if payload:
        with decompressor(data[0], members[data[0]]) as f:
            rows, deleted, opaque = tar_map(f)
        need(not deleted and not opaque, "deb_whiteout")
        return found, rows
    return found
