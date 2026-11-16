"""Source-only Debian archive authentication, then bounded public acquisition.

Sid is a SOURCE metadata authority only. Never add it to APT binary repositories.
"""

import email.utils
import io
import lzma
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import command, read, record, write_new
from legacy_auth import BAD, cleartext_envelope, valid_status
from policy import HERE, MATERIALS, copy_materials
from source_model import need, sha

BASE = "https://deb.debian.org/debian/dists/unstable/"
KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.pgp")


def fields(text):
    value, current = {}, None
    for line in text.splitlines():
        if line.startswith((" ", "\t")):
            need(current is not None, "control_continuation")
            value[current] += "\n" + line
        else:
            key, sep, content = line.partition(":")
            need(
                sep
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key)
                and key not in value
                and (not content or content.startswith(" ")),
                "control_fields",
            )
            value[key], current = content.removeprefix(" "), key
    return value


def checksums(text):
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        need(
            len(parts) == 3
            and re.fullmatch(r"[0-9a-f]{64}", parts[0])
            and parts[1].isdigit()
            and parts[2] not in out,
            "checksum_rows",
        )
        out[parts[2]] = (int(parts[1]), parts[0])
    return out


def release_fields(raw, now):
    value = fields(raw.decode("utf-8", "strict"))
    need(
        value.get("Origin") == "Debian"
        and value.get("Codename") == "sid"
        and value.get("Acquire-By-Hash") == "yes",
        "archive_identity",
    )
    dates = []
    for name in ("Date", "Valid-Until"):
        parsed = email.utils.parsedate_to_datetime(value.get(name, ""))
        need(parsed.tzinfo is not None, "archive_date_timezone")
        dates.append(parsed.timestamp())
    need(
        dates[0] <= now + 300
        and 0 <= now - dates[0] <= 7 * 86400
        and now < dates[1] <= dates[0] + 14 * 86400,
        "archive_freshness",
    )
    rows = checksums(value.get("SHA256", ""))
    need("main/source/Sources.xz" in rows, "archive_source_index")
    size, digest = rows["main/source/Sources.xz"]
    need(0 < size <= 32 * 1024**2, "archive_index_cap")
    return size, digest


def archive_status(raw):
    lines = raw.decode("ascii", "strict").splitlines()
    need(lines and all(line.startswith("[GNUPG:] ") for line in lines), "archive_status_frame")
    rows = [line[9:].split() for line in lines]
    need(all(row and row[0] not in BAD for row in rows), "archive_signature_bad")
    valid = [row for row in rows if row[0] == "VALIDSIG"]
    good = [row for row in rows if row[0] == "GOODSIG"]
    need(
        1 <= len(valid) <= 3
        and all(
            len(row) == 11
            and re.fullmatch(r"[0-9A-F]{40}", row[1])
            and re.fullmatch(r"[0-9A-F]{40}", row[10])
            and row[8] in {"8", "9", "10", "11"}
            for row in valid
        ),
        "archive_signature",
    )
    need(
        len(good) == len(valid) and len({row[1] for row in valid}) == len(valid),
        "archive_signature_ambiguity",
    )
    for row in valid:
        matching = [g for g in good if len(g) >= 2 and g[1] == row[1][-16:]]
        need(len(matching) == 1, "archive_good_signature")
        framed = (
            "[GNUPG:] " + " ".join(matching[0]) + "\n[GNUPG:] " + " ".join(row) + "\n"
        ).encode()
        valid_status(framed, row[10], row[1], int(time.time()))
    return [{"signer": row[1], "primary": row[10]} for row in valid]


def verify_release(folder, work):
    folder, work = Path(folder), Path(work)
    key = read(KEYRING, 8 * 1024**2)
    raw = read(folder / "InRelease", 2 * 1024**2)
    cleartext_envelope(raw)
    # GPG sees these captured buffers, not a reopened mutable acquisition path.
    captured_key = work / "archive-keyring.gpg"
    captured_release = work / "InRelease.input"
    write_new(captured_key, key, 0o444)
    write_new(captured_release, raw, 0o444)
    status = command(
        [
            "/usr/bin/gpgv",
            "--keyring",
            str(captured_key),
            "--status-fd",
            "1",
            "--output",
            str(work / "Release"),
            str(captured_release),
        ],
        work,
        work / "archive-verify",
        seconds=30,
    )
    signatures = archive_status(status)
    need(read(KEYRING, 8 * 1024**2) == key, "archive_keyring_changed")
    release = read(work / "Release", 2 * 1024**2)
    index = release_fields(release, time.time())
    return index, {
        "keyring_sha256": sha(key),
        "InRelease_sha256": sha(raw),
        "Release_sha256": sha(release),
        "signatures": signatures,
        "freshness_checked_at": int(time.time()),
        "authority": "builder Debian archive keyring; not uploader/WOT",
    }


def source_record(compressed, expected):
    need((len(compressed), sha(compressed)) == expected, "source_index_bytes")
    with lzma.LZMAFile(io.BytesIO(compressed)) as stream:
        raw = stream.read(128 * 1024**2 + 1)
    need(len(raw) <= 128 * 1024**2, "source_index_expansion")
    records = []
    for block in raw.decode("utf-8", "strict").strip().split("\n\n"):
        if not block.startswith("Package: krb5\n"):
            continue
        row = fields(block)
        if row.get("Version") == "1.22.1-3":
            records.append(row)
    need(
        len(records) == 1 and records[0].get("Directory") == "pool/main/k/krb5",
        "packaging_source_record",
    )
    rows = checksums(records[0].get("Checksums-Sha256", ""))
    for name in ("krb5_1.22.1-3.dsc", "krb5_1.22.1-3.debian.tar.xz"):
        need(rows.get(name) == MATERIALS[name], "packaging_index_pin")
    return {
        "Package": "krb5",
        "Version": "1.22.1-3",
        "Directory": "pool/main/k/krb5",
        "files": {
            name: list(MATERIALS[name])
            for name in ("krb5_1.22.1-3.dsc", "krb5_1.22.1-3.debian.tar.xz")
        },
        "index_sha256": sha(compressed),
    }


def download(url, target, cap, log):
    command(
        [
            "/usr/bin/curl",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "120",
            "--max-filesize",
            str(cap),
            "--output",
            str(target),
            url,
        ],
        target.parent,
        log,
        seconds=125,
    )
    need(0 < len(read(target, cap)) <= cap, "download_empty")


def main(target):
    target = Path(target)
    copy_materials(HERE / "materials", target)
    work = target / "acquisition"
    work.mkdir(mode=0o700)
    download(BASE + "InRelease", target / "InRelease", 2 * 1024**2, work / "fetch-release")
    expected, facts = verify_release(target, work)
    download(
        BASE + "main/source/by-hash/SHA256/" + expected[1],
        target / "Sources.xz",
        32 * 1024**2,
        work / "fetch-index",
    )
    source = source_record(read(target / "Sources.xz", 32 * 1024**2), expected)
    record(
        target / "ACQUISITION-DATA.json",
        {"archive": facts, "source": source, "payload_extracted": False},
    )


if __name__ == "__main__":
    need(len(sys.argv) == 2, "usage_new_materials")
    main(sys.argv[1])
