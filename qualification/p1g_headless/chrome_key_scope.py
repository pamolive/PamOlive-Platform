"""Finite public OpenPGP DATA framing/lineage, never a cryptographic verifier."""

import base64
import hashlib
import re
import time

PURPOSE = "google-release-selected-signer-certificate-v1"
PRIMARY = "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796"
SIGNER = "0E225917414670F4442C250DFD533C07C264648F"
ORIGINAL_SHA256 = "54dea5f6c2a26091578cf52a999cebc6b64df478d37ad4dce96376b711e3b27c"
KEY_BODY_SHA256 = {
    PRIMARY: "289fd1f014eac83413f99be9ee2e5f8fd6f7d52068b2b26022211a1a1278ca9e",
    SIGNER: "d11cad7f10562996c9a3195cb9b8141c0c62d8b6be6ee671b72fdca7d5b42e89",
}
LIMIT = 65536
MAX_PACKETS = 256


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def crc24(raw):
    value = 0xB704CE
    for byte in raw:
        value ^= byte << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return (value & 0xFFFFFF).to_bytes(3, "big")


def binary(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT, "scope_bytes")
    if not raw.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"):
        return raw
    lines = raw.decode("ascii", "strict").splitlines()
    need(lines[0] == "-----BEGIN PGP PUBLIC KEY BLOCK-----", "scope_armor")
    need(lines[-1] == "-----END PGP PUBLIC KEY BLOCK-----", "scope_armor")
    i = 1
    while i < len(lines) - 1 and lines[i]:
        need(re.fullmatch(r"(?:Version|Comment): [\x20-\x7e]{0,1024}", lines[i]), "scope_armor")
        i += 1
    need(i < len(lines) - 2 and lines[i] == "", "scope_armor")
    data = lines[i + 1 : -1]
    checksum = None
    if data and data[-1].startswith("="):
        need(len(data[-1]) == 5, "scope_armor_crc")
        checksum = base64.b64decode(data.pop()[1:], validate=True)
    need(data and all(re.fullmatch(r"[A-Za-z0-9+/=]{1,76}", s) for s in data), "scope_armor")
    decoded = base64.b64decode("".join(data), validate=True)
    need(checksum is None or checksum == crc24(decoded), "scope_armor_crc")
    need(0 < len(decoded) <= LIMIT, "scope_bytes")
    return decoded


def packets(raw):
    """Only finite-length v4 public certificates. Tags/bodies stay ordered."""
    raw = binary(raw)
    out, at = [], 0
    while at < len(raw):
        need(len(out) < MAX_PACKETS, "scope_packet_budget")
        start = at
        first = raw[at]
        at += 1
        need(first & 128, "scope_packet_header")
        if first & 64:
            tag = first & 63
            need(at < len(raw), "scope_packet_length")
            size = raw[at]
            at += 1
            if 192 <= size < 224:
                need(at < len(raw), "scope_packet_length")
                size = ((size - 192) << 8) + raw[at] + 192
                at += 1
            elif size == 255:
                need(at + 4 <= len(raw), "scope_packet_length")
                size = int.from_bytes(raw[at : at + 4], "big")
                at += 4
            else:
                need(size < 192, "scope_partial_length")
        else:
            tag, kind = (first >> 2) & 15, first & 3
            need(kind != 3, "scope_indeterminate_length")
            width = (1, 2, 4)[kind]
            need(at + width <= len(raw), "scope_packet_length")
            size = int.from_bytes(raw[at : at + width], "big")
            at += width
        need(tag in {2, 6, 13, 14, 17}, "scope_secret_or_unknown_tag")
        need(0 < size <= 16384 and at + size <= len(raw), "scope_packet_size")
        body = raw[at : at + size]
        at += size
        if tag in {6, 14}:
            need(len(body) >= 8 and body[0] == 4 and body[5] == 1, "scope_v4_RSA_key")
        if tag == 2:
            need(len(body) >= 10 and body[0] == 4, "scope_v4_signature")
            hashed = int.from_bytes(body[4:6], "big")
            need(6 + hashed + 2 <= len(body), "scope_signature_lengths")
            unhashed = int.from_bytes(body[6 + hashed : 8 + hashed], "big")
            need(8 + hashed + unhashed + 2 <= len(body), "scope_signature_lengths")
        out.append((tag, body, raw[start:at]))
    need(out and out[0][0] == 6, "scope_primary_first")
    return out


def fingerprint(body):
    need(type(body) is bytes and 0 < len(body) <= 65535 and body[0] == 4, "scope_v4_fingerprint")
    # Public DATA identifier only; GPG, not SHA1 framing, establishes authenticity.
    return (
        hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body, usedforsecurity=False)
        .hexdigest()
        .upper()
    )


def blocks(raw):
    rows = packets(raw)
    primary, subkeys, current = [], {}, None
    for tag, body, encoded in rows:
        if tag == 6:
            need(not primary, "scope_multiple_primaries")
        if tag == 14:
            key = fingerprint(body)
            need(key not in subkeys, "scope_duplicate_subkey")
            subkeys[key] = []
            current = subkeys[key]
        if current is None:
            need(tag != 14, "scope_packet_order")
            if tag == 2:
                need(
                    body[1] in {0x10, 0x11, 0x12, 0x13, 0x1F, 0x20, 0x30},
                    "scope_primary_signature_type",
                )
            primary.append((tag, body, encoded))
        else:
            need(tag in {14, 2}, "scope_packet_order")
            if tag == 2:
                need(body[1] in {0x18, 0x19, 0x28}, "scope_subkey_signature_type")
            current.append((tag, body, encoded))
    need(len([r for r in primary if r[0] == 6]) == 1, "scope_multiple_primaries")
    return fingerprint(primary[0][1]), primary, subkeys


def lineage(original, scoped):
    need(sha(original) == ORIGINAL_SHA256, "scope_original_pin")
    p, primary, subs = blocks(original)
    q, exported_primary, exported_subs = blocks(scoped)
    need(
        p == q == PRIMARY and SIGNER in subs and set(exported_subs) == {SIGNER}, "scope_exact_keys"
    )
    for key, body in ((PRIMARY, primary[0][1]), (SIGNER, subs[SIGNER][0][1])):
        need(sha(body) == KEY_BODY_SHA256[key], "scope_key_body_pin")

    def content(rows):
        return [(tag, body) for tag, body, _ in rows]

    need(content(primary) == content(exported_primary), "scope_primary_block_changed")
    need(content(subs[SIGNER]) == content(exported_subs[SIGNER]), "scope_signer_block_changed")
    return {
        "purpose": PURPOSE,
        "original_sha256": sha(original),
        "scoped_sha256": sha(scoped),
        "exact_keyset": True,
        "signed_blocks_preserved": True,
        "crypto_verified": False,
    }


def options(home):
    return [
        "/usr/bin/gpg",
        "--no-options",
        "--homedir",
        str(home),
        "--batch",
        "--no-tty",
        "--no-autostart",
        "--no-auto-key-retrieve",
        "--no-auto-key-import",
        "--auto-key-locate",
        "clear",
        "--no-auto-check-trustdb",
        "--require-cross-certification",
    ]


def authenticate(commands, support, staged, private, gpg, original, *, diagnostic_sink=None):
    """Six H1 commands, fixed existing authority, no failed-original-verify catch."""
    need(
        type(original) is bytes and len(original) <= LIMIT and sha(original) == ORIGINAL_SHA256,
        "scope_original_pin",
    )
    home = private / "gnupg-original"
    home.mkdir(mode=0o700)
    base = options(home)
    commands.run(base + ["--import", str(staged / "google-key.asc")], seconds=10)
    listed = commands.run(
        base
        + [
            "--with-colons",
            "--fixed-list-mode",
            "--fingerprint",
            "--with-subkey-fingerprint",
            "--list-keys",
        ],
        seconds=10,
        cap=16384,
    )
    keys = gpg.one_primary(listed, PRIMARY)
    now = int(time.time())
    gpg.signing_capability(keys, PRIMARY, SIGNER, now)
    p, _, subs = blocks(original)
    need(p == PRIMARY and set(keys) == {PRIMARY, *subs}, "scope_original_keyset")
    exported = commands.run(
        base + ["--export-filter", "drop-subkey=fpr <> " + SIGNER, "--export", PRIMARY],
        seconds=10,
        cap=LIMIT,
    )
    proof = lineage(original, exported)
    selected = private / "selected-public-certificate.gpg"
    support.fresh_write(selected, exported, mode=0o400)
    scoped_home = private / "gnupg-scoped"
    scoped_home.mkdir(mode=0o700)
    verify = options(scoped_home)
    commands.run(verify + ["--import", str(selected)], seconds=10)
    narrowed = commands.run(
        verify
        + [
            "--with-colons",
            "--fixed-list-mode",
            "--fingerprint",
            "--with-subkey-fingerprint",
            "--list-keys",
        ],
        seconds=10,
        cap=16384,
    )
    selected_keys = gpg.one_primary(narrowed, PRIMARY)
    need(set(selected_keys) == {PRIMARY, SIGNER}, "scope_exact_keys")
    need(
        all(selected_keys[k] == keys[k] for k in (PRIMARY, SIGNER)), "scope_selected_state_changed"
    )
    status = commands.run(
        verify
        + ["--status-fd", "1", "--verify", str(staged / "Release.gpg"), str(staged / "Release")],
        seconds=10,
        cap=16384,
    )
    now = int(time.time())
    if diagnostic_sink is not None:
        diagnostic_sink(status, narrowed, now)
    valid = gpg.valid_status(status, PRIMARY, SIGNER, now)
    for keyset in (keys, selected_keys):
        gpg.signing_capability(keyset, PRIMARY, SIGNER, now, valid["timestamp"])
    proof.update(crypto_verified=True, signature=valid, selected_states_identical=True)
    return valid, proof, status, narrowed
