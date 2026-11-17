"""Verify three distinct publishers in NEW key homes; never use a real keyring."""

import json
import re
import sys
import time
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    ENV,
    check_materials,
    command,
    material,
    material_rows,
    need,
    read,
    record,
    sha,
    write_new,
)

ROOT_BOOTSTRAP_SHA256 = "f1b8959301fcbdc59e52a2064d86efd654af7db4cac6fb327eeb0ce1830c9e29"
Authority = namedtuple(
    "Authority", "purpose key primary signer signature data bundle_sha256 bundle_bytes"
)
AUTHORITIES = (
    Authority(
        "debian",
        "debian-expat-maintainer.asc",
        "A0DF7E0D3851E0EE45C00BC8ACE1F33CB933BBBB",
        "7D887DC8BA7BBBA7B835E3BADCE310E7864CC8BF",
        "expat-2.10.0-1.dsc",
        None,
        "40adb6ae82d9961eda53ff4620530747632abbb7686fa8c206005e9ef021bb92",
        21416,
    ),
    Authority(
        "expat",
        "expat-maintainer.asc",
        "3176EF7DB2367F1FCA4F306B1F9B0E909AF37285",
        "CB8DE70A90CFBF6C3BF5CC5696262ACFFBD3AEC6",
        "expat-2.10.0.tar.gz.asc",
        "expat-2.10.0.tar.gz",
        "94ecb6d2dce61f22935c1352552ab3d75599c2ef4ff5e42d4ae0724c32431898",
        5413,
    ),
    Authority(
        "python",
        "python-release-manager.asc",
        "7169605F62C751356D054A26A821E680E5FA6305",
        "7169605F62C751356D054A26A821E680E5FA6305",
        "Python-3.12.16.tar.xz.asc",
        "Python-3.12.16.tar.xz",
        "1de2bbd31e2dd10aab4098c3ab2f937c530d924ddbfa2dd091f0c7cfb2ee182a",
        12310,
    ),
)
SCOPES = {
    "debian": ("debian-expat-maintainer.asc", "expat-2.10.0-1.dsc", None),
    "expat": ("expat-maintainer.asc", "expat-2.10.0.tar.gz.asc", "expat-2.10.0.tar.gz"),
    "python": ("python-release-manager.asc", "Python-3.12.16.tar.xz.asc", "Python-3.12.16.tar.xz"),
}
BAD = {
    "BADSIG",
    "ERRSIG",
    "EXPSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "NO_PUBKEY",
    "NODATA",
    "FAILURE",
    "ERROR",
    "KEYEXPIRED",
    "SIGEXPIRED",
    "KEYREVOKED",
    "BADARMOR",
}


def cleartext_envelope(raw):
    # Debian still lists CVE-2025-68972 for gpg: refuse its form-feed precondition.
    # This is an input shape guard, not an implementation of OpenPGP canonicalisation.
    need(
        raw.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n") and b"\x0c" not in raw,
        "cleartext_envelope",
    )
    need(
        raw.count(b"-----BEGIN PGP SIGNATURE-----")
        == raw.count(b"-----END PGP SIGNATURE-----")
        == 1,
        "cleartext_signature_count",
    )
    need(raw.rstrip().endswith(b"-----END PGP SIGNATURE-----"), "cleartext_trailing_data")


def validate_authorities(authorities, decision):
    """Finite purposes, bound to the separately Root-approved exact decision."""
    need(
        decision.get("schema") == "pamolive.Root.expat4.vendor-key-bootstrap-decision/1",
        "bootstrap_schema",
    )
    entries = decision.get("entries", [])
    need(len(authorities) == len(entries) == 3, "authority_count")
    need({a.purpose for a in authorities} == set(SCOPES), "authority_purposes")
    need({e["purpose"] for e in entries} == set(SCOPES), "bootstrap_purposes")
    used = set()
    for authority in authorities:
        need(
            (authority.key, authority.signature, authority.data) == SCOPES[authority.purpose],
            "authority_scope",
        )
        need(
            all(re.fullmatch(r"[0-9A-F]{40}", f) for f in (authority.primary, authority.signer)),
            "authority_fingerprint",
        )
        identities = {authority.primary, authority.signer}
        need(not (used & identities), "authority_overlap")
        used.update(identities)
        approved = next(e for e in entries if e["purpose"] == authority.purpose)
        need(
            (authority.primary, authority.signer, authority.bundle_sha256, authority.bundle_bytes)
            == (
                approved["primary_fingerprint"],
                approved["artifact_signer_fingerprint"],
                approved["bundle_sha256"],
                approved["bundle_bytes"],
            ),
            "authority_Root_pin",
        )
    return authorities


def approved_authorities():
    raw = read(Path(__file__).resolve().parent / "Root-bootstrap-decision.json", 32768)
    need(sha(raw) == ROOT_BOOTSTRAP_SHA256, "Root_bootstrap_bytes")
    return validate_authorities(AUTHORITIES, json.loads(raw))


def valid_status(raw, primary, signer, now):
    need(
        all(re.fullmatch(r"[0-9A-F]{40}", f) for f in (primary, signer)),
        "expected_signature_fields",
    )
    lines = raw.decode("ascii", "strict").splitlines()
    need(lines and all(line.startswith("[GNUPG:] ") for line in lines), "status_framing")
    rows = [line[9:].split() for line in lines]
    need(all(row and row[0] not in BAD for row in rows), "status_bad")
    valid = [r for r in rows if r[0] == "VALIDSIG"]
    good = [r for r in rows if r[0] == "GOODSIG"]
    need(len(valid) == len(good) == 1, "signature_ambiguity")
    r = valid[0]
    need(len(r) == 11 and re.fullmatch(r"[0-9A-F]{40}", r[1]), "signature_fields")
    need(
        r[10] == primary and r[1] == signer and good[0][1] == signer[-16:],
        "signature_authority",
    )
    need(r[3].isdigit() and int(r[3]) <= now + 300, "signature_future")
    need(r[4] == "0" or r[4].isdigit() and int(r[4]) > now, "signature_expired")
    need(r[8] in {"8", "9", "10", "11"}, "signature_hash")
    return {"primary": primary, "signing_key": r[1], "timestamp": int(r[3])}


def one_primary(raw, expected):
    rows = [r.split(":") for r in raw.decode("utf-8", "strict").splitlines()]
    pubs = [i for i, r in enumerate(rows) if r[0] == "pub"]
    need(len(pubs) == 1, "key_bundle_ambiguity")
    i = pubs[0]
    need(rows[i][1] not in {"r", "e", "d", "i"}, "key_unusable")
    following = rows[i + 1]
    need(following[0] == "fpr" and following[9] == expected, "key_primary")
    keys = {}
    for i, row in enumerate(rows):
        if row[0] not in {"pub", "sub"}:
            continue
        need(len(row) >= 12 and i + 1 < len(rows), "key_fields")
        fingerprint = rows[i + 1]
        need(
            fingerprint[0] == "fpr" and re.fullmatch(r"[0-9A-F]{40}", fingerprint[9]),
            "key_fingerprint",
        )
        need(fingerprint[9] not in keys, "key_duplicate")
        keys[fingerprint[9]] = {
            "validity": row[1],
            "created": row[5],
            "expires": row[6],
            "caps": row[11],
        }
    return keys


def signing_capability(keys, primary, signer, now, signature_time=None):
    need(primary in keys and signer in keys, "signer_not_in_purpose_certificate")
    for fingerprint in {primary, signer}:
        row = keys[fingerprint]
        need(row["validity"] not in {"r", "e", "d", "i"} and "D" not in row["caps"], "key_unusable")
        need(row["created"].isdigit() and int(row["created"]) <= now + 300, "key_future")
        expiry = row["expires"]
        need(expiry in {"", "0"} or expiry.isdigit() and int(expiry) > now, "key_expired")
        if signature_time is not None:
            need(int(row["created"]) <= signature_time, "signature_before_key")
            need(expiry in {"", "0"} or int(expiry) > signature_time, "signature_after_key_expiry")
    need("s" in keys[signer]["caps"], "signing_capability_missing")


def main(materials, work):
    authorities = approved_authorities()
    materials, work = Path(materials).resolve(), Path(work).resolve()
    check_materials(materials)
    work.mkdir(mode=0o700)
    staged = work / "inputs"
    staged.mkdir(mode=0o700)
    for row in material_rows():
        write_new(staged / row["name"], material(materials, row["name"]))
    materials = staged
    cleartext_envelope(material(materials, "expat-2.10.0-1.dsc"))
    evidence = []
    for authority in authorities:
        name, key, primary, signer, signature, data, key_sha, key_bytes = authority
        raw_key = material(materials, key)
        need(len(raw_key) == key_bytes and sha(raw_key) == key_sha, "purpose_bundle_bytes")
        home = work / (name + "-home")
        home.mkdir(mode=0o700)
        env = ENV | {"GNUPGHOME": str(home)}
        base = [
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
        command(
            base + ["--import", str(materials / key)], work, work / (name + "-import"),
            seconds=30, env=env,
        )
        listed = command(
            base + ["--with-colons", "--fixed-list-mode", "--fingerprint",
                    "--with-subkey-fingerprint", "--list-keys"],
            work,
            work / (name + "-keys"),
            seconds=30, env=env,
        )
        keys = one_primary(listed, primary)
        output = work / "debian-cleartext"
        operation = (
            ["--output", str(output), "--decrypt", str(materials / signature)]
            if data is None
            else ["--verify", str(materials / signature), str(materials / data)]
        )
        status = command(
            base + ["--status-fd", "1"] + operation, work, work / (name + "-verify"),
            seconds=30, env=env,
        )
        now = int(time.time())
        verified = valid_status(status, primary, signer, now)
        signing_capability(keys, primary, signer, now, verified["timestamp"])
        evidence.append({
            "purpose": name, "signature": signature, "data": data,
            "bundle_sha256": key_sha, **verified, "checked_at_unix": now,
            "binding_verifier": "offline GPG with required signing-subkey cross-certification",
        })
    text = read(work / "debian-cleartext", 32768).decode("utf-8", "strict")
    # Do not confuse upstream detached signature with the DIFFERENT Debian orig bytes.
    need(text.count("Source: expat\n") == text.count("Version: 2.10.0-1\n") == 1, "dsc_identity")
    match = re.search(r"^Checksums-Sha256:\n((?: .+\n)+)", text, re.M)
    need(match is not None, "dsc_checksums")
    rows = [line.split() for line in match[1].splitlines()]
    expected = []
    for filename in ("expat_2.10.0.orig.tar.gz", "expat_2.10.0-1.debian.tar.xz"):
        raw = read(materials / filename, 16 * 1024**2)
        expected.append([sha(raw), str(len(raw)), filename])
    need(sorted(rows) == sorted(expected), "dsc_tuple")
    record(
        work / "AUTHENTICATED.json",
        {
            "signatures": evidence,
            "Root_bootstrap_sha256": ROOT_BOOTSTRAP_SHA256,
            "dsc_tuples": rows,
            "trust": "Root-approved exact publisher keys and purposes; not WOT/build attestation",
            "revocation_limit": (
                "Supplied publisher bundles; global revocation completeness not proved"
            ),
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_work")
    main(*sys.argv[1:])
