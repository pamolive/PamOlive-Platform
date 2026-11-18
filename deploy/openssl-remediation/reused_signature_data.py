"""Reused signature-status text contracts; no OpenPGP verification at import."""

import re

from reused_text_helpers import need

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
