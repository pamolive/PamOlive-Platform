"""GPG predicates reused from reviewed Expat R3; no native import."""

import re


def need(value, code):
    if not value:
        raise ValueError(code)


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


def valid_status(raw, primary, signer, now):
    need(
        all(re.fullmatch("[0-9A-F]{40}", f) for f in (primary, signer)),
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
    need(len(r) == 11 and re.fullmatch("[0-9A-F]{40}", r[1]), "signature_fields")
    need(
        r[10] == primary and r[1] == signer and (good[0][1] == signer[-16:]), "signature_authority"
    )
    need(r[3].isdigit() and int(r[3]) <= now + 300, "signature_future")
    need(r[4] == "0" or (r[4].isdigit() and int(r[4]) > now), "signature_expired")
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
            fingerprint[0] == "fpr" and re.fullmatch("[0-9A-F]{40}", fingerprint[9]),
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
        need(expiry in {"", "0"} or (expiry.isdigit() and int(expiry) > now), "key_expired")
        if signature_time is not None:
            need(int(row["created"]) <= signature_time, "signature_before_key")
            need(expiry in {"", "0"} or int(expiry) > signature_time, "signature_after_key_expiry")
    need("s" in keys[signer]["caps"], "signing_capability_missing")
