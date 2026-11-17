"""Both source authority chains must pass before any source-tar extraction."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acquire import checksums, fields, source_record, verify_release
from common import ENV, command, read, record, write_new
from legacy_auth import cleartext_envelope, one_primary, signing_capability, valid_status
from policy import MATERIALS, ROOT_PURPOSE, material
from source_model import PRIMARY, json_value, need, sha


def dsc_packaging(raw):
    cleartext_envelope(raw)
    text = raw.decode("ascii", "strict").split("\n\n", 1)[1]
    text = text.split("-----BEGIN PGP SIGNATURE-----\n", 1)[0]
    text = "\n".join(
        line[2:] if line.startswith("- ") else line for line in text.splitlines()
    ).rstrip()
    row = fields(text)
    need(row.get("Source") == "krb5" and row.get("Version") == "1.22.1-3", "dsc_identity")
    need(
        checksums(row.get("Checksums-Sha256", "")).get("krb5_1.22.1-3.debian.tar.xz")
        == MATERIALS["krb5_1.22.1-3.debian.tar.xz"],
        "dsc_packaging_tuple",
    )


def authenticate(materials, work):
    materials, work = Path(materials), Path(work)
    need(
        json_value(read(materials / "Root-purpose.json", 16384)) == ROOT_PURPOSE,
        "Root_purpose_exact",
    )
    # Capture fixed public payloads once. All subsequent parsing/extraction uses these buffers.
    captured = {name: material(materials, name) for name in MATERIALS}
    work.mkdir(mode=0o700)
    archive = work / "archive"
    archive.mkdir(mode=0o700)
    expected, debian = verify_release(materials, archive)
    source = source_record(read(materials / "Sources.xz", 32 * 1024**2), expected)
    dsc_packaging(captured["krb5_1.22.1-3.dsc"])
    staged = work / "mit-inputs"
    staged.mkdir(mode=0o700)
    for name in (
        "MIT-C449-keyserver-untrusted.asc",
        "krb5-1.22.3.tar.gz.asc",
        "krb5-1.22.3.tar.gz",
    ):
        write_new(staged / name, captured[name], 0o444)
    home = work / "mit-home"
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
        base + ["--import", str(staged / "MIT-C449-keyserver-untrusted.asc")],
        work,
        work / "mit-import",
        seconds=30,
        env=env,
    )
    listed = command(
        base
        + [
            "--with-colons",
            "--fixed-list-mode",
            "--fingerprint",
            "--with-subkey-fingerprint",
            "--list-keys",
        ],
        work,
        work / "mit-keys",
        seconds=30,
        env=env,
    )
    keys = one_primary(listed, PRIMARY)
    status = command(
        base
        + [
            "--status-fd",
            "1",
            "--verify",
            str(staged / "krb5-1.22.3.tar.gz.asc"),
            str(staged / "krb5-1.22.3.tar.gz"),
        ],
        work,
        work / "mit-verify",
        seconds=30,
        env=env,
    )
    now = int(time.time())
    mit = valid_status(status, PRIMARY, PRIMARY, now)
    signing_capability(keys, PRIMARY, PRIMARY, now, mit["timestamp"])
    receipt = {
        "schema": "pamolive.krb5-upgrade-authentication/1",
        "purpose": ROOT_PURPOSE,
        "MIT": mit,
        "Debian_archive": debian,
        "Debian_source_record": source,
        "materials": {
            name: {"sha256": sha(raw), "bytes": len(raw)} for name, raw in captured.items()
        },
        "DSC_uploader_signature_verified": False,
        "both_source_chains_authenticated": True,
        "source_payload_extracted": False,
        "product_admission": False,
        "operational_GO": False,
    }
    record(work / "AUTHENTICATED.json", receipt)
    return captured, receipt


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_work")
    authenticate(*sys.argv[1:])
