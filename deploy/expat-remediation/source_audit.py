"""DATA-only linkage of Debian code to the complete upstream release, not crypto."""

import io
import re
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, check_materials, material, need, read, record, sha

# These are local transformations of authenticated 2.10.0, not a new upstream release.
POLICY = "expat-2.10.0-local-two-advisory-v1"
LOCAL_VERSION = "2.10.0-1+pamolive2"
PATCHES = {
    "CVE-2026-124317.patch": "453f41710ea2394887a8fa5f4b3121ebce36ffb5eadcc4404de2e0dbdf204d1a",
    "CVE-2026-128241.patch": "78203c87cb0d854e3a7a6d36840e90c9370070cb2e49e36cb4ce5e01c8a974f1",
}
FILE_PINS = {
    "expat/lib/xmltok.c": {
        "base_sha256": "44baab2a4970749f6f29992bbbc1b3c62239ef9ec2a20de96332ef4659b9e32d",
        "post_sha256": "07dda873d9d75643f9e4a1b83878ba0230f7782966375449928387c85a62caf8",
    },
    "expat/tests/misc_tests.c": {
        "base_sha256": "a2e4bd074fbd83a87ab298e79a13599e5a4afe65f542d6026a314b98a4ddfd9b",
        "post_sha256": "828923bf773317386dff577ccf26c0e2b04d3b6762fdd633bbe6324214a13dcf",
    },
    "expat/xmlwf/xmltchar.h": {
        "base_sha256": "3ca28b7ff0f149de1e022ce4031aed1092a8981cc86e62e45131fa1b04964755",
        "post_sha256": "c92e56aec7e5803b2213e9bcd276515b554041d6474ecabaa7def8a4876d29d5",
    },
    "expat/xmlwf/xmlwf.c": {
        "base_sha256": "12b11917c336ab01e580c17f02018986838482a51f7c61708a50e55cc5e83afc",
        "post_sha256": "94d0aeeb889b06f9cb6e3865427510804216797a5ece71fe60653976e7bc5c37",
    },
}


def transform(files, patches):
    """Apply only exact pinned LF hunks, at their declared positions, without fuzz."""
    need(type(files) is dict and set(files) == set(FILE_PINS), "backport_source_closure")
    need(type(patches) is dict and set(patches) == set(PATCHES), "backport_patch_closure")
    for name, raw in files.items():
        need(type(raw) is bytes and sha(raw) == FILE_PINS[name]["base_sha256"], "backport_preimage")
    made = dict(files)
    seen = set()
    for patch_name, expected in PATCHES.items():
        raw = patches[patch_name]
        need(
            type(raw) is bytes and len(raw) <= 16384 and sha(raw) == expected, "backport_patch_pin"
        )
        lines = raw.splitlines(keepends=True)
        index = 0
        while index < len(lines):
            header = lines[index]
            need(header.startswith(b"--- a/") and header.endswith(b"\n"), "backport_header")
            name = header[6:-1].decode("ascii")
            need(name in FILE_PINS and name not in seen, "backport_path_or_duplicate")
            seen.add(name)
            need(
                index + 1 < len(lines) and lines[index + 1] == ("+++ b/" + name + "\n").encode(),
                "backport_post_header",
            )
            index += 2
            old, output, position, hunks = made[name].splitlines(keepends=True), [], 0, 0
            while index < len(lines) and lines[index].startswith(b"@@ "):
                match = re.fullmatch(rb"@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n", lines[index])
                need(match is not None, "backport_hunk_header")
                start, old_count, new_start, new_count = map(int, match.groups())
                need(
                    start >= 1 and start - 1 >= position and start - 1 <= len(old),
                    "backport_hunk_position",
                )
                output.extend(old[position : start - 1])
                position = start - 1
                need(len(output) == new_start - 1, "backport_new_position")
                consumed = produced = 0
                index += 1
                while index < len(lines) and not lines[index].startswith((b"@@ ", b"--- a/")):
                    line = lines[index]
                    need(
                        line[:1] in (b" ", b"+", b"-") and line.endswith(b"\n"),
                        "backport_hunk_line",
                    )
                    kind, body = line[:1], line[1:]
                    if kind in (b" ", b"-"):
                        need(position < len(old) and old[position] == body, "backport_context")
                        position += 1
                        consumed += 1
                    if kind in (b" ", b"+"):
                        output.append(body)
                        produced += 1
                    index += 1
                need((consumed, produced) == (old_count, new_count), "backport_hunk_counts")
                hunks += 1
            need(hunks > 0, "backport_missing_hunks")
            output.extend(old[position:])
            made[name] = b"".join(output)
    need(seen == set(FILE_PINS), "backport_target_closure")
    for name, raw in made.items():
        need(sha(raw) == FILE_PINS[name]["post_sha256"], "backport_postimage")
    return made


def capture_patches():
    return {name: read(HERE / name, 16384) for name in PATCHES}


def proof():
    return {
        "schema": "pamolive.expat-local-backports/1",
        "policy": POLICY,
        "local_package_version": LOCAL_VERSION,
        "patches": PATCHES,
        "files": FILE_PINS,
        "base_authentication_required_before_extraction": True,
        "upstream_signature_covers_local_changes": False,
        "fixed4_admitted": False,
        "new_advisories_admitted": False,
        "product_qualified": False,
        "operational_go": False,
    }


def apply_backports(source, receipt, *, debian):
    # Private authenticated build tree. All inputs are captured and validated before writes.
    root = Path(source)
    targets = {name: root / (name if debian else name.removeprefix("expat/")) for name in FILE_PINS}
    captured = {name: read(path, 1024**2) for name, path in targets.items()}
    result = transform(captured, capture_patches())
    for name, path in targets.items():
        need(read(path, 1024**2) == captured[name], "backport_source_changed")
    for name, path in targets.items():
        need(path.write_bytes(result[name]) == len(result[name]), "backport_short_write")
    for name, path in targets.items():
        need(read(path, 1024**2) == result[name], "backport_write_postimage")
    value = proof()
    record(receipt, value)
    return value


def member(raw, name):
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        found = [r for r in archive if r.name == name]
        need(len(found) == 1 and found[0].isfile() and found[0].size <= 1024**2, "source_entry")
        return archive.extractfile(found[0]).read(1024**2 + 1)


def audit(materials):
    materials = Path(materials)
    check_materials(materials)
    debian = material(materials, "expat_2.10.0.orig.tar.gz")
    upstream = material(materials, "expat-2.10.0.tar.gz")
    evidence = {}
    for name in ("lib/xmlparse.c", "Changes", "tests/acc_tests.c", "tests/alloc_tests.c"):
        left = member(debian, "libexpat-R_2_10_0/expat/" + name)
        right = member(upstream, "expat-2.10.0/" + name)
        need(left == right, "debian_upstream_code_difference")
        evidence[name] = sha(left)
    code = member(upstream, "expat-2.10.0/lib/xmlparse.c").decode()
    for token in ("size_t attIndex = 0;", "size_t nPrefixes = 0;", "if (attIndex > INT_MAX)"):
        need(code.count(token) == 1, "overflow_fix_source_shape")
    changes = member(upstream, "expat-2.10.0/Changes").decode()
    release = changes.split("Release 2.9.0")[0]
    for number in ("113351", "115506", "117610", "118370", "1439"):
        need(number in release, "complete_release_security_note")
    originals = {}
    for name in FILE_PINS:
        left = member(debian, "libexpat-R_2_10_0/" + name)
        right = member(upstream, "expat-2.10.0/" + name.removeprefix("expat/"))
        need(left == right, "backport_debian_upstream_difference")
        originals[name] = left
    transform(originals, capture_patches())
    return {
        "local_backports": proof(),
        "equal_source_hashes": evidence,
        "overflow_checks": "source only; no huge trigger executed",
        "crypto_or_runtime_proved": False,
    }


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_report")
    from authenticate import main as authenticate

    output = Path(sys.argv[2])
    authenticate(sys.argv[1], output.with_name(output.name + ".authentication"))
    record(output, audit(sys.argv[1]))
