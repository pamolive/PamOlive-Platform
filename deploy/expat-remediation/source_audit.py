"""DATA-only linkage of Debian code to the complete upstream release, not crypto."""

import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import check_materials, material, need, record, sha


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
    return {
        "equal_source_hashes": evidence,
        "overflow_checks": "source only; no huge trigger executed",
        "crypto_or_runtime_proved": False,
    }


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_report")
    record(sys.argv[2], audit(sys.argv[1]))
