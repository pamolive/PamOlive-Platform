"""Linux matching oracle for preserved actual source bodies, without KDC contact."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import command, read, record, write_new
from policy import HERE
from source_model import json_value, need, sha


def helper_region(raw):
    start = raw.index(b"/* Return the passed-in character, lower-cased")
    end = raw.index(b"static int\nverify_callback", start)
    return raw[start:end]


def verify_contract(raw, old):
    new = helper_region(raw)
    need(
        new.count(b"const X509 *x") == 5 and new.replace(b"const X509 *x", b"X509 *x") == old,
        "TLS_old_hostname_contract",
    )
    return new


def main(source, work):
    source, work = Path(source), Path(work)
    work.mkdir(mode=0o700)
    raw = read(source / "src/plugins/tls/k5tls/openssl.c", 1024**2)
    old = read(HERE / "TLS-old-hostname-contract.DATA.inc", 32768)
    helpers = verify_contract(raw, old)
    preamble = (
        b'#include "k5-int.h"\n#include "k5-utf8.h"\n#include <arpa/inet.h>\n'
        b"#include <openssl/x509.h>\n#include <openssl/x509v3.h>\n"
    )
    write_new(work / "hostname-helpers.inc", preamble + helpers)
    binary = work / "hostname-oracle"
    command(
        [
            "/usr/bin/cc",
            "-std=c99",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(source / "src/include"),
            "-I" + str(source / "build/include"),
            "-I" + str(work),
            str(HERE / "tls_hostname_oracle.c"),
            "-lssl",
            "-lcrypto",
            "-o",
            str(binary),
        ],
        work,
        work / "compile",
        seconds=60,
    )
    result = json_value(command([str(binary)], work, work / "run", seconds=10))
    need(
        result == {"cases": 12, "passed": 12, "certificate_chain_verified": False},
        "TLS_matching_result",
    )
    record(
        work / "TLS-HOSTNAME-DATA.json",
        {
            "actual_source_sha256": sha(raw),
            "actual_helper_region_sha256": sha(helpers),
            "old_helper_region_sha256": sha(old),
            "matching": result,
            "certificate_chain_or_AD_interop": "NOT_EXECUTED",
            "partial_label_wildcards_admitted": False,
            "operational_GO": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_configured_source_new_work")
    main(*sys.argv[1:])
