"""Qualify the installed Debian glibc backport in a disposable amd64 image."""

import hashlib
import io
import json
import locale
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

STOCK = "2.41-12+deb13u5"
CANDIDATE = STOCK + "+pamolive1"
PACKAGES = Path("/packages")
EVIDENCE = Path("/evidence")
LIBDIR = "/usr/lib/x86_64-linux-gnu/"
LIBC = LIBDIR + "libc.so.6"
LOADER = LIBDIR + "ld-linux-x86-64.so.2"
RESOLVER = LIBDIR + "libresolv.so.2"
CONTROLS = {
    "libc6": (LIBC, LOADER, RESOLVER),
    "libc-bin": ("/usr/bin/getent", "/usr/bin/locale", "/usr/sbin/ldconfig"),
    "libc-dev-bin": ("/usr/bin/gencat",),
    "libc6-dev": (
        LIBDIR + "libc.so",
        LIBDIR + "Scrt1.o",
        "/usr/include/pthread.h",
        "/usr/include/resolv.h",
    ),
}
MATERIALS = {prefix + name + ".deb" for prefix in ("", "stock-") for name in CONTROLS}
MATERIALS.update(("buildinfo", "test-summary.txt"))
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
MAX_TAR_BYTES = 64 * 1024 * 1024

FIXTURE = r"""
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <langinfo.h>
#include <libintl.h>
#include <locale.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void *thread(void *value) {
    *(int *)value = 42;
    return value;
}

static int loopback_dns(void) {
    unsigned char query[256], received[256];
    struct sockaddr_in target = { .sin_family = AF_INET };
    struct sockaddr_in source;
    socklen_t target_size = sizeof(target), source_size = sizeof(source);
    ns_msg message;
    ns_rr question;
    int server = socket(AF_INET, SOCK_DGRAM, 0);
    int client = socket(AF_INET, SOCK_DGRAM, 0);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (server < 0 || client < 0 || bind(server, (void *)&target, sizeof(target)) ||
        getsockname(server, (void *)&target, &target_size) ||
        connect(client, (void *)&target, target_size)) return 0;

    int query_size = res_mkquery(ns_o_query, "fixture.invalid", ns_c_in, ns_t_a,
                                NULL, 0, NULL, query, sizeof(query));
    if (query_size < NS_HFIXEDSZ || send(client, query, query_size, 0) != query_size ||
        recvfrom(server, received, sizeof(received), 0,
                 (void *)&source, &source_size) != query_size ||
        source.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        ns_initparse(received, query_size, &message) ||
        ns_parserr(&message, ns_s_qd, 0, &question) ||
        strcmp(ns_rr_name(question), "fixture.invalid") ||
        ns_rr_type(question) != ns_t_a || ns_rr_class(question) != ns_c_in) return 0;

    /* A normal positive reply with one loopback A record, generated locally. */
    static const unsigned char answer[] = {
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1
    };
    if ((size_t)query_size + sizeof(answer) > sizeof(received)) return 0;
    received[2] = 0x81;
    received[3] = 0x80;
    received[7] = 1;
    memcpy(received + query_size, answer, sizeof(answer));
    int reply_size = query_size + sizeof(answer);
    int success =
        sendto(server, received, reply_size, 0, (void *)&source, source_size) == reply_size &&
        recv(client, received, sizeof(received), 0) == reply_size &&
        received[0] == query[0] && received[1] == query[1] &&
        !ns_initparse(received, reply_size, &message) &&
        ns_msg_getflag(message, ns_f_qr) && ns_msg_count(message, ns_s_an) == 1 &&
        !ns_parserr(&message, ns_s_an, 0, &question) &&
        ns_rr_type(question) == ns_t_a && ns_rr_rdlen(question) == 4 &&
        !memcmp(ns_rr_rdata(question), answer + sizeof(answer) - 4, 4);
    close(client);
    close(server);
    return success;
}

int main(void) {
    if (!setlocale(LC_ALL, "C.UTF-8") || strcmp(nl_langinfo(CODESET), "UTF-8") ||
        strcmp(dgettext("pamolive-qualification", "synthetic message"), "synthetic message"))
        return 1;
    pthread_t worker;
    int value = 0;
    void *result = NULL;
    if (pthread_create(&worker, NULL, thread, &value) || pthread_join(worker, &result) ||
        result != &value || value != 42) return 2;
    struct passwd entry, *found = NULL;
    char buffer[4096];
    if (getpwnam_r("root", &entry, buffer, sizeof(buffer), &found) || !found || entry.pw_uid)
        return 3;
    struct addrinfo hint = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM,
                            .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV };
    struct addrinfo *addresses = NULL;
    if (getaddrinfo("127.0.0.1", "80", &hint, &addresses) || !addresses) return 4;
    int numeric_loopback = addresses->ai_addrlen == sizeof(struct sockaddr_in) &&
        ((struct sockaddr_in *)addresses->ai_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    freeaddrinfo(addresses);
    if (!numeric_loopback || !loopback_dns()) return 4;
    puts("locale gettext-fallback pthread local-nss loopback-dns");
    return 0;
}
"""


class Refused(ValueError):
    """A qualification invariant failed."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def run(*args):
    result = subprocess.run(args, capture_output=True, env=ENV, check=False, timeout=35)
    require(result.returncode == 0, f"{Path(args[0]).name} exited with status {result.returncode}")
    return result.stdout


def sha_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def materials():
    require(
        {path.name for path in PACKAGES.iterdir()} == MATERIALS | {"checksums.sha256"},
        "incorrect materials directory",
    )
    for path in PACKAGES.iterdir():
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_TAR_BYTES,
            f"incorrect material file {path.name}",
        )
    checksum_file = PACKAGES / "checksums.sha256"
    require(checksum_file.stat().st_size <= 4096, "oversized checksum file")
    checksums = {}
    for line in checksum_file.read_text(encoding="ascii").splitlines():
        entry = re.fullmatch(r"([a-f0-9]{64}) [ *](?:\./)?([a-z0-9.-]+)", line)
        require(entry is not None, "invalid checksum line")
        digest, name = entry.groups()
        require(
            name in MATERIALS and name not in checksums and sha_file(PACKAGES / name) == digest,
            f"invalid checksum for {name}",
        )
        checksums[name] = digest
    require(checksums.keys() == MATERIALS, "incomplete checksum file")
    checksums[checksum_file.name] = sha_file(checksum_file)
    return checksums


def package_state(name, version, prefix):
    fmt = "${source:Package}\t${Package}\t${Version}\t${Architecture}\t${Status}\n"
    state = run("/usr/bin/dpkg-query", "-W", f"-f={fmt}", name).decode("ascii").splitlines()
    require(
        state == [f"glibc\t{name}\t{version}\tamd64\tinstall ok installed"],
        f"unexpected installed state for {name}",
    )
    archive = PACKAGES / f"{prefix}{name}.deb"
    # The archive records the manifest name, version and architecture independently of dpkg status.
    for field, expected in (("Package", name), ("Version", version), ("Architecture", "amd64")):
        require(
            run("/usr/bin/dpkg-deb", "--field", archive, field)
            == (expected + "\n").encode("ascii"),
            f"incorrect {field} for {archive.name}",
        )
    return archive


def archive_files(archive, paths):
    payload = run("/usr/bin/dpkg-deb", "--fsys-tarfile", archive)
    require(len(payload) <= MAX_TAR_BYTES, f"oversized tar stream for {archive.name}")
    installed = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as unpacked:
        for member in unpacked:
            name = "/" + member.name.removeprefix("./")
            if name not in paths:
                continue
            require(
                name not in installed and member.isfile() and member.size > 0,
                f"invalid archive member {name}",
            )
            with unpacked.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            file = Path(name)
            info = file.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_size == member.size
                and stat.S_IMODE(info.st_mode) == member.mode
                and (info.st_uid, info.st_gid) == (member.uid, member.gid)
                and sha_file(file) == digest,
                f"installed file differs from archive for {name}",
            )
            installed[name] = {"sha256": digest, "mode": f"{member.mode:04o}"}
    require(installed.keys() == set(paths), f"missing archive member for {archive.name}")
    return installed


def elf_contract(path):
    with Path(path).open("rb") as stream:
        header = stream.read(20)
    require(
        header[:6] == b"\x7fELF\x02\x01" and header[16:20] == b"\x03\x00\x3e\x00",
        f"incorrect ELF format for {path}",
    )
    output = run(
        "/usr/bin/readelf", "--wide", "--dynamic", "--dyn-syms", "--version-info", path
    ).decode("ascii")
    sonames = re.findall(r"\(SONAME\).*\[([^]]+)\]", output)
    require(
        sonames == [Path(path).name] and not re.search(r"\((?:RUNPATH|RPATH)\)", output),
        f"incorrect SONAME or library search path for {path}",
    )
    exports = []
    required = []
    for line in output.splitlines():
        if not re.match(r"^\s*\d+:", line):
            continue
        fields = line.split(maxsplit=7)
        if len(fields) != 8:
            continue
        _, _, size, kind, binding, visibility, index, name = fields
        if binding not in {"GLOBAL", "WEAK", "UNIQUE"}:
            continue
        name = name.split()[0]
        if index == "UND":
            required.append((name, kind, binding, visibility))
        else:
            # Code may change size. Data symbol sizes form part of the ABI.
            exports.append(
                (name, kind, binding, visibility, size if kind in {"OBJECT", "TLS"} else "")
            )
    versions = sorted({name.split("@")[-1] for name, *_ in exports if "@" in name})
    definitions = re.findall(
        r"\bRev:\s*\d+\s+Flags:.*?\bName:\s*(\S+)|\bParent \d+:\s*(\S+)", output
    )
    require(
        exports and "GLIBC_PRIVATE" in versions and definitions,
        f"missing versioned exports for {path}",
    )
    return {
        "soname": sonames[0],
        "needed": re.findall(r"\(NEEDED\).*\[([^]]+)\]", output),
        "export_count": len(exports),
        "exports_sha256": hashlib.sha256(json.dumps(sorted(exports)).encode("ascii")).hexdigest(),
        "versioned_exports": versions,
        "version_definitions_sha256": hashlib.sha256(
            json.dumps(definitions).encode("ascii")
        ).hexdigest(),
        "imports_sha256": hashlib.sha256(json.dumps(sorted(required)).encode("ascii")).hexdigest(),
    }


def positive_smoke():
    maps = Path("/proc/self/maps").read_text(encoding="ascii")
    for library in (LIBC, LOADER):
        paths = {
            line.split(maxsplit=5)[-1]
            for line in maps.splitlines()
            if line.endswith("/" + Path(library).name)
        }
        require(
            len(paths) == 1 and Path(paths.pop()).resolve(strict=True) == Path(library),
            f"Python maps an unexpected {Path(library).name}",
        )
    previous_locale = locale.setlocale(locale.LC_CTYPE)
    try:
        locale.setlocale(locale.LC_CTYPE, "C.UTF-8")
        require(locale.nl_langinfo(locale.CODESET) == "UTF-8", "Python C.UTF-8 locale unavailable")
    finally:
        locale.setlocale(locale.LC_CTYPE, previous_locale)

    with tempfile.TemporaryDirectory(prefix="glibc-qualification-") as directory:
        source = Path(directory) / "fixture.c"
        binary = Path(directory) / "fixture"
        source.write_text(FIXTURE, encoding="ascii")
        run(
            "/usr/bin/gcc",
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-o",
            binary,
            source,
            "-lresolv",
        )
        headers = run("/usr/bin/readelf", "-lW", binary).decode("ascii")
        interpreters = re.findall(r"\[Requesting program interpreter: ([^]]+)\]", headers)
        require(
            len(interpreters) == 1 and Path(interpreters[0]).resolve(strict=True) == Path(LOADER),
            "fixture uses an unexpected ELF interpreter",
        )
        links = run(LOADER, "--list", binary).decode("ascii")
        for library in (LIBC, RESOLVER):
            name = Path(library).name
            paths = re.findall(rf"^\s*{re.escape(name)} => (\S+)", links, re.MULTILINE)
            require(
                len(paths) == 1 and Path(paths[0]).resolve(strict=True) == Path(library),
                f"fixture resolves an unexpected {name}",
            )
        kinds = "locale gettext-fallback pthread local-nss loopback-dns"
        require(run(binary) == (kinds + "\n").encode("ascii"), "positive native fixture failed")
    return {"interpreter": interpreters[0], "checks": kinds.split()}


def capture(mode):
    version, prefix = (STOCK, "stock-") if mode == "stock" else (CANDIDATE, "")
    checksums = materials()
    archive_provenance = {}
    for name, paths in CONTROLS.items():
        archive = package_state(name, version, prefix)
        archive_provenance[name] = {
            "version": version,
            "archive": archive.name,
            "files": archive_files(archive, paths),
        }
    return {
        "mode": mode,
        "architecture": "amd64",
        "materials_sha256": checksums,
        "packages": archive_provenance,
        "abi": {path: elf_contract(path) for path in (LIBC, LOADER)},
        "smoke": positive_smoke(),
    }


def write_evidence(name, report):
    with (EVIDENCE / name).open("x", encoding="ascii") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")


def main():
    try:
        require(
            len(sys.argv) == 2 and sys.argv[1] in {"stock", "candidate"},
            "expected stock or candidate",
        )
        require(
            sys.platform == "linux"
            and platform.machine() == "x86_64"
            and os.getuid() == os.geteuid() == 65534,
            "expected linux amd64 as uid 65534",
        )
        mode = sys.argv[1]
        measured = capture(mode)
        if mode == "stock":
            write_evidence("stock.json", measured)
            return 0

        stock_file = EVIDENCE / "stock.json"
        require(
            stock_file.is_file() and stock_file.stat().st_size <= 64 * 1024, "invalid stock receipt"
        )
        stock = json.loads(stock_file.read_text(encoding="ascii"))
        require(
            stock["mode"] == "stock"
            and stock["architecture"] == "amd64"
            and stock["materials_sha256"] == measured["materials_sha256"],
            "stock inputs differ",
        )
        require(
            stock["abi"] == measured["abi"] and stock["smoke"] == measured["smoke"],
            "stock and candidate ABI or positive smoke differ",
        )
        stock_libc = stock["packages"]["libc6"]["files"][LIBC]["sha256"]
        candidate_libc = measured["packages"]["libc6"]["files"][LIBC]["sha256"]
        require(candidate_libc != stock_libc, "candidate libc bytes are unchanged")
        write_evidence("candidate.json", measured)
        write_evidence(
            "qualification.json",
            {
                "schema": "pamolive.glibc-trixie-backport-qualification/1",
                "status": "QUALIFIED",
                "scope": "installed-abi-and-positive-smoke",
                "stock_sha256": sha_file(stock_file),
                "candidate_sha256": sha_file(EVIDENCE / "candidate.json"),
                "materials_sha256": measured["materials_sha256"],
                "versions": {"stock": STOCK, "candidate": CANDIDATE},
                "installed_elf_sha256": {
                    path: measured["packages"]["libc6"]["files"][path]["sha256"]
                    for path in (LIBC, LOADER)
                },
                "product_image_verified": False,
                "release_admitted": False,
            },
        )
        return 0
    except (
        ValueError,
        OSError,
        KeyError,
        TypeError,
        tarfile.TarError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
