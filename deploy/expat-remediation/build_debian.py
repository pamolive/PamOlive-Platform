"""Offline source rebuild on trixie, after maintained GPG verification."""

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from authenticate import main as authenticate
from common import ENV, command, material, need, read, record, sha, write_new

VERSION = "2.10.0-1+pamolive1"


def publish_build_failure(log):
    """Only public Debian build logs: bounded encoded tails, never an admission."""
    streams = {}
    for name in ("stdout", "stderr"):
        try:
            data = read(log / name, 8 * 1024**2)
        except (OSError, ValueError):
            streams[name] = {"available": False}
        else:
            tail = data[-8192:]
            streams[name] = {
                "available": True,
                "received_bytes": len(data),
                "tail_bytes": len(tail),
                "tail_base64": base64.b64encode(tail).decode("ascii"),
            }
    try:
        receipt = read(log / "result.json", 4096)
    except (OSError, ValueError):
        process = {"available": False}
    else:
        process = {
            "available": True,
            "receipt_base64": base64.b64encode(receipt).decode("ascii"),
        }
    print(
        json.dumps(
            {
                "schema": "pamolive.expat-public-build-failure/1",
                "state": "FAILED_OR_UNKNOWN",
                "stage": "dpkg-buildpackage",
                "tail_cap_bytes": 8192,
                "diagnostic_only": True,
                "streams": streams,
                "process_receipt": process,
            },
            sort_keys=True,
        )
    )


def build_package(source, log):
    try:
        command(
            ["/usr/bin/dpkg-buildpackage", "-us", "-uc", "-b", "-aamd64"],
            source,
            log,
            seconds=900,
            cap=8 * 1024**2,
            env=ENV | {"DEB_BUILD_PROFILES": "noudeb"},
        )
    except BaseException as original:
        try:
            publish_build_failure(log)
        except (OSError, ValueError):
            raise original
        raise


def main(materials, output):
    materials, output = Path(materials).resolve(), Path(output).resolve()
    need(read("/usr/lib/os-release", 32768).find(b"VERSION_CODENAME=trixie\n") >= 0, "trixie_only")
    output.mkdir(mode=0o700)
    authenticate(materials, output / "authentication")
    work = output / "work"
    work.mkdir(mode=0o700)
    for name in ("expat-2.10.0-1.dsc", "expat_2.10.0.orig.tar.gz", "expat_2.10.0-1.debian.tar.xz"):
        # dpkg-source expects underscore naming for the DSC, independently of our local name.
        destination = "expat_2.10.0-1.dsc" if name.endswith(".dsc") else name
        write_new(work / destination, material(materials, name))
    source = work / "expat-2.10.0"
    command(
        ["/usr/bin/dpkg-source", "--no-check", "-x", "expat_2.10.0-1.dsc", source.name],
        work,
        output / "extract",
        seconds=60,
    )
    # --no-check disables dpkg-source signatures AND checksum checks. Explicit GPG/DSC
    # tuples and pinned same-buffer hashes above replace both, before private extraction.
    command(
        ["/usr/bin/dpkg-checkbuilddeps"],
        source,
        output / "builddeps",
        env=ENV | {"DEB_BUILD_PROFILES": "noudeb"},
    )
    changelog = source / "debian/changelog"
    old = read(changelog, 1024**2)
    prefix = (
        f"expat ({VERSION}) trixie; urgency=high\n\n"
        "  * Local source rebuild of complete upstream 2.10.0, not a Debian binary publication.\n\n"
        " -- PamOlive Build <build@example.invalid>  Mon, 16 Nov 2026 00:00:00 +0000\n\n"
    ).encode()
    changelog.write_bytes(prefix + old)
    build_package(source, output / "build")
    # Debian rules have no test target. Both configured trees must be exercised explicitly.
    for tree in ("build", "buildw"):
        command(
            ["/usr/bin/make", "-j1", "-C", tree, "check"],
            source,
            output / (tree + "-check"),
            seconds=300,
            cap=8 * 1024**2,
        )
    published = []
    for package, folder in (("libexpat1", "runtime"), ("libexpat1-dev", "sdk")):
        files = list(work.glob(f"{package}_{VERSION}_amd64.deb"))
        need(len(files) == 1, "output_package_count")
        fields = command(
            [
                "/usr/bin/dpkg-deb",
                "--show",
                "--showformat=${Package}\t${Version}\t${Architecture}\n",
                str(files[0]),
            ],
            work,
            output / (folder + "-control"),
        )
        need(fields == f"{package}\t{VERSION}\tamd64\n".encode(), "output_package_identity")
        target = output / folder
        target.mkdir(mode=0o755)
        raw = read(files[0], 32 * 1024**2)
        write_new(target / files[0].name, raw, 0o644)
        published.append(
            {"package": package, "version": VERSION, "bytes": len(raw), "sha256": sha(raw)}
        )
    record(
        output / "SOURCE-REBUILD.json",
        {
            "packages": published,
            "tests": ["build/check", "buildw/check"],
            "platform": "trixie/amd64",
            "local_build_attestation": False,
            "fixed4_admitted": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_output")
    main(*sys.argv[1:])
