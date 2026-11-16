"""Offline source rebuild on trixie, after maintained GPG verification."""

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from authenticate import main as authenticate
from common import ENV, command, material, need, read, record, sha, write_new
from negative_guard_tests import check_negative_guards
from wide_test_port import apply_wide_port, check_helpers, package_pins, suite_counts

VERSION = "2.10.0-1+pamolive1"


def publish_build_failure(log, *, stage="dpkg-buildpackage"):
    """Only public Debian build logs: bounded encoded tails, never an admission."""
    need(
        stage
        in {
            "dpkg-buildpackage",
            "make-build-check",
            "make-buildw-check",
            "wide-port-patch",
            "wide-helper-compile",
            "wide-helper-run",
            "wide-exported-c-compile",
            "wide-exported-c-run",
            "wide-exported-cpp-compile",
            "wide-exported-cpp-run",
            "ubsan-configure",
            "ubsan-build",
            "ubsan-check",
        },
        "build_stage",
    )
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
                "stage": stage,
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


def check_tree(source, output, tree):
    need(tree in {"build", "buildw"}, "build_test_tree")
    log = output / (tree + "-check")
    tests = source / tree / "tests"
    need(
        not (tests / "runtests.log").exists() and not (tests / "runtests.trs").exists(),
        "test_outputs_not_fresh",
    )
    target = tree + "/tests" if tree == "buildw" else tree
    args = ["/usr/bin/make", "-j1", "-C", target, "check"]
    if tree == "buildw":
        args.append("CC=/usr/bin/gcc -std=c11 -Werror=incompatible-pointer-types -Werror=format")
    try:
        command(
            args,
            source,
            log,
            seconds=300,
            cap=8 * 1024**2,
        )
    except BaseException as original:
        try:
            publish_build_failure(log, stage="make-" + tree + "-check")
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
    # Packages are already built; only srcw/tests is ported. No library ABI,
    # allocator, case registration or installed artifact is changed by this step.
    built_packages = package_pins(work, VERSION)
    apply_wide_port(source / "srcw", output / "wide-test-port", publish_build_failure)
    check_helpers(source, output, publish_build_failure)
    check_negative_guards(source, output)
    for tree in ("build", "buildw"):
        check_tree(source, output, tree)
    counts = suite_counts(source, output / "upstream-tests")
    need(package_pins(work, VERSION) == built_packages, "test_port_changed_packages")
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
            "tests": ["build/check", "buildw/tests/check"],
            "upstream_C_counts": counts,
            "wide_test_port_only": True,
            "packages_unchanged_across_tests": built_packages,
            "full_CXX_suite_claimed": False,
            "platform": "trixie/amd64",
            "local_build_attestation": False,
            "fixed4_admitted": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_output")
    main(*sys.argv[1:])
