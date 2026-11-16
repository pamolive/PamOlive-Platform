"""Test-only ushort harness, after source authentication and Debian package build.

No installed source/library/ABI is changed. GNU patch consumes captured pinned
bytes. The full upstream C runner, its registrations and OOM hooks remain.
"""

import json
import re
from pathlib import Path

from common import HERE, command, need, read, record, sha, write_new

# Author constants are filled before the source freeze; Root's external workflow
# source checksum closure must approve this module and these data before import.
BUNDLE = {
    "expat-ushort-tests.patch": "f1aff33cc4ae4387f3c2e330241b012199b81f54afcb0fb1e665509e230b2a1b",
    "expat-ushort-tests-source.json": (
        "b1b8a410ca2c0dc6179fe0e5eb39a1467e4e79be290de6d9c94a364618f23900"
    ),
    "test_character_support.h": "73a2e4e682c2c07e1452bc7181574476887634eb956c545bff8be55f375b68bd",
    "test_character_support_selftest.c": (
        "5916f1b53b8b0ae10e42dba36c291f0333e0b034ba386a0321208ff4edbe4367"
    ),
}


def validate_capture(buffers):
    need(set(buffers) == set(BUNDLE), "wide_bundle_closure")
    for name, body in buffers.items():
        need(isinstance(body, bytes) and sha(body) == BUNDLE[name], "wide_bundle_pin")
    value = json.loads(buffers["expat-ushort-tests-source.json"])
    need(
        isinstance(value, dict)
        and set(value["changed"])
        == {
            "tests/basic_tests.c",
            "tests/common.c",
            "tests/common.h",
            "tests/handlers.c",
            "tests/misc_tests.c",
            "tests/runtests.c",
            "tests/structdata.c",
        },
        "wide_changed_scope",
    )
    need(
        len(value["files"]) == 35
        and value["runtime_library_sources_changed"] is False
        and value["new_heap_allocations"] is False
        and value["new_skips"] is False,
        "wide_source_scope",
    )
    return value


def validate_tree(buffers, rows, field):
    need(field in {"before", "after"} and set(buffers) == set(rows), "wide_tree_closure")
    for name, body in buffers.items():
        need(
            name.startswith("tests/")
            and len(Path(name).parts) == 2
            and ".." not in Path(name).parts,
            "wide_tree_path",
        )
        need(sha(body) == rows[name][field], "wide_tree_pin")


def public_test_command(args, cwd, log, stage, publish_failure, seconds, cap=65536):
    try:
        return command(args, cwd, log, seconds=seconds, cap=cap)
    except BaseException as original:
        try:
            publish_failure(log, stage=stage)
        except (OSError, ValueError):
            raise original
        raise


def apply_wide_port(source, output, publish_failure):
    """Patch only the srcw test tree, after dpkg-buildpackage has sealed .debs."""
    source, output = Path(source), Path(output)
    buffers = {name: read(HERE / name, 1024**2) for name in BUNDLE}
    pins = validate_capture(buffers)
    before = {name: read(source / name, 1024**2) for name in pins["files"]}
    validate_tree(before, pins["files"], "before")
    for name in ("test_character_support.h", "test_character_support_selftest.c"):
        need(not (source / "tests" / name).exists(), "wide_new_file_exists")
    output.mkdir(mode=0o700)
    approved_patch = output / "approved.patch"
    write_new(approved_patch, buffers["expat-ushort-tests.patch"], 0o444)
    public_test_command(
        ["/usr/bin/patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(approved_patch)],
        source,
        output / "patch",
        "wide-port-patch",
        publish_failure,
        seconds=30,
    )
    after = {name: read(source / name, 1024**2) for name in pins["files"]}
    validate_tree(after, pins["files"], "after")
    for name in ("test_character_support.h", "test_character_support_selftest.c"):
        write_new(source / "tests" / name, buffers[name], 0o444)
    record(
        output / "PORT.json",
        {
            "state": "TEST_HARNESS_APPLIED",
            "changed": pins["changed"],
            "source_case_declarations": pins["START_TEST_count"],
            "case_names_sha256": pins["case_names_sha256"],
            "registration_lines_sha256": pins["registration_lines_sha256"],
            "patch_sha256": BUNDLE["expat-ushort-tests.patch"],
            "source_manifest_sha256": BUNDLE["expat-ushort-tests-source.json"],
            "helper_header_sha256": BUNDLE["test_character_support.h"],
            "full_CXX_suite_claimed": False,
            "package_or_ABI_admitted": False,
        },
    )


def check_helpers(source, output, publish_failure):
    """Positive self-test uses the very same header captured for full runtests."""
    source, output = Path(source), Path(output)
    binary = output / "wide-helper-selftest"
    public_test_command(
        [
            "/usr/bin/gcc",
            "-std=c11",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-Wformat=2",
            "-DXML_UNICODE",
            "-I" + str(source / "srcw/lib"),
            str(source / "srcw/tests/test_character_support_selftest.c"),
            "-o",
            str(binary),
        ],
        source,
        output / "helper-compile",
        "wide-helper-compile",
        publish_failure,
        seconds=60,
    )
    public_test_command(
        [str(binary)], source, output / "helper-run", "wide-helper-run", publish_failure, seconds=5
    )


def test_summary(log, trs):
    need(isinstance(log, bytes) and isinstance(trs, bytes), "wide_summary_bytes")
    summaries = re.findall(rb"(?m)^([0-9]+)%: Checks: ([0-9]+), Failed: ([0-9]+)\r?$", log)
    need(len(summaries) == 1, "wide_summary_count")
    percentage, count, failed = map(int, summaries[0])
    need(
        percentage == 100 and count > 0 and count % 12 == 0 and failed == 0, "wide_suite_incomplete"
    )
    results = re.findall(rb"(?m)^:(test-result|global-test-result): ([A-Z]+)\r?$", trs)
    need(
        sorted(results) == [(b"global-test-result", b"PASS"), (b"test-result", b"PASS")],
        "wide_trs_not_pass",
    )
    return {
        "checks": count,
        "configurations": 12,
        "failures": 0,
        "log_sha256": sha(log),
        "trs_sha256": sha(trs),
    }


def suite_counts(source, output=None):
    source = Path(source)
    result, captured = {}, {}
    for tree in ("build", "buildw"):
        log = read(source / tree / "tests/runtests.log", 8 * 1024**2)
        trs = read(source / tree / "tests/runtests.trs", 32768)
        result[tree] = test_summary(log, trs)
        captured[tree] = (log, trs)
    need(result["build"]["checks"] == result["buildw"]["checks"], "wide_narrow_counts_differ")
    if output is not None:
        output = Path(output)
        output.mkdir(mode=0o700)
        for tree, (log, trs) in captured.items():
            write_new(output / (tree + "-runtests.log"), log)
            write_new(output / (tree + "-runtests.trs"), trs)
    return result


def package_pins(work, version):
    """The exported Debian runtime/SDK must stay byte-exact across harness work."""
    work = Path(work)
    return {
        package: sha(read(work / f"{package}_{version}_amd64.deb", 32 * 1024**2))
        for package in ("libexpat1", "libexpat1-dev")
    }
