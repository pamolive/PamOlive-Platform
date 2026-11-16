"""LINUX CI ONLY: disposable upstream test build, never installed in runtime."""

import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authenticate import main as authenticate
from build_debian import publish_build_failure
from common import ENV, HERE, command, material, need, read, record, sha, write_new
from negative_guard_tests import json_value, lifecycle
from source_audit import apply_backports


def build_step(args, source, log, *, stage, **options):
    """Retain a bounded public diagnostic, then propagate the original failure."""
    need(stage in {"ubsan-configure", "ubsan-build", "ubsan-check"}, "sanitizer_stage")
    try:
        return command(args, source, log, **options)
    except BaseException as original:
        try:
            publish_build_failure(log, stage=stage)
        except (OSError, ValueError):
            raise original
        raise


def instrument(raw):
    # Compile-time assertions refer to the ACTUAL locals in storeAtts, not a copied model.
    text = raw.decode("utf-8")
    for name in ("attIndex", "nPrefixes"):
        original = f"size_t {name} = 0;"
        need(text.count(original) == 1, "actual_counter_not_size_t")
        text = text.replace(
            original,
            original
            + f'\n  _Static_assert(_Generic({name}, size_t: 1, default: 0), "counter_type");',
        )
    need(text.count("if (attIndex > INT_MAX)") == 1, "int_conversion_guard_absent")
    return text.encode()


def advisory_parser(source, output, env, *, before):
    """The same bounded synthetic source is compiled against each actual static library."""
    label = "before" if before else "after"
    binary = source / ("advisory-124317-" + label)
    command(
        [
            "/usr/bin/gcc",
            "-std=c11",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-I" + str(source),
            "-I" + str(source / "lib"),
            str(HERE / "expat_regression.c"),
            str(source / "lib/.libs/libexpat.a"),
            "-lm",
            "-o",
            str(binary),
        ],
        source,
        output / ("advisory-compile-" + label),
        seconds=60,
        env=env,
    )
    args = [str(binary)] + (["--advisory-124317-before"] if before else [])
    command(args, source, output / ("advisory-run-" + label), seconds=5, cap=16384, env=env)
    return {
        "mode": "guarded-unsafe-callback-before" if before else "no-unsafe-callback-after",
        "actual_unsafe_read_performed": False,
        "command_returncode": 0,
    }


def advisory_cli(source, output, env, *, before):
    """Only a private synthetic victim; expected refusal retains the real UNKNOWN journal."""
    label = "before" if before else "after"
    fixture = source / ("advisory-128241-" + label)
    fixture.mkdir(mode=0o700)
    dest = fixture / "output"
    dest.mkdir(mode=0o700)
    victim = fixture / "victim"
    body = b"synthetic-private-victim-128241\n"
    write_new(victim, body)
    document = fixture / "case.xml"
    write_new(document, b"<r/>\n")
    alias = dest / document.name
    alias.symlink_to(victim)
    tool = source / "xmlwf/xmlwf"
    need(not tool.is_symlink(), "advisory_cli_tool_alias")
    tool_hash = sha(read(tool, 64 * 1024**2))
    args = [str(tool), "-d", str(dest), str(document)]
    log = output / ("advisory-xmlwf-" + label)
    if before:
        command(args, source, log, seconds=5, cap=16384, env=env)
    else:
        try:
            command(args, source, log, seconds=5, cap=16384, env=env)
        except ValueError as error:
            need(error.args == ("child_failed_or_unknown",), "advisory_cli_failure_shape")
        else:
            raise ValueError("advisory_cli_did_not_refuse")
    # Read each H1 buffer once. No expected failure is relabelled command.ok.
    buffers = {
        name: read(log / name, 16384)
        for name in ("intent.json", "pid.json", "result.json", "stdout", "stderr")
    }
    facts = json_value(buffers["result.json"])
    lifecycle(facts, buffers["stdout"], buffers["stderr"], success=before)
    need(facts["returncode"] == (0 if before else 3), "advisory_cli_returncode")
    intent, pid = json_value(buffers["intent.json"]), json_value(buffers["pid.json"])
    need(
        intent["argv"] == args
        and intent["tool_sha256"] == tool_hash
        and pid == {"pid": facts["pid"]}
        and sha(read(tool, 64 * 1024**2)) == tool_hash,
        "advisory_cli_H1_binding",
    )
    if not before:
        need(
            json_value(read(log / "unknown.json", 128)) == {"state": "UNKNOWN"},
            "advisory_cli_unknown_not_retained",
        )
    unchanged = read(victim, 16384) == body
    need(alias.is_symlink() and unchanged == (not before), "advisory_cli_victim_state")
    return {
        "phase": label,
        "returncode": facts["returncode"],
        "victim_unchanged": unchanged,
        "leaf_symlink_retained": True,
        "expected_nonzero_unknown_retained": not before,
        "scope": "private synthetic leaf symlink; not parent/hardlink/Windows",
    }


def main(materials, output):
    materials, output = Path(materials).resolve(), Path(output).resolve()
    output.mkdir(mode=0o700)
    authenticate(materials, output / "authentication")
    raw = material(materials, "expat-2.10.0.tar.gz")
    source = output / "source"
    source.mkdir()
    total, seen = 0, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for row in archive:
            if row.name == "expat-2.10.0":
                need(row.isdir(), "tar_root_type")
                continue
            need(row.name.startswith("expat-2.10.0/"), "tar_root")
            name = row.name.removeprefix("expat-2.10.0/").rstrip("/")
            if not name:
                need(row.isdir(), "tar_root_type")
                continue
            relative = Path(name)
            need(
                not relative.is_absolute() and ".." not in relative.parts and name not in seen,
                "tar_path_or_duplicate",
            )
            seen.add(name)
            need(
                len(seen) <= 3000 and (row.isdir() or row.isfile()) and row.mode & 0o6000 == 0,
                "tar_type_mode_count",
            )
            total += row.size
            need(total <= 16 * 1024**2, "tar_total")
            target = source / relative
            if row.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                body = archive.extractfile(row).read(row.size + 1)
                need(len(body) == row.size, "tar_file_size")
                write_new(target, body, row.mode & 0o777)
    original = read(source / "lib/xmlparse.c", 1024**2)
    (source / "lib/xmlparse.c").write_bytes(instrument(original))
    env = ENV | {
        "CC": "/usr/bin/gcc",
        "CFLAGS": "-O1 -g -std=c11 -fsanitize=undefined -fno-sanitize-recover=all",
        "LDFLAGS": "-fsanitize=undefined",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=0",
    }
    build_step(
        [
            str(source / "configure"),
            "--disable-shared",
            "--enable-static",
            "--disable-maintainer-mode",
        ],
        source,
        output / "configure",
        stage="ubsan-configure",
        seconds=120,
        env=env,
    )
    build_step(
        ["/usr/bin/make", "-j1"],
        source,
        output / "build",
        stage="ubsan-build",
        seconds=300,
        cap=8 * 1024**2,
        env=env,
    )
    before_parser = advisory_parser(source, output, env, before=True)
    before_cli = advisory_cli(source, output, env, before=True)
    backports = apply_backports(source, output / "LOCAL-BACKPORTS.json", debian=False)
    build_step(
        ["/usr/bin/make", "-j1"],
        source,
        output / "patched-build",
        stage="ubsan-build",
        seconds=300,
        cap=8 * 1024**2,
        env=env,
    )
    build_step(
        ["/usr/bin/make", "-j1", "check"],
        source,
        output / "check",
        stage="ubsan-check",
        seconds=300,
        cap=8 * 1024**2,
        env=env,
    )
    after_parser = advisory_parser(source, output, env, before=False)
    after_cli = advisory_cli(source, output, env, before=False)
    record(
        output / "ADVISORY-REGRESSIONS.json",
        {
            "schema": "pamolive.expat-local-advisory-regressions/1",
            "parser": [before_parser, after_parser],
            "cli": [before_cli, after_cli],
            "native_regressions_only": True,
            "new_advisories_admitted": False,
            "operational_go": False,
        },
    )
    record(
        output / "SANITIZER.json",
        {
            "schema": "pamolive.expat-sanitizer/2",
            "local_backports": backports,
            "test_only_source_delta": "two actual-local size_t static assertions",
            "UBSan": True,
            "full_huge_attribute_trigger_executed": False,
            "installed_in_runtime": False,
            "fixed4_admitted": False,
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_output")
    main(*sys.argv[1:])
