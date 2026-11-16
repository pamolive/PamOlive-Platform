"""LINUX CI ONLY: disposable upstream test build, never installed in runtime."""

import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authenticate import main as authenticate
from build_debian import publish_build_failure
from common import ENV, command, material, need, read, record, write_new


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
        [str(source / "configure"), "--disable-shared", "--enable-static"],
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
    build_step(
        ["/usr/bin/make", "-j1", "check"],
        source,
        output / "check",
        stage="ubsan-check",
        seconds=300,
        cap=8 * 1024**2,
        env=env,
    )
    record(
        output / "SANITIZER.json",
        {
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
