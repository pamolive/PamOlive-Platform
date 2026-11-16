"""Rebuild pyexpat AND its exact-version capsule consumer _elementtree."""

import io
import re
import shlex
import sys
import sysconfig
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from authenticate import main as authenticate
from common import check_materials, command, material, need, read, record, sha, write_new

OLD_MODULE_SHAS = {
    "pyexpat": "5c099081b395cf25acfca1feda283c6730dc3647a70f3221f4d95b48fffe0219",
    "_elementtree": "47441b4b394664b6efd5b4ad6780a627962d4f105fcc8407929175fce0c0b013",
}
SUFFIX = ".cpython-312-x86_64-linux-gnu.so"
KEYS = (
    "CC",
    "CFLAGS",
    "CCSHARED",
    "LDSHARED",
    "LDFLAGS",
    "LIBS",
    "SYSLIBS",
    "SOABI",
    "EXT_SUFFIX",
    "CONFIG_ARGS",
    "MULTIARCH",
    "Py_DEBUG",
    "Py_ENABLE_SHARED",
    "PY_STDMODULE_CFLAGS",
    "PY_CFLAGS",
    "PY_CFLAGS_NODIST",
    "PY_CPPFLAGS",
    "CFLAGSFORSHARED",
    "PY_LDFLAGS",
    "PY_LDFLAGS_NODIST",
)


def flags(text):
    result = shlex.split(text or "")
    for word in result:
        if word == "-fuse-linker-plugin":  # ordinary GCC LTO switch, not a supplied plugin path
            continue
        need(
            not any(
                bad in word
                for bad in (
                    "@",
                    "plugin",
                    "specs=",
                    "sysroot",
                    "-B",
                    "-include",
                    "-fprofile",
                    "rpath",
                    "dynamic-linker",
                )
            ),
            "unsupported_build_flag",
        )
    return result


def stdmodule_flags(text):
    need(isinstance(text, str) and bool(text), "stdlib_build_flags_missing")
    result = flags(text)
    aliases = {
        "-I.": "-I/usr/local/include/python3.12",
        "-I./Include": "-I/usr/local/include/python3.12",
        "-I./Include/internal": "-I/usr/local/include/python3.12/internal",
        "-I/usr/src/python/Include": "-I/usr/local/include/python3.12",
        "-I/usr/src/python/Include/internal": "-I/usr/local/include/python3.12/internal",
    }
    converted = [aliases.get(item, item) for item in result]
    need(
        all(
            not item.startswith("-I")
            or item
            in {"-I/usr/local/include/python3.12", "-I/usr/local/include/python3.12/internal"}
            for item in converted
        ),
        "unknown_original_header_path",
    )
    return converted


def abi(config, version):
    need(tuple(version) == (3, 12, 16), "cpython_exact_version")
    need(
        config["SOABI"] == "cpython-312-x86_64-linux-gnu" and config["EXT_SUFFIX"] == SUFFIX,
        "cpython_soabi",
    )
    need(
        config["MULTIARCH"] == "x86_64-linux-gnu"
        and not config["Py_DEBUG"]
        and config["Py_ENABLE_SHARED"] == 1,
        "cpython_config",
    )
    cc, ld = flags(config["CC"]), flags(config["LDSHARED"])
    need(cc == ["gcc"] and ld[0] == "gcc" and "-shared" in ld, "compiler_model")
    return [
        "/usr/bin/gcc",
        *ld[1:],
        *stdmodule_flags(config["PY_STDMODULE_CFLAGS"]),
        *flags(config["CCSHARED"]),
        *flags(config["PY_LDFLAGS"]),
        *flags(config["PY_LDFLAGS_NODIST"]),
    ]


def source_parts(raw):
    names = {
        "Python-3.12.16/Modules/pyexpat.c": "pyexpat.c",
        "Python-3.12.16/Modules/clinic/pyexpat.c.h": "clinic/pyexpat.c.h",
        "Python-3.12.16/Modules/_elementtree.c": "_elementtree.c",
        "Python-3.12.16/Modules/clinic/_elementtree.c.h": "clinic/_elementtree.c.h",
    }
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
        count, total = 0, 0
        for row in archive:
            count += 1
            total += row.size
            need(count <= 30000 and total <= 256 * 1024**2, "python_tar_budget")
            if row.name in names:
                need(
                    row.isfile() and row.name not in result and row.size < 2 * 1024**2,
                    "python_source_entry",
                )
                result[row.name] = archive.extractfile(row).read(row.size + 1)
    need(set(result) == set(names), "python_source_count")
    selected = {names[k]: v for k, v in result.items()}
    capsule_contract(selected)
    return selected


def capsule_contract(source):
    producer = source["pyexpat.c"].decode("utf-8")
    consumer = source["_elementtree.c"].decode("utf-8")
    for field in ("MAJOR", "MINOR", "MICRO"):
        need(
            producer.count(f"capi->{field}_VERSION = XML_{field}_VERSION;") == 1,
            "capsule_producer_version_changed",
        )
        need(
            consumer.count(f"st->expat_capi->{field}_VERSION != XML_{field}_VERSION") == 1,
            "capsule_consumer_guard_changed",
        )


def header_trace(trace, name, include):
    includes = set(re.findall(r"^\.+ (/[^\n]+)$", trace, re.M))
    for header in ("expat.h", "Python.h", "pyexpat.h"):
        expected = "/usr/include/expat.h" if header == "expat.h" else str(include / header)
        need(
            {path for path in includes if path.endswith("/" + header)} == {expected},
            "compiler_consumed_wrong_header",
        )
    if name == "pyexpat":
        need(
            {path for path in includes if path.endswith("/expat_config.h")}
            == {"/usr/include/x86_64-linux-gnu/expat_config.h"},
            "compiler_consumed_wrong_config",
        )
    return sha(trace.encode())


def main(materials, output):
    materials, output = Path(materials).resolve(), Path(output).resolve()
    check_materials(materials)
    output.mkdir(mode=0o700)
    authenticate(materials, output / "authentication")
    config = {k: sysconfig.get_config_var(k) for k in KEYS}
    base_argv = abi(config, sys.version_info[:3])
    for name, expected in OLD_MODULE_SHAS.items():
        old_module = Path("/usr/local/lib/python3.12/lib-dynload/" + name + SUFFIX)
        need(sha(read(old_module, 2 * 1024**2)) == expected, "original_module_pin")
    include = Path("/usr/local/include/python3.12")
    header_names = (
        "Python.h",
        "pyconfig.h",
        "pyexpat.h",
        "internal/pycore_ceval.h",
        "internal/pycore_runtime.h",
    )
    headers = {name: sha(read(include / name, 2 * 1024**2)) for name in header_names}
    system_config = read("/usr/include/x86_64-linux-gnu/expat_config.h", 65536)
    expat_header = read("/usr/include/expat.h", 128 * 1024)
    for field, value in (("MAJOR", 2), ("MINOR", 10), ("MICRO", 0)):
        need(
            re.search(
                rb"^\s*#\s*define\s+XML_"
                + field.encode()
                + rb"_VERSION\s+"
                + str(value).encode()
                + rb"\s*$",
                expat_header,
                re.M,
            ),
            "system_sdk_version",
        )
    for macro in ("XML_GE", "XML_DTD", "XML_NS"):
        need(
            re.search(rb"^\s*#\s*define\s+" + macro.encode() + rb"\s+1\s*$", system_config, re.M),
            "expat_feature_config",
        )
    source = source_parts(material(materials, "Python-3.12.16.tar.xz"))
    (output / "clinic").mkdir()
    for name, raw in source.items():
        write_new(output / name, raw)
    built = {}
    for name in OLD_MODULE_SHAS:
        target = output / (name + SUFFIX)
        # Same Expat2.10 header for BOTH; no version lie or bypass of the capsule guard.
        argv = base_argv + [
            "-H",
            "-I" + str(include),
            "-I" + str(include / "internal"),
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include",
            "-o",
            str(target),
            str(output / (name + ".c")),
            *(["-lexpat"] if name == "pyexpat" else []),
            *flags(config["LIBS"]),
            *flags(config["SYSLIBS"]),
        ]
        command(argv, output, output / ("compile-" + name), seconds=180)
        trace = read(output / ("compile-" + name) / "stderr", 2 * 1024**2).decode("utf-8")
        built[name] = {
            "old_sha256": OLD_MODULE_SHAS[name],
            "new_sha256": sha(read(target, 4 * 1024**2)),
            "command": argv,
            "header_trace_sha256": header_trace(trace, name, include),
        }
    record(
        output / "BUILD.json",
        {
            "interpreter": sys.version,
            "sysconfig": config,
            "headers": headers,
            "source_sha256": {k: sha(v) for k, v in source.items()},
            "modules": built,
            "expat_config_sha256": sha(system_config),
            "expat_header_sha256": sha(expat_header),
            "fixed4_admitted": False,
            "pending": [
                "ELF/provider/ABI",
                "runtime feature/capsule tests",
                "four-CVE regressions",
            ],
        },
    )


if __name__ == "__main__":
    need(len(sys.argv) == 3, "usage_materials_new_output")
    main(*sys.argv[1:])
