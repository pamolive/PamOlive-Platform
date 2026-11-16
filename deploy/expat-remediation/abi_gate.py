"""Static GNU readelf comparison. Never run ldd or the inspected ELF."""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import command, need, read, record, sha

ROOT = Path("/usr/lib/x86_64-linux-gnu")
MODULE = Path("/usr/local/lib/python3.12/lib-dynload/pyexpat.cpython-312-x86_64-linux-gnu.so")


def symbols(text):
    result = []
    for line in text.splitlines():
        if not re.match(r"\s*\d+:\s", line):
            continue
        row = line.split()
        need(7 <= len(row) <= 9, "symbol_shape")
        if len(row) == 7:  # STN_UNDEF null symbol has no name.
            need(row[0] == "0:", "nameless_symbol")
            continue
        _, _, size, kind, binding, visibility, section, name, *index = row
        if binding not in {"GLOBAL", "WEAK"} or visibility not in {"DEFAULT", "PROTECTED"}:
            continue
        if kind not in {"FUNC", "OBJECT", "IFUNC", "NOTYPE", "TLS"}:
            continue
        if "@@" in name:
            plain, version = name.split("@@")
            default = True
        elif "@" in name:
            plain, version = name.split("@")
            default = False
        else:
            plain, version, default = name, None, True
        need(bool(plain) and (version is None or bool(version)), "symbol_name")
        result.append(
            {
                "name": plain,
                "version": version,
                "default": default,
                "defined": section != "UND",
                "weak": binding == "WEAK",
                "kind": kind,
                "size": int(size, 0) if size.startswith("0x") else int(size),
            }
        )
    need(len(result) < 100000, "symbol_count")
    return result


def resolves(required, exports):
    return any(
        e["defined"]
        and e["name"] == required["name"]
        and (not required.get("defined") or not required.get("default") or e["default"])
        and (required.get("kind", "NOTYPE") == "NOTYPE" or e["kind"] == required["kind"])
        and (
            required.get("kind") not in {"OBJECT", "TLS"}
            or e.get("size", 0) >= required.get("size", 0)
        )
        and (
            e["version"] == required["version"] if required["version"] is not None else e["default"]
        )
        for e in exports
    )


def compare(before, after):
    for name in ("pyexpat", "_elementtree"):
        need(before[name]["sha256"] != after[name]["sha256"], "old_python_xml_module_retained")
        need(
            any(s["defined"] and s["name"] == "PyInit_" + name for s in after[name]["symbols"]),
            "module_initializer_missing",
        )
        need(not after[name]["rpath"] and not after[name]["runpath"], "python_search_override")
        need(
            not any(s["defined"] and s["name"].startswith("XML_") for s in after[name]["symbols"]),
            "vendored_xml_exports",
        )
        for symbol in before[name].get("symbols", []):
            if symbol["defined"]:
                need(resolves(symbol, after[name]["symbols"]), "python_module_export_removed")
    for name in ("libexpat.so.1", "libexpatw.so.1"):
        old, new = before[name], after[name]
        need(old["soname"] == new["soname"] == name, "soname_changed")
        for symbol in old["symbols"]:
            if symbol["defined"]:
                need(resolves(symbol, new["symbols"]), "export_removed_or_nondefault")
        need(new["rpath"] == [] and new["runpath"] == [], "library_search_override")
    module = after["pyexpat"]
    need(
        "libexpat.so.1" in module["needed"] and not module["rpath"] and not module["runpath"],
        "pyexpat_still_vendored_or_search_override",
    )
    xml = [
        s
        for s in module["symbols"]
        if not s["defined"] and not s["weak"] and s["name"].startswith("XML_")
    ]
    need(len(xml) >= 20, "system_xml_imports_absent")
    need(
        not any(s["defined"] and s["name"].startswith("XML_") for s in module["symbols"]),
        "vendored_xml_exports",
    )
    need(all(resolves(s, after["libexpat.so.1"]["symbols"]) for s in xml), "xml_import_unresolved")


def capture(output):
    output = Path(output)
    output.mkdir(mode=0o700, parents=True)
    result = {}
    for name, alias in (
        ("libexpat.so.1", ROOT / "libexpat.so.1"),
        ("libexpatw.so.1", ROOT / "libexpatw.so.1"),
        ("pyexpat", MODULE),
        ("_elementtree", MODULE.with_name("_elementtree.cpython-312-x86_64-linux-gnu.so")),
    ):
        target = alias.resolve(strict=True)
        need(target.parent == alias.parent and target.is_file(), "provider_alias")
        raw = read(target, 4 * 1024**2)
        header = command(
            ["/usr/bin/readelf", "-W", "-h", str(target)], output, output / (name + "-header")
        )
        need(b"ELF64" in header and b"Advanced Micro Devices X86-64" in header, "elf_arch")
        dynamic = command(
            ["/usr/bin/readelf", "-W", "-d", str(target)], output, output / (name + "-dynamic")
        )
        dynsym = command(
            ["/usr/bin/readelf", "-W", "--dyn-syms", str(target)],
            output,
            output / (name + "-symbols"),
        )

        def tags(label):
            return re.findall(r"\(" + label + r"\).*?\[([^\]]*)\]", dynamic.decode("ascii"))

        soname = tags("SONAME")
        need(len(soname) <= 1, "multiple_soname")
        result[name] = {
            "alias": str(alias),
            "target": str(target),
            "sha256": sha(raw),
            "bytes": len(raw),
            "soname": soname[0] if soname else None,
            "needed": tags("NEEDED"),
            "rpath": tags("RPATH"),
            "runpath": tags("RUNPATH"),
            "symbols": symbols(dynsym.decode("ascii")),
        }
    record(output / "ABI.json", result)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "capture":
        capture(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "compare":
        compare(*(json.loads(read(p, 4 * 1024**2)) for p in sys.argv[2:]))
    else:
        raise SystemExit("capture NEW_DIR | compare BEFORE_ABI_JSON AFTER_ABI_JSON")
