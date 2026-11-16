"""Separate ABI DATA API. Legacy v1 policy/verification remains byte-exact."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import read
from legacy_inventory import MAX_FILE, Krb5Error, canonical, digest, require
from source_model import need, sha

LIBRARIES = {
    "libkrb5-3": ("libkrb5.so.3.3", "libkrb5.so.3"),
    "libk5crypto3": ("libk5crypto.so.3.1", "libk5crypto.so.3"),
    "libkrb5support0": ("libkrb5support.so.0.1", "libkrb5support.so.0"),
    "libgssapi-krb5-2": ("libgssapi_krb5.so.2.2", "libgssapi_krb5.so.2"),
}
# Old product witness, not a result for 1.22.3. Complete export lists are measured afresh
# and MUST hash to this old contract before any new/old tuple comparison is accepted.
OLD_ANCHORS = {
    "libgssapi-krb5-2": (171, "cca26b66225c33cb83da15a516922795df12f292bca90d23d09d3d77181e4a94"),
    "libk5crypto3": (107, "b2cf7cbaa77165d8d6f0bcd7294a4c8476a033e01705627cb760303ed4601215"),
    "libkrb5-3": (657, "f7f635232ccd9ccaa388ad9d3e9e45b09952874cc55055c73fdc8c79df1f0848"),
    "libkrb5support0": (101, "0c86c87a4931a4fd746531b649eafaa5ab8d7efec2b8bc53d9103e8f6753cbd0"),
}


def bind_old_product_baseline(value):
    need(type(value) is dict and type(value.get("libraries")) is dict, "old_ABI_record_type")
    need(set(value["libraries"]) == set(OLD_ANCHORS), "old_ABI_library_set")
    need(
        all(
            type(row) is dict and type(row.get("symbols")) is list
            for row in value["libraries"].values()
        ),
        "old_ABI_record_type",
    )
    compare(value, value)  # Validate every tuple type/visibility/data size and duplicate key.
    for package, expected in OLD_ANCHORS.items():
        row = value["libraries"][package]
        need(
            type(row.get("exported_symbols")) is int
            and 0 < row["exported_symbols"] == len(row["symbols"]) <= 100000
            and type(row.get("abi_sha256")) is str
            and row["abi_sha256"] == digest(canonical(sorted(row["symbols"])).encode()),
            "old_ABI_record_digest_count",
        )
        need(
            (row["exported_symbols"], row["abi_sha256"]) == expected
            and row["soname"] == LIBRARIES[package][1],
            "baseline_must_match_received_old_product_ABI",
        )


def elf_exports(data):
    """ELF64/amd64 SONAME and exported symbols, including GNU symbol versions."""
    require(64 <= len(data) <= MAX_FILE and data[:6] == b"\x7fELF\x02\x01", "elf_platform")
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        require(
            header[1] == 3 and header[2] == 62 and header[11] == 64 and 0 < header[12] <= 512,
            "elf_header",
        )
        sections = [
            struct.unpack_from("<IIQQQQIIQQ", data, header[6] + i * 64) for i in range(header[12])
        ]
        require(all(s[1] == 8 or s[4] + s[5] <= len(data) for s in sections), "elf_bounds")

        def blob(section):
            return data[section[4] : section[4] + section[5]]

        def text(table, offset):
            end = table.find(b"\0", offset)
            require(0 <= offset < len(table) and offset <= end <= offset + 1024, "elf_string")
            return table[offset:end].decode("ascii")

        symbols = [s for s in sections if s[1] == 11]
        dynamics = [s for s in sections if s[1] == 6]
        require(len(symbols) == len(dynamics) == 1, "elf_tables")
        sym, dynamic = symbols[0], dynamics[0]
        require(
            sym[9] == 24
            and sym[5] % 24 == 0
            and sym[5] // 24 <= 100000
            and sym[6] < len(sections)
            and dynamic[6] < len(sections),
            "elf_symbols",
        )
        strings = blob(sections[sym[6]])
        dynstrings = blob(sections[dynamic[6]])
        sonames = []
        require(dynamic[5] % 16 == 0, "elf_dynamic")
        for offset in range(dynamic[4], dynamic[4] + dynamic[5], 16):
            tag, value = struct.unpack_from("<qQ", data, offset)
            if tag == 14:
                sonames.append(text(dynstrings, value))
            require(tag not in (15, 29), "elf_search_path")
        require(len(sonames) == 1, "elf_soname")
        versions = {0: "", 1: ""}
        definitions = [s for s in sections if s[1] == 0x6FFFFFFD]
        require(len(definitions) == 1, "elf_version_definitions")
        definition = definitions[0]
        require(definition[6] < len(sections), "elf_version_strings")
        version_strings = blob(sections[definition[6]])
        offset, visits = 0, set()
        while True:
            require(offset not in visits and offset + 20 <= definition[5], "elf_version_bounds")
            visits.add(offset)
            version, flags, ndx, cnt, _, aux, nxt = struct.unpack_from(
                "<HHHHIII", data, definition[4] + offset
            )
            require(
                version == 1 and cnt > 0 and offset + aux + 8 <= definition[5],
                "elf_version_definition",
            )
            name, _ = struct.unpack_from("<II", data, definition[4] + offset + aux)
            require(ndx not in versions or ndx == 1 and flags & 1, "elf_version_duplicate")
            versions[ndx] = text(version_strings, name)
            if not nxt:
                break
            require(nxt >= 20, "elf_version_next")
            offset += nxt
        version_sections = [
            s for s in sections if s[1] == 0x6FFFFFFF and s[6] == sections.index(sym)
        ]
        require(
            len(version_sections) == 1 and version_sections[0][5] == sym[5] // 24 * 2,
            "elf_symbol_versions",
        )
        versym = version_sections[0]
        exported = []
        for i in range(sym[5] // 24):
            name, info, other, shndx, _, size = struct.unpack_from("<IBBHQQ", data, sym[4] + i * 24)
            if shndx == 0 or info >> 4 not in (1, 2, 10) or other & 3 not in (0, 3):
                continue
            ndx = struct.unpack_from("<H", data, versym[4] + i * 2)[0]
            require(ndx & 0x7FFF in versions, "elf_export_version")
            exported.append(
                [
                    text(strings, name),
                    info,
                    other & 3,
                    versions[ndx & 0x7FFF],
                    bool(ndx & 0x8000),
                    size if info & 15 in (1, 6) else None,
                ]
            )
        require(
            exported and len(exported) == len({x[0] + "@" + x[3] for x in exported}),
            "elf_export_duplicates",
        )
        return {
            "soname": sonames[0],
            "exported_symbols": len(exported),
            "abi_sha256": digest(canonical(sorted(exported)).encode()),
            "symbols": sorted(exported),
        }
    except (struct.error, UnicodeError, IndexError) as exc:
        raise Krb5Error("elf_malformed") from exc


def capture(root):
    root = Path(root).resolve(strict=True)
    libraries = {}
    for package, (filename, soname) in LIBRARIES.items():
        path = root / "usr/lib/x86_64-linux-gnu" / filename
        target = path.resolve(strict=True)
        need(target.is_relative_to(root), "provider_escape")
        raw = read(target, MAX_FILE)
        value = elf_exports(raw)
        need(value["soname"] == soname, "provider_soname")
        libraries[package] = {"file": filename, "file_sha256": sha(raw), **value}
    return {
        "schema": "pamolive.krb5-ABI-DATA/1",
        "libraries": libraries,
        "product_admission": False,
        "operational_GO": False,
    }


def compare(before, after):
    need(set(before["libraries"]) == set(after["libraries"]) == set(LIBRARIES), "ABI_library_set")
    additions = {}
    for package in LIBRARIES:
        old, new = before["libraries"][package], after["libraries"][package]
        need(old["soname"] == new["soname"] == LIBRARIES[package][1], "ABI_soname_changed")
        old_rows, new_rows = old["symbols"], new["symbols"]
        for rows in (old_rows, new_rows):
            need(
                rows
                and all(
                    type(row) is list
                    and len(row) == 6
                    and type(row[0]) is str
                    and 0 < len(row[0]) <= 1024
                    and type(row[1]) is int
                    and 0 <= row[1] <= 255
                    and type(row[2]) is int
                    and row[2] in {0, 3}
                    and type(row[3]) is str
                    and len(row[3]) <= 1024
                    and type(row[4]) is bool
                    and (row[5] is None or type(row[5]) is int and 0 <= row[5] < 2**64)
                    for row in rows
                ),
                "ABI_row_shape",
            )
            need(len({(row[0], row[3]) for row in rows}) == len(rows), "ABI_duplicate")
        new_map = {(row[0], row[3]): row for row in new_rows}
        for row in old_rows:
            need(new_map.get((row[0], row[3])) == row, "ABI_old_export_changed")
        old_keys = {(row[0], row[3]) for row in old_rows}
        additions[package] = [row for row in new_rows if (row[0], row[3]) not in old_keys]
    return {
        "schema": "pamolive.krb5-ABI-comparison-DATA/1",
        "all_old_exports_preserved": True,
        "compared_fields": [
            "name",
            "binding_and_type",
            "visibility",
            "GNU_version",
            "hidden_version_bit",
            "OBJECT_or_TLS_size",
        ],
        "candidate_additions": additions,
        "candidate_profile_v2_admitted": False,
        "product_admission": False,
        "operational_GO": False,
    }
