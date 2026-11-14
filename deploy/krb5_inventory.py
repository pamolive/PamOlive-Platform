"""Offline verification of a reviewed, source-built Debian Kerberos backport.

Only trusted qualification roots are supported. Metadata consistency is not a
cryptographic proof of compilation or an independently authenticated review.
This tool never connects to a KDC, invokes a library or modifies package state.
"""

import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import struct
from pathlib import Path, PurePosixPath

SCHEMA = "pamolive.krb5-backport-inventory.v1"
BASE_SCHEMA = "pamolive.krb5-backport-baseline.v1"
PROVENANCE_SCHEMA = "pamolive.krb5-backport-provenance.v1"
PREFIX = "/usr/share/pamolive/krb5-backport"
MANIFEST_PATH = PREFIX + "/inventory.json"
VERSION = "1.21.3-5+deb13u1+pamolive1"
BASE_VERSION = "1.21.3-5+deb13u1"
COMMIT = "205832663330da308d9d031a17326b68a16715fd"
PATCH = "e676f3727b3c984aa5a7baaafdb39394c8774c913ace0c3ce302e9b81aaa19ee"
TEST_COMPAT_PATCH = "1227fc24b76e62371bd94346e1a653906e2e964d39ac25f095c32ccbe8a9cd27"
KEYRING_TESTS = ("keyring collection tests", "keyring ccache tests")
KEYRING_COMMAND = ["/usr/bin/keyctl", "add", "user", "pamolive-krb5-probe", "synthetic", "@p"]
KEYRING_STDERR = hashlib.sha256(b"add_key: Operation not permitted\n").hexdigest()
DECODER_SOURCE = {
    "before": "c35b90cfb1b765a112b091843aebb774d1c45b5f966ee99edfdfdd4bd2d6a0bc",
    "after": "218616414321edb52a00f8bb2659429bf9f820d3353978b705292088bf914740",
}
SOURCES = {
    "krb5_1.21.3.orig.tar.gz": "b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35",
    "krb5_1.21.3-5+deb13u1.debian.tar.xz":
        "02b873b239fbe7ddf016dfe44deba4130673f4606c18c93da0622e2bc8500fb4",
}
LIBRARIES = {
    "libkrb5-3": ("libkrb5.so.3.3", "libkrb5.so.3"),
    "libk5crypto3": ("libk5crypto.so.3.1", "libk5crypto.so.3"),
    "libkrb5support0": ("libkrb5support.so.0.1", "libkrb5support.so.0"),
    "libgssapi-krb5-2": ("libgssapi_krb5.so.2.2", "libgssapi_krb5.so.2"),
}
MAX_FILE = 64 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")


class Krb5Error(ValueError):
    """Bounded failure code, never raw build output or local path contents."""


def require(condition, code):
    if not condition:
        raise Krb5Error(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024**2,
            "json_file_budget")
    value = json.loads(path.read_bytes(), object_pairs_hook=pairs)
    # Traversal itself is bounded; deeply nested JSON fails closed in the CLI.
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        require(depth <= 24 and count <= 50000, "json_structure_budget")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            require(len(item) <= 65536 and "\0" not in item, "json_string_budget")
    return value


def local(root, name):
    require(isinstance(name, str) and name.startswith("/") and "\\" not in name,
            "path_invalid")
    pure = PurePosixPath(name)
    require(".." not in pure.parts and str(pure) == name, "path_invalid")
    path = root / name.lstrip("/")
    # Final files and ancestors must be ordinary paths, never followed symlinks.
    require(not path.is_symlink() and all(not p.is_symlink() for p in path.parents
                                        if p != root and p.is_relative_to(root)),
            "path_symlink")
    require(path.resolve(strict=True).is_relative_to(root), "path_escape")
    return path


def read_file(root, name, maximum=MAX_FILE):
    path = local(root, name)
    require(path.is_file() and path.stat().st_size <= maximum, "file_budget")
    return path.read_bytes()


def elf_abi(data):
    """ELF64/amd64 SONAME and exported symbols, including GNU symbol versions."""
    require(64 <= len(data) <= MAX_FILE and data[:6] == b"\x7fELF\x02\x01", "elf_platform")
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        require(header[1] == 3 and header[2] == 62 and header[11] == 64 and
                0 < header[12] <= 512, "elf_header")
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + i * 64)
                    for i in range(header[12])]
        require(all(s[1] == 8 or s[4] + s[5] <= len(data) for s in sections), "elf_bounds")

        def blob(section):
            return data[section[4]:section[4] + section[5]]

        def text(table, offset):
            end = table.find(b"\0", offset)
            require(0 <= offset < len(table) and offset <= end <= offset + 1024,
                    "elf_string")
            return table[offset:end].decode("ascii")

        symbols = [s for s in sections if s[1] == 11]
        dynamics = [s for s in sections if s[1] == 6]
        require(len(symbols) == len(dynamics) == 1, "elf_tables")
        sym, dynamic = symbols[0], dynamics[0]
        require(sym[9] == 24 and sym[5] % 24 == 0 and sym[5] // 24 <= 100000 and
                sym[6] < len(sections) and dynamic[6] < len(sections), "elf_symbols")
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
                "<HHHHIII", data, definition[4] + offset)
            require(version == 1 and cnt > 0 and offset + aux + 8 <= definition[5],
                    "elf_version_definition")
            name, _ = struct.unpack_from("<II", data, definition[4] + offset + aux)
            require(ndx not in versions or ndx == 1 and flags & 1, "elf_version_duplicate")
            versions[ndx] = text(version_strings, name)
            if not nxt:
                break
            require(nxt >= 20, "elf_version_next")
            offset += nxt
        version_sections = [s for s in sections if s[1] == 0x6FFFFFFF and
                            s[6] == sections.index(sym)]
        require(len(version_sections) == 1 and version_sections[0][5] == sym[5] // 24 * 2,
                "elf_symbol_versions")
        versym = version_sections[0]
        exported = []
        for i in range(sym[5] // 24):
            name, info, other, shndx, _, size = struct.unpack_from("<IBBHQQ", data, sym[4] + i * 24)
            if shndx == 0 or info >> 4 not in (1, 2, 10) or other & 3 not in (0, 3):
                continue
            ndx = struct.unpack_from("<H", data, versym[4] + i * 2)[0]
            require(ndx & 0x7FFF in versions, "elf_export_version")
            exported.append([text(strings, name), info, other & 3, versions[ndx & 0x7FFF],
                             bool(ndx & 0x8000), size if info & 15 in (1, 6) else None])
        require(exported and len(exported) == len({x[0] + "@" + x[3] for x in exported}),
                "elf_export_duplicates")
        return {"soname": sonames[0], "exported_symbols": len(exported),
                "abi_sha256": digest(canonical(sorted(exported)).encode())}
    except (struct.error, UnicodeError, IndexError) as exc:
        raise Krb5Error("elf_malformed") from exc


def packages(root):
    raw = read_file(root, "/var/lib/dpkg/status", 8 * 1024**2).decode().replace("\r\n", "\n")
    result = {}
    for paragraph in raw.split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if ": " in line and not line.startswith((" ", "\t")):
                key, value = line.split(": ", 1)
                require(key not in fields, "dpkg_duplicate_field")
                fields[key] = value
        name = fields.get("Package")
        if name in LIBRARIES:
            require(name not in result and fields.get("Status") == "install ok installed" and
                    fields.get("Architecture") == "amd64", "dpkg_identity")
            result[name] = fields.get("Version")
    require(set(result) == set(LIBRARIES), "dpkg_missing")
    return result


def baseline(*, root=Path("/"), version=BASE_VERSION):
    root = root.resolve(strict=True)
    installed = packages(root)
    require(set(installed.values()) == {version}, "dpkg_version")
    libraries = []
    for package, (filename, soname) in sorted(LIBRARIES.items()):
        path = "/usr/lib/x86_64-linux-gnu/" + filename
        data = read_file(root, path)
        abi = elf_abi(data)
        require(abi["soname"] == soname, "library_soname")
        libraries.append({"package": package, "version": version, "path": path,
                          "sha256": digest(data), "class": 64, **abi})
    return {"schema": BASE_SCHEMA, "packages": installed, "libraries": libraries}


def evidence_name(name):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}", name)
            is not None, "evidence_name")
    return name


def cleartext(data):
    text = data.decode("utf-8").replace("\r\n", "\n")
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
        require("\n\n" in text and "\n-----BEGIN PGP SIGNATURE-----\n" in text,
                "signed_document")
        text = text.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----\n", 1)[0] + "\n"
        text = "\n".join(line[2:] if line.startswith("- ") else line for line in text.split("\n"))
    return text


def checksum_section(text, field):
    lines, result, inside = text.splitlines(), {}, False
    for line in lines:
        if line == field + ":":
            require(not inside and not result, "checksum_section_duplicate")
            inside = True
        elif inside and line.startswith(" "):
            parts = line.split()
            require(len(parts) == 3 and SHA.fullmatch(parts[0]) and parts[1].isdigit() and
                    parts[2] not in result, "checksum_entry")
            result[parts[2]] = {"sha256": parts[0], "size": int(parts[1])}
        elif inside:
            inside = False
    require(result, "checksum_section_missing")
    return result


def validate_chain(provenance, files):
    """Check signed-chain byte links; cryptographic gpgv runs in the build."""
    chain = provenance.get("apt_chain", {})
    fields = ("status_file", "inrelease_file", "release_file", "index_file",
              "source_record_file", "keyring_file", "dsc_file")
    names = [chain.get(key) for key in fields]
    require(all(name in files for name in names) and len(set(names)) == len(fields),
            "apt_chain_missing")
    signers = chain.get("signer_fingerprints")
    require(isinstance(signers, list) and 1 <= len(signers) <= 8 and
            len(set(signers)) == len(signers) and all(isinstance(signer, str) and
            re.fullmatch(r"(?:[A-F0-9]{40}|[A-F0-9]{64})", signer) for signer in signers),
            "apt_signers")
    status = files[chain["status_file"]].decode("ascii")
    lines = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] ")]
    require(not any(len(row) < 2 or row[1] in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG",
                    "REVKEYSIG", "NO_PUBKEY", "FAILURE") for row in lines), "apt_signature_failed")
    require(any(len(row) >= 3 and row[1] == "VALIDSIG" and
                (row[2] in signers or row[-1] in signers) for row in lines),
            "apt_signature_missing")
    signed = files[chain["inrelease_file"]]
    require(signed.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----"), "inrelease_signed")
    release = files[chain["release_file"]]
    require(cleartext(signed) == release.decode().replace("\r\n", "\n"), "release_payload")
    index_name = chain.get("index_release_path")
    require(isinstance(index_name, str) and re.fullmatch(
        r"main/source/Sources\.(?:xz|gz)", index_name), "source_index_path")
    index = files[chain["index_file"]]
    require(checksum_section(cleartext(signed), "SHA256").get(index_name) == {
        "sha256": digest(index), "size": len(index)}, "source_index_hash")
    opener = lzma.open if index_name.endswith(".xz") else gzip.open
    try:
        with opener(io.BytesIO(index), "rb") as stream:
            plain = stream.read(64 * 1024**2 + 1)
    except (lzma.LZMAError, EOFError) as exc:
        raise Krb5Error("source_index_compression") from exc
    require(len(plain) <= 64 * 1024**2, "source_index_budget")
    record = files[chain["source_record_file"]].decode().replace("\r\n", "\n").strip()
    paragraphs = plain.decode().replace("\r\n", "\n").split("\n\n")
    require(sum(part.strip() == record for part in paragraphs) == 1 and
            "Package: krb5" in record.splitlines() and
            "Version: " + BASE_VERSION in record.splitlines(), "source_record")
    checksums = checksum_section(record, "Checksums-Sha256")
    require(all(checksums.get(name, {}).get("sha256") == sha
                for name, sha in SOURCES.items()), "source_archive_hashes")
    dsc = files[chain["dsc_file"]]
    require(checksums.get("krb5_" + BASE_VERSION + ".dsc") == {
        "sha256": digest(dsc), "size": len(dsc)}, "dsc_hash")
    dsc_checksums = checksum_section(cleartext(dsc), "Checksums-Sha256")
    require(all(dsc_checksums.get(name, {}).get("sha256") == sha
                for name, sha in SOURCES.items()), "dsc_source_hashes")


def validate_regression(value):
    require(value.get("schema") == "pamolive.krb5-asn1-regression.v1" and
            value.get("patch_sha256") == PATCH, "asn1_identity")
    require(value.get("source_original_sha256") == DECODER_SOURCE["before"] and
            value.get("source_patched_sha256") == DECODER_SOURCE["after"], "asn1_source_hash")
    cases = {"long_valid", "empty", "bad_tag", "truncated", "allocation_failure", "partial_cleanup"}
    for phase in ("before", "after"):
        result = value.get(phase, {})
        require(result.get("schema") == "pamolive.krb5-asn1-regression.v1" and
                result.get("verified") is True and result.get("phase") ==
                ("baseline" if phase == "before" else "patched") and
                result.get("source_file_sha256") == DECODER_SOURCE[phase] and
                result.get("patch_sha256") == PATCH and
                result.get("upstream_make_check_replaced") is False and
                result.get("case_count") == 6 and result.get("element_count") == 256 and
                set(result.get("cases", {})) == cases, "asn1_cases")
        for key in ("harness_sha256", "executable_sha256"):
            require(SHA.fullmatch(str(result.get(key))), "asn1_artifact_hash")
        objects = result.get("objects")
        require(isinstance(objects, list) and len(objects) == 2 and
                {item.get("name", "").rsplit(".", 1)[0] for item in objects} ==
                {"asn1_encode", "asn1_k_encode"} and all(
                re.fullmatch(r"asn1_(?:k_)?encode\.(?:o|so)", item.get("name", "")) and
                SHA.fullmatch(str(item.get("sha256"))) for item in objects), "asn1_object_hashes")
        for name, case in result["cases"].items():
            require(case.get("status") == "passed" and
                    case.get("decoder_success") is (name in ("long_valid", "empty")) and
                    type(case.get("live_allocations_after_cleanup")) is int and
                    case["live_allocations_after_cleanup"] == 0, "asn1_case_failed")
            require(all(type(case.get(key)) is int and 0 <= case[key] <= 10000 for key in (
                "allocation_attempts", "malloc_calls", "calloc_calls", "realloc_calls",
                "failure_points")), "asn1_allocation_counts")
        long = result["cases"]["long_valid"]
        attempts = 257 if phase == "before" else 2
        require(long.get("decoded_count") == 256 and
                long.get("decoded_value") == 7, "asn1_decoded_semantics")
        require(long["allocation_attempts"] == attempts and long["malloc_calls"] == 0 and
                long["calloc_calls"] == (1 if phase == "before" else 2) and
                result["cases"]["allocation_failure"]["failure_points"] == attempts,
                "asn1_failure_sweep")
    require(value["before"]["cases"]["long_valid"].get("realloc_calls") == 256 and
            value["after"]["cases"]["long_valid"].get("realloc_calls") == 0 and
            value["after"]["cases"]["long_valid"].get("calloc_calls") == 2,
            "asn1_allocation_regression")
    require(value["before"]["harness_sha256"] == value["after"]["harness_sha256"],
            "asn1_harness_changed")


def validate_debian_tests(tests, provenance):
    evidence = provenance["evidence"]
    require(tests.get("schema") == "pamolive.krb5-debian-tests.v1" and
            tests.get("tests_enabled") is True and tests.get("exit_code") == 0 and
            type(tests.get("jobs")) is int and tests["jobs"] == 1 and
            tests.get("command") == "dpkg-buildpackage -B -us -uc -j1" and
            SHA.fullmatch(str(tests.get("log_sha256"))) and
            tests["log_sha256"] == evidence.get("debian-build.log"), "debian_tests_failed")
    skips = tests.get("capability_skips", [])
    if tests.get("status") == "passed":
        require(skips == [], "undocumented_capability_skips")
        return
    require(tests.get("status") == "passed_with_capability_skips" and
            isinstance(skips, list) and len(skips) == 1, "debian_tests_failed")
    item = skips[0]
    require(item.get("capability") == "kernel_keyring" and
            item.get("reason") == "docker_seccomp_eperm" and
            item.get("tests") == list(KEYRING_TESTS) and
            item.get("historical_test_message") == "keyring support not built" and
            tests.get("test_python") == "/usr/bin/python3", "capability_scope")
    names = {"probe_file": "keyctl-probe.json", "probe_script_file": "keyctl-probe.py",
             "test_patch_file": "test-keyring-compat.patch"}
    require(all(item.get(key) == name and name in evidence for key, name in names.items()) and
            SHA.fullmatch(str(TEST_COMPAT_PATCH)) and
            evidence["test-keyring-compat.patch"] == TEST_COMPAT_PATCH, "capability_evidence")
    require(item.get("phase_logs") == {"baseline": "baseline-build.log",
            "patched": "debian-build.log"} and "baseline-build.log" in evidence,
            "capability_logs")
    counts = item.get("phase_counts", {})
    require(set(counts) == {"baseline", "patched"} and all(
            isinstance(values, dict) and set(values) == set(KEYRING_TESTS) and all(
            type(count) is int and 1 <= count <= 64 for count in values.values())
            for values in counts.values()), "capability_counts")
    require(type(item.get("count")) is int and item["count"] ==
            sum(sum(values.values()) for values in counts.values()), "capability_count_total")


def validate_capability_files(tests, provenance, files):
    if tests.get("status") != "passed_with_capability_skips":
        return
    item = tests["capability_skips"][0]
    probe = json.loads(files[item["probe_file"]], object_pairs_hook=pairs)
    require(probe.get("schema") == "pamolive.krb5-keyring-probe.v1" and
            probe.get("exit_code") == 1 and probe.get("errno") == "EPERM" and
            probe.get("stderr_sha256") == KEYRING_STDERR and
            probe.get("probe_script_sha256") == provenance["evidence"][item["probe_script_file"]]
            and probe.get("command") == KEYRING_COMMAND and probe.get("seccomp_mode") == 2 and
            probe.get("network") == "none" and probe.get("supported") is False,
            "capability_probe")
    for phase, name in item["phase_logs"].items():
        text = files[name].decode("utf-8", errors="replace")
        counts = {test: 0 for test in KEYRING_TESTS}
        for test in KEYRING_TESTS:
            counts[test] = len(re.findall(r"^\*\*\* Skipping: " + re.escape(test) +
                              r": keyring support not built$", text, re.M))
        require(counts == item["phase_counts"][phase], "capability_log_counts")


def validate_manifest(value):
    """Pure typed claim checks; file and package checks are done by inventory()."""
    require(isinstance(value, dict) and value.get("schema") == SCHEMA, "inventory_schema")
    provenance = value.get("provenance", {})
    require(provenance.get("schema") == PROVENANCE_SCHEMA and
            provenance.get("version") == VERSION and
            provenance.get("base_version") == BASE_VERSION and
            provenance.get("upstream_commit") == COMMIT and
            provenance.get("patch_sha256") == PATCH and
            provenance.get("sources") == SOURCES, "backport_identity")
    require(provenance.get("build") == {"jobs": 1, "tests_enabled": True}, "build_profile")
    evidence = provenance.get("evidence")
    require(isinstance(evidence, dict) and 5 <= len(evidence) <= 20, "evidence_budget")
    for name, sha in evidence.items():
        evidence_name(name)
        require(SHA.fullmatch(str(sha)) is not None, "evidence_hash")
    require(evidence.get("baseline.json") and evidence.get("upstream.patch") == PATCH,
            "required_evidence")
    require(SHA.fullmatch(str(value.get("provenance_sha256"))) is not None,
            "provenance_hash")
    require(value.get("packages") == dict.fromkeys(LIBRARIES, VERSION), "inventory_packages")
    previous = value.get("baseline", {})
    require(previous.get("schema") == BASE_SCHEMA and
            previous.get("packages") == dict.fromkeys(LIBRARIES, BASE_VERSION), "baseline_packages")
    for rows, version in ((previous.get("libraries"), BASE_VERSION),
                          (value.get("libraries"), VERSION)):
        require(isinstance(rows, list) and len(rows) == 4 and
                {item.get("package") for item in rows} == set(LIBRARIES), "library_set")
        for item in rows:
            filename, soname = LIBRARIES[item["package"]]
            require(item.get("path") == "/usr/lib/x86_64-linux-gnu/" + filename and
                    item.get("version") == version and item.get("soname") == soname and
                    item.get("class") == 64 and type(item.get("exported_symbols")) is int and
                    0 < item["exported_symbols"] <= 100000 and
                    SHA.fullmatch(str(item.get("sha256"))) and
                    SHA.fullmatch(str(item.get("abi_sha256"))), "library_record")
    before = {item["package"]: item for item in previous["libraries"]}
    for item in value["libraries"]:
        require(all(item[key] == before[item["package"]][key]
                    for key in ("soname", "abi_sha256", "exported_symbols")), "abi_changed")
    require(next(item for item in value["libraries"] if item["package"] == "libkrb5-3")["sha256"] !=
            before["libkrb5-3"]["sha256"], "patched_library_unchanged")
    validate_regression(value.get("asn1", {}))
    validate_debian_tests(value.get("debian_tests", {}), provenance)
    return value


def inventory(*, root=Path("/")):
    root = root.resolve(strict=True)
    path = local(root, PREFIX + "/provenance.json")
    provenance = read_json(path)
    evidence = provenance.get("evidence", {})
    require(isinstance(evidence, dict) and 5 <= len(evidence) <= 20, "evidence_budget")
    files, total = {}, 0
    for name, sha in evidence.items():
        data = read_file(root, PREFIX + "/" + evidence_name(name), 32 * 1024**2)
        total += len(data)
        require(total <= 128 * 1024**2, "evidence_total_budget")
        require(digest(data) == sha, "evidence_changed")
        files[name] = data
    previous = read_json(local(root, PREFIX + "/baseline.json"))
    outputs = provenance.get("test_outputs", {})
    require(set(outputs) == {"debian", "asn1", "before", "after", "harness", "wrapper"} and
            len(set(outputs.values())) == 6 and all(name in evidence for name in outputs.values()),
            "test_outputs")
    asn1 = read_json(local(root, PREFIX + "/" + evidence_name(outputs["asn1"])))
    debian = read_json(local(root, PREFIX + "/" + evidence_name(outputs["debian"])))
    require(all(asn1.get(phase) == read_json(local(root, PREFIX + "/" +
                evidence_name(outputs[phase]))) for phase in ("before", "after")),
            "asn1_phase_binding")
    require(all(asn1.get(phase, {}).get("harness_sha256") == evidence[outputs["harness"]]
                for phase in ("before", "after")), "asn1_harness_binding")
    validate_chain(provenance, files)
    validate_debian_tests(debian, provenance)
    validate_capability_files(debian, provenance, files)
    current = baseline(root=root, version=VERSION)
    result = {"schema": SCHEMA, "provenance": provenance,
              "provenance_sha256": digest(path.read_bytes()), "baseline": previous,
              "packages": current["packages"], "libraries": current["libraries"],
              "asn1": asn1, "debian_tests": debian}
    return validate_manifest(result)


def archive_conditions(manifest):
    """All image bytes that an individual backport policy must bind."""
    validate_manifest(manifest)
    result = [{"kind": "file_sha256", "path": MANIFEST_PATH,
               "sha256": digest((canonical(manifest) + "\n").encode())},
              {"kind": "file_sha256", "path": PREFIX + "/provenance.json",
               "sha256": manifest["provenance_sha256"]}]
    result.extend({"kind": "file_sha256", "path": PREFIX + "/" + name, "sha256": sha}
                  for name, sha in sorted(manifest["provenance"]["evidence"].items()))
    result.extend({"kind": "elf", "path": item["path"], "class": 64, "sha256": item["sha256"]}
                  for item in manifest["libraries"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--capture-baseline", action="store_true")
    mode.add_argument("--capture", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("--manifest", default=MANIFEST_PATH)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    fd = None
    try:
        fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        value = baseline() if args.capture_baseline else inventory()
        if args.verify:
            require(value == read_json(Path(args.manifest)), "inventory_changed")
        result = value if not args.verify else {"schema": SCHEMA, "verified": True,
                    "inventory": value, "coverage": "four Debian Kerberos libraries; no network",
                    "compilation_proof": False}
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            fd = None
            stream.write(canonical(result) + "\n")
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        if fd is not None:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(canonical({"verified": False, "error": str(exc) if isinstance(
                    exc, Krb5Error) else "krb5_verification_failed"}) + "\n")
        print(json.dumps({"verified": False, "error": str(exc) if isinstance(
            exc, Krb5Error) else "krb5_verification_failed"}))
        return 1
    print(json.dumps({"verified": True, "libraries": 4, "mode": "baseline" if
                      args.capture_baseline else "verify" if args.verify else "capture"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
