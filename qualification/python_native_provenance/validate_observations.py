"""Bind observed C compilation and link inputs to their exact Python wheels."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

try:
    from deploy import native_inventory
    from deploy import python_materials as materials
except ModuleNotFoundError:
    import native_inventory
    import python_materials as materials

SCHEMA = "pamolive.python-native-compiler-call/1"
BUILD_SCHEMA = "pamolive.python-native-wheel-build/1"
FILE = re.compile(r"(compile|link)-[a-f0-9]{64}\.(json|d|map)")
STATIC_SUPPORT = {"libgcc.a", "libgcc_eh.a", "libc_nonshared.a"}
MAX_RECORD = 1024 * 1024
MAX_OBSERVATIONS = 5 * 1024**2
MAX_TOOL = 64 * 1024**2
SDK_PACKAGES = (
    "gcc", "binutils", "libldap2-dev", "libsasl2-dev", "libpq-dev", "libpq5", "libc6-dev",
)
SDIST_OUTPUTS = {
    "psycopg-c": {
        "_psycopg": {"psycopg_c/_psycopg.c", "psycopg_c/types/numutils.c"},
        "pq": {"psycopg_c/pq.c"},
    },
    "python-ldap": {
        "_ldap": {path for path in materials.SOURCE_PATHS["python-ldap"] if path.endswith(".c")},
    },
}
LIBRARIES = {
    "psycopg-c": {"libpq.so.5", "libc.so.6"},
    "python-ldap": {"libldap.so.2", "liblber.so.2", "libc.so.6"},
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(record, *, maximum=materials.MAX_FILE):
    require(set(record) == {"path", "sha256", "size"}, "compiler_file_identity")
    name = record["path"]
    path = PurePosixPath(name)
    require(path.is_absolute() and str(path) == name and ".." not in path.parts
            and 0 < len(name) <= 1024 and all(32 < ord(char) < 127 for char in name),
            "compiler_file_path")
    materials.digest(record["sha256"])
    require(type(record["size"]) is int and 0 < record["size"] <= maximum,
            "compiler_file_size")
    return path


def collect_records(directory):
    files = {path.name: path for path in directory.iterdir()}
    require(len(files) == 30 and all(FILE.fullmatch(name) for name in files),
            "compiler_observation_file_set")
    records = []
    for name in sorted(files):
        if not name.endswith(".json"):
            continue
        data = materials.regular(files[name], MAX_RECORD)
        row = json.loads(data, object_pairs_hook=materials.pairs)
        kind = name.split("-", 1)[0]
        require(row["schema"] == SCHEMA and row["kind"] == kind, "compiler_observation_schema")
        suffix, field = ((".d", "dependency_sha256") if kind == "compile"
                         else (".map", "map_sha256"))
        raw = materials.regular(files[name[:-5] + suffix], MAX_RECORD)
        require(materials.sha(raw) == row[field], "compiler_detail_digest")
        records.append({"record": row, "detail": raw.decode("ascii")})
    require(len(records) == 15, "compiler_observation_count")
    return records


def match_calls(records, materials_by_name):
    compiled, linked = {}, {}
    require(len(records) == 15, "compiler_observation_count")
    toolchain = records[0]["tool"]
    require(
        set(toolchain) == {"path", "sha256", "size", "machine", "version", "subprograms"}
        and toolchain["machine"] == "x86_64-linux-gnu"
        and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", toolchain["version"])
        and set(toolchain["subprograms"]) == {"cc1", "as", "collect2", "ld"},
        "compiler_toolchain",
    )
    identity({key: toolchain[key] for key in ("path", "sha256", "size")}, maximum=MAX_TOOL)
    for program in toolchain["subprograms"].values():
        identity(program, maximum=MAX_TOOL)
    for row in records:
        kind = row["kind"]
        output = identity(row["output"])
        cwd = PurePosixPath(row["cwd"])
        require(cwd.is_relative_to("/tmp") and output.is_relative_to(cwd),
                "compiler_work_directory")
        require(row["tool"] == toolchain, "compiler_toolchain_inconsistent")
        if kind == "compile":
            require(output.suffix == ".o" and output not in compiled, "compiler_object_duplicate")
            source = identity(row["source"]).relative_to(cwd).as_posix()
            headers = [identity(item) for item in row["headers"]]
            require(headers, "compiler_system_headers")
            compiled[output] = (source, row, headers)
        else:
            require(kind == "link" and output.suffix == ".so" and output not in linked,
                    "compiler_link_duplicate")
            linked[output] = row

    results = {}
    consumed = set()
    for name, wheel in materials_by_name.items():
        for extension, expected in sorted(wheel["extensions"].items()):
            matching = [path for path in linked if path.as_posix().endswith("/" + extension)]
            require(len(matching) == 1, "compiler_link_extension")
            link = linked.pop(matching[0])
            require(all(link["output"][key] == expected[key] for key in ("size", "sha256")),
                    "compiler_link_wheel_digest")
            loaded = {}
            for item in link["load"]:
                path = identity(item)
                require(loaded.setdefault(path, item) == item, "compiler_link_input_conflict")
            archives = {path for path in loaded if path.suffix == ".a"}
            require(all(path.name in STATIC_SUPPORT and path.is_relative_to("/usr/lib")
                        for path in archives), "compiler_unreviewed_static_input")
            require(not any(path.name.startswith(("libstdc++", "libc++")) for path in loaded),
                    "compiler_cxx_link_input")
            extension_name = PurePosixPath(extension).name.split(".", 1)[0]
            actual_sources = set()
            objects = link["objects"]
            for linked_object in objects:
                path = identity(linked_object)
                require(path not in consumed and path in compiled,
                        "compiler_object_not_observed")
                require(loaded.get(path) == linked_object, "compiler_link_object_digest")
                consumed.add(path)
                source, call, _ = compiled[path]
                require(wheel["source_files"][source] == call["source"]["sha256"]
                        and linked_object == call["output"], "compiler_object_source_digest")
                actual_sources.add(source)
            require(len(objects) == len(actual_sources)
                    and actual_sources == SDIST_OUTPUTS[name][extension_name],
                    "compiler_extension_sources")
            headers = {header for record in objects
                       for header in compiled[PurePosixPath(record["path"])][2]}
            require(any(header.name == "Python.h" for header in headers)
                    and any(header.is_relative_to("/usr/include") for header in headers),
                    "compiler_extension_system_headers")
            results[extension] = {
                "package": name, **expected, "sources": sorted(actual_sources),
                "static_support_paths": sorted(path.as_posix() for path in archives),
                "wheel_sha256": wheel["wheel_sha256"],
            }
    require(len(results) == 3 and not linked and consumed == set(compiled),
            "compiler_observation_closure")
    return results


def wheel_rows(raw, input_manifest, input_sha):
    require(0 < len(raw) <= materials.MAX_JSON, "compiler_derived_budget")
    derived = json.loads(raw, object_pairs_hook=materials.pairs)
    require(derived["schema"] == "pamolive.python-derived-wheels.v1"
            and derived["target"] == materials.TARGET
            and derived["input_manifest_sha256"] == input_sha
            and derived["build_verified"] is False and derived["attestation_verified"] is False,
            "compiler_derived_schema")
    inputs = {row["name"]: row for row in input_manifest["materials"] if row["kind"] == "sdist"}
    wheels = {row["name"]: row for row in derived["materials"]}
    require(len(derived["materials"]) == 2 and set(wheels) == set(inputs) == set(SDIST_OUTPUTS),
            "compiler_derived_packages")
    for name, row in wheels.items():
        source = inputs[name]
        require(
            row["version"] == source["version"] and row["source_filename"] == source["filename"]
            and row["source_sha256"] == source["sha256"]
            and row["source_files"] == source["source_files"]
            and set(row["extensions"]) == materials.SO_PATHS[name],
            "compiler_derived_materials",
        )
        materials.digest(row["wheel_sha256"])
    return wheels


def replay(raw, wheels):
    require(0 < len(raw) <= MAX_OBSERVATIONS, "compiler_evidence_budget")
    traces = json.loads(raw, object_pairs_hook=materials.pairs)
    require(type(traces) is list and len(traces) == 15, "compiler_observation_count")
    records = []
    for item in traces:
        require(set(item) == {"record", "detail"}, "compiler_observation_schema")
        row = item["record"]
        require(row["schema"] == SCHEMA and row["kind"] in {"compile", "link"},
                "compiler_observation_schema")
        field = "dependency_sha256" if row["kind"] == "compile" else "map_sha256"
        detail = item["detail"].encode("ascii")
        require(0 < len(detail) <= MAX_RECORD and materials.sha(detail) == row[field],
                "compiler_detail_digest")
        records.append(row)
    return match_calls(records, wheels)


def inspect_extensions(extensions, read_bytes):
    observed = {}
    for path, extension in extensions.items():
        data = read_bytes(path)
        require(len(data) == extension["size"] and materials.sha(data) == extension["sha256"],
                "compiler_installed_extension")
        linkage = native_inventory.observe_elf_needed(data)
        require(linkage["status"] == "observed"
                and set(linkage["needed"]) == LIBRARIES[extension["package"]],
                "compiler_dynamic_dependencies")
        observed[path] = {**extension, "needed": sorted(linkage["needed"])}
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-build", action="store_true")
    args = parser.parse_args()
    try:
        output = Path("/opt/python-build/evidence" if args.product_build else "/evidence")
        derived_root = output if args.product_build else Path("/opt/qualification-work/derived")
        inputs = Path("/opt/python-build-inputs" if args.product_build else "/opt/qualification")
        manifest, digest = materials.load_manifest(inputs / "python-materials.linux-amd64.json")
        derived = materials.regular(derived_root / "derived-manifest.json", materials.MAX_JSON)
        traces = collect_records(Path("/opt/trace"))
        observations = (json.dumps(traces, sort_keys=True, separators=(",", ":")) + "\n").encode()
        extensions = replay(observations, wheel_rows(derived, manifest, digest))
        versions = subprocess.check_output(
            ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}=${Version}\n", *SDK_PACKAGES],
            text=True, encoding="ascii", timeout=5, env={"LC_ALL": "C"},
        ).splitlines()
        report = {
            "compiler_calls": len(traces), "extensions": extensions,
            "derived_manifest_sha256": materials.sha(derived),
            "observations_sha256": materials.sha(observations),
            "sdk_versions": sorted(versions),
            "product_image_measured": False, "policy_disposition": None,
        }
        files = {"compiler-observations.json": observations}
        if args.product_build:
            report["schema"] = BUILD_SCHEMA
            report_name = "compiler-build.json"
        else:
            report["schema"] = "pamolive.python-native-provenance-lab/1"
            report["extensions"] = inspect_extensions(
                extensions, lambda path: materials.regular(Path("/opt/installed") / path),
            )
            files["derived-manifest.json"] = derived
            report_name = "qualification.json"
        files[report_name] = (json.dumps(report, sort_keys=True) + "\n").encode()
        os.umask(0o077)
        for name, data in files.items():
            with (output / name).open("xb") as stream:
                stream.write(data)
    except (KeyError, TypeError, OSError, subprocess.SubprocessError):
        raise SystemExit("Python native compiler evidence refused.") from None
    except ValueError as error:
        reason = str(error)
        raise SystemExit(reason if re.fullmatch(r"compiler_[a-z_]+", reason)
                         else "Python native compiler evidence refused.") from None


if __name__ == "__main__":
    main()
