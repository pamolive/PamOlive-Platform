"""Bind the observed C compilation and link inputs to the exact lab wheels."""

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
FILE = re.compile(r"(compile|link)-[a-f0-9]{64}\.(json|d|map)")
STATIC_SUPPORT = {"libgcc.a", "libgcc_eh.a", "libc_nonshared.a"}
MAX_RECORD = 1024 * 1024
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


def identity(record):
    require(set(record) == {"path", "sha256", "size"}, "compiler_file_identity")
    name = record["path"]
    path = PurePosixPath(name)
    require(path.is_absolute() and str(path) == name and ".." not in path.parts
            and 0 < len(name) <= 1024 and all(32 < ord(char) < 127 for char in name),
            "compiler_file_path")
    materials.digest(record["sha256"])
    require(type(record["size"]) is int and 0 < record["size"] <= materials.MAX_FILE,
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
    for row in records:
        kind = row["kind"]
        output = identity(row["output"])
        cwd = PurePosixPath(row["cwd"])
        require(cwd.is_relative_to("/tmp") and output.is_relative_to(cwd),
                "compiler_work_directory")
        tool = row["tool"]
        require(tool["machine"] == "x86_64-linux-gnu"
                and set(tool["subprograms"]) == {"cc1", "as", "collect2", "ld"},
                "compiler_toolchain")
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


def main():
    try:
        traces = collect_records(Path("/opt/trace"))
        derived = materials.regular(
            Path("/opt/qualification-work/derived/derived-manifest.json"), materials.MAX_JSON
        )
        manifest = json.loads(derived, object_pairs_hook=materials.pairs)
        require(manifest["schema"] == "pamolive.python-derived-wheels.v1"
                and manifest["build_verified"] is False
                and manifest["attestation_verified"] is False,
                "compiler_derived_schema")
        wheels = {row["name"]: row for row in manifest["materials"]}
        require(len(manifest["materials"]) == 2 and set(wheels) == set(SDIST_OUTPUTS),
                "compiler_derived_packages")
        extensions = match_calls([row["record"] for row in traces], wheels)
        for path, extension in extensions.items():
            data = materials.regular(Path("/opt/installed") / path)
            require(len(data) == extension["size"] and materials.sha(data) == extension["sha256"],
                    "compiler_installed_extension")
            observation = native_inventory.observe_elf_needed(data)
            require(observation["status"] == "observed"
                    and LIBRARIES[extension["package"]] <= set(observation["needed"])
                    and not any(lib.startswith(("libstdc++", "libc++"))
                                for lib in observation["needed"]), "compiler_dynamic_dependencies")
            extension["needed"] = sorted(observation["needed"])
        versions = subprocess.check_output(
            ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}=${Version}\n", "gcc", "binutils",
             "libldap2-dev", "libsasl2-dev", "libpq-dev", "libpq5", "libc6-dev"],
            text=True, encoding="ascii", timeout=5, env={"LC_ALL": "C"},
        ).splitlines()
        observations = (json.dumps(traces, sort_keys=True, separators=(",", ":")) + "\n").encode()
        require(len(observations) <= 5 * 1024**2, "compiler_evidence_budget")
        report = {
            "schema": "pamolive.python-native-provenance-lab/1",
            "compiler_calls": len(traces), "extensions": extensions,
            "derived_manifest_sha256": materials.sha(derived),
            "observations_sha256": materials.sha(observations),
            "sdk_versions": sorted(versions),
            "product_image_measured": False, "policy_disposition": None,
        }
        os.umask(0o077)
        for name, data in (
            ("compiler-observations.json", observations), ("derived-manifest.json", derived),
            ("qualification.json", (json.dumps(report, sort_keys=True) + "\n").encode()),
        ):
            with (Path("/evidence") / name).open("xb") as output:
                output.write(data)
    except (KeyError, TypeError, OSError, subprocess.SubprocessError):
        raise SystemExit("Python native compiler evidence refused.") from None
    except ValueError as error:
        reason = str(error)
        raise SystemExit(reason if re.fullmatch(r"compiler_[a-z_]+", reason)
                         else "Python native compiler evidence refused.") from None


if __name__ == "__main__":
    main()
