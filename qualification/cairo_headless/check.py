"""Qualify the Cairo image backend with the X11 and XCB backends disabled."""

import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "x11_check.py"
if not FIXTURE.is_file():
    FIXTURE = HERE.parent / "x11_trixie_build" / "check.py"
x11 = SimpleNamespace(**runpy.run_path(str(FIXTURE)))

RUNTIME_SCHEMA = "pamolive.cairo-headless-runtime/1"
COMPARE_SCHEMA = "pamolive.cairo-headless-qualification/1"
VERSIONS = {"baseline": "1.18.4-1+b1", "candidate": "1.18.4-1+pamolive13u1"}
PANGOCAIRO_VERSION = "1.56.3-1"
PACKAGES = ("libcairo2", "libcairo2-dev", "libcairo-gobject2", "libcairo-script-interpreter2")
X_PACKAGES = (
    "libx11",
    "libxau",
    "libxaw",
    "libxcb",
    "libxcomposite",
    "libxcursor",
    "libxdamage",
    "libxdmcp",
    "libxext",
    "libxfixes",
    "libxfont",
    "libxft",
    "libxinerama",
    "libxkbcommon-x11",
    "libxkbfile",
    "libxmu",
    "libxpm",
    "libxpresent",
    "libxrandr",
    "libxrender",
    "libxres",
    "libxshmfence",
    "libxss",
    "libxtst",
    "libxvmc",
    "libxxf86",
    "x11-",
    "xserver-",
)
REQUIRED_X_PACKAGES = {"libx11-6", "libxrender1"}
LIBRARY_NAME = re.compile(r"[A-Za-z0-9.+_-]{1,128}")
SYMBOL_NAME = r"[A-Za-z_.$][A-Za-z0-9_.$]*"
SYMBOL_VERSION = r"(?:@@?[A-Za-z0-9_.$-]+)?"
SYMBOL_RECORD = re.compile(
    rf"(?:(?:FUNC|IFUNC) ({SYMBOL_NAME}){SYMBOL_VERSION}"
    rf"|OBJECT ({SYMBOL_NAME}){SYMBOL_VERSION} [0-9]+)"
)
MAX_LIBRARY_ENTRIES = 100_000


def needs(table):
    names = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\[\]]+)\]", table)
    x11.require(
        0 < len(names) <= 128 and all(LIBRARY_NAME.fullmatch(name) for name in names),
        "cairo_needed",
    )
    return sorted(set(names))


def x_library(name):
    return name.startswith(("libX", "libxcb")) and bool(re.search(r"\.so(?:\.|$)", name))


def x_package(name):
    return (
        name.startswith(X_PACKAGES)
        or name in {"xauth", "xwayland"}
        or bool(re.match(r"libx(?:i|t|v)(?:[0-9]|-)", name))
    )


def installed_x_packages():
    listing = x11.run("dpkg-query", "-W", "-f=${Package}\t${db:Status-Status}\n")
    x11.require(len(listing) <= x11.MAX_REPORT, "package_listing_size")
    result = []
    for line in listing.splitlines():
        package, status = line.split("\t")
        if status == "installed" and x_package(package):
            x11.require(LIBRARY_NAME.fullmatch(package), "package_name")
            result.append(package)
    x11.require(len(result) <= 128, "x_package_count")
    return sorted(set(result))


def raise_walk_error(error):
    raise error


def x_files_present():
    roots = tuple(
        map(
            Path,
            (
                "/usr/lib",
                "/lib",
                "/usr/lib64",
                "/lib64",
                "/usr/local/lib",
                "/usr/local/lib64",
                "/opt",
            ),
        )
    )
    checked = 0
    for root in dict.fromkeys(root.resolve(strict=True) for root in roots if root.is_dir()):
        for _, directories, files in os.walk(root, onerror=raise_walk_error):
            checked += len(directories) + len(files)
            x11.require(checked <= MAX_LIBRARY_ENTRIES, "library_inventory_size")
            if any(x_library(name) for name in (*directories, *files)):
                return True
    return False


def x_mappings_present():
    with Path("/proc/self/maps").open("rb") as stream:
        maps = stream.read(x11.MAX_REPORT + 1)
    x11.require(len(maps) <= x11.MAX_REPORT, "maps_size")
    for line in maps.decode("utf-8", errors="surrogateescape").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5].startswith("/"):
            path = Path(fields[5].removesuffix(" (deleted)"))
            if x_library(path.name):
                return True
    return False


def check_package(name, source, version):
    expected = f"{source}|amd64|{version}|install ok installed"
    identity = x11.run(
        "dpkg-query", "-W", "-f=${source:Package}|${Architecture}|${Version}|${Status}", name
    )
    x11.require(identity == expected, "package_identity")


def check_runtime_profile(report, mode):
    cairo = report["cairo"]
    path = PurePosixPath(cairo["path"])
    x11.require(
        cairo["soname"] == x11.CAIRO
        and path.parent == x11.LIBDIR
        and (path.name == x11.CAIRO or path.name.startswith(x11.CAIRO + "."))
        and cairo["mapped"] is True
        and x11.SHA256.fullmatch(cairo["sha256"]),
        "cairo_identity",
    )
    libraries = cairo["needed"]
    x11.require(
        type(libraries) is list
        and 0 < len(libraries) <= 128
        and all(type(name) is str and LIBRARY_NAME.fullmatch(name) for name in libraries)
        and libraries == sorted(set(libraries)),
        "cairo_needed",
    )
    x_dependencies = {name for name in libraries if x_library(name)}
    x_runtime = report["x_runtime"]
    packages = x_runtime["packages"]
    x11.require(
        type(packages) is list
        and len(packages) <= 128
        and all(
            type(name) is str and LIBRARY_NAME.fullmatch(name) and x_package(name)
            for name in packages
        )
        and packages == sorted(set(packages)),
        "x_package_list",
    )
    if mode == "baseline":
        x11.require(
            {x11.X11, x11.XRENDER} <= x_dependencies
            and REQUIRED_X_PACKAGES <= set(packages)
            and x_runtime["files_present"] is True
            and x_runtime["mapped"] is True,
            "baseline_x_runtime",
        )
    else:
        x11.require(
            not x_dependencies
            and not packages
            and x_runtime["files_present"] is False
            and x_runtime["mapped"] is False,
            "candidate_x_runtime",
        )


def runtime(mode):
    x11.require(mode in VERSIONS, "runtime_mode")
    x11.require(sys.platform == "linux" and os.uname().machine == "x86_64", "runtime_architecture")
    paths = {name: x11.elf_path(name) for name in (x11.CAIRO, x11.PANGO, x11.PANGOCAIRO)}
    cairo = paths[x11.CAIRO]
    check_package("libcairo2", "cairo", VERSIONS[mode])
    check_package("libpangocairo-1.0-0", "pango1.0", PANGOCAIRO_VERSION)
    owner = x11.run("dpkg-query", "-S", cairo).strip()
    x11.require(owner == f"libcairo2:amd64: {cairo}", "cairo_elf_owner")
    table = x11.dynamic(cairo)
    x11.require(f"Library soname: [{x11.CAIRO}]" in table, "cairo_soname")
    dependencies = needs(table)
    packages = installed_x_packages()
    files_present = x_files_present()
    if mode == "baseline":
        paths.update({name: x11.elf_path(name) for name in (x11.X11, x11.XRENDER)})
    else:
        x11.require(
            not any(map(x_library, dependencies)) and not packages and not files_present,
            "candidate_x_runtime",
        )
    pango_dependencies = needs(x11.dynamic(paths[x11.PANGOCAIRO]))
    x11.require({x11.CAIRO, x11.PANGO} <= set(pango_dependencies), "pangocairo_linkage")
    rendering = x11.render()
    x11.mapped_libraries(paths)
    report = {
        "schema": RUNTIME_SCHEMA,
        "verified": True,
        "architecture": "amd64",
        "mode": mode,
        "version": VERSIONS[mode],
        "pangocairo_version": PANGOCAIRO_VERSION,
        "cairo": {
            "soname": x11.CAIRO,
            "path": str(cairo),
            "mapped": True,
            "sha256": x11.sha(cairo),
            "needed": dependencies,
            "exports": x11.exports(cairo),
        },
        "x_runtime": {
            "packages": packages,
            "files_present": files_present,
            "mapped": x_mappings_present(),
        },
        "rendering": rendering,
    }
    check_runtime_profile(report, mode)
    return report


def read_report(path, mode):
    x11.require(0 < path.stat().st_size <= x11.MAX_REPORT, "runtime_report_size")
    report = json.loads(path.read_bytes())
    x11.require(
        report["schema"] == RUNTIME_SCHEMA
        and report["verified"] is True
        and report["architecture"] == "amd64"
        and report["mode"] == mode
        and report["version"] == VERSIONS[mode]
        and report["pangocairo_version"] == PANGOCAIRO_VERSION,
        "runtime_identity",
    )
    check_runtime_profile(report, mode)
    rendering = report["rendering"]
    x11.require(
        rendering.keys() == x11.RENDER_PROFILE.keys() | {"png_sha256"}
        and all(rendering[key] == value for key, value in x11.RENDER_PROFILE.items())
        and x11.SHA256.fullmatch(rendering["png_sha256"]),
        "render_profile",
    )
    return report


def export_names(records):
    x11.require(type(records) is list and 0 < len(records) <= x11.MAX_EXPORTS, "exports_count")
    by_name = {}
    for record in records:
        x11.require(type(record) is str and len(record) <= 256, "export_record")
        match = SYMBOL_RECORD.fullmatch(record)
        x11.require(match is not None, "export_record")
        name = match[1] or match[2]
        by_name.setdefault(name, set()).add(record)
    x11.require(records == sorted(set(records)), "export_order")
    return by_name


def compare(root):
    baseline_path = x11.artifact(root, "baseline.json")
    candidate_path = x11.artifact(root, "candidate.json")
    baseline = read_report(baseline_path, "baseline")
    candidate = read_report(candidate_path, "candidate")
    x11.require(baseline["cairo"]["sha256"] != candidate["cairo"]["sha256"], "unchanged_cairo")
    x11.require(baseline["rendering"] == candidate["rendering"], "png_mismatch")

    allowlist = HERE / "disabled-exports.txt"
    if not allowlist.is_file():
        allowlist = HERE.parents[1] / "deploy/cairo-headless/disabled-exports.txt"
    x11.require(0 < allowlist.stat().st_size <= 4096, "disabled_exports_size")
    rows = allowlist.read_text(encoding="ascii").splitlines()
    disabled = set(rows)
    x11.require(
        len(rows) == len(disabled) == 26 and all(re.fullmatch(SYMBOL_NAME, name) for name in rows),
        "disabled_exports",
    )
    before = export_names(baseline["cairo"]["exports"])
    after = export_names(candidate["cairo"]["exports"])
    x11.require(
        disabled <= before.keys() and before.keys() - disabled == after.keys(), "export_names"
    )
    x11.require(all(before[name] == after[name] for name in after), "preserved_abi")

    return {
        "schema": COMPARE_SCHEMA,
        "verified": True,
        "architecture": "amd64",
        "version": candidate["version"],
        "pangocairo_version": candidate["pangocairo_version"],
        "cairo_sha256": candidate["cairo"]["sha256"],
        "needed": candidate["cairo"]["needed"],
        "x_runtime_absent": True,
        "disabled_exports": sorted(disabled),
        "preserved_exports": sum(map(len, after.values())),
        "rendering": candidate["rendering"],
        "package_sha256": {name: x11.sha(x11.artifact(root, f"{name}.deb")) for name in PACKAGES},
        "buildinfo_sha256": x11.sha(x11.artifact(root, "buildinfo")),
        "runtime_reports_sha256": {
            "baseline": x11.sha(baseline_path),
            "candidate": x11.sha(candidate_path),
        },
    }


def main():
    action = sys.argv[1] if len(sys.argv) == 3 else None
    schema = RUNTIME_SCHEMA if action == "runtime" else COMPARE_SCHEMA
    try:
        x11.require(action in {"runtime", "compare"}, "qualification_arguments")
        value = sys.argv[2]
        report = runtime(value) if action == "runtime" else compare(Path(value))
    except x11.QualificationError as error:
        report = {"schema": schema, "verified": False, "error": str(error)}
    except (AttributeError, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        report = {"schema": schema, "verified": False, "error": "qualification_failed"}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
