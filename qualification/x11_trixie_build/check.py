"""Check the X11 client-library ABI and an in-memory Cairo/Pango PNG render."""

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

LIBDIR = PurePosixPath("/usr/lib/x86_64-linux-gnu")
X11 = "libX11.so.6"
XRENDER = "libXrender.so.1"
CAIRO = "libcairo.so.2"
PANGO = "libpango-1.0.so.0"
PANGOCAIRO = "libpangocairo-1.0.so.0"
GOBJECT = "libgobject-2.0.so.0"
LIBRARIES = {X11: "libx11-6", XRENDER: "libxrender1"}
PACKAGES = {
    "libx11-6": ("libx11", "amd64"),
    "libx11-data": ("libx11", "all"),
    "libxrender1": ("libxrender", "amd64"),
}
VERSIONS = {
    "baseline": {
        "libx11-6": "2:1.8.12-1",
        "libx11-data": "2:1.8.12-1",
        "libxrender1": "1:0.9.12-1",
    },
    "candidate": {
        "libx11-6": "2:1.8.14-1~pamolive13u1",
        "libx11-data": "2:1.8.14-1~pamolive13u1",
        "libxrender1": "1:0.9.13-1~pamolive13u1",
    },
}
RUNTIME_SCHEMA = "pamolive.x11-trixie-runtime/1"
COMPARE_SCHEMA = "pamolive.x11-trixie-qualification/1"
SHA256 = re.compile(r"[0-9a-f]{64}")
FONT = "DejaVu Sans"
FONT_FILE = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
WIDTH, HEIGHT = 240, 64
RENDER_PROFILE = {"backend": "image", "width": WIDTH, "height": HEIGHT, "font": FONT}
MAX_PNG = 256 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_ARTIFACT = 64 * 1024 * 1024
MAX_EXPORTS = 8192


class QualificationError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise QualificationError(code)


def run(*arguments):
    return subprocess.check_output(
        arguments,
        text=True,
        encoding="ascii",
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=10,
    )


def sha(path):
    require(path.is_file() and 0 < path.stat().st_size <= MAX_ARTIFACT, "artifact_size")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check_packages(mode):
    versions = VERSIONS[mode]
    for package, (source, architecture) in PACKAGES.items():
        result = run(
            "dpkg-query", "-W", "-f=${source:Package}|${Architecture}|${Version}|${Status}", package
        )
        expected = f"{source}|{architecture}|{versions[package]}|install ok installed"
        require(result == expected, "package_identity")
    return versions


def elf_path(soname):
    directory = Path(LIBDIR)
    path = (directory / soname).resolve(strict=True)
    require(path.parent == directory and path.is_file(), "library_path")
    return path


def dynamic(path):
    return run("readelf", "--wide", "--dynamic", path)


def exports(path):
    names = set()
    for line in run("readelf", "--wide", "--dyn-syms", path).splitlines():
        fields = line.split()
        if len(fields) < 8 or not re.fullmatch(r"\d+:", fields[0]):
            continue
        _, _, size, kind, binding, visibility, index, name = fields[:8]
        if not (
            binding in {"GLOBAL", "WEAK"}
            and visibility in {"DEFAULT", "PROTECTED"}
            and index not in {"UND", "ABS"}
        ):
            continue
        if kind in {"FUNC", "IFUNC"}:
            names.add(f"{kind} {name}")
        elif kind == "OBJECT":
            names.add(f"{kind} {name} {int(size, 0)}")
    require(0 < len(names) <= MAX_EXPORTS, "export_count")
    return sorted(names)


def mapped_libraries(paths):
    prefix_to_path = {soname.split(".so.")[0] + ".so": path for soname, path in paths.items()}
    identities = {path: path.stat() for path in paths.values()}
    mapped = set()
    with Path("/proc/self/maps").open("rb") as stream:
        maps = stream.read(MAX_REPORT + 1)
    require(len(maps) <= MAX_REPORT, "maps_size")
    for line in maps.decode("utf-8", errors="surrogateescape").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        name, deleted, _ = fields[5].partition(" (deleted)")
        stem, separator, _ = Path(name).name.partition(".so")
        path = prefix_to_path.get(stem + separator)
        if path is None:
            continue
        identity = identities[path]
        device = tuple(int(part, 16) for part in fields[3].split(":"))
        require(
            not deleted
            and Path(name).resolve(strict=True) == path
            and device == (os.major(identity.st_dev), os.minor(identity.st_dev))
            and int(fields[4]) == identity.st_ino,
            "mapping_identity",
        )
        if "x" in fields[1]:
            mapped.add(path)
    require(mapped == set(paths.values()), "loaded_libraries")


def bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


def own(resources, pointer, destroy):
    require(pointer, "render_resource")
    resources.callback(destroy, pointer)
    return pointer


def render_png(cairo, surface):
    pointer, integer = ctypes.c_void_p, ctypes.c_int
    write_callback = ctypes.CFUNCTYPE(integer, pointer, pointer, ctypes.c_uint)
    write_png = bind(
        cairo, "cairo_surface_write_to_png_stream", integer, pointer, write_callback, pointer
    )
    png = bytearray()

    @write_callback
    def append(_closure, data, length):
        if length > MAX_PNG - len(png):
            return 11  # CAIRO_STATUS_WRITE_ERROR
        png.extend(ctypes.string_at(data, length))
        return 0

    require(write_png(surface, append, None) == 0, "png_write")
    require(
        png.startswith(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR")
        and int.from_bytes(png[16:20], "big") == WIDTH
        and int.from_bytes(png[20:24], "big") == HEIGHT,
        "png_dimensions",
    )
    return hashlib.sha256(png).hexdigest()


def render():
    require(FONT_FILE.is_file(), "dejavu_unavailable")
    os.environ.pop("DISPLAY", None)
    os.environ.pop("WAYLAND_DISPLAY", None)
    # PangoCairo loads the X client libraries through Cairo's ELF dependencies.
    pangocairo = ctypes.CDLL(PANGOCAIRO)
    cairo = ctypes.CDLL(CAIRO)
    pango = ctypes.CDLL(PANGO)
    gobject = ctypes.CDLL(GOBJECT)
    pointer, integer, double, string = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_double,
        ctypes.c_char_p,
    )
    int_ref = ctypes.POINTER(integer)
    create_surface = bind(cairo, "cairo_image_surface_create", pointer, integer, integer, integer)
    surface_status = bind(cairo, "cairo_surface_status", integer, pointer)
    surface_type = bind(cairo, "cairo_surface_get_type", integer, pointer)
    create_context = bind(cairo, "cairo_create", pointer, pointer)
    context_status = bind(cairo, "cairo_status", integer, pointer)
    set_color = bind(cairo, "cairo_set_source_rgb", None, pointer, double, double, double)
    paint = bind(cairo, "cairo_paint", None, pointer)
    move_to = bind(cairo, "cairo_move_to", None, pointer, double, double)
    get_data = bind(cairo, "cairo_image_surface_get_data", pointer, pointer)
    get_stride = bind(cairo, "cairo_image_surface_get_stride", integer, pointer)
    flush = bind(cairo, "cairo_surface_flush", None, pointer)
    create_layout = bind(pangocairo, "pango_cairo_create_layout", pointer, pointer)
    show_layout = bind(pangocairo, "pango_cairo_show_layout", None, pointer, pointer)
    describe = bind(pango, "pango_font_description_from_string", pointer, string)
    destroy_description = bind(pango, "pango_font_description_free", None, pointer)
    layout_context = bind(pango, "pango_layout_get_context", pointer, pointer)
    load_font = bind(pango, "pango_context_load_font", pointer, pointer, pointer)
    font_description = bind(pango, "pango_font_describe", pointer, pointer)
    family = bind(pango, "pango_font_description_get_family", string, pointer)
    set_font = bind(pango, "pango_layout_set_font_description", None, pointer, pointer)
    set_text = bind(pango, "pango_layout_set_text", None, pointer, string, integer)
    pixel_size = bind(pango, "pango_layout_get_pixel_size", None, pointer, int_ref, int_ref)
    unref = bind(gobject, "g_object_unref", None, pointer)

    with ExitStack() as resources:
        surface = own(
            resources,
            create_surface(0, WIDTH, HEIGHT),
            bind(cairo, "cairo_surface_destroy", None, pointer),
        )
        require(surface_status(surface) == 0 and surface_type(surface) == 0, "image_surface")
        context = own(
            resources, create_context(surface), bind(cairo, "cairo_destroy", None, pointer)
        )
        require(context_status(context) == 0, "image_context")
        set_color(context, 1, 1, 1)
        paint(context)

        layout = own(resources, create_layout(context), unref)
        description = own(resources, describe(f"{FONT} 14".encode("ascii")), destroy_description)
        font = own(resources, load_font(layout_context(layout), description), unref)
        actual = own(resources, font_description(font), destroy_description)
        require(family(actual) == FONT.encode("ascii"), "unexpected_font")
        set_font(layout, description)
        set_text(layout, b"PamOlive X11 fixture", -1)
        width, height = integer(), integer()
        pixel_size(layout, ctypes.byref(width), ctypes.byref(height))
        require(0 < width.value < WIDTH - 20 and 0 < height.value < HEIGHT - 20, "text_bounds")
        move_to(context, 10, 10)
        set_color(context, 0.07, 0.24, 0.45)
        show_layout(context, layout)
        flush(surface)
        require(context_status(context) == 0 and surface_status(surface) == 0, "render_status")
        data, stride = get_data(surface), get_stride(surface)
        require(data and stride == WIDTH * 4, "image_buffer")
        pixels = ctypes.string_at(data, stride * HEIGHT)
        require(
            pixels.startswith(b"\xff" * 4) and pixels.count(b"\xff") < len(pixels), "blank_render"
        )
        return {**RENDER_PROFILE, "png_sha256": render_png(cairo, surface)}


def runtime(mode):
    require(mode in VERSIONS, "runtime_mode")
    require(sys.platform == "linux" and os.uname().machine == "x86_64", "runtime_architecture")
    versions = check_packages(mode)
    paths = {name: elf_path(name) for name in (X11, XRENDER, CAIRO, PANGO, PANGOCAIRO)}
    libraries = {}
    for name, package in LIBRARIES.items():
        path = paths[name]
        owner, separator, owned_path = run("dpkg-query", "-S", path).strip().partition(": ")
        require(
            separator and owner == f"{package}:amd64" and owned_path == str(path), "library_owner"
        )
        require(f"Library soname: [{name}]" in dynamic(path), "library_soname")
        libraries[name] = {"path": str(path), "sha256": sha(path), "exports": exports(path)}

    for consumer, dependencies in ((PANGOCAIRO, (CAIRO, PANGO)), (CAIRO, (X11, XRENDER))):
        table = dynamic(paths[consumer])
        require(
            all(f"Shared library: [{name}]" in table for name in dependencies), "renderer_linkage"
        )
    rendering = render()
    mapped_libraries(paths)
    for library in libraries.values():
        library["mapped"] = True
    return {
        "schema": RUNTIME_SCHEMA,
        "verified": True,
        "architecture": "amd64",
        "mode": mode,
        "versions": versions,
        "libraries": libraries,
        "rendering": rendering,
    }


def artifact(root, name):
    path = root / name
    require(not path.is_symlink() and path.is_file(), "evidence_file")
    return path


def read_report(path, mode):
    require(0 < path.stat().st_size <= MAX_REPORT, "report_size")
    report = json.loads(path.read_bytes())
    require(
        report["schema"] == RUNTIME_SCHEMA
        and report["verified"] is True
        and report["mode"] == mode
        and report["architecture"] == "amd64"
        and report["versions"] == VERSIONS[mode]
        and report["libraries"].keys() == LIBRARIES.keys(),
        "runtime_profile",
    )
    for soname, library in report["libraries"].items():
        path = PurePosixPath(library["path"])
        names = library["exports"]
        require(
            path.parent == LIBDIR
            and (path.name == soname or path.name.startswith(soname + "."))
            and library["mapped"] is True
            and SHA256.fullmatch(library["sha256"])
            and type(names) is list
            and 0 < len(names) <= MAX_EXPORTS
            and all(type(name) is str and 0 < len(name) <= 256 for name in names)
            and names == sorted(set(names)),
            "runtime_library",
        )
    rendering = report["rendering"]
    require(
        rendering.keys() == RENDER_PROFILE.keys() | {"png_sha256"}
        and all(rendering[key] == value for key, value in RENDER_PROFILE.items())
        and SHA256.fullmatch(rendering["png_sha256"]),
        "render_profile",
    )
    return report


def compare(root):
    baseline_path = artifact(root, "baseline.json")
    candidate_path = artifact(root, "candidate.json")
    baseline = read_report(baseline_path, "baseline")
    candidate = read_report(candidate_path, "candidate")
    require(baseline["rendering"] == candidate["rendering"], "png_mismatch")
    preserved, elf_digests = {}, {}
    for name in LIBRARIES:
        before, after = baseline["libraries"][name], candidate["libraries"][name]
        require(set(before["exports"]) <= set(after["exports"]), "missing_legacy_exports")
        require(before["sha256"] != after["sha256"], "unchanged_library")
        preserved[name] = len(before["exports"])
        elf_digests[name] = after["sha256"]
    return {
        "schema": COMPARE_SCHEMA,
        "verified": True,
        "architecture": "amd64",
        "versions": candidate["versions"],
        "elf_sha256": elf_digests,
        "preserved_exports": preserved,
        "rendering": candidate["rendering"],
        "package_sha256": {name: sha(artifact(root, f"{name}.deb")) for name in PACKAGES},
        "buildinfo_sha256": {
            name: sha(artifact(root, f"{name}.buildinfo")) for name in ("libx11", "libxrender")
        },
        "runtime_reports_sha256": {
            "baseline": sha(baseline_path),
            "candidate": sha(candidate_path),
        },
    }


def main():
    action = sys.argv[1] if len(sys.argv) == 3 else None
    schema = RUNTIME_SCHEMA if action == "runtime" else COMPARE_SCHEMA
    try:
        require(action in {"runtime", "compare"}, "qualification_arguments")
        value = sys.argv[2]
        report = runtime(value) if action == "runtime" else compare(Path(value))
    except QualificationError as error:
        report = {"schema": schema, "verified": False, "error": str(error)}
    except (AttributeError, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        report = {"schema": schema, "verified": False, "error": "qualification_failed"}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
