#!/usr/local/bin/python3
"""Record bounded C compilation and GNU ld inputs in the offline Python wheel lab."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = "pamolive.python-native-compiler-call/1"
GCC = "/usr/bin/gcc"
TRIPLE = "x86_64-linux-gnu"
BUILD_ROOT = Path("/tmp")
TRACE_ROOT = Path("/opt/trace")
INCLUDE_ROOTS = (Path("/usr/include"), Path("/usr/local/include"), Path("/usr/lib/gcc"))
DEPENDENCY_ROOTS = (*INCLUDE_ROOTS, Path("/usr/lib/linux/uapi/x86"))
LIBRARY_ROOTS = (Path("/usr/lib"), Path("/usr/local/lib"))
TOOL_ROOTS = (Path("/usr/bin"), Path("/usr/lib/gcc"), Path("/usr/libexec/gcc"))
MAX_FILE = 64 * 1024**2
MAX_DATA = 2 * 1024**2
MAX_ITEMS = 512
TIMEOUT = 180
PATH_WORD = re.compile(r"[A-Za-z0-9_+./~-]{1,512}\Z")
MACRO = re.compile(r"-[DU][A-Za-z_][A-Za-z0-9_]*(?:=[ -~]{1,256})?\Z")
WARNING = re.compile(r"-W[A-Za-z0-9-]+(?:=[A-Za-z0-9-]+)?\Z")
COMPILE_FLAGS = frozenset(
    {
        "-c",
        "-g",
        "-g0",
        "-g1",
        "-g2",
        "-g3",
        "-O0",
        "-O1",
        "-O2",
        "-O3",
        "-Os",
        "-fPIC",
        "-fpic",
        "-fwrapv",
        "-fno-strict-aliasing",
        "-fno-strict-overflow",
        "-fno-semantic-interposition",
        "-fstack-protector",
        "-fstack-protector-strong",
        "-fvisibility=hidden",
        "-fvisibility=default",
        "-pthread",
        "-pipe",
        "-std=c99",
        "-std=c11",
        "-std=gnu99",
        "-std=gnu11",
        "-std=gnu17",
    }
)
LINK_FLAGS = frozenset(
    {
        "-shared",
        "-g",
        "-fPIC",
        "-fpic",
        "-pthread",
        "-Wl,-O1",
        "-Wl,--as-needed",
        "-Wl,-z,relro",
        "-Wl,-z,now",
        "-Wl,-Bsymbolic-functions",
    }
)
OUTPUT_LIBRARIES = {
    "_ldap.cpython-312-x86_64-linux-gnu.so": ("ldap", "lber"),
    "_psycopg.cpython-312-x86_64-linux-gnu.so": ("pq",),
    "pq.cpython-312-x86_64-linux-gnu.so": ("pq",),
}
SUPPORT_ARCHIVES = {"libgcc.a", "libc_nonshared.a"}
OVERRIDES = {
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "GCC_EXEC_PREFIX",
    "COMPILER_PATH",
    "LIBRARY_PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_AUDIT",
    "DEPENDENCIES_OUTPUT",
    "SUNPRO_DEPENDENCIES",
    "GNUTARGET",
    "LDEMULATION",
}


class ProbeError(ValueError):
    """The invocation or measured artifact lies outside the observed build."""


def require(condition, code):
    if not condition:
        raise ProbeError(code)


def bounded_path(value, cwd, roots, *, output=False, scope_error="path_scope"):
    require(isinstance(value, str) and PATH_WORD.fullmatch(value), "path_shape")
    path = cwd / value
    if output:
        resolved = path.parent.resolve(strict=True) / path.name
        require(not path.exists() and not path.is_symlink(), "output_exists")
    else:
        resolved = path.resolve(strict=True)
    require(any(resolved.is_relative_to(root) for root in roots), scope_error)
    return resolved


def parse_invocation(arguments, cwd, *, include_roots=None, library_roots=None):
    """Accept only the C/object forms emitted by the two pinned package backends."""
    include_roots = INCLUDE_ROOTS if include_roots is None else include_roots
    library_roots = LIBRARY_ROOTS if library_roots is None else library_roots
    require(
        1 <= len(arguments) <= 160
        and all(
            0 < len(arg) <= 1024 and all(32 <= ord(char) < 127 for char in arg) for arg in arguments
        ),
        "argv_budget",
    )
    compile_call = arguments.count("-c") == 1 and "-shared" not in arguments
    link_call = arguments.count("-shared") == 1 and "-c" not in arguments
    require(compile_call or link_call, "call_kind")
    output = None
    inputs, libraries = [], []
    args = iter(arguments)
    for arg in args:
        if arg == "-o":
            require(output is None, "duplicate_output")
            output = bounded_path(next(args, ""), cwd, (cwd,), output=True)
        elif compile_call and (
            arg in COMPILE_FLAGS or MACRO.fullmatch(arg) or WARNING.fullmatch(arg)
        ):
            continue
        elif link_call and arg in LINK_FLAGS:
            continue
        elif (compile_call and arg.startswith("-I")) or (link_call and arg.startswith("-L")):
            roots = (cwd, *include_roots) if compile_call else library_roots
            value = arg[2:] or next(args, "")
            require(bounded_path(value, cwd, roots).is_dir(), "search_path_directory")
        elif link_call and arg.startswith("-l") and arg[2:] in {"ldap", "lber", "pq"}:
            libraries.append(arg[2:])
        elif not arg.startswith("-") and arg.endswith(".c" if compile_call else ".o"):
            inputs.append(bounded_path(arg, cwd, (cwd,)))
        else:
            raise ProbeError("unexpected_compiler_argument")
    require(output is not None and len(set(inputs)) == len(inputs), "call_paths")
    if compile_call:
        require(len(inputs) == 1 and output.suffix == ".o", "compile_shape")
        return "compile", inputs, output
    require(
        1 <= len(inputs) <= 40 and tuple(libraries) == OUTPUT_LIBRARIES.get(output.name),
        "link_shape",
    )
    return "link", inputs, output


def measured(path, *, capture=False):
    """Read one regular file once and detect mutation while reading it."""
    cap = MAX_DATA if capture else MAX_FILE
    original = path.stat(follow_symlinks=False)
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_BINARY", 0))
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, "file_type_or_budget")
        digester, chunks, count = hashlib.sha256(), [], 0
        while block := stream.read(65536):
            count += len(block)
            require(count <= cap, "file_read_budget")
            digester.update(block)
            if capture:
                chunks.append(block)
        after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)

        def identity(info):
            return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns

        require(
            count == before.st_size
            and identity(original) == identity(before) == identity(after) == identity(current)
            and before.st_ctime_ns == after.st_ctime_ns
            and original.st_ctime_ns == current.st_ctime_ns,
            "file_changed",
        )
    result = {"path": str(path), "sha256": digester.hexdigest(), "size": count}
    return (result, b"".join(chunks)) if capture else result


def read_dependencies(raw, cwd, source, *, include_roots=None):
    include_roots = DEPENDENCY_ROOTS if include_roots is None else include_roots
    text = raw.decode("ascii").replace("\\\n", " ").strip()
    lines = text.splitlines()
    require(len(lines) == 1 and lines[0].startswith("pamolive-provenance:"), "dependency_shape")
    words = lines[0].removeprefix("pamolive-provenance:").split()
    require(2 <= len(words) <= MAX_ITEMS, "dependency_count")
    paths = [bounded_path(word, cwd, (cwd, *include_roots), scope_error="dependency_path_scope")
             for word in words]
    require(paths[0] == source and source not in paths[1:], "dependency_source")
    return [measured(path) for path in dict.fromkeys(paths[1:])]


def read_load_entries(raw, cwd, objects, *, library_roots=None):
    library_roots = LIBRARY_ROOTS if library_roots is None else library_roots
    paths = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not line.lstrip().startswith("LOAD "):
            continue
        value = line.lstrip().removeprefix("LOAD ")
        path = bounded_path(value, cwd, (cwd, *library_roots), scope_error="link_path_scope")
        if path.is_relative_to(cwd):
            require(path in objects, "link_unexpected_build_input")
        else:
            require(
                not path.name.startswith(("libstdc++", "libc++", "libsupc++"))
                and (path.suffix != ".a" or path.name in SUPPORT_ARCHIVES),
                "link_unexpected_archive",
            )
        paths.append(path)
        require(len(paths) <= MAX_ITEMS, "link_load_count")
    require(paths and all(item in paths for item in objects), "link_objects_missing")
    return [measured(path) for path in paths]


def gcc_environment(environ):
    require(not any(environ.get(name) for name in OVERRIDES), "compiler_environment")
    return {
        **environ,
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": str(BUILD_ROOT),
    }


def gcc_tool(environment):
    def query(option):
        value = subprocess.check_output([GCC, option], env=environment, timeout=10)
        require(0 < len(value) <= 1024, "gcc_query_budget")
        return value.decode("ascii").strip()

    machine, version = query("-dumpmachine"), query("-dumpfullversion")
    require(machine == TRIPLE and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version), "gcc_identity")
    programs = {}
    for name in ("cc1", "as", "collect2", "ld"):
        value = query("-print-prog-name=" + name)
        require(PATH_WORD.fullmatch(value), "gcc_program_path")
        if not value.startswith("/"):
            value = shutil.which(value, path=environment["PATH"])
        path = bounded_path(value, Path("/"), TOOL_ROOTS, scope_error="tool_path_scope")
        require(os.access(path, os.X_OK), "gcc_program_executable")
        programs[name] = measured(path)
    path = bounded_path(GCC, Path("/"), TOOL_ROOTS)
    return {**measured(path), "machine": machine, "version": version, "subprograms": programs}


def exclusive_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def record(arguments, cwd, trace, environment):
    kind, inputs, output = parse_invocation(arguments, cwd)
    before = [measured(path) for path in inputs]
    tool = gcc_tool(environment)
    key = hashlib.sha256(json.dumps([str(cwd), kind, arguments], separators=(",", ":")).encode())
    stem = kind + "-" + key.hexdigest()

    with tempfile.TemporaryDirectory(prefix="compiler-", dir=trace) as work:
        suffix = ".d" if kind == "compile" else ".map"
        auxiliary = Path(work) / ("result" + suffix)
        capture_flags = (
            ["-MD", "-MF", str(auxiliary), "-MT", "pamolive-provenance"]
            if kind == "compile"
            else ["-Wl,-Map," + str(auxiliary)]
        )
        argv = [GCC, *arguments, *capture_flags]
        subprocess.run(argv, cwd=cwd, env=environment, timeout=TIMEOUT, check=True)
        require([measured(path) for path in inputs] == before, "compiler_input_changed")
        require(output.resolve(strict=True) == output, "compiler_output_changed")
        auxiliary_info, raw = measured(auxiliary, capture=True)
        result = {
            "schema": SCHEMA,
            "kind": kind,
            "cwd": str(cwd),
            "argv": argv,
            "tool": tool,
            "output": measured(output),
        }
        if kind == "compile":
            result.update(
                source=before[0],
                headers=read_dependencies(raw, cwd, inputs[0]),
                dependency_sha256=auxiliary_info["sha256"],
            )
        else:
            result.update(
                objects=before,
                load=read_load_entries(raw, cwd, inputs),
                map_sha256=auxiliary_info["sha256"],
            )
        metadata = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
        require(len(metadata) <= MAX_DATA, "compiler_report_budget")
        exclusive_write(trace / (stem + suffix), raw)
        exclusive_write(trace / (stem + ".json"), metadata)


def main():
    try:
        require(sys.platform == "linux", "linux_required")
        cwd = Path.cwd().resolve(strict=True)
        require(cwd != BUILD_ROOT and cwd.is_relative_to(BUILD_ROOT), "build_directory")
        trace = Path(os.environ.get("PAMOLIVE_PROVENANCE_DIR", str(TRACE_ROOT)))
        require(trace == TRACE_ROOT and trace.resolve(strict=True) == trace, "trace_directory")
        info = trace.stat(follow_symlinks=False)
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            "trace_permissions",
        )
        record(sys.argv[1:], cwd, trace, gcc_environment(os.environ))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
        print(f"Python native compiler observation refused ({reason}).", file=sys.stderr)
        return 42
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
