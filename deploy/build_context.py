"""Create a bounded Docker context from one committed Git tree, never local extras."""

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from contextlib import ExitStack, contextmanager
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from tempfile import TemporaryFile

MAX_BYTES = 128 * 1024**2
MAX_FILES = 5000
MAX_FILE = 32 * 1024**2
FORBIDDEN = {
    ".github/workflows/diagnose-partition.yml",
    "deploy/Dockerfile.partition-probe",
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def checked_members(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "context_archive_budget")
    files, seen, folded, total = [], set(), set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            path = PurePosixPath(name)
            require(
                0 < len(name) <= 512
                and not path.is_absolute()
                and str(path) == name
                and ".." not in path.parts
                and "\\" not in name
                and "\0" not in name
                and all(":" not in part for part in path.parts),
                "context_path",
            )
            require(
                all(
                    part == part.rstrip(" .")
                    and not re.fullmatch(
                        r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part, re.IGNORECASE
                    )
                    for part in path.parts
                ),
                "context_windows_alias",
            )
            require(name not in seen and name.casefold() not in folded, "context_duplicate")
            seen.add(name)
            folded.add(name.casefold())
            require(len(seen) <= MAX_FILES, "context_file_count")
            require(name not in FORBIDDEN and ".git" not in path.parts, "context_private_path")
            require(member.isdir() or member.isfile(), "context_file_type")
            require(not member.mode & 0o7000, "context_special_mode")
            if member.isdir():
                continue
            require(0 <= member.size <= MAX_FILE, "context_file_budget")
            total += member.size
            require(total <= MAX_BYTES, "context_total_budget")
            with archive.extractfile(member) as stream:
                content = stream.read(MAX_FILE + 1)
            require(len(content) == member.size, "context_file_size")
            files.append((name, content, 0o755 if member.mode & 0o111 else 0o644))
    require(
        files and {"Dockerfile", ".dockerignore"} <= {row[0] for row in files},
        "context_required_inputs",
    )
    # A file may not also be an ancestor of another member (even on Windows).
    names = {name for name, _, _ in files}
    require(
        not any(str(parent) in names for name in seen for parent in PurePosixPath(name).parents),
        "context_path_collision",
    )
    return files


def create(root, destination, revision, *, sealed_archive=None, sealed_receipt=None):
    require(type(revision) is str and re.fullmatch(r"[a-f0-9]{40}", revision), "context_revision")
    require((sealed_archive is None) == (sealed_receipt is None), "context_seal_outputs")
    if sealed_archive is not None:
        require(sys.platform == "linux", "sealed_context_linux_required")
    root = Path(root).resolve(strict=True)
    destination = Path(destination)
    require(not destination.exists() and not destination.is_symlink(), "context_destination_exists")
    command = ["git", "-c", "safe.directory=" + root.as_posix(), "-C", str(root)]
    # Spool Git output to disk; cap archive size before parsing or creating files.
    with TemporaryFile() as stream:
        result = subprocess.run(
            [*command, "archive", "--format=tar", revision],
            stdout=stream,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        require(result.returncode == 0, "context_git_archive")
        require(stream.tell() <= MAX_BYTES, "context_archive_budget")
        stream.seek(0)
        raw = stream.read(MAX_BYTES + 1)
    files = checked_members(raw)
    destination.mkdir(mode=0o700)
    manifest, written = {}, {}
    for name, content, mode in files:
        target = destination / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(content)
            if sealed_archive is not None:
                output.flush()
                target.chmod(mode)
                written[name] = identity(os.fstat(output.fileno()))
        if sealed_archive is None:
            target.chmod(mode)
        manifest[name] = hashlib.sha256(content).hexdigest()
    report = {
        "schema": "pamolive.committed-build-context.v1",
        "revision": revision,
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "files": manifest,
    }
    if sealed_archive is not None:
        seal_context(destination, files, written, report, sealed_archive, sealed_receipt)
    return report


def bind_recipe(report, recipe):
    """Tie reviewed inputs to committed context bytes, including Dockerfile."""
    from deploy.build_recipe import validate

    validate(recipe)
    require(
        type(report) is dict
        and report.get("schema") == "pamolive.committed-build-context.v1"
        and type(report.get("files")) is dict,
        "context_manifest",
    )
    actual = {
        name: value
        for name, value in report["files"].items()
        if name not in recipe["excluded_exact_paths"]
    }
    require(actual == recipe["files"], "context_recipe_changed")
    return {
        "recipe_bound": True,
        "revision": report["revision"],
        "source_files": len(actual),
        "compilation_proof": False,
    }


# This finite profile reproduces only the existing public credential-exclusion canaries.
CANARY = b"must-not-enter-the-image"
CANARIES = (
    ".bootstrap-admin",
    ".image-private-check.dump",
    ".image-private-context/undesignated.txt",
    "config/.nas-access/key-without-extension",
    "config/qualification.pem",
    "tests/.env.qualification",
    "tests/qualification.tar",
)
SEAL_SCHEMA = "pamolive.sealed-build-context/1"
IDENTITY_FIELDS = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")


# Finite current-profile policy: never parse arbitrary future .dockerignore rules.
PROFILE_ID = "pamolive-current-dockerignore-v1"
DOCKERIGNORE_SHA = "5ae994f8624c68308c7b6070364db7371c63a719fd1efe818f891624ae387d87"
DOCKERFILE_SHA = "618bad8a36158bfecff7df0f1a5039d89904e18881c41cd12553b9b45aa2c01c"
ROOT_FILES = frozenset(
    {
        "Dockerfile",
        "README.md",
        "LICENSE",
        "manage.py",
        "pyproject.toml",
        "requirements.lock",
        "requirements-bootstrap.lock",
        "requirements-native-build.lock",
        "requirements-database-build.lock",
        "requirements-dev.lock",
        "requirements-directory.lock",
        "requirements-native-test.lock",
        "requirements-python-runtime-linux.lock",
        "requirements-python-build-tools-linux.lock",
        "requirements-python-native-sources-linux.lock",
        "requirements-python-native-test-linux.lock",
    }
)
ROOT_DIRS = frozenset(
    {
        "config",
        "deploy",
        "docs",
        "examples",
        "integrations",
        "platform_core",
        "platform_modules",
        "templates",
        "tests",
        "third_party",
    }
)
EXCLUDED_COMPONENTS = (
    ".git",
    ".venv",
    ".nas-access",
    ".ssh",
    ".docker",
    ".env",
    ".env.*",
    "*.env",
    "*.secret",
    ".bootstrap-admin",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.tgz",
    "*.tar",
    "*.tar.gz",
    "*.zip",
    "*.dump",
    "*.backup",
    "*.pgdump",
    "*.sqlite3",
    "__pycache__",
    "*.py[cod]",
    ".pytest_cache",
    ".ruff_cache",
    "*.whl",
    "*.egg-info",
    "build",
    "dist",
)
EXCLUDED_PATHS = (
    "deploy/bootstrap-nas.sh",
    "deploy/Dockerfile.partition-probe",
    "deploy/check_image_scan_ci.sh",
)
CONTROLS = ("Dockerfile", ".dockerignore")


def copy_selected(name):
    if name == ".env.example":
        return True
    path = PurePosixPath(name)
    if name not in ROOT_FILES and path.parts[0] not in ROOT_DIRS:
        return False
    return not (
        any(fnmatchcase(part, pattern) for part in path.parts for pattern in EXCLUDED_COMPONENTS)
        or any(name == path or name.startswith(path + "/") for path in EXCLUDED_PATHS)
    )


def profile():
    return {
        "id": PROFILE_ID,
        "dockerignore_sha256": DOCKERIGNORE_SHA,
        "dockerfile_sha256": DOCKERFILE_SHA,
    }


def selection(files):
    table = {name: data for name, data, _ in files}
    require(
        set(CONTROLS) <= table.keys()
        and hashlib.sha256(table["Dockerfile"]).hexdigest() == DOCKERFILE_SHA
        and hashlib.sha256(table[".dockerignore"]).hexdigest() == DOCKERIGNORE_SHA
        and "Dockerfile.dockerignore" not in table,
        "context_selection_profile",
    )
    selected = [row for row in files if row[0] in CONTROLS or copy_selected(row[0])]
    omitted = sorted(name for name in table if name not in {row[0] for row in selected})
    require(all(not copy_selected(name) for name in CANARIES), "context_canary_selected")
    return selected, {
        "profile": profile(),
        "git_files_in_tar": len(selected),
        "omitted_git_files": len(omitted),
        "omitted_git_paths_sha256": hashlib.sha256(canonical(omitted)).hexdigest(),
        "control_files": list(CONTROLS),
        "synthetic_in_tar": 0,
    }


def source_manifest(path, receipt, revision):
    value, raw = read_json_file(path, 2 * 1024**2, (0o600, 0o644))
    require(
        type(value) is dict
        and set(value) == {"schema", "revision", "archive_sha256", "files", "recipe_bound"}
        and value["schema"] == "pamolive.committed-build-context.v1"
        and value["revision"] == revision == receipt["revision"]
        and value["archive_sha256"] == receipt["git_archive_sha256"]
        and value["recipe_bound"] is False
        and hashlib.sha256(raw).hexdigest() == receipt["committed_manifest_sha256"],
        "context_source_manifest",
    )
    files = value["files"]
    require(
        type(files) is dict
        and len(files) == receipt["source_files"]
        and 2 <= len(files) <= MAX_FILES
        and all(
            type(name) is str and type(digest) is str and re.fullmatch(r"[a-f0-9]{64}", digest)
            for name, digest in files.items()
        ),
        "context_source_files",
    )
    expected_nodes([(name, b"", 0o644) for name in files])
    require(
        all(
            name not in FORBIDDEN
            and ".git" not in PurePosixPath(name).parts
            and all(
                part == part.rstrip(" .")
                and not re.fullmatch(
                    r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part, re.IGNORECASE
                )
                for part in PurePosixPath(name).parts
            )
            for name in files
        ),
        "context_source_path",
    )
    require(
        files.get("Dockerfile") == DOCKERFILE_SHA
        and files.get(".dockerignore") == DOCKERIGNORE_SHA
        and "Dockerfile.dockerignore" not in files,
        "context_selection_profile",
    )
    selected = [name for name in files if name in CONTROLS or copy_selected(name)]
    omitted = sorted(set(files) - set(selected))
    require(
        type(receipt["selection"]) is dict
        and all(
            type(receipt["selection"].get(key)) is int
            for key in ("git_files_in_tar", "omitted_git_files", "synthetic_in_tar")
        )
        and receipt["selection"]
        == {
            "profile": profile(),
            "git_files_in_tar": len(selected),
            "omitted_git_files": len(omitted),
            "omitted_git_paths_sha256": hashlib.sha256(canonical(omitted)).hexdigest(),
            "control_files": list(CONTROLS),
            "synthetic_in_tar": 0,
        },
        "context_selection_changed",
    )
    return value


def identity(value):
    return {key: getattr(value, "st_" + key) for key in IDENTITY_FIELDS}


@contextmanager
def directory(path):
    """Open only named absolute ancestors; never follow an alias or list outside context."""
    require(sys.platform == "linux", "sealed_context_linux_required")
    path = Path(path).absolute()
    require(".." not in path.parts, "context_parent_path")
    require(len(path.parts) <= 64, "context_parent_depth")
    with ExitStack() as descriptors:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.callback(os.close, descriptor)
        for part in path.parts[1:]:
            descriptor = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor
            )
            descriptors.callback(os.close, descriptor)
        yield descriptor


@contextmanager
def exclusive(path, mode=0o600):
    path = Path(path)
    with directory(path.parent) as parent:
        parent_state = os.fstat(parent)
        require(
            stat.S_IMODE(parent_state.st_mode) == 0o700
            and parent_state.st_uid == os.geteuid()
            and parent_state.st_gid == os.getegid(),
            "context_private_output_parent",
        )
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb", buffering=0) as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
            require(
                identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                == identity(os.fstat(stream.fileno())),
                "context_output_changed",
            )


def expected_nodes(files):
    names, directories, folded = {}, set(), set()
    total = 0
    for name, data, mode in files:
        path = PurePosixPath(name)
        require(
            bool(path.parts)
            and str(path) == name
            and not path.is_absolute()
            and ".." not in path.parts
            and len(path.parts) <= 32
            and 0 < len(name) <= 512
            and "\\" not in name
            and "\0" not in name
            and all(":" not in part for part in path.parts),
            "context_seal_path",
        )
        require(name not in names and name.casefold() not in folded, "context_seal_duplicate")
        require(
            mode in (0o644, 0o755) and type(data) is bytes and len(data) <= MAX_FILE,
            "context_seal_file",
        )
        names[name] = (len(data), mode)
        folded.add(name.casefold())
        directories.update(str(parent) for parent in path.parents if str(parent) != ".")
        total += len(data)
    require(
        not set(names) & directories
        and len(names) + len(directories) <= MAX_FILES
        and total <= MAX_BYTES,
        "context_seal_members_budget",
    )
    all_names = set(names) | directories
    require(len({name.casefold() for name in all_names}) == len(all_names), "context_seal_alias")
    return names, directories


def metadata_tree(root, files, written):
    """Metadata only: no filesystem file content is opened or read here."""
    names, directories = expected_nodes(files)
    expected = set(names) | directories
    found, aliases = {}, set()
    with directory(root) as root_fd:
        root_state = identity(os.fstat(root_fd))
        require(
            stat.S_IMODE(root_state["mode"]) == 0o700
            and root_state["uid"] == os.geteuid()
            and root_state["gid"] == os.getegid(),
            "context_root_metadata",
        )

        def visit(parent, prefix):
            before = identity(os.fstat(parent))
            with os.scandir(parent) as entries:
                for entry in entries:
                    name = prefix + entry.name
                    require(name in expected and name not in found, "context_unknown_entry")
                    value = identity(os.stat(entry.name, dir_fd=parent, follow_symlinks=False))
                    require((value["dev"], value["ino"]) not in aliases, "context_inode_alias")
                    aliases.add((value["dev"], value["ino"]))
                    require(
                        value["uid"] == os.geteuid() and value["gid"] == os.getegid(),
                        "context_entry_owner",
                    )
                    found[name] = value
                    if name in directories:
                        require(value["mode"] == stat.S_IFDIR | 0o755, "context_directory_mode")
                        child = os.open(
                            entry.name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent,
                        )
                        try:
                            require(identity(os.fstat(child)) == value, "context_directory_changed")
                            visit(child, name + "/")
                        finally:
                            os.close(child)
                    else:
                        size, mode = names[name]
                        require(
                            value["mode"] == stat.S_IFREG | mode
                            and value["nlink"] == 1
                            and value["size"] == size
                            and (written is None or value == written[name]),
                            "context_file_changed",
                        )
            require(identity(os.fstat(parent)) == before, "context_directory_changed")

        visit(root_fd, "")
        require(
            set(found) == expected and identity(os.fstat(root_fd)) == root_state,
            "context_members_changed",
        )
    return {"root": root_state, "nodes": found}


class BoundedWriter:
    def __init__(self, stream):
        self.stream, self.count = stream, 0

    def tell(self):
        return self.count

    def write(self, data):
        require(self.count + len(data) <= MAX_BYTES, "context_sealed_archive_budget")
        require(self.stream.write(data) == len(data), "context_archive_short_write")
        self.count += len(data)
        return len(data)


def write_tar(stream, files):
    """Use only original Git buffers and constant public canary buffers."""
    _, directories = expected_nodes(files)
    writer = BoundedWriter(stream)
    with tarfile.open(fileobj=writer, mode="w:", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(directories):
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(member)
        for name, data, mode in sorted(files):
            member = tarfile.TarInfo(name)
            member.mode, member.size = mode, len(data)
            archive.addfile(member, io.BytesIO(data))
    return writer.count


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def seal_context(destination, files, written, report, archive_path, receipt_path):
    require(sys.platform == "linux", "sealed_context_linux_required")
    require(
        all(
            not Path(path).absolute().is_relative_to(destination.absolute())
            for path in (archive_path, receipt_path)
        ),
        "context_output_inside_input",
    )
    selected, selected_report = selection(files)
    original = metadata_tree(destination, files, written)
    require(not set(CANARIES) & set(report["files"]), "context_canary_collision")
    all_files = [*files, *((name, CANARY, 0o644) for name in CANARIES)]
    expected_nodes(all_files)
    # New canary directories and files are exclusive, never adopted or overwritten.
    for name in (".image-private-context", "config/.nas-access"):
        path = destination / name
        with directory(path.parent) as parent:
            os.mkdir(path.name, 0o755, dir_fd=parent)
    for name in CANARIES:
        path = destination / name
        with directory(path.parent) as parent:
            fd = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=parent,
            )
            with os.fdopen(fd, "wb", buffering=0) as stream:
                require(stream.write(CANARY) == len(CANARY), "context_canary_short_write")
                os.fchmod(stream.fileno(), 0o644)
                written[name] = identity(os.fstat(stream.fileno()))
    captured = metadata_tree(destination, all_files, written)
    for name in ["root", *original["nodes"]]:
        before = original["root"] if name == "root" else original["nodes"][name]
        after = captured["root"] if name == "root" else captured["nodes"][name]
        require(
            all(before[key] == after[key] for key in ("dev", "ino", "mode", "uid", "gid")),
            "context_ancestor_changed",
        )
    # Both files remain local. Only the finite receipt is a public diagnostic.
    with exclusive(archive_path) as stream:
        count = write_tar(stream, selected)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o400)
        archive_identity = identity(os.fstat(stream.fileno()))
    require(
        metadata_tree(destination, all_files, written) == captured, "context_changed_during_seal"
    )
    # Hash this exact descriptor, checked against the identity captured while writing.
    with bound_archive(archive_path, archive_identity) as stream:
        digest = stream_hash(stream, count)
    receipt = {
        "schema": SEAL_SCHEMA,
        "revision": report["revision"],
        "committed_manifest_sha256": hashlib.sha256(
            canonical({**report, "recipe_bound": False})
        ).hexdigest(),
        "git_archive_sha256": report["archive_sha256"],
        "source_files": len(files),
        "selection": selected_report,
        "synthetic_files": list(CANARIES),
        "synthetic_sha256": hashlib.sha256(CANARY).hexdigest(),
        "archive": {"sha256": digest, "bytes": count, "identity": archive_identity},
        "tar_policy": "sorted-pax-source-modes-uid0-gid0-mtime0-v1",
        "recipe_bound": False,
        "build_verified": False,
        "cryptographic_build_attestation_verified": False,
        "authority": False,
    }
    raw = canonical(receipt)
    require(len(raw) <= 16384, "context_receipt_budget")
    with exclusive(receipt_path) as stream:
        require(stream.write(raw) == len(raw), "context_receipt_short_write")


@contextmanager
def bound_archive(path, expected):
    path = Path(path)
    require(
        type(expected) is dict
        and set(expected) == set(IDENTITY_FIELDS)
        and all(type(value) is int and value >= 0 for value in expected.values())
        and expected["mode"] == stat.S_IFREG | 0o400
        and expected["nlink"] == 1
        and expected["uid"] == os.geteuid()
        and expected["gid"] == os.getegid()
        and 0 < expected["size"] <= MAX_BYTES,
        "context_archive_identity",
    )
    with directory(path.parent) as parent:
        require(
            identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == expected,
            "context_archive_path_changed",
        )
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb", buffering=0) as stream:
            require(identity(os.fstat(stream.fileno())) == expected, "context_archive_fd_changed")
            yield stream
            require(
                identity(os.fstat(stream.fileno())) == expected
                and identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == expected,
                "context_archive_changed",
            )


def stream_hash(stream, count):
    require(type(count) is int and 0 < count <= MAX_BYTES, "context_archive_size")
    stream.seek(0)
    digest, size = hashlib.sha256(), 0
    while data := stream.read(min(65536, count + 1 - size)):
        size += len(data)
        require(size <= count, "context_archive_growth")
        digest.update(data)
    require(size == count, "context_archive_size")
    stream.seek(0)
    return digest.hexdigest()


def read_json_file(path, maximum, modes):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "context_receipt_duplicate")
            value[key] = item
        return value

    path = Path(path)
    with directory(path.parent) as parent:
        before = identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
        require(
            stat.S_IMODE(before["mode"]) in modes
            and stat.S_ISREG(before["mode"])
            and before["nlink"] == 1
            and before["uid"] == os.geteuid()
            and before["gid"] == os.getegid()
            and 0 < before["size"] <= maximum,
            "context_receipt_file",
        )
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb", buffering=0) as stream:
            require(identity(os.fstat(fd)) == before, "context_receipt_changed")
            raw = stream.read(maximum + 1)
            require(
                len(raw) == before["size"]
                and identity(os.fstat(fd)) == before
                and identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == before,
                "context_receipt_changed",
            )
    return json.loads(raw, object_pairs_hook=pairs), raw


def read_receipt(path):
    return read_json_file(path, 16384, (0o600,))[0]


PROBE_DOCKERFILE = b"FROM scratch\nCOPY . /proof\n"
PROBE_PREFIX = b"pamolive public context parity/1\n"
PROBE_COUNTERS = (
    (".env.example", True),
    ("config/__profile_probe__/PUBLIC.PEM", True),
    ("config/__profile_probe__/public.env.example", True),
    ("config/__profile_probe__/building/public.txt", True),
    ("deploy/check_image_scan_ci.sh.txt", True),
    ("unreviewed-root/public.txt", False),
    ("requirements-unreviewed.lock", False),
    ("config/__profile_probe__/n01/.git/marker", False),
    ("config/__profile_probe__/n02/.venv/marker", False),
    ("config/__profile_probe__/n03/.nas-access/marker", False),
    ("config/__profile_probe__/n04/.ssh/marker", False),
    ("config/__profile_probe__/n05/.docker/marker", False),
    ("config/__profile_probe__/n06/.env", False),
    ("config/__profile_probe__/n07/.env.fixture", False),
    ("config/__profile_probe__/n08/public.env", False),
    ("config/__profile_probe__/n09/public.secret", False),
    ("config/__profile_probe__/n10/.bootstrap-admin", False),
    ("config/__profile_probe__/n11/id_rsa", False),
    ("config/__profile_probe__/n12/id_ed25519", False),
    ("config/__profile_probe__/n13/id_ecdsa", False),
    ("config/__profile_probe__/n14/public.pem", False),
    ("config/__profile_probe__/n15/public.key", False),
    ("config/__profile_probe__/n16/public.p12", False),
    ("config/__profile_probe__/n17/public.pfx", False),
    ("config/__profile_probe__/n18/public.tgz", False),
    ("config/__profile_probe__/n19/public.tar", False),
    ("config/__profile_probe__/n20/public.tar.gz", False),
    ("config/__profile_probe__/n21/public.zip", False),
    ("config/__profile_probe__/n22/public.dump", False),
    ("config/__profile_probe__/n23/public.backup", False),
    ("config/__profile_probe__/n24/public.pgdump", False),
    ("config/__profile_probe__/n25/public.sqlite3", False),
    ("config/__profile_probe__/n26/__pycache__/marker", False),
    ("config/__profile_probe__/n27/public.pyc", False),
    ("config/__profile_probe__/n28/public.pyo", False),
    ("config/__profile_probe__/n29/public.pyd", False),
    ("config/__profile_probe__/n30/.pytest_cache/marker", False),
    ("config/__profile_probe__/n31/.ruff_cache/marker", False),
    ("config/__profile_probe__/n32/public.whl", False),
    ("config/__profile_probe__/n33/public.egg-info/marker", False),
    ("config/__profile_probe__/n34/build/marker", False),
    ("config/__profile_probe__/n35/dist/marker", False),
    ("deploy/bootstrap-nas.sh", False),
    ("deploy/Dockerfile.partition-probe", False),
    ("deploy/check_image_scan_ci.sh", False),
)
PROBE_SCHEMA = "pamolive.context-selection-parity/1"


def probe_files(manifest, dockerignore):
    require(hashlib.sha256(dockerignore).hexdigest() == DOCKERIGNORE_SHA, "context_probe_control")
    return marker_files(manifest, dockerignore)


def marker_files(manifest, dockerignore):
    names = set(manifest["files"])
    # Counterexample paths deliberately remain independent of the observed output.
    for name, expected in PROBE_COUNTERS:
        require(copy_selected(name) is expected, "context_probe_case_policy")
        names.add(name)
    names.update(CANARIES)
    files = [
        (name, PROBE_PREFIX + name.encode("utf8") + b"\n", 0o644)
        for name in sorted(names - set(CONTROLS))
    ]
    files += [("Dockerfile", PROBE_DOCKERFILE, 0o644), (".dockerignore", dockerignore, 0o644)]
    expected_nodes(files)
    require(sum(len(row[1]) for row in files) <= 4 * 1024**2, "context_probe_bytes")
    return files


def make_probe_tree(destination, files):
    destination.mkdir(mode=0o700)
    written = {}
    for name, data, mode in files:
        target = destination / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with target.open("xb") as output:
            require(output.write(data) == len(data), "context_probe_short_write")
            output.flush()
            target.chmod(mode)
            written[name] = identity(os.fstat(output.fileno()))
    return metadata_tree(destination, files, written), written


def exported_probe(root, files):
    # Complete membership/type/size/mode/owner pass BEFORE any output content read.
    captured = metadata_tree(root, files, None)
    for name, data, _ in files:
        path = root / name
        before = captured["nodes"][name]
        with directory(path.parent) as parent:
            require(
                identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == before,
                "context_probe_output_changed",
            )
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
            )
            with os.fdopen(descriptor, "rb", buffering=0) as stream:
                require(identity(os.fstat(descriptor)) == before, "context_probe_output_changed")
                require(stream.read(len(data) + 1) == data, "context_probe_output_bytes")
                require(
                    identity(os.fstat(descriptor)) == before
                    and identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                    == before,
                    "context_probe_output_changed",
                )
    require(metadata_tree(root, files, None) == captured, "context_probe_output_changed")
    return hashlib.sha256(
        canonical(
            [
                (name, len(data), mode, hashlib.sha256(data).hexdigest())
                for name, data, mode in sorted(files)
            ]
        )
    ).hexdigest()


def verified_tar(stream, receipt, manifest):
    stream.seek(0)
    raw = stream.read(MAX_BYTES + 1)
    require(
        len(raw) == receipt["archive"]["bytes"]
        and hashlib.sha256(raw).hexdigest() == receipt["archive"]["sha256"],
        "context_archive_hash",
    )
    rows = checked_members(raw)
    actual = {name: data for name, data, _ in rows}
    expected = {
        name: digest
        for name, digest in manifest["files"].items()
        if name in CONTROLS or copy_selected(name)
    }
    require(
        set(actual) == set(expected)
        and all(
            hashlib.sha256(actual[name]).hexdigest() == digest for name, digest in expected.items()
        ),
        "context_tar_manifest",
    )
    require(not set(CANARIES) & set(actual), "context_canary_in_tar")
    stream.seek(0)
    return actual[".dockerignore"]


def probe(archive_path, receipt_path, source_path, probe_path, revision):
    receipt, manifest = checked_seal(receipt_path, source_path, revision)
    parent = Path(receipt_path).absolute().parent
    require(Path(probe_path).absolute() == parent / "probe.json", "context_probe_receipt_path")
    source, exported = parent / "probe-source", parent / "probe-export"
    # Fail before contacting Docker if either private name already exists, including links.
    with directory(parent) as fd:
        for name in ("probe-source", "probe-export", "probe.json"):
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("context_probe_destination_exists")
    with bound_archive(archive_path, receipt["archive"]["identity"]) as stream:
        dockerignore = verified_tar(stream, receipt, manifest)
        files = probe_files(manifest, dockerignore)
        captured, written = make_probe_tree(source, files)
        argv = [
            "docker",
            "build",
            "--file",
            str(source / "Dockerfile"),
            "--network=none",
            "--provenance=false",
            "--sbom=false",
            "--output",
            "type=local,dest=" + str(exported),
            str(source),
        ]
        result = subprocess.run(argv, check=False)
        require(
            type(result.returncode) is int and result.returncode == 0, "context_probe_docker_exit"
        )
        require(metadata_tree(source, files, written) == captured, "context_probe_source_changed")
        expected = [
            ("proof/" + name, data, mode) for name, data, mode in files if copy_selected(name)
        ]
        digest = exported_probe(exported, expected)
        require(
            stream_hash(stream, receipt["archive"]["bytes"]) == receipt["archive"]["sha256"],
            "context_archive_hash",
        )
    value = {
        "schema": PROBE_SCHEMA,
        "revision": revision,
        "profile": profile(),
        "status": "PASS",
        "committed_manifest_sha256": receipt["committed_manifest_sha256"],
        "git_archive_sha256": receipt["git_archive_sha256"],
        "archive_sha256": receipt["archive"]["sha256"],
        "source_files": receipt["source_files"],
        "probe_files": len(files),
        "exported_files": len(expected),
        "exported_public_markers_sha256": digest,
        "docker_returncode": result.returncode,
        "H1_qualified": False,
        "global_cleanup_qualified": False,
        "authority": False,
    }
    raw = canonical(value)
    require(len(raw) <= 16384, "context_probe_receipt_budget")
    with exclusive(probe_path) as output:
        require(output.write(raw) == len(raw), "context_probe_receipt_short_write")
    return 0


def require_probe(path, receipt, manifest):
    require(path is not None, "context_probe_receipt_required")
    value = read_receipt(path)
    files = marker_files(manifest, b"")
    expected = [("proof/" + name, data, mode) for name, data, mode in files if copy_selected(name)]
    expected_digest = hashlib.sha256(
        canonical(
            [
                (name, len(data), mode, hashlib.sha256(data).hexdigest())
                for name, data, mode in sorted(expected)
            ]
        )
    ).hexdigest()
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "revision",
            "profile",
            "status",
            "committed_manifest_sha256",
            "git_archive_sha256",
            "archive_sha256",
            "source_files",
            "probe_files",
            "exported_files",
            "exported_public_markers_sha256",
            "docker_returncode",
            "H1_qualified",
            "global_cleanup_qualified",
            "authority",
        }
        and value["schema"] == PROBE_SCHEMA
        and value["status"] == "PASS"
        and value["profile"] == profile()
        and all(
            value[key] == receipt[key]
            for key in (
                "revision",
                "committed_manifest_sha256",
                "git_archive_sha256",
                "source_files",
            )
        )
        and value["archive_sha256"] == receipt["archive"]["sha256"]
        and value["probe_files"] == len(files)
        and value["exported_files"] == len(expected)
        and value["exported_public_markers_sha256"] == expected_digest
        and all(
            type(value[key]) is int and 1 <= value[key] <= MAX_FILES
            for key in ("source_files", "probe_files", "exported_files")
        )
        and type(value["docker_returncode"]) is int
        and value["docker_returncode"] == 0
        and type(value["exported_public_markers_sha256"]) is str
        and re.fullmatch(r"[a-f0-9]{64}", value["exported_public_markers_sha256"])
        and all(
            value[key] is False for key in ("H1_qualified", "global_cleanup_qualified", "authority")
        ),
        "context_probe_receipt",
    )


def checked_seal(receipt_path, source_path, revision):
    receipt = read_receipt(receipt_path)
    require(
        type(receipt) is dict
        and set(receipt)
        == {
            "schema",
            "revision",
            "committed_manifest_sha256",
            "git_archive_sha256",
            "source_files",
            "selection",
            "synthetic_files",
            "synthetic_sha256",
            "archive",
            "tar_policy",
            "recipe_bound",
            "build_verified",
            "cryptographic_build_attestation_verified",
            "authority",
        },
        "context_receipt_schema",
    )
    require(
        receipt["schema"] == SEAL_SCHEMA
        and receipt["revision"] == revision
        and re.fullmatch(r"[a-f0-9]{40}", revision)
        and all(
            receipt[key] is False
            for key in (
                "recipe_bound",
                "build_verified",
                "cryptographic_build_attestation_verified",
                "authority",
            )
        )
        and receipt["synthetic_files"] == list(CANARIES)
        and receipt["synthetic_sha256"] == hashlib.sha256(CANARY).hexdigest()
        and receipt["tar_policy"] == "sorted-pax-source-modes-uid0-gid0-mtime0-v1"
        and type(receipt["source_files"]) is int
        and 1 <= receipt["source_files"] <= MAX_FILES,
        "context_receipt_contract",
    )
    require(source_path is not None, "context_source_manifest_required")
    manifest = source_manifest(source_path, receipt, revision)
    archive = receipt["archive"]
    require(
        type(archive) is dict
        and set(archive) == {"sha256", "bytes", "identity"}
        and type(archive["bytes"]) is int
        and 0 < archive["bytes"] <= MAX_BYTES
        and type(archive["identity"]) is dict
        and archive["bytes"] == archive["identity"].get("size")
        and all(
            type(receipt[key]) is str and re.fullmatch(r"[a-f0-9]{64}", receipt[key])
            for key in ("committed_manifest_sha256", "git_archive_sha256")
        )
        and type(archive["sha256"]) is str
        and re.fullmatch(r"[a-f0-9]{64}", archive["sha256"]),
        "context_receipt_hash",
    )
    return receipt, manifest


def consume(
    archive_path,
    receipt_path,
    revision,
    target,
    oracle_output=None,
    source_path=None,
    probe_path=None,
):
    require(target in ("production", "native-test", "json-reference-data"), "context_target")
    receipt, manifest = checked_seal(receipt_path, source_path, revision)
    archive = receipt["archive"]
    require_probe(probe_path, receipt, manifest)
    argv = ["docker", "build", "--target", target]
    if target == "production":
        argv += [
            "--provenance=false",
            "--sbom=false",
            "--label",
            "org.opencontainers.image.source=https://github.com/pamolive/PamOlive-Platform",
            "--label",
            "org.opencontainers.image.revision=" + revision,
            "--label",
            "io.pamolive.source.license=AGPL-3.0-or-later",
        ]
    if target == "json-reference-data":
        runner_temp = Path(os.environ["RUNNER_TEMP"])
        expected_output = runner_temp / "pamolive-jansson-reference-data"
        require(
            runner_temp.is_absolute()
            and ".." not in runner_temp.parts
            and oracle_output is not None
            and Path(oracle_output) == expected_output,
            "context_reference_output",
        )
        with directory(expected_output.parent) as parent:
            try:
                os.stat(expected_output.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("context_reference_output_exists")
        argv += [
            "--provenance=false",
            "--sbom=false",
            "--output",
            "type=local,dest=" + str(expected_output),
        ]
    else:
        require(oracle_output is None, "context_unexpected_reference_output")
        argv += ["-t", "pamolive-platform:" + ("ci" if target == "production" else "native-test")]
    argv += ["--file", "Dockerfile", "-"]
    with bound_archive(archive_path, archive["identity"]) as stream:
        verified_tar(stream, receipt, manifest)
        # Same descriptor goes to Docker; no path reopen, pipe reconstruction or context walk.
        result = subprocess.run(argv, stdin=stream, check=False)
        require(type(result.returncode) is int, "context_docker_returncode")
        require(stream_hash(stream, archive["bytes"]) == archive["sha256"], "context_archive_hash")
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--sealed-archive", type=Path)
    parser.add_argument("--sealed-receipt", type=Path)
    parser.add_argument(
        "--build-target", choices=("production", "native-test", "json-reference-data")
    )
    parser.add_argument("--oracle-output", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--probe-receipt", type=Path)
    parser.add_argument("--probe", action="store_true")
    args = parser.parse_args()
    if args.probe:
        try:
            require(
                args.build_target is None
                and args.destination is None
                and args.output is None
                and args.recipe is None
                and args.oracle_output is None
                and args.source_manifest is not None
                and args.probe_receipt is not None
                and args.sealed_archive is not None
                and args.sealed_receipt is not None,
                "context_probe_arguments",
            )
            return probe(
                args.sealed_archive,
                args.sealed_receipt,
                args.source_manifest,
                args.probe_receipt,
                args.revision,
            )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            RecursionError,
            tarfile.TarError,
            subprocess.SubprocessError,
        ):
            print(
                '{"parity_probe":false,"error":"context_parity_refused","global_cleanup_qualified":false}'
            )
            return 1
    if args.build_target is not None:
        try:
            require(
                args.destination is None
                and args.output is None
                and args.recipe is None
                and args.sealed_archive is not None
                and args.sealed_receipt is not None,
                "context_consume_arguments",
            )
            return consume(
                args.sealed_archive,
                args.sealed_receipt,
                args.revision,
                args.build_target,
                args.oracle_output,
                args.source_manifest,
                args.probe_receipt,
            )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            RecursionError,
            tarfile.TarError,
            subprocess.SubprocessError,
        ):
            print('{"consumed":false,"error":"sealed_context_refused","build_may_have_run":true}')
            return 1
    try:
        require(
            args.destination is not None
            and args.output is not None
            and (args.sealed_archive is None) == (args.sealed_receipt is None)
            and (args.sealed_archive is None or args.recipe is None)
            and args.oracle_output is None
            and args.source_manifest is None
            and args.probe_receipt is None
            and not args.probe,
            "context_create_arguments",
        )
        with args.output.open("x", encoding="utf8", newline="\n") as output:
            report = create(
                args.root,
                args.destination,
                args.revision,
                sealed_archive=args.sealed_archive,
                sealed_receipt=args.sealed_receipt,
            )
            report["recipe_bound"] = False
            if args.recipe is not None:
                from deploy.build_recipe import read_json

                bind_recipe(report, read_json(args.recipe))
                report["recipe_bound"] = True
            output.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError):
        print('{"created":false,"error":"committed_context_failed"}')
        return 1
    print(json.dumps({"created": True, "source_files": len(report["files"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
