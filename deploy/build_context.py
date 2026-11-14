"""Create a bounded Docker context from one committed Git tree, never local extras."""

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
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


def create(root, destination, revision):
    require(type(revision) is str and re.fullmatch(r"[a-f0-9]{40}", revision), "context_revision")
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
    manifest = {}
    for name, content, mode in files:
        target = destination / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(content)
        target.chmod(mode)
        manifest[name] = hashlib.sha256(content).hexdigest()
    return {
        "schema": "pamolive.committed-build-context.v1",
        "revision": revision,
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "files": manifest,
    }


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--recipe", type=Path)
    args = parser.parse_args()
    try:
        with args.output.open("x", encoding="utf8", newline="\n") as output:
            report = create(args.root, args.destination, args.revision)
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
