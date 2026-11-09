"""Export or verify the exact Docker image exercised by CI; never rebuild during promotion."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

REPOSITORY = "pamolive/PamOlive-Platform"
SOURCE = "https://github.com/" + REPOSITORY
TAG = "pamolive-platform:ci"
ARCHIVE = "pamolive-linux-amd64.tar"
METADATA = "qualified-image.json"
FORMAT = "pamolive.qualified-image/1"
MAX_ARCHIVE_SIZE = 2 * 1024**3
HASH = re.compile(r"[a-f0-9]{64}\Z")
REVISION = re.compile(r"[a-f0-9]{40}\Z")


class QualificationError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise QualificationError(reason)


def checked_revision(value):
    require(isinstance(value, str) and REVISION.fullmatch(value), "Invalid full Git revision.")
    return value


def read_json(path, limit):
    require(path.is_file() and not path.is_symlink(), "Missing or nonregular metadata file.")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Metadata too large.")
    return json.loads(data)


def archive_hash(path):
    require(path.is_file() and not path.is_symlink(), "Missing or nonregular image archive.")
    require(0 < path.stat().st_size <= MAX_ARCHIVE_SIZE, "Unsupported image archive size.")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024**2):
            digest.update(block)
    return digest.hexdigest()


def tar_metadata(bundle, name, maximum):
    members = [item for item in bundle if item.name == name]
    require(len(members) == 1 and members[0].isfile(), "Duplicate or nonregular Docker metadata.")
    member = members[0]
    require(0 < member.size <= maximum, "Unsupported Docker metadata size.")
    with bundle.extractfile(member) as stream:
        return stream.read()


def verify_labels(labels, revision):
    require(
        labels.get("org.opencontainers.image.source") == SOURCE
        and labels.get("org.opencontainers.image.revision") == revision
        and labels.get("io.pamolive.source.license") == "AGPL-3.0-or-later",
        "Image source, revision or license does not match.",
    )


def archive_image_id(path, revision):
    checked_revision(revision)
    with tarfile.open(path, mode="r:") as bundle:
        entries = json.loads(tar_metadata(bundle, "manifest.json", 65536))
        require(isinstance(entries, list) and len(entries) == 1, "Expected one Docker image.")
        item = entries[0]
        require(item.get("RepoTags") == [TAG], "Unexpected archived Docker tag.")
        config_name = item["Config"]
        require(
            re.fullmatch(r"(?:blobs/sha256/)?[a-f0-9]{64}(?:\.json)?", config_name),
            "Unexpected Docker configuration path.",
        )
        raw = tar_metadata(bundle, config_name, 262144)
    config = json.loads(raw)
    require(
        config.get("architecture") == "amd64" and config.get("os") == "linux",
        "Expected a native Linux amd64 image.",
    )
    runtime = config["config"]
    verify_labels(runtime.get("Labels", {}), revision)
    require(
        not {item.partition("=")[0] for item in runtime.get("Env", [])}
        & {"DATABASE_URL", "SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY"},
        "Application credentials must not be image environment defaults.",
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def docker_inspect(image):
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .}}", image],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    return json.loads(result.stdout)


def export_bundle(directory, revision):
    checked_revision(revision)
    info = docker_inspect(TAG)
    require(info["Os"] == "linux" and info["Architecture"] == "amd64", "Wrong image platform.")
    verify_labels(info["Config"].get("Labels", {}), revision)
    directory.mkdir()
    archive = directory / ARCHIVE
    subprocess.run(
        ["docker", "image", "save", "--output", str(archive), TAG], check=True, timeout=180
    )
    checksum = archive_hash(archive)
    image_id = archive_image_id(archive, revision)
    require(info["Id"] == image_id, "The archive does not match the tested image.")
    data = {
        "schema": FORMAT,
        "source": SOURCE,
        "revision": revision,
        "platform": "linux/amd64",
        "image_id": image_id,
        "archive_sha256": checksum,
    }
    with (directory / METADATA).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(data, sort_keys=True, indent=2) + "\n")
    return data


def verify_bundle(directory, revision):
    checked_revision(revision)
    require(directory.is_dir() and not directory.is_symlink(), "Missing bundle directory.")
    require(
        {item.name for item in directory.iterdir()} == {ARCHIVE, METADATA},
        "Unexpected bundle files.",
    )
    meta = read_json(directory / METADATA, 8192)
    require(
        meta.keys() == {"schema", "source", "revision", "platform", "image_id", "archive_sha256"}
        and meta["schema"] == FORMAT
        and meta["source"] == SOURCE
        and meta["revision"] == revision
        and meta["platform"] == "linux/amd64"
        and HASH.fullmatch(meta["archive_sha256"]),
        "Unexpected image qualification metadata.",
    )
    archive = directory / ARCHIVE
    require(archive_hash(archive) == meta["archive_sha256"], "Archive checksum differs.")
    require(archive_image_id(archive, revision) == meta["image_id"], "Archive image ID differs.")
    return meta


def verify_run(run, revision):
    checked_revision(revision)
    require(
        run.get("path") == ".github/workflows/ci.yml"
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and run.get("head_sha") == revision
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and (run.get("head_repository") or {}).get("full_name") == REPOSITORY
        and (run.get("repository") or {}).get("full_name") == REPOSITORY,
        "Expected successful push CI on this repository's exact main revision.",
    )


def verify_compose(source, registry, expected_image):
    for definition in (source, registry):
        require(set(definition["services"]) == {"web"}, "Expected a single application service.")
    source_web = dict(source["services"]["web"])
    registry_web = dict(registry["services"]["web"])
    require(source_web.pop("build", None), "Expected a source build.")
    require("build" not in registry_web, "Registry deployment must not compile locally.")
    require(registry_web.pop("image", None) == expected_image, "Unexpected registry image.")
    require(source_web == registry_web, "The runtime controls differ between deployment modes.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for operation in ("export", "verify"):
        command = sub.add_parser(operation)
        command.add_argument("directory", type=Path)
        command.add_argument("--revision", required=True)
    command = sub.add_parser("verify-run")
    command.add_argument("run", type=Path)
    command.add_argument("--revision", required=True)
    command = sub.add_parser("compare-compose")
    command.add_argument("source", type=Path)
    command.add_argument("registry", type=Path)
    command.add_argument("--image", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation in ("export", "verify"):
            action = export_bundle if args.operation == "export" else verify_bundle
            print(json.dumps(action(args.directory, args.revision), sort_keys=True))
        elif args.operation == "verify-run":
            verify_run(read_json(args.run, 524288), args.revision)
        else:
            verify_compose(
                read_json(args.source, 524288), read_json(args.registry, 524288), args.image
            )
    except QualificationError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (
        OSError,
        ValueError,
        AttributeError,
        KeyError,
        TypeError,
        tarfile.TarError,
        subprocess.SubprocessError,
    ):
        print("Invalid image qualification artifact or Docker operation.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
