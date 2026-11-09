"""Export or verify the exact Docker image exercised by CI; never rebuild during promotion."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

REPOSITORY = "pamolive/PamOlive-Platform"
SOURCE = "https://github.com/" + REPOSITORY
TAG = "pamolive-platform:ci"
REGISTRY = "ghcr.io/pamolive/pamolive-platform"
REGISTRY_CHECK_TAG = "pamolive-platform:registry-check"
ARCHIVE = "pamolive-linux-amd64.tar"
METADATA = "qualified-image.json"
FORMAT = "pamolive.qualified-image/1"
MAX_ARCHIVE_SIZE = 2 * 1024**3
HASH = re.compile(r"[a-f0-9]{64}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
REVISION = re.compile(r"[a-f0-9]{40}\Z")
OCI_INDEX_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
OCI_MANIFEST_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)


class QualificationError(ValueError):
    pass


@dataclass(frozen=True)
class ImageIdentity:
    config_id: str
    descriptors: frozenset[str]


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


def oci_descriptors(bundle, config_id, config_size):
    if not any(member.name == "index.json" for member in bundle):
        return frozenset()
    index = json.loads(tar_metadata(bundle, "index.json", 262144))
    found = set()
    for _ in range(4):
        require(index["schemaVersion"] == 2, "Unexpected OCI index version.")
        descriptors = index["manifests"]
        require(
            isinstance(descriptors, list) and len(descriptors) == 1,
            "Expected one OCI image descriptor, with no additional platforms.",
        )
        descriptor = descriptors[0]
        target = descriptor["digest"]
        require(DIGEST.fullmatch(target) and target not in found, "Invalid OCI image digest.")
        raw = tar_metadata(bundle, "blobs/sha256/" + target[7:], 262144)
        require(
            len(raw) == descriptor["size"]
            and "sha256:" + hashlib.sha256(raw).hexdigest() == target,
            "OCI descriptor digest or size differs from its content.",
        )
        found.add(target)
        manifest = json.loads(raw)
        media_type = descriptor["mediaType"]
        if media_type in OCI_INDEX_TYPES:
            index = manifest
            continue
        require(media_type in OCI_MANIFEST_TYPES, "Unexpected OCI image descriptor type.")
        require(
            manifest["schemaVersion"] == 2
            and manifest["config"]["digest"] == config_id
            and manifest["config"]["size"] == config_size,
            "OCI manifest and Docker archive refer to different image configurations.",
        )
        return frozenset(found)
    raise QualificationError("Too many levels of OCI image descriptors.")


def archive_identity(path, revision, *, tag=TAG):
    checked_revision(revision)
    with tarfile.open(path, mode="r:") as bundle:
        entries = json.loads(tar_metadata(bundle, "manifest.json", 65536))
        require(isinstance(entries, list) and len(entries) == 1, "Expected one Docker image.")
        item = entries[0]
        require(item.get("RepoTags") == [tag], "Unexpected archived Docker tag.")
        config_name = item["Config"]
        require(
            re.fullmatch(r"(?:blobs/sha256/)?[a-f0-9]{64}(?:\.json)?", config_name),
            "Unexpected Docker configuration path.",
        )
        raw = tar_metadata(bundle, config_name, 262144)
        config_id = "sha256:" + hashlib.sha256(raw).hexdigest()
        require(
            config_name.rsplit("/", 1)[-1].removesuffix(".json") == config_id[7:],
            "Docker configuration path does not match its digest.",
        )
        descriptors = oci_descriptors(bundle, config_id, len(raw))
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
    return ImageIdentity(config_id, descriptors)


def archive_image_id(path, revision):
    return archive_identity(path, revision).config_id


def bind_engine_image(info, archived, revision):
    require(info["Os"] == "linux" and info["Architecture"] == "amd64", "Wrong image platform.")
    verify_labels(info["Config"].get("Labels", {}), revision)
    descriptor = info.get("Descriptor")
    if descriptor:
        # Containerd's inspect ID names the OCI target, not config.json.
        require(
            info["Id"] == descriptor["digest"] and info["Id"] in archived.descriptors,
            "The archive OCI target does not match the tested Docker image.",
        )
    else:
        require(
            info["Id"] == archived.config_id,
            "The archive configuration does not match the tested Docker image.",
        )


def docker_inspect(image):
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .}}", image],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    return json.loads(result.stdout)


def docker_save(image, archive):
    subprocess.run(
        ["docker", "image", "save", "--output", str(archive), image], check=True, timeout=180
    )


def export_bundle(directory, revision):
    checked_revision(revision)
    info = docker_inspect(TAG)
    directory.mkdir()
    archive = directory / ARCHIVE
    docker_save(TAG, archive)
    checksum = archive_hash(archive)
    archived = archive_identity(archive, revision)
    bind_engine_image(info, archived, revision)
    data = {
        "schema": FORMAT,
        "source": SOURCE,
        "revision": revision,
        "platform": "linux/amd64",
        "image_id": archived.config_id,
        "archive_sha256": checksum,
    }
    with (directory / METADATA).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(data, sort_keys=True, indent=2) + "\n")
    return data


def verify_bundle(directory, revision, *, loaded=False):
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
    archived = archive_identity(archive, revision)
    require(archived.config_id == meta["image_id"], "Archive image configuration differs.")
    if loaded:
        bind_engine_image(docker_inspect(TAG), archived, revision)
    return meta


def verify_registry_image(directory, revision, digest):
    require(DIGEST.fullmatch(digest), "Invalid registry digest.")
    expected = verify_bundle(directory, revision)["image_id"]
    reference = REGISTRY + "@" + digest
    info = docker_inspect(reference)
    require(reference in (info.get("RepoDigests") or ()), "Pulled registry digest differs.")
    subprocess.run(
        ["docker", "image", "tag", reference, REGISTRY_CHECK_TAG], check=True, timeout=45
    )
    with TemporaryDirectory(prefix="pamolive-registry-verify-") as temp:
        archive = Path(temp) / ARCHIVE
        docker_save(REGISTRY_CHECK_TAG, archive)
        require(
            0 < archive.stat().st_size <= MAX_ARCHIVE_SIZE, "Unsupported registry archive size."
        )
        archived = archive_identity(archive, revision, tag=REGISTRY_CHECK_TAG)
        bind_engine_image(info, archived, revision)
        require(archived.config_id == expected, "Registry image configuration differs.")


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
    for operation in ("export", "verify", "verify-registry"):
        command = sub.add_parser(operation)
        command.add_argument("directory", type=Path)
        command.add_argument("--revision", required=True)
        if operation == "verify":
            command.add_argument("--loaded", action="store_true")
        if operation == "verify-registry":
            command.add_argument("--digest", required=True)
    command = sub.add_parser("verify-run")
    command.add_argument("run", type=Path)
    command.add_argument("--revision", required=True)
    command = sub.add_parser("compare-compose")
    command.add_argument("source", type=Path)
    command.add_argument("registry", type=Path)
    command.add_argument("--image", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "export":
            print(json.dumps(export_bundle(args.directory, args.revision), sort_keys=True))
        elif args.operation == "verify":
            result = verify_bundle(args.directory, args.revision, loaded=args.loaded)
            print(json.dumps(result, sort_keys=True))
        elif args.operation == "verify-registry":
            verify_registry_image(args.directory, args.revision, args.digest)
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
