import io
import json
import tarfile
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from deploy import qualified_image as image

REV = "a" * 40
CONFIG = "blobs/sha256/" + "b" * 64


def add(tar, name, value):
    raw = json.dumps(value).encode()
    member = tarfile.TarInfo(name)
    member.size = len(raw)
    tar.addfile(member, io.BytesIO(raw))


class QualifiedImageTests(SimpleTestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.archive = self.directory / image.ARCHIVE
        self.config = {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/bin"],
                "Labels": {
                    "org.opencontainers.image.source": image.SOURCE,
                    "org.opencontainers.image.revision": REV,
                    "io.pamolive.source.license": "AGPL-3.0-or-later",
                },
            },
        }

    def archive_fixture(self, *, tag=None, duplicate=False):
        with tarfile.open(self.archive, "w") as tar:
            add(tar, CONFIG, self.config)
            add(tar, "manifest.json", [{"Config": CONFIG, "RepoTags": [tag or image.TAG]}])
            if duplicate:
                add(tar, CONFIG, self.config)

    def test_exact_archive_revision_checksum_and_image_id_are_bound(self):
        self.archive_fixture()
        actual = image.archive_image_id(self.archive, REV)
        metadata = {
            "schema": image.FORMAT,
            "source": image.SOURCE,
            "revision": REV,
            "platform": "linux/amd64",
            "image_id": actual,
            "archive_sha256": image.archive_hash(self.archive),
        }
        (self.directory / image.METADATA).write_text(json.dumps(metadata), encoding="utf-8")
        self.assertEqual(image.verify_bundle(self.directory, REV), metadata)
        with self.assertRaises(image.QualificationError):
            image.verify_bundle(self.directory, "c" * 40)
        with self.archive.open("ab") as stream:
            stream.write(b"modified")
        with self.assertRaisesMessage(image.QualificationError, "checksum differs"):
            image.verify_bundle(self.directory, REV)

    def test_unexpected_tag_platform_credential_and_duplicate_config_are_rejected(self):
        self.archive_fixture(tag="other-image:latest")
        with self.assertRaisesMessage(image.QualificationError, "Unexpected archived Docker tag"):
            image.archive_image_id(self.archive, REV)
        self.archive_fixture(duplicate=True)
        with self.assertRaisesMessage(image.QualificationError, "Duplicate"):
            image.archive_image_id(self.archive, REV)
        self.config["architecture"] = "arm64"
        self.archive_fixture()
        with self.assertRaisesMessage(image.QualificationError, "Linux amd64"):
            image.archive_image_id(self.archive, REV)
        self.config["architecture"] = "amd64"
        self.config["config"]["Env"].append("SECRET_KEY=synthetic")
        self.archive_fixture()
        with self.assertRaisesMessage(image.QualificationError, "credentials"):
            image.archive_image_id(self.archive, REV)

    def test_only_completed_main_push_of_exact_workflow_and_repo_can_publish(self):
        run = {
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "head_branch": "main",
            "head_sha": REV,
            "status": "completed",
            "conclusion": "success",
            "head_repository": {"full_name": image.REPOSITORY},
            "repository": {"full_name": image.REPOSITORY},
        }
        image.verify_run(run, REV)
        for patch in (
            {"head_repository": {"full_name": "fork/PamOlive-Platform"}},
            {"repository": {"full_name": "other/PamOlive-Platform"}},
            {"head_sha": "c" * 40},
            {"head_branch": "agent/branch"},
            {"event": "pull_request"},
            {"path": ".github/workflows/other.yml"},
            {"conclusion": "failure"},
            {"status": "in_progress"},
        ):
            with self.subTest(patch=patch), self.assertRaises(image.QualificationError):
                image.verify_run({**run, **patch}, REV)

    def test_registry_compose_has_one_service_no_build_and_equal_runtime_controls(self):
        reference = "ghcr.io/pamolive/pamolive-platform@sha256:" + "b" * 64
        common = {"read_only": True, "cap_drop": ["ALL"], "restart": "unless-stopped"}
        normal = {"services": {"web": {**common, "build": {"context": "."}}}}
        registry = {"services": {"web": {**common, "image": reference}}}
        image.verify_compose(normal, registry, reference)
        for changed in (
            {"image": "different"},
            {"build": "."},
            {"read_only": False},
            {"cap_drop": []},
        ):
            candidate = deepcopy(registry)
            candidate["services"]["web"].update(changed)
            with self.subTest(changed=changed), self.assertRaises(image.QualificationError):
                image.verify_compose(normal, candidate, reference)
        registry["services"]["postgres"] = {}
        with self.assertRaises(image.QualificationError):
            image.verify_compose(normal, registry, reference)
