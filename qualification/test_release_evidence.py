"""Exercise exact release bindings with local archives and a fake gh process."""

import io
import tarfile
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from deploy import qualified_image as image
from qualification import release_evidence as proof
from qualification.build_origin import contract

REVISION = "a" * 40
RUN = 100
ATTEMPT = 2
ZIP = "sha256:" + "b" * 64
ARTIFACT = {"id": 200, "digest": ZIP}


def write_tar_member(archive, name, payload):
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.directory = self.root / "evidence"
        self.report = self.root / proof.REPORT
        config = contract.canonical(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {
                    "Labels": {
                        "org.opencontainers.image.source": image.SOURCE,
                        "org.opencontainers.image.revision": REVISION,
                        "io.pamolive.source.license": "AGPL-3.0-or-later",
                    }
                },
            }
        )
        config_name = contract.digest(config) + ".json"
        archive = self.bundle / image.ARCHIVE
        with tarfile.open(archive, "w") as tar:
            write_tar_member(tar, config_name, config)
            write_tar_member(
                tar,
                "manifest.json",
                contract.canonical(
                    [
                        {"Config": config_name, "RepoTags": [image.TAG], "Layers": []},
                    ]
                ),
            )
        metadata = {
            "schema": image.FORMAT,
            "source": image.SOURCE,
            "revision": REVISION,
            "platform": "linux/amd64",
            "archive_sha256": image.archive_hash(archive),
            "image_id": "sha256:" + contract.digest(config),
        }
        raw = contract.canonical(metadata)
        (self.bundle / image.METADATA).write_bytes(raw)
        self.policy = {
            "schema": proof.REPORT_SCHEMA,
            "passed": True,
            "blockers": [],
            "all_findings_clear": False,
            "config_id": metadata["image_id"],
            "input_sha256": {
                "archive": metadata["archive_sha256"],
                "qualified_image": contract.digest(raw),
            },
        }
        self.report.write_bytes(contract.canonical(self.policy))

    def create(self):
        proof.create(
            self.bundle,
            self.report,
            self.directory,
            revision=REVISION,
            run_id=RUN,
            attempt=ATTEMPT,
            artifact_id=ARTIFACT["id"],
            artifact_digest=ZIP[7:],
        )

    def test_matches_exact_archive_and_preserves_report(self):
        self.create()
        raw, index = proof.check_index(self.directory, REVISION, RUN, ATTEMPT)
        self.assertEqual(index["image_artifact"], ARTIFACT)
        self.assertEqual((self.directory / proof.REPORT).read_bytes(), self.report.read_bytes())
        with (
            patch.object(proof, "selected_artifacts", return_value=(ATTEMPT, ARTIFACT, {})),
            patch.object(proof, "verify_attestation") as verify,
        ):
            proof.verify_release(self.bundle, self.directory, revision=REVISION, run_id=RUN)
        verify.assert_called_once_with(
            str(self.directory / proof.INDEX),
            proof.INDEX,
            contract.digest(raw),
            revision=REVISION,
            run_id=RUN,
            attempt=ATTEMPT,
            workflow=proof.CI,
            event="push",
        )

    def test_refuses_failed_report_or_wrong_subject(self):
        changes = (
            {"passed": False},
            {"passed": 1},
            {"blockers": [1]},
            {"config_id": ZIP},
            {"input_sha256": {"archive": "f" * 64, "qualified_image": "a" * 64}},
        )
        for change in changes:
            with self.subTest(change=change):
                self.report.write_bytes(contract.canonical({**self.policy, **change}))
                with self.assertRaises(ValueError):
                    self.create()
                self.assertFalse(self.directory.exists())

    def test_refuses_prior_attempt_and_report_changed_after_collection(self):
        self.create()
        with self.assertRaisesRegex(ValueError, "release_index_invocation"):
            proof.check_index(self.directory, REVISION, RUN, ATTEMPT + 1)
        (self.directory / proof.REPORT).write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "release_report_digest"):
            proof.check_index(self.directory, REVISION, RUN, ATTEMPT)

    def test_refuses_duplicate_fields_or_unexpected_files(self):
        self.create()
        index = self.directory / proof.INDEX
        index.write_bytes(index.read_bytes().replace(b"{", b'{"attempt":2,', 1))
        with self.assertRaisesRegex(ValueError, "origin_json_duplicate"):
            proof.check_index(self.directory, REVISION, RUN, ATTEMPT)
        (self.directory / "unexpected").touch()
        with self.assertRaisesRegex(ValueError, "release_evidence_files"):
            proof.check_index(self.directory, REVISION, RUN, ATTEMPT)

    def test_refuses_replaced_zip_or_tampered_tar_before_attestation(self):
        self.create()
        with patch.object(proof, "verify_attestation") as verify:
            with patch.object(
                proof, "selected_artifacts", return_value=(ATTEMPT, {**ARTIFACT, "id": 201}, {})
            ):
                with self.assertRaisesRegex(ValueError, "release_image_artifact_mismatch"):
                    proof.verify_release(self.bundle, self.directory, revision=REVISION, run_id=RUN)
            with (self.bundle / image.ARCHIVE).open("ab") as archive:
                archive.write(b"changed")
            with patch.object(proof, "selected_artifacts", return_value=(ATTEMPT, ARTIFACT, {})):
                with self.assertRaisesRegex(ValueError, "Archive checksum"):
                    proof.verify_release(self.bundle, self.directory, revision=REVISION, run_id=RUN)
            verify.assert_not_called()


def github_run():
    repo = {
        "full_name": image.REPOSITORY,
        "id": proof.REPOSITORY_ID,
        "owner": {"id": proof.OWNER_ID},
        "private": False,
    }
    return {
        "repository": repo,
        "head_repository": repo,
        "path": proof.CI,
        "id": RUN,
        "head_branch": "main",
        "head_sha": REVISION,
        "event": "push",
        "run_attempt": ATTEMPT,
        "status": "completed",
        "conclusion": "success",
    }


class OriginTests(unittest.TestCase):
    def test_accepts_only_successful_exact_main_run_from_numeric_repository(self):
        run = github_run()
        self.assertEqual(proof.run_attempt(run, REVISION, RUN), ATTEMPT)
        for changed in (
            {"event": "pull_request"},
            {"head_sha": "f" * 40},
            {"id": RUN + 1},
            {"status": "in_progress"},
            {"conclusion": "failure"},
            {"run_attempt": True},
            {"head_repository": {**run["head_repository"], "id": proof.REPOSITORY_ID + 1}},
            {"repository": {**run["repository"], "owner": {"id": proof.OWNER_ID + 1}}},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                proof.run_attempt({**run, **changed}, REVISION, RUN)

    def test_rest_artifact_selection_is_exact_and_rerun_names_are_distinct(self):
        name, evidence = proof.artifact_names(REVISION, RUN, ATTEMPT)
        self.assertNotEqual(name, proof.artifact_names(REVISION, RUN, ATTEMPT + 1)[0])
        self.assertNotEqual(name, evidence)
        row = {
            **ARTIFACT,
            "name": name,
            "expired": False,
            "size_in_bytes": 100,
            "workflow_run": {
                "id": RUN,
                "head_sha": REVISION,
                "head_branch": "main",
                "repository_id": proof.REPOSITORY_ID,
                "head_repository_id": proof.REPOSITORY_ID,
            },
        }
        arguments = {"name": name, "run_id": RUN, "revision": REVISION, "cap": 200}
        body = {"total_count": 1, "artifacts": [row]}
        self.assertEqual(proof.select_artifact(body, **arguments), ARTIFACT)
        for changed in (
            {"total_count": 2, "artifacts": [row, row]},
            {**body, "artifacts": [{**row, "expired": True}]},
            {**body, "artifacts": [{**row, "digest": "b" * 64}]},
            {**body, "artifacts": [{**row, "name": name[:-1] + "1"}]},
            {**body, "artifacts": [{**row, "size_in_bytes": 201}]},
            {
                **body,
                "artifacts": [{**row, "workflow_run": {**row["workflow_run"], "id": RUN + 1}}],
            },
        ):
            with self.assertRaises(ValueError):
                proof.select_artifact(changed, **arguments)

    @staticmethod
    def result(workflow=proof.CI, event="push", name=proof.INDEX):
        signer = f"{image.SOURCE}/{workflow}@{proof.MAIN}"
        return {
            "verificationResult": {
                "mediaType": contract.VERIFIER_MEDIA,
                "signature": {
                    "certificate": {
                        "issuer": "https://token.actions.githubusercontent.com",
                        "subjectAlternativeName": signer,
                        "buildSignerURI": signer,
                        "buildSignerDigest": REVISION,
                        "buildConfigURI": signer,
                        "buildConfigDigest": REVISION,
                        "runnerEnvironment": "github-hosted",
                        "sourceRepositoryURI": image.SOURCE,
                        "sourceRepositoryIdentifier": str(proof.REPOSITORY_ID),
                        "sourceRepositoryOwnerIdentifier": str(proof.OWNER_ID),
                        "sourceRepositoryDigest": REVISION,
                        "sourceRepositoryRef": proof.MAIN,
                        "buildTrigger": event,
                        "runInvocationURI": f"{image.SOURCE}/actions/runs/{RUN}/attempts/{ATTEMPT}",
                        "sourceRepositoryVisibilityAtSigning": "public",
                    }
                },
                "verifiedTimestamps": [{"type": "Tlog"}],
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": proof.SLSA,
                    "subject": [{"name": name, "digest": {"sha256": ZIP[7:]}}],
                },
            }
        }

    def test_verifier_invocation_has_fixed_source_controls_and_refuses_wrong_identity(self):
        args = {
            "revision": REVISION,
            "run_id": RUN,
            "attempt": ATTEMPT,
            "workflow": proof.CI,
            "event": "push",
        }
        valid = self.result()
        with patch.object(proof, "read_api_result", return_value=[valid]) as native:
            proof.verify_attestation(proof.INDEX, proof.INDEX, ZIP[7:], **args)
        command = native.call_args.args[0]
        self.assertIn("--deny-self-hosted-runners", command)
        self.assertEqual(command[command.index("--source-digest") + 1], REVISION)
        self.assertEqual(command[command.index("--source-ref") + 1], proof.MAIN)
        for key, value in (
            ("runInvocationURI", f"{image.SOURCE}/actions/runs/{RUN}/attempts/{ATTEMPT - 1}"),
            ("buildTrigger", "workflow_dispatch"),
            ("runnerEnvironment", "self-hosted"),
            ("buildSignerDigest", "f" * 40),
            ("sourceRepositoryIdentifier", "1"),
        ):
            variant = deepcopy(valid)
            variant["verificationResult"]["signature"]["certificate"][key] = value
            with patch.object(proof, "read_api_result", return_value=[variant]):
                with self.assertRaisesRegex(ValueError, "release_attestation_invocation"):
                    proof.verify_attestation(proof.INDEX, proof.INDEX, ZIP[7:], **args)
        for rows in ([valid, valid], [self.result(name="another.json")]):
            with patch.object(proof, "read_api_result", return_value=rows):
                with self.assertRaisesRegex(ValueError, "release_attestation_invocation"):
                    proof.verify_attestation(proof.INDEX, proof.INDEX, ZIP[7:], **args)

    def test_promotion_uses_registry_bundle_and_its_own_workflow(self):
        row = self.result(proof.PUBLISH, "workflow_dispatch", image.REGISTRY)
        with patch.object(proof, "read_api_result", return_value=[row]) as native:
            proof.verify_attestation(
                "oci://" + image.REGISTRY + "@" + ZIP,
                image.REGISTRY,
                ZIP[7:],
                revision=REVISION,
                run_id=RUN,
                attempt=ATTEMPT,
                workflow=proof.PUBLISH,
                event="workflow_dispatch",
            )
        self.assertIn("--bundle-from-oci", native.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
