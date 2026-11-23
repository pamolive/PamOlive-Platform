"""Bind the tested archive and image-policy verdict to the main Actions invocation."""

import argparse
import os
import sys
import tarfile
from pathlib import Path

from deploy import qualified_image as image
from qualification.build_origin import bounded_io, contract

INDEX = "release-evidence.json"
REPORT = "policy-result.json"
SCHEMA = "pamolive.release-evidence/1"
REPORT_SCHEMA = "pamolive.image-scan-result.v1"
REPOSITORY_ID = 1449671447
OWNER_ID = 305596298
MAIN = "refs/heads/main"
CI = ".github/workflows/ci.yml"
PUBLISH = ".github/workflows/publish-image.yml"
SLSA = "https://slsa.dev/provenance/v1"
REPORT_CAP = 2 * 1024**2
INDEX_CAP = 8192

need = contract.need


def positive(value):
    need(type(value) is int and 0 < value < 2**63, "release_numeric_identity")
    return value


def regular(path, limit):
    return bounded_io.read_regular(path, limit)


def zip_digest(value):
    need(type(value) is str, "release_artifact_digest")
    value = value if value.startswith("sha256:") else "sha256:" + value
    need(image.DIGEST.fullmatch(value), "release_artifact_digest")
    return value


def artifact_names(revision, run_id, attempt):
    suffix = f"{image.checked_revision(revision)}-{positive(run_id)}-{positive(attempt)}"
    return f"pamolive-linux-amd64-{suffix}", f"pamolive-release-evidence-{suffix}"


def read_api_result(args, *, maximum=1024**2):
    result = bounded_io.run_capped(
        ["gh", *args],
        env=dict(os.environ),
        cwd=Path.cwd(),
        timeout=75,
        stdout_cap=maximum,
        stderr_cap=64 * 1024,
    )
    need(result.ok, "release_github_command_failed")
    return contract.load(result.stdout, maximum, members=256, nodes=50000)


def api(path):
    return read_api_result(["api", "--hostname", "github.com", f"repos/{image.REPOSITORY}/{path}"])


def run_attempt(row, revision, run_id):
    image.verify_run(row, revision)
    need(positive(row["id"]) == run_id, "release_run_identity")
    repo = row["repository"]
    need(
        positive(repo["id"]) == positive(row["head_repository"]["id"]) == REPOSITORY_ID
        and positive(repo["owner"]["id"]) == OWNER_ID
        and repo["private"] is False,
        "release_repository_identity",
    )
    return positive(row["run_attempt"])


def select_artifact(body, *, name, run_id, revision, cap):
    need(type(body) is dict and positive(body["total_count"]) == 1, "release_artifact_count")
    rows = body["artifacts"]
    need(type(rows) is list and len(rows) == 1, "release_artifact_count")
    artifact = rows[0]
    source = artifact["workflow_run"]
    need(
        artifact["expired"] is False
        and artifact["name"] == name
        and positive(artifact["size_in_bytes"]) <= cap
        and positive(source["id"]) == run_id
        and positive(source["repository_id"]) == REPOSITORY_ID
        and positive(source["head_repository_id"]) == REPOSITORY_ID
        and source["head_branch"] == "main"
        and source["head_sha"] == revision,
        "release_artifact_source",
    )
    need(
        type(artifact["digest"]) is str and image.DIGEST.fullmatch(artifact["digest"]),
        "release_artifact_digest",
    )
    return {"id": positive(artifact["id"]), "digest": artifact["digest"]}


def selected_artifacts(revision, run_id):
    attempt = run_attempt(api(f"actions/runs/{positive(run_id)}"), revision, run_id)
    names = artifact_names(revision, run_id, attempt)
    bundle, evidence = (
        select_artifact(
            api(f"actions/runs/{run_id}/artifacts?per_page=2&name={name}"),
            name=name,
            run_id=run_id,
            revision=revision,
            cap=cap,
        )
        for name, cap in zip(
            names, (image.MAX_ARCHIVE_SIZE + 2**20, REPORT_CAP + INDEX_CAP + 2**20), strict=True
        )
    )
    return attempt, bundle, evidence


def check_report(raw, archive_sha, metadata_sha, config_id):
    report = contract.load(raw, REPORT_CAP, members=1024, nodes=100000)
    need(
        type(report) is dict
        and report.get("schema") == REPORT_SCHEMA
        and report.get("passed") is True
        and report.get("blockers") == []
        and report.get("config_id") == config_id,
        "release_policy_refused",
    )
    inputs = report["input_sha256"]
    need(
        type(inputs) is dict
        and inputs.get("archive") == archive_sha
        and inputs.get("qualified_image") == metadata_sha,
        "release_policy_subject",
    )


def bindings(bundle, revision):
    metadata = image.verify_bundle(bundle, revision)
    return {
        "archive_sha256": metadata["archive_sha256"],
        "metadata_sha256": contract.digest(regular(bundle / image.METADATA, 8192)),
        "config_id": metadata["image_id"],
    }


def create(bundle, report, directory, *, revision, run_id, attempt, artifact_id, artifact_digest):
    observed = bindings(bundle, revision)
    report = regular(report, REPORT_CAP)
    check_report(
        report, observed["archive_sha256"], observed["metadata_sha256"], observed["config_id"]
    )
    index = {
        "schema": SCHEMA,
        "repository": image.REPOSITORY,
        "revision": revision,
        "run_id": positive(run_id),
        "attempt": positive(attempt),
        "image_artifact": {"id": positive(artifact_id), "digest": zip_digest(artifact_digest)},
        "report_sha256": contract.digest(report),
        **observed,
    }
    directory.mkdir(mode=0o700)
    for name, raw in ((INDEX, contract.canonical(index)), (REPORT, report)):
        with (directory / name).open("xb") as stream:
            stream.write(raw)


def check_index(directory, revision, run_id, attempt):
    need(
        directory.is_dir()
        and not directory.is_symlink()
        and {file.name for file in directory.iterdir()} == {INDEX, REPORT},
        "release_evidence_files",
    )
    raw = regular(directory / INDEX, INDEX_CAP)
    index = contract.load(raw, INDEX_CAP)
    need(
        type(index) is dict
        and set(index)
        == {
            "schema",
            "repository",
            "revision",
            "run_id",
            "attempt",
            "image_artifact",
            "report_sha256",
            "archive_sha256",
            "metadata_sha256",
            "config_id",
        }
        and contract.canonical(index) == raw,
        "release_index_format",
    )
    need(
        index["schema"] == SCHEMA
        and index["repository"] == image.REPOSITORY
        and index["revision"] == image.checked_revision(revision)
        and positive(index["run_id"]) == run_id
        and positive(index["attempt"]) == attempt,
        "release_index_invocation",
    )
    artifact = index["image_artifact"]
    need(
        type(artifact) is dict
        and set(artifact) == {"id", "digest"}
        and positive(artifact["id"])
        and type(artifact["digest"]) is str
        and image.DIGEST.fullmatch(artifact["digest"]),
        "release_index_artifact",
    )
    for key in ("archive_sha256", "metadata_sha256", "report_sha256"):
        need(type(index[key]) is str and image.HASH.fullmatch(index[key]), "release_index_digest")
    need(
        type(index["config_id"]) is str and image.DIGEST.fullmatch(index["config_id"]),
        "release_index_config",
    )
    report = regular(directory / REPORT, REPORT_CAP)
    need(contract.digest(report) == index["report_sha256"], "release_report_digest")
    check_report(report, index["archive_sha256"], index["metadata_sha256"], index["config_id"])
    return raw, index


def verify_attestation(target, name, digest, *, revision, run_id, attempt, workflow, event):
    workflow_uri = f"{image.SOURCE}/{workflow}@{MAIN}"
    transport = ["--bundle-from-oci"] if workflow == PUBLISH else []
    rows = read_api_result(
        [
            "attestation",
            "verify",
            target,
            "--hostname",
            "github.com",
            "--repo",
            image.REPOSITORY,
            "--cert-identity",
            workflow_uri,
            "--signer-digest",
            revision,
            "--source-ref",
            MAIN,
            "--source-digest",
            revision,
            "--deny-self-hosted-runners",
            "--predicate-type",
            SLSA,
            "--limit",
            "20",
            "--format",
            "json",
            *transport,
        ],
        maximum=8 * 1024**2,
    )
    need(type(rows) is list and 0 < len(rows) <= 20, "release_verified_results")
    expected = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": workflow_uri,
        "buildSignerURI": workflow_uri,
        "buildSignerDigest": revision,
        "buildConfigURI": workflow_uri,
        "buildConfigDigest": revision,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": image.SOURCE,
        "sourceRepositoryIdentifier": str(REPOSITORY_ID),
        "sourceRepositoryOwnerIdentifier": str(OWNER_ID),
        "sourceRepositoryDigest": revision,
        "sourceRepositoryRef": MAIN,
        "buildTrigger": event,
        "runInvocationURI": f"{image.SOURCE}/actions/runs/{run_id}/attempts/{attempt}",
        "sourceRepositoryVisibilityAtSigning": "public",
    }
    count = 0
    for entry in rows:
        result = entry["verificationResult"]
        cert = result["signature"]["certificate"]
        statement = result["statement"]
        if (
            result["mediaType"] == contract.VERIFIER_MEDIA
            and all(cert.get(key) == value for key, value in expected.items())
            and statement["_type"] == "https://in-toto.io/Statement/v1"
            and statement["predicateType"] == SLSA
            and statement["subject"] == [{"name": name, "digest": {"sha256": digest}}]
            and any(row.get("type") == "Tlog" for row in result["verifiedTimestamps"])
        ):
            count += 1
    need(count == 1, "release_attestation_invocation")


def verify_release(bundle, directory, *, revision, run_id):
    attempt, artifact, _ = selected_artifacts(revision, run_id)
    raw, index = check_index(directory, revision, run_id, attempt)
    need(index["image_artifact"] == artifact, "release_image_artifact_mismatch")
    observed = bindings(bundle, revision)
    need(all(index[key] == value for key, value in observed.items()), "release_bundle_mismatch")
    verify_attestation(
        str(directory / INDEX),
        INDEX,
        contract.digest(raw),
        revision=revision,
        run_id=run_id,
        attempt=attempt,
        workflow=CI,
        event="push",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    operations = parser.add_subparsers(dest="operation", required=True)
    collect = operations.add_parser("create")
    collect.add_argument("--bundle", type=Path, required=True)
    collect.add_argument("--report", type=Path, required=True)
    collect.add_argument("--directory", type=Path, required=True)
    collect.add_argument("--attempt", type=int, required=True)
    collect.add_argument("--artifact-id", type=int, required=True)
    collect.add_argument("--artifact-digest", required=True)
    operations.add_parser("select")
    subject = operations.add_parser("subject")
    subject.add_argument("--directory", type=Path, required=True)
    subject.add_argument("--attempt", type=int, required=True)
    receive = operations.add_parser("verify")
    receive.add_argument("--bundle", type=Path, required=True)
    receive.add_argument("--directory", type=Path, required=True)
    promote = operations.add_parser("verify-promotion")
    promote.add_argument("--attempt", type=int, required=True)
    promote.add_argument("--digest", required=True)
    args = parser.parse_args()
    try:
        image.checked_revision(args.revision)
        positive(args.run_id)
        if args.operation == "create":
            create(
                args.bundle,
                args.report,
                args.directory,
                revision=args.revision,
                run_id=args.run_id,
                attempt=args.attempt,
                artifact_id=args.artifact_id,
                artifact_digest=args.artifact_digest,
            )
        elif args.operation == "select":
            _, image_artifact, evidence_artifact = selected_artifacts(args.revision, args.run_id)
            print(f"image-id={image_artifact['id']}\nevidence-id={evidence_artifact['id']}")
        elif args.operation == "subject":
            raw, _ = check_index(args.directory, args.revision, args.run_id, positive(args.attempt))
            print("sha256:" + contract.digest(raw))
        elif args.operation == "verify":
            verify_release(args.bundle, args.directory, revision=args.revision, run_id=args.run_id)
        else:
            need(image.DIGEST.fullmatch(args.digest), "release_promotion_digest")
            verify_attestation(
                "oci://" + image.REGISTRY + "@" + args.digest,
                image.REGISTRY,
                args.digest[7:],
                revision=args.revision,
                run_id=args.run_id,
                attempt=positive(args.attempt),
                workflow=PUBLISH,
                event="workflow_dispatch",
            )
    except (
        ValueError,
        OSError,
        TypeError,
        AttributeError,
        KeyError,
        RecursionError,
        tarfile.TarError,
        EOFError,
    ):
        print("Exact release evidence verification refused.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
