"""Exercise the release verifier with a GitHub-signed, synthetic-only subject."""

import argparse
import os
from pathlib import Path
from unittest.mock import patch

from deploy import qualified_image as image
from qualification import release_evidence as proof
from qualification.build_origin import contract

LAB_REF = "refs/heads/agent/release-provenance-lab"
LAB_WORKFLOW = ".github/workflows/vault-runtime-installed.yml"
NAME = "pamolive-release-attestation-lab.json"


def context():
    env = os.environ
    contract.need(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REF") == LAB_REF
        and env.get("GITHUB_REPOSITORY") == image.REPOSITORY
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "release_attestation_lab_github_only",
    )
    root = Path(env["RUNNER_TEMP"]) / "pamolive-release-attestation-lab"
    revision = image.checked_revision(env["GITHUB_SHA"])
    run_id = proof.positive(int(env["GITHUB_RUN_ID"]))
    attempt = proof.positive(int(env["GITHUB_RUN_ATTEMPT"]))
    return root, revision, run_id, attempt


def fixture(revision, run_id, attempt):
    return contract.canonical(
        {
            "schema": "pamolive.release-attestation-lab/1",
            "revision": revision,
            "run_id": run_id,
            "attempt": attempt,
            "production_authority": False,
        }
    )


def write_once(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)


def verify(root, raw, revision, run_id, attempt):
    subject = root / NAME
    contract.need(proof.regular(subject, 1024) == raw, "release_attestation_lab_subject")
    digest = contract.digest(raw)
    claims = {
        "revision": revision,
        "run_id": run_id,
        "attempt": attempt,
        "workflow": LAB_WORKFLOW,
        "event": "workflow_dispatch",
    }
    with patch.object(proof, "MAIN", LAB_REF):
        proof.verify_attestation(str(subject), NAME, digest, **claims)
        try:
            proof.verify_attestation(
                str(subject), NAME, digest, **{**claims, "attempt": attempt + 1}
            )
        except ValueError as exc:
            contract.need(
                str(exc) == "release_attestation_invocation",
                "release_attestation_lab_wrong_attempt_postcondition",
            )
        else:
            raise ValueError("release_attestation_lab_wrong_attempt_accepted")

    try:
        proof.verify_attestation(str(subject), NAME, digest, **claims)
    except ValueError as exc:
        contract.need(
            str(exc) in {"release_github_command_failed", "release_attestation_invocation"},
            "release_attestation_lab_main_postcondition",
        )
    else:
        raise ValueError("release_attestation_lab_accepted_by_main_policy")
    with patch.object(proof, "MAIN", LAB_REF):
        proof.verify_attestation(str(subject), NAME, digest, **claims)
    write_once(
        root / "public-results.json",
        contract.canonical(
            {
                "schema": "pamolive.release-attestation-lab-results/1",
                "actual_signature_verified": True,
                "different_attempt_refused": True,
                "main_reference_required": True,
                "signature_reverified_after_refusal": True,
                "production_authority": False,
                "subject_sha256": digest,
            }
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("create", "verify"))
    args = parser.parse_args()
    root, revision, run_id, attempt = context()
    raw = fixture(revision, run_id, attempt)
    if args.operation == "create":
        root.mkdir(mode=0o700)
        write_once(root / NAME, raw)
        print("sha256:" + contract.digest(raw))
    else:
        verify(root, raw, revision, run_id, attempt)


if __name__ == "__main__":
    main()
