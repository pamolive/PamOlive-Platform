"""Self-contained public selection and reference replay checks, never native execution."""

import hashlib
import json
import unittest
from pathlib import Path, PurePosixPath

import source_data as data
from reused_text_helpers import transform

HERE = Path(__file__).resolve().parent


class PublicationContracts(unittest.TestCase):
    def test_public_source_manifest_is_complete_UTF8_and_not_authority(self):
        manifest = json.loads((HERE / "source-manifest.json").read_bytes())
        self.assertEqual(manifest["base"], "6d4c7db")
        self.assertIs(manifest["not_signature_or_approval_authority"], True)
        rows = manifest["files"]
        actual = {p.relative_to(HERE).as_posix() for p in HERE.rglob("*") if p.is_file()}
        self.assertEqual(actual, set(rows) | {"source-manifest.json"})
        for name, row in rows.items():
            with self.subTest(name=name):
                path = HERE / name
                pure = PurePosixPath(name)
                self.assertFalse(pure.is_absolute())
                self.assertNotIn("..", pure.parts)
                self.assertNotIn("__pycache__", pure.parts)
                self.assertFalse(path.is_symlink())
                raw = path.read_bytes()
                raw.decode("utf-8-sig", "strict")
                self.assertNotIn(b"\0", raw)
                self.assertEqual(
                    (len(raw), hashlib.sha256(raw).hexdigest()),
                    (row["bytes"], row["sha256"]),
                )
        config = json.loads((HERE / "recipe-inputs.json").read_bytes())
        for name in (
            "trust_policy_sha256",
            "exact_debian_patch_plan_sha256",
            "build_dependency_lock_sha256",
        ):
            self.assertIsNone(config[name])
        self.assertEqual(data.verify_text_materials(), 47)

    def test_three_reference_proposals_replay_exact_public_postimages(self):
        replay = json.loads((HERE / "static-source-replay.json").read_bytes())
        rows = [
            r for r in replay["rows"] if r["action"] == "APPLY_TEXT_ONLY_UPSTREAM_TAG_REFERENCE"
        ]
        self.assertEqual(len(rows), 3)
        names = {name for row in rows for name in row["before"]}
        result = {
            name: (HERE / "materials/baseline/upstream-3.5.7" / name).read_bytes() for name in names
        }
        for row in rows:
            self.assertEqual(
                {name: data.sha(result[name]) for name in row["before"]}, row["before"]
            )
            result = transform(result, (HERE / row["proposed_patch"]).read_bytes())
            self.assertEqual({name: data.sha(result[name]) for name in row["after"]}, row["after"])
            self.assertIs(row["exact_Debian_u3_applicability_proved"], False)
        self.assertEqual(
            result,
            {
                name: (HERE / "proposal/postimages-upstream-tag-reference" / name).read_bytes()
                for name in names
            },
        )
