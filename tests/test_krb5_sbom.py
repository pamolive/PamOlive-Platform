"""Synthetic backport SBOM export with the real bundled schema validator."""

import copy
import io
import json
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import krb5_inventory as inventory
from deploy import krb5_sbom as sbom
from deploy import native_sbom as standard
from tests import test_krb5_inventory as fixtures


class Krb5SbomTests(TestCase):
    def setUp(self):
        # These are explicitly synthetic source/build claims, not real APT or
        # decoder qualification results. Use the established validated fixture.
        fixture = fixtures.Krb5InventoryTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.manifest = inventory.inventory(root=fixture.root)
        self.report = {
            "schema": inventory.SCHEMA,
            "verified": True,
            "compilation_proof": False,
            "inventory": copy.deepcopy(self.manifest),
        }
        self.kwargs = dict(
            image_digest="sha256:" + "a" * 64,
            image_digest_kind="image_config",
            input_hashes={"manifest": "b" * 64, "report": "c" * 64},
        )

    def export(self):
        return sbom.export(self.manifest, self.report, **self.kwargs)

    def test_standard_sbom_preserves_real_versions_scope_hashes_and_refs(self):
        before = copy.deepcopy(self.manifest)
        result = self.export()
        self.assertEqual(result["specVersion"], "1.6")
        self.assertEqual(len(result["components"]), 9)
        self.assertEqual(self.manifest, before)
        source = result["components"][0]
        self.assertEqual(source["purl"], "pkg:generic/mit-krb5@1.21.3")
        self.assertEqual(source["pedigree"]["patches"][0]["type"], "backport")
        packages = [item for item in result["components"] if item.get("group") == "debian"]
        self.assertEqual({item["name"] for item in packages}, set(inventory.LIBRARIES))
        for package in packages:
            self.assertEqual(package["version"], inventory.VERSION)
            self.assertIn("%2Bdeb13u1%2Bpamolive1?arch=amd64&distro=debian-13", package["purl"])
            self.assertNotIn("hashes", package)  # ELF hash is not a .deb archive hash.
            self.assertNotIn("licenses", package)  # No fabricated SPDX assertion.
        files = [item for item in result["components"] if item["type"] == "file"]
        self.assertEqual(
            {item["hashes"][0]["content"] for item in files},
            {item["sha256"] for item in self.manifest["libraries"]},
        )
        self.assertNotIn("hashes", result["metadata"]["component"])
        self.assertNotIn('"cpe"', json.dumps(result))
        self.assertEqual(standard.canonical(result), standard.canonical(self.export()))

    def test_complete_test_status_is_explicit_without_unqualified_capability(self):
        values = {item["name"]: item["value"] for item in self.export()["metadata"]["properties"]}
        self.assertEqual(values["pamolive:krb5:debian-test-status"], "passed")
        self.assertNotIn("pamolive:krb5:unqualified-capability", values)
        self.assertNotIn("pamolive:krb5:capability-skip-count", values)

    def capability_manifest(self):
        self.fixture.add_capability_skip()
        return inventory.inventory(root=self.fixture.root)

    def test_verified_capability_skips_remain_visible_in_strict_sbom(self):
        manifest = self.capability_manifest()
        report = {**self.report, "inventory": copy.deepcopy(manifest)}
        before = copy.deepcopy(manifest)
        result = sbom.export(manifest, report, **self.kwargs)
        values = {item["name"]: item["value"] for item in result["metadata"]["properties"]}
        self.assertEqual(values["pamolive:krb5:debian-test-status"], "passed_with_capability_skips")
        self.assertEqual(values["pamolive:krb5:unqualified-capability"], "kernel_keyring")
        self.assertEqual(values["pamolive:krb5:capability-skip-count"], "4")
        self.assertEqual(manifest, before)
        self.assertEqual(manifest["asn1"], self.manifest["asn1"])
        self.assertEqual(len(result["components"]), 9)

    def test_ambiguous_capability_claims_fail_even_if_report_matches(self):
        valid = self.capability_manifest()
        variants = []
        for status in ("passed", "unknown", None):
            changed = copy.deepcopy(valid)
            changed["debian_tests"]["status"] = status
            variants.append(changed)
        for field, value in (
            ("capability", "network"),
            ("reason", "unexplained"),
            ("count", 3),
            ("tests", ["keyring collection tests"]),
            ("phase_counts", {"baseline": {}, "patched": {}}),
        ):
            changed = copy.deepcopy(valid)
            changed["debian_tests"]["capability_skips"][0][field] = value
            variants.append(changed)
        duplicate = copy.deepcopy(valid)
        duplicate["debian_tests"]["capability_skips"] *= 2
        variants.append(duplicate)
        for index, manifest in enumerate(variants):
            with self.subTest(variant=index), self.assertRaises(inventory.Krb5Error):
                sbom.export(manifest, {**self.report, "inventory": manifest}, **self.kwargs)

    def test_bad_version_or_changed_abi_is_refused_even_if_report_matches(self):
        for field, value in (
            ("version", "1.22.3"),
            ("soname", "libkrb5.so.4"),
            ("abi_sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest["libraries"][0][field] = value
                report = {**self.report, "inventory": manifest}
                with self.assertRaises(ValueError):
                    sbom.export(manifest, report, **self.kwargs)

    def test_verified_report_exact_equality_and_no_compilation_claim_required(self):
        for change in (
            {"verified": False},
            {"verified": 1},
            {"compilation_proof": True},
            {"inventory": {}},
        ):
            with self.subTest(change=change), self.assertRaises(standard.SbomError):
                sbom.export(self.manifest, {**self.report, **change}, **self.kwargs)

    def test_configuration_kind_digest_and_raw_input_hashes_are_strict(self):
        for change in (
            {"image_digest_kind": "oci_manifest"},
            {"image_digest": "sha256:bad"},
            {"input_hashes": {"manifest": "b" * 64}},
            {"input_hashes": {"manifest": "bad", "report": "c" * 64}},
        ):
            with self.subTest(change=change), self.assertRaises(standard.SbomError):
                sbom.export(self.manifest, self.report, **{**self.kwargs, **change})

    def test_invalid_backport_and_failed_regression_cannot_be_exported(self):
        for section, field, value in (
            ("provenance", "upstream_commit", "0" * 40),
            ("debian_tests", "tests_enabled", False),
        ):
            manifest = copy.deepcopy(self.manifest)
            manifest[section][field] = value
            with self.subTest(section=section), self.assertRaises(ValueError):
                sbom.export(manifest, {**self.report, "inventory": manifest}, **self.kwargs)

    def test_output_exclusive_before_any_input_read(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "bom.json"
            output.write_bytes(b"old-proof")
            with patch.object(standard, "load") as load, redirect_stdout(io.StringIO()):
                self.assertEqual(
                    sbom.main(
                        [
                            "--manifest",
                            "absent",
                            "--report",
                            "absent",
                            "--image-digest",
                            self.kwargs["image_digest"],
                            "--image-digest-kind",
                            "image_config",
                            "--output",
                            str(output),
                        ]
                    ),
                    1,
                )
            load.assert_not_called()
            self.assertEqual(output.read_bytes(), b"old-proof")

    def test_missing_schema_validator_is_a_failure_not_an_unvalidated_export(self):
        with patch.object(
            standard,
            "validate_schema",
            side_effect=standard.SbomError("schema_validator_unavailable"),
        ):
            with self.assertRaisesRegex(standard.SbomError, "schema_validator_unavailable"):
                self.export()

    def test_duplicate_json_and_input_budget_remain_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            path.write_text('{"schema":"synthetic","schema":"duplicate"}')
            with self.assertRaises(standard.SbomError):
                standard.load(path)
            with patch.object(standard, "MAX_INPUT", 8), self.assertRaises(standard.SbomError):
                standard.load(path)
