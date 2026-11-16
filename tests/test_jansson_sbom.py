"""Targeted pure native-SBOM metadata gate; schema validators run in Linux CI."""

import copy
from unittest import TestCase

from deploy import native_sbom as sbom
from tests.test_native_sbom import NativeSbomTests


class JanssonSbomTests(TestCase):
    def setUp(self):
        fixture = NativeSbomTests()
        fixture.setUp()
        self.manifest, self.report = fixture.manifest, fixture.report

    def evaluate(self):
        return sbom.native_components(self.manifest, self.report)

    def test_jansson_patch_pin_is_retained_as_a_native_component_property(self):
        components, _, _ = self.evaluate()
        freerdp = next(row for row in components if row.get("name") == "freerdp")
        props = {row["name"]: row["value"] for row in freerdp["properties"]}
        self.assertIn(sbom.JSON_PATCH_SHA, props["pamolive:native:json_backend_patch_sha256"])

    def test_absent_or_changed_patch_pin_cannot_produce_a_native_sbom(self):
        for val in (None, "0" * 64):
            comp = self.manifest["components"][0]
            if val is None:
                comp.pop("json_backend_patch_sha256")
            else:
                comp["json_backend_patch_sha256"] = val
            self.report["inventory"] = copy.deepcopy(self.manifest)
            with self.assertRaisesRegex(sbom.SbomError, "native_json_patch"):
                self.evaluate()

    def test_runtime_fallback_backend_flags_refuse(self):
        self.manifest["runtime_versions"]["freerdp_build_options"]["WITH_JANSSON_REQUIRED"] = "OFF"
        self.report["inventory"] = copy.deepcopy(self.manifest)
        with self.assertRaisesRegex(sbom.SbomError, "native_runtime_identity"):
            self.evaluate()
