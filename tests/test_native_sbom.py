"""Synthetic SBOM qualification; requires isolated schema validation tools."""

import copy
import io
import json
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import native_sbom as sbom


class NativeSbomTests(TestCase):
    def setUp(self):
        self.app = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
                    "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
                    "components": [{"type": "library", "name": "synthetic-package",
                                    "version": "1.0", "bom-ref": "original-ref",
                                    "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                                    "properties": [{"name": "original", "value": "preserve"}]}],
                    "metadata": {"properties": [{"name": "original", "value": "metadata"}]},
                    "dependencies": [{"ref": "original-ref"}]}
        self.manifest = {"schema": sbom.SCHEMA, "components": [
            {"name": name, "prefix": sbom.PREFIXES[name], "version": value[0],
             "source_sha256": value[1]} for name, value in sbom.SOURCES.items()],
            "runtime_versions": {"freerdp": "3.33.1", "winpr": "3.33.1", "guacd": "1.6.0",
                                 "freerdp_build_options": dict(sbom.RUNTIME_OPTIONS)},
            "files": [{"path": sbom.PREFIXES[name] + "/lib/library.so.3.0",
                       "component": name, "sha256": character * 64}
                      for name, character in (("freerdp", "b"), ("guacd", "c"))]}
        self.manifest["aliases"] = {item["path"]: item["path"]
                                    for item in self.manifest["files"]}
        self.manifest["aliases"]["/opt/pamolive-freerdp/lib/library.so"] = (
            "/opt/pamolive-freerdp/lib/library.so.3.0")
        self.manifest["components"][0]["json_backend_patch_sha256"] = sbom.JSON_PATCH_SHA
        guacd = self.manifest["components"][1]
        guacd["compat_patch_sha256"] = sbom.COMPAT_PATCH_SHA
        guacd["compat_upstream_commit"] = sbom.COMPAT_UPSTREAM_COMMIT
        self.report = {"schema": sbom.SCHEMA, "verified": True, "live_link_probe": True,
                       "inventory": copy.deepcopy(self.manifest)}
        self.hashes = {name: value * 64 for name, value in (
            ("app", "a"), ("manifest", "b"), ("report", "c"))}

    def merge(self, **kwargs):
        return sbom.merge(self.app, self.manifest, self.report,
                          image_digest="sha256:" + "d" * 64, input_hashes=self.hashes, **kwargs)

    def sync(self):
        self.report["inventory"] = copy.deepcopy(self.manifest)

    def test_valid_merge_preserves_application_authority_and_standard_schema(self):
        before = copy.deepcopy(self.app)
        result = self.merge()
        self.assertEqual(self.app, before)
        self.assertEqual(result["components"][0], before["components"][0])
        self.assertEqual(result["dependencies"][0], before["dependencies"][0])
        self.assertEqual(result["specVersion"], "1.4")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["metadata"]["properties"][0],
                         before["metadata"]["properties"][0])
        self.assertEqual(len(result["components"]), 6)
        cpes = [component["cpe"] for component in result["components"] if "cpe" in component]
        self.assertEqual(set(cpes), {
            "cpe:2.3:a:freerdp:freerdp:3.33.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:guacamole:1.6.0:*:*:*:*:*:*:*"})

    def test_source_hash_file_hash_aliases_and_image_digest_remain_distinct(self):
        result = self.merge()
        library = next(item for item in result["components"] if item["name"] == "freerdp")
        self.assertEqual(library["purl"], "pkg:generic/freerdp@3.33.1")
        self.assertEqual(library["externalReferences"][0]["hashes"][0]["content"],
                         sbom.SOURCES["freerdp"][1])
        files = [item for item in result["components"] if item["type"] == "file"]
        aliases = [prop["value"] for item in files for prop in item["properties"]
                   if prop["name"] == "pamolive:native:aliases"]
        self.assertTrue(any("/lib/library.so\"" in value for value in aliases))
        properties = {prop["name"]: prop["value"] for prop in result["metadata"]["properties"]}
        self.assertEqual(properties["pamolive:sbom:manifest-canonical-sha256"],
                         sbom.digest(self.manifest))
        self.assertEqual(properties["pamolive:sbom:app-input-sha256"], self.hashes["app"])
        self.assertIn("OS archive scan required", properties["pamolive:sbom:coverage"])

    def test_canonical_output_and_identity_are_deterministic(self):
        self.assertEqual(sbom.canonical(self.merge()), sbom.canonical(self.merge()))
        original = self.merge()["serialNumber"]
        self.hashes["report"] = "e" * 64
        self.assertNotEqual(self.merge()["serialNumber"], original)

    def test_invalid_image_tag_or_digest_fails(self):
        for value in ("latest", "host.invalid/image:latest", "sha256:short", "sha256:" + "A" * 64):
            with self.subTest(value=value), self.assertRaises(sbom.SbomError):
                sbom.merge(self.app, self.manifest, self.report,
                           image_digest=value, input_hashes=self.hashes)

    def test_invalid_image_digest_kind_fails_closed(self):
        for kind in ("registry", "config", "", None):
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    sbom.SbomError, "image_digest_kind"):
                self.merge(image_digest_kind=kind)

    def test_configuration_hash_and_registry_manifest_identity_are_distinct(self):
        registry = self.merge()
        config = self.merge(image_digest_kind="image_config")
        registry_image = next(item for item in registry["components"]
                              if item["type"] == "container")
        config_image = next(item for item in config["components"] if item["type"] == "container")
        self.assertNotEqual(registry_image["bom-ref"], config_image["bom-ref"])
        self.assertNotEqual(registry["serialNumber"], config["serialNumber"])
        self.assertEqual(config_image["version"], "image_config:sha256:" + "d" * 64)
        self.assertNotIn("hashes", config_image)
        self.assertEqual(registry_image["hashes"][0]["content"], "d" * 64)
        for result, kind in ((registry, "oci_manifest"), (config, "image_config")):
            properties = {value["name"]: value["value"]
                          for value in result["metadata"]["properties"]}
            self.assertEqual(properties["pamolive:sbom:image-digest-kind"], kind)
            self.assertEqual(len(result["components"]), 6)
            self.assertEqual(result["components"][0], self.app["components"][0])

    def debian_report(self):
        from qualification.debian_138_refresh.verify_refresh import NATIVE_FILES, PACKAGES

        runtime = {*NATIVE_FILES, "libc-bin"}
        return {
            "schema": "pamolive.debian-refresh-runtime/1",
            "architecture": "amd64",
            "receipt_sha256": "9" * 64,
            "packages": [
                {
                    "package": name,
                    "source": PACKAGES[name][0],
                    "version": PACKAGES[name][1],
                    "suite": PACKAGES[name][2],
                    "archive_sha256": "8" * 64,
                    "archive_bytes": 2048,
                }
                for name in sorted(runtime)
            ],
            "installed_elf_sha256": {
                path: "7" * 64 for paths in NATIVE_FILES.values() for path in paths
            },
            "image_config_id": "sha256:" + "d" * 64,
            "archive_sha256": "6" * 64,
            "revision": "5" * 40,
        }

    def test_debian_sbom_links_official_packages_and_verified_installed_files(self):
        self.hashes["debian"] = "4" * 64
        report = self.debian_report()
        result = self.merge(image_digest_kind="image_config", debian_report=report)
        packages = [row for row in result["components"] if ":debian:" in row["bom-ref"]]
        self.assertEqual({row["name"] for row in packages},
                         {item["package"] for item in report["packages"]})
        package = next(item for item in packages if item["name"] == "libkrb5-3")
        self.assertIn("deb13u2", package["purl"])
        self.assertIn("%2B", package["purl"])
        source = package["externalReferences"][0]
        self.assertIn("/debian-security/", source["url"])
        self.assertEqual(source["hashes"][0]["content"], "8" * 64)
        files = [row for row in result["components"] if ":debian-elf:" in row["bom-ref"]]
        self.assertEqual(len(files), 6)
        self.assertTrue(all(row["hashes"][0]["content"] == "7" * 64 for row in files))

    def debian_backport_report(self):
        from deploy import debian_refresh_inventory as inventory
        from deploy import krb5_trixie_materials as materials

        reviewed = materials.load_reviewed()
        report = self.debian_report()
        report["schema"] = inventory.SCHEMA_V2
        report["kerberos_receipt_sha256"] = materials.SHA256
        report["installed_elf_sha256"].update(reviewed["installed_elf_sha256"])
        for row in report["packages"]:
            if row["source"] == "krb5":
                package = reviewed["packages"][row["package"]]
                row.update(version=materials.VERSION, suite=inventory.KERBEROS_SUITE,
                           archive_sha256=package["sha256"], archive_bytes=package["bytes"])
        return report, reviewed

    def test_debian_sbom_separates_the_kerberos_deb_and_github_zip_digests(self):
        self.hashes["debian"] = "4" * 64
        report, reviewed = self.debian_backport_report()
        result = self.merge(image_digest_kind="image_config", debian_report=report)
        packages = {row["name"]: row for row in result["components"]
                    if ":debian:" in row["bom-ref"]}
        package = packages["libkrb5-3"]
        self.assertEqual(package["purl"],
                         "pkg:deb/debian/libkrb5-3@1.21.3-5%2Bdeb13u2%2Bpamolive1"
                         "?arch=amd64&distro=debian-13&upstream=krb5")
        deb_sha = reviewed["packages"]["libkrb5-3"]["sha256"]
        zip_sha = reviewed["qualification"]["artifact_digest"].removeprefix("sha256:")
        self.assertEqual(package["hashes"], [{"alg": "SHA-256", "content": deb_sha}])
        ref, = package["externalReferences"]
        self.assertEqual(ref["url"], "https://github.com/pamolive/PamOlive-Platform/actions/runs/"
                         "45131107539/artifacts/14798285716")
        self.assertEqual(ref["hashes"], [{"alg": "SHA-256", "content": zip_sha}])
        self.assertNotEqual(deb_sha, zip_sha)
        properties = {prop["name"]: prop["value"] for prop in package["properties"]}
        self.assertEqual(properties["pamolive:debian:receipt-sha256"],
                         report["kerberos_receipt_sha256"])
        self.assertEqual(properties["pamolive:debian:origin"], "pamolive-kerberos-backport")
        self.assertEqual(properties["pamolive:debian:qualification-commit"],
                         reviewed["qualification"]["commit"])

        official = self.merge(image_digest_kind="image_config", debian_report=self.debian_report())
        self.assertEqual(packages["libc6"],
                         next(row for row in official["components"] if row["name"] == "libc6"))

    def test_debian_sbom_rejects_unreviewed_kerberos_materials(self):
        self.hashes["debian"] = "4" * 64
        valid, reviewed = self.debian_backport_report()
        path = next(iter(reviewed["installed_elf_sha256"]))
        for field, replacement in (
            ("kerberos_receipt_sha256", "e" * 64),
            ("installed_elf_sha256", {**valid["installed_elf_sha256"], path: "e" * 64}),
            ("packages", [{**row, "archive_bytes": row["archive_bytes"] + 1}
                          if row["package"] == "libkrb5-3" else row for row in valid["packages"]]),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(sbom.SbomError, "debian_report"):
                self.merge(image_digest_kind="image_config",
                           debian_report={**valid, field: replacement})

    def openssl_backport_report(self):
        from deploy import debian_refresh_inventory as inventory
        from deploy import openssl_trixie_materials as openssl

        report, _ = self.debian_backport_report()
        reviewed = openssl.load_reviewed()
        report["schema"] = inventory.SCHEMA_V3
        report["openssl_receipt_sha256"] = openssl.SHA256
        report["installed_elf_sha256"].update(reviewed["installed_elf_sha256"])
        for name in openssl.RUNTIME_PACKAGES:
            package = reviewed["packages"][name]
            report["packages"].append({
                "package": name, "source": "openssl", "version": openssl.VERSION,
                "suite": inventory.BACKPORT_SUITE, "archive_sha256": package["sha256"],
                "archive_bytes": package["bytes"],
            })
        report["packages"].sort(key=lambda row: row["package"])
        return report, reviewed

    def test_openssl_sbom_links_packages_elfs_and_provenance_to_the_image_archive(self):
        from deploy import openssl_trixie_materials as openssl

        self.hashes["debian"] = "4" * 64
        report, reviewed = self.openssl_backport_report()
        result = self.merge(image_digest_kind="image_config", debian_report=report)
        components = {row["bom-ref"]: row for row in result["components"]}
        packages = {row["name"]: row for row in components.values()
                    if ":debian:" in row["bom-ref"]}
        dependencies = {row["ref"]: row.get("dependsOn", []) for row in result["dependencies"]}
        expected_url = ("https://github.com/pamolive/PamOlive-Platform/actions/runs/"
                        "45243975566/artifacts/14853358671")
        artifact_sha = reviewed["qualification"]["artifact_digest"].removeprefix("sha256:")
        for name in openssl.RUNTIME_PACKAGES:
            package = packages[name]
            self.assertEqual(package["purl"], f"pkg:deb/debian/{name}@3.5.9-1~deb13u1%2Bpamolive2"
                             "?arch=amd64&distro=debian-13&upstream=openssl")
            self.assertEqual(package["hashes"][0]["content"], reviewed["packages"][name]["sha256"])
            ref, = package["externalReferences"]
            self.assertEqual(ref["url"], expected_url)
            self.assertEqual(ref["hashes"][0]["content"], artifact_sha)
            self.assertNotEqual(package["hashes"][0]["content"], artifact_sha)
            properties = {item["name"]: item["value"] for item in package["properties"]}
            self.assertEqual(properties["pamolive:debian:origin"], "pamolive-openssl-backport")
            self.assertEqual(properties["pamolive:debian:receipt-sha256"], openssl.SHA256)
            self.assertEqual(properties["pamolive:debian:qualification-commit"],
                             reviewed["qualification"]["commit"])
            files = [components[ref] for ref in dependencies[package["bom-ref"]]]
            self.assertEqual({file["properties"][0]["value"]: file["hashes"][0]["content"]
                              for file in files},
                             {path: reviewed["installed_elf_sha256"][path]
                              for path in openssl.ELF_BY_PACKAGE[name]})
        self.assertEqual(packages["openssl"]["type"], "application")
        metadata = {item["name"]: item["value"] for item in result["metadata"]["properties"]}
        self.assertEqual(metadata["pamolive:sbom:image-digest"], report["image_config_id"])
        self.assertEqual(metadata["pamolive:sbom:debian-archive-sha256"], report["archive_sha256"])
        self.assertEqual(metadata["pamolive:sbom:openssl-receipt-sha256"], openssl.SHA256)
        prior, _ = self.debian_backport_report()
        before = self.merge(image_digest_kind="image_config", debian_report=prior)
        for name in ("libc6", "libkrb5-3"):
            self.assertEqual(packages[name], next(row for row in before["components"]
                                                 if row["name"] == name))

    def test_openssl_sbom_rejects_changed_provenance_and_mismatched_image(self):
        self.hashes["debian"] = "4" * 64
        report, reviewed = self.openssl_backport_report()
        path = next(iter(reviewed["installed_elf_sha256"]))
        for field, replacement, code in (
            ("openssl_receipt_sha256", "e" * 64, "debian_report"),
            ("installed_elf_sha256", {**report["installed_elf_sha256"], path: "e" * 64},
             "debian_report"),
            ("packages", [{**row, "archive_sha256": "e" * 64} if row["package"] == "libssl3t64"
                          else row for row in report["packages"]], "debian_report"),
            ("archive_sha256", "unknown", "debian_report"),
            ("image_config_id", "sha256:" + "e" * 64, "debian_image_binding"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(sbom.SbomError, code):
                self.merge(image_digest_kind="image_config",
                           debian_report={**report, field: replacement})

    def test_debian_sbom_requires_one_exact_image_and_unambiguous_package_identity(self):
        self.hashes["debian"] = "4" * 64
        report = self.debian_report()
        with self.assertRaisesRegex(sbom.SbomError, "debian_image_digest_kind"):
            self.merge(debian_report=report)
        with self.assertRaisesRegex(sbom.SbomError, "debian_image_binding"):
            self.merge(image_digest_kind="image_config", debian_report={
                **report, "image_config_id": "sha256:" + "e" * 64,
            })
        self.app["components"].append({"type": "library", "name": "libc6", "version": "2.41"})
        with self.assertRaisesRegex(sbom.SbomError, "component_identity_conflict"):
            self.merge(image_digest_kind="image_config", debian_report=report)

    def test_missing_or_fake_live_native_verification_fails(self):
        for key, value in (("verified", False), ("verified", "true"),
                           ("live_link_probe", False), ("schema", "other")):
            with self.subTest(key=key, value=value):
                old = self.report[key]
                self.report[key] = value
                with self.assertRaises(sbom.SbomError):
                    self.merge()
                self.report[key] = old

    def test_manifest_and_verified_report_must_match(self):
        self.report["inventory"]["files"].pop()
        with self.assertRaisesRegex(sbom.SbomError, "native_report_mismatch"):
            self.merge()

    def test_native_source_and_runtime_cross_version_conflicts_fail(self):
        for key, value in (("version", "3.15.0"), ("source_sha256", "0" * 64)):
            with self.subTest(key=key):
                original = self.manifest["components"][0][key]
                self.manifest["components"][0][key] = value
                self.sync()
                with self.assertRaises(sbom.SbomError):
                    self.merge()
                self.manifest["components"][0][key] = original
        self.manifest["runtime_versions"]["freerdp"] = "3.15.0"
        self.sync()
        with self.assertRaisesRegex(sbom.SbomError, "native_runtime_identity"):
            self.merge()

    def test_unrecognized_metadata_or_unapproved_build_flags_are_not_published(self):
        component = self.manifest["components"][0]
        component["unapproved_url"] = "https://attacker.invalid/private"
        self.sync()
        with self.assertRaisesRegex(sbom.SbomError, "native_metadata_fields"):
            self.merge()
        component.pop("unapproved_url")
        component["build_options"] = {"WITH_FFMPEG": "ON"}
        self.sync()
        with self.assertRaisesRegex(sbom.SbomError, "native_build_options"):
            self.merge()

    def test_guacd_missing_or_unreviewed_compatibility_patch_is_refused(self):
        component = self.manifest["components"][1]
        for key in ("compat_patch_sha256", "compat_upstream_commit"):
            original = component.pop(key)
            self.sync()
            with self.assertRaisesRegex(sbom.SbomError, "native_compat_patch"):
                self.merge()
            component[key] = original

    def test_application_cannot_claim_native_component_or_duplicate_identity(self):
        for component in ({"type": "library", "name": "FreeRDP", "version": "3.15.0"},
                          {"type": "library", "name": "synthetic_package", "version": "2.0"}):
            with self.subTest(component=component):
                self.app["components"].append(component)
                with self.assertRaisesRegex(sbom.SbomError, "component_identity_conflict"):
                    self.merge()
                self.app["components"].pop()

    def test_nested_native_conflict_is_also_refused(self):
        self.app["components"][0]["components"] = [
            {"type": "library", "name": "FreeRDP", "version": "3.15.0"}]
        with self.assertRaisesRegex(sbom.SbomError, "component_identity_conflict"):
            self.merge()

    def test_existing_metadata_component_and_refs_are_preserved(self):
        component = {"type": "application", "name": "existing-root", "version": "1",
                     "bom-ref": "existing-root-ref"}
        self.app["metadata"]["component"] = component
        result = self.merge()
        self.assertEqual(result["metadata"]["component"], component)
        image_ref = next(item["bom-ref"] for item in result["components"]
                         if item["type"] == "container")
        image_deps = next(item for item in result["dependencies"] if item["ref"] == image_ref)
        self.assertIn("existing-root-ref", image_deps["dependsOn"])

    def test_conflicting_same_algorithm_hashes_are_not_silently_merged(self):
        self.app["components"][0]["hashes"].append({"alg": "SHA-256", "content": "b" * 64})
        with self.assertRaisesRegex(sbom.SbomError, "conflicting_hash_algorithm"):
            self.merge()

    def test_shared_bom_refs_and_missing_dependency_targets_fail(self):
        self.app["components"].append({"type": "library", "name": "other", "version": "1",
                                       "bom-ref": "original-ref"})
        with self.assertRaisesRegex(sbom.SbomError, "duplicate_bom_ref"):
            self.merge()
        self.app["components"].pop()
        self.app["dependencies"][0]["dependsOn"] = ["missing"]
        with self.assertRaisesRegex(sbom.SbomError, "dependency_target"):
            self.merge()

    def test_reserved_reference_and_property_names_fail(self):
        self.app["components"][0]["bom-ref"] = sbom.PREFIX + "forged"
        with self.assertRaisesRegex(sbom.SbomError, "reserved_bom_ref"):
            self.merge()

    def test_native_alias_cross_component_or_path_escape_fails(self):
        for key, value in (("/tmp/alias", self.manifest["files"][0]["path"]),
                           ("/opt/pamolive-guac/lib/alias", self.manifest["files"][0]["path"]),
                           ("/opt/pamolive-freerdp/../alias", self.manifest["files"][0]["path"])):
            with self.subTest(alias=key):
                self.manifest["aliases"][key] = value
                self.sync()
                with self.assertRaisesRegex(sbom.SbomError, "native_alias"):
                    self.merge()
                del self.manifest["aliases"][key]

    def test_remote_schema_or_embedded_schema_reference_is_refused(self):
        self.app["$schema"] = "https://attacker.invalid/schema.json"
        with self.assertRaisesRegex(sbom.SbomError, "schema_location"):
            self.merge()
        self.app.pop("$schema")
        self.app["components"][0]["$ref"] = "https://attacker.invalid/payload"
        with self.assertRaisesRegex(sbom.SbomError, "embedded_schema_reference"):
            self.merge()

    def test_actual_schema_validation_refuses_invalid_cyclonedx(self):
        self.app["components"][0]["type"] = "invented-component-type"
        with self.assertRaisesRegex(sbom.SbomError, "cyclonedx_schema"):
            self.merge()

    def test_missing_schema_validator_fails_closed(self):
        with patch.dict("sys.modules", {"cyclonedx.schema": None}):
            with self.assertRaisesRegex(sbom.SbomError, "schema_validator_unavailable"):
                self.merge()

    def test_json_duplicates_byte_depth_and_node_budgets(self):
        with tempfile.TemporaryDirectory(prefix="pamolive-sbom-input-") as folder:
            path = Path(folder) / "input.json"
            path.write_text('{"components":[],"components":[]}')
            with self.assertRaises(sbom.SbomError):
                sbom.load(path)
            path.write_bytes(b" " * (sbom.MAX_INPUT + 1))
            with self.assertRaisesRegex(sbom.SbomError, "input_budget"):
                sbom.load(path)
        nested = []
        for _ in range(34):
            nested = [nested]
        with self.assertRaisesRegex(sbom.SbomError, "structure_budget"):
            sbom.bounded(nested)

    def test_cli_never_overwrites_or_reads_inputs_if_output_already_exists(self):
        with tempfile.TemporaryDirectory(prefix="pamolive-sbom-output-") as folder:
            output = Path(folder) / "preserve.json"
            output.write_text("preserve")
            args = ["--app-sbom", "missing", "--native-manifest", "missing",
                    "--native-report", "missing", "--image-digest", "sha256:" + "d" * 64,
                    "--output", str(output)]
            with patch.object(sbom, "load") as load, redirect_stdout(io.StringIO()):
                self.assertEqual(sbom.main(args), 1)
            load.assert_not_called()
            self.assertEqual(output.read_text(), "preserve")

    def test_cli_round_trip_uses_exact_input_byte_hashes(self):
        with tempfile.TemporaryDirectory(prefix="pamolive-sbom-cli-") as folder:
            folder = Path(folder)
            for name, value in (("app", self.app), ("manifest", self.manifest),
                                ("report", self.report)):
                (folder / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
            output = folder / "combined.json"
            args = ["--app-sbom", str(folder / "app.json"), "--native-manifest",
                    str(folder / "manifest.json"), "--native-report", str(folder / "report.json"),
                    "--image-digest", "sha256:" + "d" * 64, "--output", str(output)]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(sbom.main(args), 0)
            result = json.loads(output.read_text())
            properties = {prop["name"]: prop["value"]
                          for prop in result["metadata"]["properties"]}
            self.assertEqual(properties["pamolive:sbom:app-input-sha256"],
                             sbom.load(folder / "app.json")[1])
