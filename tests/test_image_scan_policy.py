"""Synthetic policy tests: no scanner, network, Docker or real identities."""

import base64
import copy
import hashlib
import io
import json
import tarfile
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import qualify_image_scan as gate


class ImageScanPolicyTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pamolive-scan-policy-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()
        self.now = datetime.now(UTC)
        self.config = b'{"synthetic":true}'
        self.config_id = "sha256:" + hashlib.sha256(self.config).hexdigest()
        self.os = self.report("docker-archive")
        self.os["source"] = {"type": "image", "target": {
            "imageID": self.config_id, "os": "linux", "architecture": "amd64",
            "config": base64.b64encode(self.config).decode()}}
        self.compiled = self.report("sbom")
        self.positive = self.report("sbom")
        self.positive["matches"] = [self.match(cve, name=name, version=version)
                                    for name, version, cve in gate.EXPECTED_CONTROL]
        self.sbom = {"metadata": {"properties": [
            {"name": "pamolive:sbom:image-digest-kind", "value": "image_config"},
            {"name": "pamolive:sbom:image-digest", "value": self.config_id}]}, "components": [
            {"cpe": "cpe:2.3:a:freerdp:freerdp:3.33.1:*:*:*:*:*:*:*"},
            {"cpe": "cpe:2.3:a:apache:guacamole:1.6.0:*:*:*:*:*:*:*"}]}
        self.policy = {"schema": gate.SCHEMA, "version": 1, "findings": []}

    def report(self, source):
        return {"source": {"type": "sbom-file", "target": "synthetic.cdx.json"},
                "matches": [], "ignoredMatches": [],
                "distro": {"name": "debian", "version": "13.7"},
                "descriptor": {"name": "grype", "version": gate.TOOL_VERSION,
                    "timestamp": self.now.isoformat(), "db": {"status": {
                        "valid": True, "schemaVersion": "v6.1.10",
                        "built": (self.now - timedelta(hours=1)).isoformat()}},
                    "configuration": {"from": [source], "ignore": [], "exclude": [],
                        "vex-documents": [], "vex-add": [], "only-fixed": False,
                        "only-notfixed": False, "ignore-wontfix": "",
                        "match-upstream-kernel-headers": True,
                        "include-matcher-suppressions": True,
                        "match": {"stock": {"using-cpes": True}},
                        "externalSources": {"enable": False}, "db": {
                            "auto-update": False, "validate-age": True,
                            "validate-by-hash-on-start": True}}}}

    def match(self, cve="CVE-2026-123456", *, severity="High", state="not-fixed",
              name="synthetic-library", version="1.0", source="synthetic-source"):
        return {"artifact": {"name": name, "version": version, "type": "deb",
                             "purl": f"pkg:deb/debian/{name}@{version}",
                             "upstreams": [{"name": source}]},
                "vulnerability": {"id": cve, "severity": severity,
                    "fix": {"state": state, "versions": ["2.0"] if state == "fixed" else []},
                    "namespace": "debian:distro:debian:13",
                    "dataSource": "https://security-tracker.debian.org/tracker/" + cve}}

    def evaluate(self, facts=None):
        return gate.qualify(self.os, self.compiled, self.positive, self.sbom, self.policy,
                            config_id=self.config_id, config_bytes=self.config,
                            facts=facts or (set(), {}), repo=self.repo, now=self.now)

    def add_exception(self):
        self.os["matches"] = [self.match()]
        key, finding = next(iter(gate.high_groups(self.os, "os").items()))
        folder = self.repo / "docs"
        folder.mkdir(exist_ok=True)
        proof = folder / "synthetic-proof.md"
        proof.write_bytes(b"Synthetic test evidence only. No real security exception.")
        entry = {"fingerprint": key, "finding": finding, "disposition": "not_reachable",
            "analyst": "synthetic-analyst",
            "reviewers": ["synthetic-reviewer1", "synthetic-reviewer2"],
            "analysis": "Synthetic exposure analysis for an isolated test. " * 3,
            "reviewed_at": (self.now - timedelta(hours=1)).isoformat(),
            "expires": (self.now + timedelta(days=1)).isoformat(),
            "vendor_evidence": [finding["data_source"]],
            "local_evidence": [{"path": "docs/synthetic-proof.md",
                                "sha256": gate.hash_file(proof)}],
            "conditions": [{"kind": "absent_basename_glob", "pattern": "synthetic-absent.so*"}]}
        self.policy["findings"] = [entry]
        return entry

    def test_complete_empty_reports_with_positive_control_pass(self):
        result = self.evaluate()
        self.assertTrue(result["passed"])
        self.assertTrue(result["all_findings_clear"])

    def test_medium_findings_remain_visible_even_when_policy_passes(self):
        self.os["matches"] = [self.match(severity="Medium", state="fixed")]
        result = self.evaluate()
        self.assertTrue(result["passed"])
        self.assertFalse(result["all_findings_clear"])
        self.assertEqual(result["summary"]["os"]["matches"], 1)

    def test_critical_and_high_available_fix_are_unconditionally_blocking(self):
        for severity, state in (("Critical", "not-fixed"), ("High", "fixed")):
            self.os["matches"] = [self.match(severity=severity, state=state)]
            with self.subTest(severity=severity):
                self.assertFalse(self.evaluate()["passed"])
        entry = self.add_exception()
        self.os["matches"][0]["vulnerability"]["fix"]["versions"] = ["2.0"]
        self.assertFalse(self.evaluate()["passed"])
        self.assertEqual(entry["disposition"], "not_reachable")

    def test_every_new_high_and_untriaged_known_high_blocks(self):
        self.os["matches"] = [self.match()]
        result = self.evaluate()
        self.assertEqual(result["high_finding_groups"], 1)
        self.assertEqual(result["blockers"][0]["code"], "untriaged_high")
        key, finding = next(iter(gate.high_groups(self.os, "os").items()))
        self.policy["findings"] = [{"fingerprint": key, "finding": finding,
                                    "disposition": "untriaged"}]
        self.assertFalse(self.evaluate()["passed"])

    def test_narrow_review_and_true_archive_condition_can_pass_without_claiming_clear(self):
        self.add_exception()
        result = self.evaluate()
        self.assertTrue(result["passed"])
        self.assertFalse(result["all_findings_clear"])
        self.assertFalse(self.evaluate(({"/usr/lib/synthetic-absent.so.1"}, {}))["passed"])

    def test_changed_distro_binary_source_version_or_status_invalidates_fingerprint(self):
        self.add_exception()
        original = copy.deepcopy(self.os)
        mutations = [lambda: self.os["distro"].update(version="13.8"),
                     lambda: self.os["matches"][0]["artifact"].update(version="1.1"),
                     lambda: self.os["matches"][0]["artifact"]["upstreams"][0].update(name="other"),
                     lambda: self.os["matches"][0]["vulnerability"]["fix"].update(state="wont-fix")]
        for change in mutations:
            self.os = copy.deepcopy(original)
            change()
            self.assertFalse(self.evaluate()["passed"])

    def test_same_cve_cannot_reuse_os_exception_for_compiled_package(self):
        self.add_exception()
        self.compiled["matches"] = copy.deepcopy(self.os["matches"])
        self.assertFalse(self.evaluate()["passed"])

    def test_expired_same_author_or_missing_evidence_rejected(self):
        entry = self.add_exception()
        original = copy.deepcopy(entry)
        for key, value in (("expires", (self.now - timedelta(seconds=1)).isoformat()),
                           ("reviewers", ["synthetic-analyst", "other"]),
                           ("vendor_evidence", []), ("local_evidence", []), ("conditions", [])):
            self.policy["findings"] = [{**original, key: value}]
            with self.subTest(key=key), self.assertRaises(gate.ScanPolicyError):
                self.evaluate()

    def test_changed_evidence_or_no_longer_absent_component_blocks(self):
        self.add_exception()
        (self.repo / "docs/synthetic-proof.md").write_bytes(b"changed")
        with self.assertRaisesRegex(gate.ScanPolicyError, "proof_changed"):
            self.evaluate()

    def test_all_filter_suppression_and_disabled_validation_paths_are_rejected(self):
        original = copy.deepcopy(self.os)
        for key, value in (("ignore", [{"package": "*"}]), ("exclude", ["**"]),
                           ("vex-documents", ["fake"]), ("only-fixed", True),
                           ("match-upstream-kernel-headers", False),
                           ("include-matcher-suppressions", False)):
            self.os = copy.deepcopy(original)
            self.os["descriptor"]["configuration"][key] = value
            with self.subTest(key=key), self.assertRaises(gate.ScanPolicyError):
                self.evaluate()

    def test_suppressed_results_do_not_silently_pass(self):
        self.os["ignoredMatches"] = [self.match()]
        self.assertFalse(self.evaluate()["passed"])

    def test_grype_empty_ignored_omitempty_is_supported_but_null_is_refused(self):
        for report in (self.os, self.compiled, self.positive):
            report.pop("ignoredMatches")
        self.assertTrue(self.evaluate()["passed"])
        self.os["ignoredMatches"] = None
        with self.assertRaisesRegex(gate.ScanPolicyError, "ignored_matches_missing"):
            self.evaluate()

    def test_missing_positive_cve_or_disabled_cpe_matching_rejected(self):
        self.positive["matches"].pop()
        with self.assertRaisesRegex(gate.ScanPolicyError, "positive_control_not_detected"):
            self.evaluate()
        self.positive["descriptor"]["configuration"]["match"]["stock"]["using-cpes"] = False
        with self.assertRaisesRegex(gate.ScanPolicyError, "cpe_matching_disabled"):
            self.evaluate()

    def test_stale_invalid_mixed_or_future_database_and_scans_fail(self):
        original = copy.deepcopy(self.os)
        changes = [lambda: self.os["descriptor"]["db"]["status"].update(valid=False),
                   lambda: self.os["descriptor"]["db"]["status"].update(
                       built=(self.now - timedelta(days=3)).isoformat()),
                   lambda: self.os["descriptor"].update(
                       timestamp=(self.now + timedelta(hours=1)).isoformat()),
                   lambda: self.os["descriptor"]["db"]["status"].update(
                       built=(self.now - timedelta(hours=2)).isoformat())]
        for change in changes:
            self.os = copy.deepcopy(original)
            change()
            with self.assertRaises(gate.ScanPolicyError):
                self.evaluate()

    def test_wrong_config_bytes_kind_platform_or_missing_native_inventory_fails(self):
        self.os["source"]["target"]["config"] = base64.b64encode(b"other").decode()
        with self.assertRaisesRegex(gate.ScanPolicyError, "os_configuration_bytes"):
            self.evaluate()
        self.os["source"]["target"]["config"] = base64.b64encode(self.config).decode()
        self.sbom["metadata"]["properties"][0]["value"] = "oci_manifest"
        with self.assertRaisesRegex(gate.ScanPolicyError, "sbom_image_identity"):
            self.evaluate()

    def test_error_unknown_severity_and_policy_tampering_fail_closed(self):
        self.os["error"] = "synthetic failure"
        with self.assertRaisesRegex(gate.ScanPolicyError, "scanner_error"):
            self.evaluate()
        self.os.pop("error")
        self.os["matches"] = [self.match(severity="invented")]
        with self.assertRaisesRegex(gate.ScanPolicyError, "unknown_severity"):
            self.evaluate()
        self.add_exception()["finding"]["source_package"] = "tampered"
        with self.assertRaisesRegex(gate.ScanPolicyError, "policy_fingerprint"):
            self.evaluate()

    def test_duplicate_json_oversize_and_existing_output_are_refused(self):
        path = self.repo / "duplicate.json"
        path.write_bytes(b'{"matches":[],"matches":[]}')
        with self.assertRaisesRegex(gate.ScanPolicyError, "duplicate_json_key"):
            gate.read_json(path)
        path.write_bytes(b" " * 20)
        with self.assertRaisesRegex(gate.ScanPolicyError, "json_byte_budget"):
            gate.read_json(path, 10)
        args = []
        for name in ("bundle", "revision", "os-report", "compiled-sbom", "compiled-report",
                     "positive-report", "scanner-archive", "policy"):
            args.extend(["--" + name, "missing"])
        with patch.object(gate, "read_json") as reader:
            self.assertEqual(gate.main([*args, "--output", str(path)]), 1)
        reader.assert_not_called()
        self.assertEqual(path.read_bytes(), b" " * 20)

    def test_archive_conditions_inspect_layers_without_extracting_or_following_symlinks(self):
        binary = b"\x7fELF\x02\x01" + b"synthetic" * 10
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as inner:
            for name in ("./", "usr/lib/"):
                directory = tarfile.TarInfo(name)
                directory.type = tarfile.DIRTYPE
                inner.addfile(directory)
            member = tarfile.TarInfo("usr/lib/synthetic.so")
            member.size = len(binary)
            inner.addfile(member, io.BytesIO(binary))
        archive = self.repo / "synthetic.tar"
        with tarfile.open(archive, "w") as outer:
            for name, data in (("manifest.json", b'[{"Layers":["layer.tar"]}]'),
                               ("layer.tar", layer.getvalue())):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                outer.addfile(member, io.BytesIO(data))
        condition = {"kind": "elf", "path": "/usr/lib/synthetic.so", "class": 64,
                     "sha256": hashlib.sha256(binary).hexdigest()}
        facts = gate.archive_facts(archive, [condition])
        self.assertTrue(gate.conditions_hold([condition], facts))
        condition["class"] = 32
        self.assertFalse(gate.conditions_hold([condition], facts))
        self.assertFalse(gate.conditions_hold([
            {"kind": "absent_path_suffix", "suffix": "/lib/synthetic.so"}], facts))

    def test_complete_cli_binds_synthetic_bundle_reports_fixture_and_tool_hash(self):
        revision = "a" * 40
        folder = self.repo / ".github/qualification"
        folder.mkdir(parents=True)
        bundle = self.repo / "bundle"
        bundle.mkdir()
        config = {"os": "linux", "architecture": "amd64", "config": {"Env": [], "Labels": {
            "org.opencontainers.image.source": gate.qualified_image.SOURCE,
            "org.opencontainers.image.revision": revision,
            "io.pamolive.source.license": "AGPL-3.0-or-later"}}}
        self.config = gate.canonical(config).encode()
        self.config_id = "sha256:" + hashlib.sha256(self.config).hexdigest()
        self.os["source"]["target"].update(imageID=self.config_id,
                                           config=base64.b64encode(self.config).decode())
        self.sbom["metadata"]["properties"][1]["value"] = self.config_id
        archive = bundle / gate.qualified_image.ARCHIVE
        config_name = self.config_id[7:] + ".json"
        manifest = [{"Config": config_name, "RepoTags": [gate.qualified_image.TAG], "Layers": []}]
        with tarfile.open(archive, "w") as output:
            for name, data in (("manifest.json", json.dumps(manifest).encode()),
                               (config_name, self.config)):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        def write(path, value):
            path.write_bytes((gate.canonical(value) + "\n").encode())
            return gate.hash_file(path)
        write(bundle / gate.qualified_image.METADATA, {
            "schema": gate.qualified_image.FORMAT, "source": gate.qualified_image.SOURCE,
            "revision": revision, "platform": "linux/amd64", "image_id": self.config_id,
            "archive_sha256": gate.hash_file(archive)})
        fixture = Path(__file__).resolve().parents[1] / (
            ".github/qualification/native-positive-control.cdx.json")
        control = folder / fixture.name
        control.write_bytes(fixture.read_bytes())
        scanner = self.repo / "synthetic-scanner.tar.gz"
        scanner.write_bytes(b"Synthetic checksum-only scanner artifact; never executed.")
        scanner_sha = gate.hash_file(scanner)
        pin = folder / "tool.json"
        pin_sha = write(pin, {"schema": "pamolive.grype-release-pin.v1",
                             "version": gate.TOOL_VERSION, "archive_sha256": scanner_sha})
        self.policy.update(scanner_pin={"file": pin.name, "sha256": pin_sha},
                           positive_control={"file": control.name,
                                             "sha256": gate.hash_file(control)})
        policy_path = folder / "policy.json"
        write(policy_path, self.policy)
        self.compiled["source"]["target"] = "/combined.cdx.json"
        self.positive["source"]["target"] = "/control.cdx.json"
        args = ["--bundle", str(bundle), "--revision", revision, "--scanner-archive", str(scanner),
                "--policy", str(policy_path), "--output", str(self.repo / "result.json")]
        for flag, value in (("os-report", self.os), ("compiled-report", self.compiled),
                            ("positive-report", self.positive), ("compiled-sbom", self.sbom)):
            path = self.repo / (flag + ".json")
            write(path, value)
            args.extend(["--" + flag, str(path)])
        with patch.object(gate, "TOOL_SHA256", scanner_sha):
            self.assertEqual(gate.main(args), 0)
        result = gate.read_json(self.repo / "result.json")
        self.assertTrue(result["passed"])
        self.assertEqual(result["config_id"], self.config_id)
        self.assertEqual(result["input_sha256"]["archive"], gate.hash_file(archive))
        scanner.write_bytes(b"tampered synthetic release")
        changed = list(args)
        changed[changed.index("--output") + 1] = str(self.repo / "rejected.json")
        with patch.object(gate, "TOOL_SHA256", scanner_sha):
            self.assertEqual(gate.main(changed), 1)
        self.assertEqual(gate.read_json(self.repo / "rejected.json")["error"],
                         "scanner_archive_hash")

    def layered_facts(self, changes):
        binary = b"\x7fELF\x02\x01" + b"synthetic compiled bytes"
        target = "/usr/lib/private/probe.so"
        condition = {"kind": "elf", "path": target, "class": 64,
                     "sha256": hashlib.sha256(binary).hexdigest()}
        layers = []
        initial = [("usr/lib/private/", "directory"), (target.lstrip("/"), "elf")]
        for entries in [initial, *changes]:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as inner:
                for name, kind in entries:
                    item = tarfile.TarInfo(name)
                    data = binary if kind == "elf" else b""
                    if kind == "directory":
                        item.type = tarfile.DIRTYPE
                    elif kind == "symlink":
                        item.type = tarfile.SYMTYPE
                        item.linkname = "/synthetic-elsewhere"
                    elif kind == "hardlink":
                        item.type = tarfile.LNKTYPE
                        item.linkname = "synthetic-elsewhere"
                    item.size = len(data)
                    inner.addfile(item, io.BytesIO(data) if data else None)
            layers.append(buffer.getvalue())
        archive = self.repo / "overlay-test.tar"
        names = [f"layer{n}.tar" for n in range(len(layers))]
        with tarfile.open(archive, mode="w") as outer:
            for name, data in [("manifest.json", json.dumps([{"Layers": names}]).encode()),
                               *zip(names, layers, strict=True)]:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                outer.addfile(item, io.BytesIO(data))
        return gate.archive_facts(archive, [condition]), condition

    def test_directory_whiteout_and_opaque_layer_invalidate_all_selected_elf_descendants(self):
        for deletion in ("usr/lib/.wh.private", "usr/lib/private/.wh..wh..opq"):
            with self.subTest(deletion=deletion):
                facts, condition = self.layered_facts([[(deletion, "file")]])
                self.assertFalse(gate.conditions_hold([condition], facts))
                self.assertIn(condition["path"], facts[0])  # historical absence is conservative

    def test_ancestor_symlink_hardlink_or_file_replacement_cannot_preserve_elf_proof(self):
        for replacement in ("symlink", "hardlink", "file"):
            with self.subTest(replacement=replacement):
                facts, condition = self.layered_facts([[("usr/lib/private", replacement)]])
                self.assertFalse(gate.conditions_hold([condition], facts))

    def test_three_layers_do_not_follow_symlink_ancestor_even_if_child_bytes_reappear(self):
        facts, condition = self.layered_facts([
            [("usr/lib/private", "symlink")], [("usr/lib/private/probe.so", "elf")]])
        self.assertFalse(gate.conditions_hold([condition], facts))
        facts, condition = self.layered_facts([
            [("usr/lib/private", "symlink")],
            [("usr/lib/private/", "directory"), ("usr/lib/private/probe.so", "elf")]])
        self.assertTrue(gate.conditions_hold([condition], facts))
