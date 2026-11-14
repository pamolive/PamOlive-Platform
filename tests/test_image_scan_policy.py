"""Synthetic policy tests: no scanner, network, Docker or real identities."""

import base64
import copy
import gzip
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
from tests import test_krb5_inventory as krbtest


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

    def test_archive_layer_manifest_duplicates_paths_and_layer_links_are_refused(self):
        archive = self.repo / "unsafe-outer.tar"
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w"):
            pass
        cases = [
            (b'[{"Layers":["layer.tar"],"Layers":["layer.tar"]}]', "regular"),
            (b'[{"Layers":["layer.tar","layer.tar"]}]', "regular"),
            (b'[{"Layers":["../layer.tar"]}]', "regular"),
            (b'[{"Layers":["layer.tar"]}]', "duplicate"),
            (b'[{"Layers":["layer.tar"]}]', "hardlink"),
            (b'[{"Layers":["layer.tar"]}]', "symlink"),
        ]
        for raw, kind in cases:
            with self.subTest(kind=kind, manifest=raw):
                with tarfile.open(archive, mode="w") as outer:
                    item = tarfile.TarInfo("manifest.json")
                    item.size = len(raw)
                    outer.addfile(item, io.BytesIO(raw))
                    for _ in range(2 if kind == "duplicate" else 1):
                        item = tarfile.TarInfo("layer.tar")
                        if kind in ("hardlink", "symlink"):
                            item.type = tarfile.LNKTYPE if kind == "hardlink" else tarfile.SYMTYPE
                            item.linkname = "manifest.json"
                            outer.addfile(item)
                        else:
                            item.size = len(layer.getvalue())
                            outer.addfile(item, io.BytesIO(layer.getvalue()))
                with self.assertRaises(gate.ScanPolicyError):
                    gate.archive_facts(archive, [])

    def test_outer_member_count_and_extended_headers_are_bounded_before_payload_read(self):
        archive = self.repo / "metadata-budget.tar"
        with tarfile.open(archive, mode="w") as outer:
            for number in range(2049):
                outer.addfile(tarfile.TarInfo(f"empty-{number}"))
        with self.assertRaisesRegex(gate.ScanPolicyError, "archive_metadata_budget"):
            gate.archive_facts(archive, [])
        for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            header = tarfile.TarInfo("extended-metadata")
            header.type, header.size = kind, 65537
            # No payload exists: rejection must precede any attempted payload read.
            archive.write_bytes(header.tobuf(format=tarfile.USTAR_FORMAT))
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    gate.ScanPolicyError, "archive_extended_metadata_budget"):
                gate.archive_facts(archive, [])
        with tarfile.open(archive, mode="w", format=tarfile.PAX_FORMAT) as outer:
            item = tarfile.TarInfo("sparse-file")
            raw = b"1000000000\n"
            item.size = len(raw)
            item.pax_headers = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
                                "GNU.sparse.name": "sparse-file", "GNU.sparse.realsize": "1"}
            outer.addfile(item, io.BytesIO(raw))
        with self.assertRaisesRegex(gate.ScanPolicyError, "archive_sparse_unsupported"):
            gate.archive_facts(archive, [])

    def test_configuration_diff_ids_bind_every_raw_or_gzip_layer_in_order(self):
        archive = self.repo / "layer-binding.tar"
        raw_layers = []
        for number in range(2):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as inner:
                item = tarfile.TarInfo(f"tmp/synthetic-{number}.txt")
                raw = f"synthetic layer {number}".encode()
                item.size = len(raw)
                inner.addfile(item, io.BytesIO(raw))
            raw_layers.append(buffer.getvalue())
        diff_ids = ["sha256:" + hashlib.sha256(raw).hexdigest() for raw in raw_layers]

        def write(*, declared=None, layers=None, rootfs_type="layers", omit_rootfs=False):
            config = {"architecture": "amd64", "os": "linux"}
            if not omit_rootfs:
                config["rootfs"] = {"type": rootfs_type,
                                    "diff_ids": diff_ids if declared is None else declared}
            files = [("manifest.json", b'[{"Config":"config.json",'
                      b'"Layers":["layer0.tar","layer1.tar"]}]'),
                     ("config.json", gate.canonical(config).encode()),
                     *[(f"layer{n}.tar", raw) for n, raw in enumerate(
                         raw_layers if layers is None else layers)]]
            with tarfile.open(archive, mode="w") as outer:
                for name, raw in files:
                    item = tarfile.TarInfo(name)
                    item.size = len(raw)
                    outer.addfile(item, io.BytesIO(raw))

        for layers in (raw_layers, [gzip.compress(raw, mtime=0) for raw in raw_layers]):
            write(layers=layers)
            facts = gate.archive_facts(archive, [])
            self.assertEqual(facts.layer_digests, diff_ids)
        cases = [{"declared": list(reversed(diff_ids))}, {"declared": diff_ids[:1]},
                 {"declared": [diff_ids[0], diff_ids[0]]},
                 {"declared": [diff_ids[0], "sha256:" + "0" * 64]},
                 {"rootfs_type": "unknown"}, {"omit_rootfs": True},
                 {"layers": list(reversed(raw_layers))},
                 {"layers": [raw_layers[0], raw_layers[1] + b"changed trailing padding"]},
                 {"layers": [raw_layers[0], gzip.compress(raw_layers[1])[:-8]]}]
        for changes in cases:
            write(**changes)
            with self.subTest(changes=list(changes)), self.assertRaises(
                    (gate.ScanPolicyError, EOFError, tarfile.TarError, OSError)):
                gate.archive_facts(archive, [])
        budget = [4 * 1024**3 - 1]
        with self.assertRaisesRegex(gate.ScanPolicyError, "layer_stream_budget"):
            gate.LayerReader(io.BytesIO(b"synthetic"), budget).read(8)

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
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w"):
            pass
        config["rootfs"] = {"type": "layers", "diff_ids": [
            "sha256:" + hashlib.sha256(layer.getvalue()).hexdigest()]}
        self.config = gate.canonical(config).encode()
        self.config_id = "sha256:" + hashlib.sha256(self.config).hexdigest()
        self.os["source"]["target"].update(imageID=self.config_id,
                                           config=base64.b64encode(self.config).decode())
        self.sbom["metadata"]["properties"][1]["value"] = self.config_id
        archive = bundle / gate.qualified_image.ARCHIVE
        config_name = self.config_id[7:] + ".json"
        manifest = [{"Config": config_name, "RepoTags": [gate.qualified_image.TAG],
                     "Layers": ["layer.tar"]}]
        with tarfile.open(archive, "w") as output:
            for name, data in (("manifest.json", json.dumps(manifest).encode()),
                               (config_name, self.config), ("layer.tar", layer.getvalue())):
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

    def layered_facts(self, changes, capture_set=False):
        binary = b"\x7fELF\x02\x01" + b"synthetic compiled bytes"
        target = "/usr/lib/private/probe.so"
        condition = {"kind": "elf", "path": target, "class": 64,
                     "sha256": hashlib.sha256(binary).hexdigest()}
        layers = []
        initial = [("usr/lib/private/", "directory"), (target.lstrip("/"), "elf")]
        if capture_set:
            initial.append(("usr/lib/anchor.so", "elf"))
        for entries in [initial, *changes]:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as inner:
                for name, kind in entries:
                    item = tarfile.TarInfo(name)
                    data = binary if kind in ("elf", "elf_changed") else b""
                    if kind == "elf_changed":
                        data += b"changed code"
                    if kind == "directory":
                        item.type = tarfile.DIRTYPE
                    elif kind in ("symlink", "symlink_changed"):
                        item.type = tarfile.SYMTYPE
                        item.linkname = ("/synthetic-elsewhere" if kind == "symlink"
                                         else "/new-target")
                    elif kind == "hardlink":
                        item.type = tarfile.LNKTYPE
                        item.linkname = ("usr/lib/anchor.so" if capture_set
                                         else "synthetic-elsewhere")
                    elif kind == "hardlink_probe":
                        item.type = tarfile.LNKTYPE
                        item.linkname = "usr/lib/private/probe.so"
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
        conditions = [condition, {"kind": "elf_set"}] if capture_set else [condition]
        return gate.archive_facts(archive, conditions), condition

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

    def add_backport(self):
        fixture = krbtest.Krb5InventoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        manifest = fixture.manifest()
        entry = self.add_exception()
        self.os["matches"] = [self.match("CVE-2026-119079", name="libkrb5-3",
            version=gate.krb5_inventory.VERSION, source="krb5")]
        key, finding = next(iter(gate.high_groups(self.os, "os").items()))
        entry.update(fingerprint=key, finding=finding, disposition="fixed_by_backport")
        path = self.repo / "docs/backport.json"
        path.write_bytes((gate.krb5_inventory.canonical(manifest) + "\n").encode())
        proof = {"path": "docs/backport.json", "sha256": gate.hash_file(path)}
        entry["local_evidence"].append(proof)
        entry["backport_inventory"] = proof
        entry["conditions"] = gate.krb5_inventory.archive_conditions(manifest)
        facts = (set(), {item["path"]: {"sha256": item["sha256"],
                         "class": item.get("class")} for item in entry["conditions"]})
        return entry, facts

    def test_backport_has_distinct_disposition_and_exact_archive_proofs(self):
        entry, facts = self.add_backport()
        result = self.evaluate(facts)
        self.assertTrue(result["passed"])
        self.assertFalse(result["all_findings_clear"])
        self.assertEqual(result["decisions"][0]["disposition"], "fixed_by_backport")
        entry["conditions"].pop()
        with self.assertRaisesRegex(gate.ScanPolicyError, "backport_archive_binding"):
            self.evaluate(facts)

    def test_backport_changed_elf_or_provenance_in_archive_cannot_pass(self):
        entry, facts = self.add_backport()
        for condition in entry["conditions"]:
            changed = copy.deepcopy(facts)
            changed[1][condition["path"]]["sha256"] = "0" * 64
            with self.subTest(path=condition["path"]):
                self.assertFalse(self.evaluate(changed)["passed"])

    def test_backport_cannot_cover_different_cve_source_or_package_version(self):
        entry, facts = self.add_backport()
        original = copy.deepcopy(entry["finding"])
        for key, value in (("vulnerability_id", "CVE-2026-107778"),
                           ("source_package", "gcc-14"), ("scope", "compiled")):
            finding = {**original, key: value}
            changed = {**entry, "finding": finding, "fingerprint": gate.fingerprint(finding)}
            with self.subTest(key=key), self.assertRaisesRegex(
                    gate.ScanPolicyError, "backport_finding_scope"):
                gate.reviewed_exception(changed, finding, facts=facts, repo=self.repo, now=self.now)

    def test_file_sha256_conditions_do_not_follow_overlay_symlinks(self):
        facts, elf = self.layered_facts([[("usr/lib/private", "symlink")]])
        condition = {"kind": "file_sha256", "path": elf["path"], "sha256": elf["sha256"]}
        self.assertFalse(gate.conditions_hold([condition], facts))

    def test_elf_set_changes_on_addition_removal_modification_whiteout_or_opaque(self):
        original, _ = self.layered_facts([], capture_set=True)
        condition = {"kind": "elf_set", **original.elf_set}
        self.assertTrue(gate.conditions_hold([condition], original))
        mutations = [[("usr/lib/new.so", "elf")], [("usr/lib/private/probe.so", "elf_changed")],
                     [("usr/lib/private/.wh.probe.so", "file")],
                     [("usr/lib/private/.wh..wh..opq", "file")]]
        for change in mutations:
            with self.subTest(change=change):
                facts, _ = self.layered_facts([change], capture_set=True)
                self.assertFalse(gate.conditions_hold([condition], facts))

    def test_elf_set_counts_all_symlink_hardlink_aliases_and_refuses_ancestor_writes(self):
        summaries = []
        for kind in ("symlink", "symlink_changed", "hardlink"):
            facts, _ = self.layered_facts([[("usr/lib/alias.so", kind)]], capture_set=True)
            self.assertEqual(facts.elf_set["alias_count"], 1)
            summaries.append(facts.elf_set["sha256"])
        self.assertEqual(len(set(summaries)), 3)
        for ancestor in ("symlink", "hardlink", "file"):
            with self.subTest(ancestor=ancestor), self.assertRaisesRegex(
                    gate.ScanPolicyError, "elf_set_ambiguous_ancestor"):
                self.layered_facts([[("usr/lib/private", ancestor)],
                                   [("usr/lib/private/hidden.so", "elf")]], capture_set=True)
        restored, _ = self.layered_facts([[("usr/lib/private", "symlink")],
            [("usr/lib/private", "directory"), ("usr/lib/private/probe.so", "elf")]],
            capture_set=True)
        initial, _ = self.layered_facts([], capture_set=True)
        self.assertEqual(restored.elf_set, initial.elf_set)

    def test_opaque_and_whiteout_hide_lower_layers_not_new_files_from_same_layer(self):
        for whiteout in ("usr/lib/private/.wh..wh..opq", "usr/lib/private/.wh.probe.so"):
            with self.subTest(whiteout=whiteout):
                before, _ = self.layered_facts([[(whiteout, "file"),
                    ("usr/lib/private/probe.so", "elf_changed")]], capture_set=True)
                after, _ = self.layered_facts([[('usr/lib/private/probe.so', "elf_changed"),
                                              (whiteout, "file")]], capture_set=True)
                self.assertEqual(before.elf_set, after.elf_set)
                self.assertEqual(before[1], after[1])

    def test_hardlink_content_remains_bound_after_original_path_is_whiteouted(self):
        # Both final names/alias targets are the same, but the surviving inode
        # contains different bytes. A target-string-only sentinel would miss it.
        baseline, _ = self.layered_facts([
            [("usr/lib/survivor.so", "hardlink_probe")],
            [("usr/lib/private/.wh.probe.so", "file")]], capture_set=True)
        changed, _ = self.layered_facts([
            [("usr/lib/private/probe.so", "elf_changed"),
             ("usr/lib/survivor.so", "hardlink_probe")],
            [("usr/lib/private/.wh.probe.so", "file")]], capture_set=True)
        self.assertEqual(baseline.elf_set["count"], changed.elf_set["count"])
        self.assertEqual(baseline.elf_set["alias_count"], changed.elf_set["alias_count"])
        self.assertNotEqual(baseline.elf_set["sha256"], changed.elf_set["sha256"])

    def test_overwriting_a_live_hardlink_group_is_refused_not_guessed(self):
        with self.assertRaisesRegex(gate.ScanPolicyError, "elf_set_hardlink_replacement"):
            self.layered_facts([[("usr/lib/survivor.so", "hardlink_probe")],
                [("usr/lib/private/probe.so", "elf_changed")]], capture_set=True)

    def test_new_hardlink_cannot_read_lower_target_masked_in_same_layer_in_either_order(self):
        for whiteout in ("usr/lib/private/.wh..wh..opq", "usr/lib/private/.wh.probe.so"):
            link = ("usr/lib/survivor.so", "hardlink_probe")
            for changes in ([link, (whiteout, "file")], [(whiteout, "file"), link]):
                with self.subTest(whiteout=whiteout, order=changes), self.assertRaisesRegex(
                        gate.ScanPolicyError, "elf_set_hardlink_(whiteout|target)"):
                    self.layered_facts([changes], capture_set=True)

    def test_new_hardlink_lower_dependency_cannot_be_hidden_by_ancestor_replacement(self):
        for path, kind in (("usr/lib/private", "file"), ("usr/lib/private", "symlink"),
                           ("usr/lib/private/probe.so", "directory")):
            with self.subTest(path=path, kind=kind), self.assertRaisesRegex(
                    gate.ScanPolicyError, "elf_set_hardlink_replacement"):
                self.layered_facts([[('usr/lib/survivor.so', "hardlink_probe"),
                                     (path, kind)]], capture_set=True)

    def test_new_hardlink_to_new_same_layer_file_survives_lower_whiteout_order(self):
        for whiteout in ("usr/lib/private/.wh..wh..opq", "usr/lib/private/.wh.probe.so"):
            creation = [("usr/lib/private/probe.so", "elf_changed"),
                        ("usr/lib/survivor.so", "hardlink_probe")]
            before, _ = self.layered_facts([[(whiteout, "file"), *creation]], capture_set=True)
            after, _ = self.layered_facts([[*creation, (whiteout, "file")]], capture_set=True)
            self.assertEqual(before.elf_set, after.elf_set)

    def test_elf_set_conditions_are_typed_without_wildcards_or_missing_capture(self):
        facts, _ = self.layered_facts([], capture_set=True)
        original = {"kind": "elf_set", **facts.elf_set}
        for change in ({"count": 5001}, {"alias_count": -1}, {"sha256": "*"},
                       {"schema": "unknown"}, {"roots": ["/opt/*"]}, {"count": True}):
            with self.subTest(change=change), self.assertRaises(gate.ScanPolicyError):
                gate.conditions_hold([{**original, **change}], facts)
        self.assertFalse(gate.conditions_hold([original], (set(), {})))
        with self.assertRaisesRegex(gate.ScanPolicyError, "elf_set_count"):
            gate.elf_set_summary({str(i): {} for i in range(5001)})

    def add_gcc(self, disposition):
        entry = self.add_exception()
        cve = "CVE-2026-95619" if disposition == "not_affected_build" else "CVE-2026-102010"
        self.os["matches"] = [self.match(cve, name=name, version=gate.GCC_VERSION,
                                          source="gcc-14") for name in sorted(gate.GCC_PACKAGES)]
        key, finding = next(iter(gate.high_groups(self.os, "os").items()))
        entry.update(fingerprint=key, finding=finding, disposition=disposition)
        primary = "https://github.com/gcc-mirror/gcc/commit/" + gate.GCC_COMMITS[disposition]
        entry["vendor_evidence"].append(primary)
        evidence = {"schema": "pamolive.gcc-finding-evidence.v1",
                    "source_version": gate.GCC_VERSION,
                    "vulnerability_id": cve, "upstream_commit": gate.GCC_COMMITS[disposition]}
        sentinel = None
        if disposition == "not_affected_build":
            evidence.update(justification="posix_memalign_implementation", platform="linux/amd64",
                function={"name": "_ZnwmSt11align_val_t", "size": 125,
                          "allocation_backend": "posix_memalign"},
                library={"path": gate.GCC_LIBRARY, "class": 64, "sha256": gate.GCC_LIBRARY_SHA})
        else:
            sentinel = {"schema": gate.ELF_SET_SCHEMA, "count": 27, "elf_count": 27,
                        "alias_count": 0, "sha256": "1" * 64}
            evidence.update(justification="gnu_pbds_binary_heap_erase_if_not_instantiated",
                template="__gnu_pbds::priority_queue<binary_heap_tag>::erase_if",
                sources=copy.deepcopy(gate.GCC_SOURCES), reviewed_files=7112, affected_type_uses=0,
                consumers=[{"path": f"/usr/lib/{name}-{i}.so", "class": 64,
                            "sha256": "2" * 64, "source_package": name}
                           for name, count in (("icu", 6), ("apt", 20), ("harfbuzz", 1))
                           for i in range(count)], elf_set=sentinel)
        path = self.repo / "docs/gcc-evidence.json"
        path.write_bytes((gate.canonical(evidence) + "\n").encode())
        proof = {"path": "docs/gcc-evidence.json", "sha256": gate.hash_file(path)}
        entry["local_evidence"].append(proof)
        entry["gcc_evidence"] = proof
        entry["conditions"] = gate.gcc_conditions(entry, finding,
                                                  proofs=entry["local_evidence"], repo=self.repo)
        files = {item["path"]: {"sha256": item["sha256"], "class": item["class"]}
                 for item in entry["conditions"] if item["kind"] == "elf"}
        return entry, gate.ArchiveFacts(set(), files, sentinel)

    def test_two_gcc_dispositions_preserve_visible_high_findings_and_distinct_justification(self):
        for disposition in ("not_affected_build", "code_not_present"):
            with self.subTest(disposition=disposition):
                entry, facts = self.add_gcc(disposition)
                result = self.evaluate(facts)
                self.assertTrue(result["passed"])
                self.assertFalse(result["all_findings_clear"])
                self.assertEqual(result["decisions"][0]["disposition"], disposition)
                entry["conditions"].pop()
                with self.assertRaisesRegex(gate.ScanPolicyError, "gcc_archive_binding"):
                    self.evaluate(facts)

    def test_gcc_dispositions_cannot_spread_to_another_cve_source_scope_or_version(self):
        for disposition in ("not_affected_build", "code_not_present"):
            entry, facts = self.add_gcc(disposition)
            for key, value in (("source_package", "krb5"), ("scope", "compiled"),
                               ("vulnerability_id", "CVE-2026-123456")):
                finding = {**entry["finding"], key: value}
                changed = {**entry, "finding": finding, "fingerprint": gate.fingerprint(finding)}
                with self.subTest(disposition=disposition, key=key), self.assertRaisesRegex(
                        gate.ScanPolicyError, "gcc_finding_scope"):
                    gate.reviewed_exception(changed, finding, facts=facts,
                                            repo=self.repo, now=self.now)
            finding = copy.deepcopy(entry["finding"])
            finding["packages"][0]["version"] = "14.2.0-20"
            changed = {**entry, "finding": finding, "fingerprint": gate.fingerprint(finding)}
            with self.assertRaisesRegex(gate.ScanPolicyError, "gcc_finding_scope"):
                gate.reviewed_exception(changed, finding, facts=facts, repo=self.repo, now=self.now)
            finding = copy.deepcopy(entry["finding"])
            finding["packages"][0]["name"] = "unexpected-gcc-package"
            changed = {**entry, "finding": finding, "fingerprint": gate.fingerprint(finding)}
            with self.assertRaisesRegex(gate.ScanPolicyError, "gcc_finding_scope"):
                gate.reviewed_exception(changed, finding, facts=facts, repo=self.repo, now=self.now)

    def test_gcc_expired_or_future_review_wrong_bytes_or_new_elf_set_blocks(self):
        for disposition in ("not_affected_build", "code_not_present"):
            entry, facts = self.add_gcc(disposition)
            original = copy.deepcopy(entry)
            for field, value in (("reviewed_at", (self.now + timedelta(days=1)).isoformat()),
                                  ("expires", (self.now - timedelta(seconds=1)).isoformat())):
                self.policy["findings"] = [{**original, field: value}]
                with self.assertRaisesRegex(gate.ScanPolicyError, "review_expired"):
                    self.evaluate(facts)
            self.policy["findings"] = [original]
            changed = copy.deepcopy(facts)
            changed[1][next(iter(changed[1]))]["sha256"] = "0" * 64
            self.assertFalse(self.evaluate(changed)["passed"])
            if disposition == "code_not_present":
                changed = gate.ArchiveFacts(facts[0], facts[1],
                                            {**facts.elf_set, "sha256": "3" * 64})
                self.assertFalse(self.evaluate(changed)["passed"])

    def test_gcc_typed_source_and_build_evidence_cannot_be_replaced_by_generic_claims(self):
        for disposition in ("not_affected_build", "code_not_present"):
            entry, facts = self.add_gcc(disposition)
            path = self.repo / entry["gcc_evidence"]["path"]
            value = json.loads(path.read_text())
            if disposition == "not_affected_build":
                value["function"]["allocation_backend"] = "aligned_alloc"
            else:
                # A malicious kind key must not override the mandatory sentinel.
                value["elf_set"]["kind"] = "file_sha256"
            path.write_text(gate.canonical(value))
            entry["gcc_evidence"]["sha256"] = gate.hash_file(path)
            with self.assertRaisesRegex(gate.ScanPolicyError, "gcc_(build_proof|elf_set_missing)"):
                self.evaluate(facts)
