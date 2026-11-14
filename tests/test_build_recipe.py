"""Synthetic tracked sources and TAR bytes; no image, network or ELF execution."""

import base64
import copy
import io
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from deploy import build_recipe as recipe
from deploy import qualify_image_scan as gate
from tests import test_image_scan_policy as policytest
from tests import test_krb5_inventory as krbtest


class RecipeFixture(TestCase):
    def setUp(self):
        super().setUp()
        self.fixture = krbtest.Krb5InventoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.add_capability_skip()
        self.append_log(b"destest: 171 tests passed successfully\n"
                        b"create-stamp debian/debhelper-build-stamp\n"
                        b"dpkg-buildpackage: info: binary-only upload (no source included)\n")
        self.temp = tempfile.TemporaryDirectory(prefix="pamolive-recipe-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()
        self.git("init", "-q")
        sources = {"Dockerfile": b"Synthetic Dockerfile\n", ".dockerignore": b"\n",
                   ".gitignore": b"\n", "platform_core/app.py": b"SYNTHETIC = True\n",
                   ".github/workflows/ci.yml": b"name: synthetic\n"}
        outputs = self.fixture.provenance["test_outputs"]
        for name, path in {"upstream.patch": "deploy/krb5-asn1-sequence.patch",
            outputs["harness"]: "tests/fixtures/krb5_asn1_regression.c",
            outputs["wrapper"]: "deploy/check_krb5_asn1.sh",
            "test-keyring-compat.patch": "deploy/krb5-test-keyring-seccomp.patch"}.items():
            sources[path] = (self.fixture.folder / name).read_bytes()
        for name, data in sources.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.git("add", ".")
        manifest = self.fixture.manifest()
        self.elf_entries = [{"path": item["path"], "type": "elf", "class": 64,
                             "machine": 62, "sha256": item["sha256"]}
                            for item in manifest["libraries"]]
        self.recipe = recipe.capture(self.repo, backport_manifest=manifest,
                                     elf_entries=self.elf_entries)
        self.config = b'{"synthetic":true}'
        self.archive = self.repo.parent / (self.repo.name + ".tar")
        self.addCleanup(self.archive.unlink, missing_ok=True)

    def git(self, *args):
        result = subprocess.run(["git", "-c", "safe.directory=" + self.repo.as_posix(),
                                 "-C", str(self.repo), *args], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, "Synthetic Git operation failed")

    def append_log(self, data):
        for name in ("baseline-build.log", "debian-build.log"):
            path = self.fixture.folder / name
            self.fixture.write(name, path.read_bytes() + data)
            self.fixture.provenance["evidence"][name] = recipe.sha(path.read_bytes())
        path = self.fixture.folder / "debian-tests.json"
        tests = json.loads(path.read_bytes())
        tests["log_sha256"] = self.fixture.provenance["evidence"]["debian-build.log"]
        self.fixture.write("debian-tests.json", tests)
        self.fixture.provenance["evidence"]["debian-tests.json"] = recipe.sha(path.read_bytes())
        self.fixture.write("provenance.json", self.fixture.provenance)

    def archive_files(self):
        manifest = self.fixture.manifest()
        result = {str(path.relative_to(self.fixture.root)).replace("\\", "/"): path.read_bytes()
                  for path in self.fixture.root.rglob("*") if path.is_file()}
        result[gate.krb5_inventory.MANIFEST_PATH.lstrip("/")] = (
            gate.krb5_inventory.canonical(manifest) + "\n").encode()
        for name in self.recipe["files"]:
            if name.startswith(("deploy/", "tests/", "platform_core/")):
                result["app/" + name] = (self.repo / name).read_bytes()
        return result

    def write_archive(self, *, extra=None, remove=(), config=None):
        files = self.archive_files()
        for name in remove:
            files.pop(name, None)
        files.update(extra or {})
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as stream:
            for name, raw in sorted(files.items()):
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                stream.addfile(item, io.BytesIO(raw))
        config_value = json.loads(self.config if config is None else config)
        config_value.update(os="linux", architecture="amd64", rootfs={"type": "layers",
            "diff_ids": ["sha256:" + recipe.sha(layer.getvalue())]})
        config_bytes = recipe.canonical(config_value).encode()
        if config is None:
            self.config = config_bytes
        with tarfile.open(self.archive, mode="w") as stream:
            manifest = b'[{"Config":"config.json","Layers":["layer.tar"]}]'
            for name, raw in (("manifest.json", manifest),
                              ("config.json", config_bytes),
                              ("layer.tar", layer.getvalue())):
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                stream.addfile(item, io.BytesIO(raw))
        return self.archive


class BuildRecipeTests(RecipeFixture):
    def test_tracked_sources_and_per_artifact_proofs_verify_without_crypto_claim(self):
        checked = recipe.verify(self.recipe, self.repo)
        self.assertTrue(checked["verified"])
        self.assertFalse(checked["cryptographic_attestation_verified"])
        facts, report = gate.verify_archive_backport(self.write_archive(), self.recipe, self.repo)
        self.assertTrue(report["verified"])
        self.assertEqual(len(report["conditions"]), 26)
        self.assertFalse(report["cryptographic_build_attestation_verified"])
        self.assertFalse(report["compilation_proof"])
        self.assertTrue(gate.elf_delta(self.recipe, facts))

    def test_new_removed_changed_tracked_source_and_workflow_fail(self):
        path = self.repo / "platform_core/app.py"
        for name in ("platform_core/new.py", ".github/workflows/new.yml"):
            target = self.repo / name
            target.write_text("synthetic newly tracked source")
            self.git("add", name)
            with self.assertRaisesRegex(recipe.RecipeError, "recipe_source_changed"):
                recipe.verify(self.recipe, self.repo)
            self.git("rm", "--cached", name)
            target.unlink()
        original = path.read_bytes()
        path.write_bytes(original + b"# changed\n")
        with self.assertRaisesRegex(recipe.RecipeError, "recipe_source_changed"):
            recipe.verify(self.recipe, self.repo)
        path.unlink()
        with self.assertRaisesRegex(recipe.RecipeError, "recipe_source_file"):
            recipe.verify(self.recipe, self.repo)

    def test_untracked_future_work_is_not_read_but_runtime_injection_fails(self):
        private = self.repo / "future-private.py"
        private.write_bytes(b"synthetic untracked work")
        self.assertTrue(recipe.verify(self.recipe, self.repo)["verified"])
        with self.assertRaisesRegex(gate.ScanPolicyError, "source_archive_changed"):
            gate.verify_archive_backport(self.write_archive(extra={
                "app/platform_core/unknown.py": b"synthetic injected code"}),
                self.recipe, self.repo)

    def test_source_in_image_must_equal_recipe_even_if_checkout_is_unchanged(self):
        with self.assertRaisesRegex(gate.ScanPolicyError, "source_archive_changed"):
            gate.verify_archive_backport(self.write_archive(extra={
                "app/platform_core/app.py": b"different ctypes caller"}), self.recipe, self.repo)

    def test_only_exact_external_nonruntime_metadata_can_be_excluded(self):
        for path in ("platform_core/app.py", ".github/workflows/ci.yml",
                     ".github/qualification/evidence/tool.py", "../outside.json"):
            with self.subTest(path=path), self.assertRaises(recipe.RecipeError):
                recipe.exclusions([path])
        self.assertIn(".secrets.baseline", recipe.exclusions())
        self.assertIn(".github/qualification/evidence/decision.json", recipe.exclusions([
            ".github/qualification/evidence/decision.json"]))

    def test_private_diagnostic_cannot_become_a_tracked_exclusion(self):
        for name in sorted(recipe.FORBIDDEN_TRACKED):
            path = self.repo / name
            path.write_bytes(b"synthetic private diagnostic")
            self.git("add", str(path))
            with self.assertRaisesRegex(recipe.RecipeError, "recipe_private_diagnostic_tracked"):
                recipe.verify(self.recipe, self.repo)
            self.git("rm", "--cached", str(path))

    def test_git_symlink_mode_is_refused_even_on_a_windows_regular_worktree_file(self):
        name = "platform_core/app.py"
        blob = recipe.sha((self.repo / name).read_bytes())
        # Ask Git for its blob ID (SHA1 by default); do not rely on host symlink privileges.
        result = subprocess.run(["git", "-c", "safe.directory=" + self.repo.as_posix(),
            "-C", str(self.repo), "hash-object", "-w", name], capture_output=True, check=True)
        self.assertNotEqual(result.stdout.decode().strip(), blob)
        self.git("update-index", "--cacheinfo",
                 "120000," + result.stdout.decode().strip() + "," + name)
        with self.assertRaisesRegex(recipe.RecipeError, "recipe_git_file_mode"):
            recipe.verify(self.recipe, self.repo)

    def test_fixed_keyring_probe_and_typed_baseline_cannot_be_removed(self):
        for name in (self.recipe["backport"]["apt_chain"]["keyring_file"], "keyctl-probe.py"):
            changed = copy.deepcopy(self.recipe)
            changed["backport"]["fixed_evidence"].pop(name)
            with self.subTest(name=name), self.assertRaisesRegex(
                    recipe.RecipeError, "recipe_fixed_evidence"):
                recipe.validate(changed)
        changed = copy.deepcopy(self.recipe)
        changed["backport"]["baseline"]["libraries"][0]["exported_symbols"] = True
        with self.assertRaisesRegex(recipe.RecipeError, "recipe_baseline"):
            recipe.validate(changed)

    def test_legitimate_log_variation_binds_new_manifest_not_old_output_hash(self):
        _, before = gate.verify_archive_backport(self.write_archive(), self.recipe, self.repo)
        self.append_log(b"Synthetic build time 2026-11-12T11:12:13Z duration 1.25 seconds\n")
        _, after = gate.verify_archive_backport(self.write_archive(), self.recipe, self.repo)
        self.assertNotEqual(before["manifest_sha256"], after["manifest_sha256"])
        self.assertEqual(before["libraries"], after["libraries"])
        self.assertEqual(before["recipe_content_sha256"], after["recipe_content_sha256"])

    def test_changed_log_without_updated_links_and_failed_or_incomplete_log_refuse(self):
        name = gate.krb5_inventory.PREFIX.lstrip("/") + "/debian-build.log"
        with self.assertRaisesRegex(gate.ScanPolicyError, "backport_evidence_changed"):
            gate.verify_archive_backport(self.write_archive(extra={name: b"tampered"}),
                                        self.recipe, self.repo)
        self.append_log(b"FAIL: synthetic test failed\n")
        with self.assertRaisesRegex(gate.ScanPolicyError, "backport_log_failure"):
            gate.verify_archive_backport(self.write_archive(), self.recipe, self.repo)

    def test_changed_source_abi_baseline_recipe_and_patch_fail(self):
        changed = copy.deepcopy(self.recipe)
        changed["backport"]["baseline"]["libraries"][0]["abi_sha256"] = "0" * 64
        with self.assertRaisesRegex(gate.ScanPolicyError, "backport_recipe_changed"):
            gate.verify_archive_backport(self.write_archive(), changed, self.repo)
        changed = copy.deepcopy(self.recipe)
        changed["backport"]["fixed_evidence"]["upstream.patch"] = "0" * 64
        with self.assertRaisesRegex(recipe.RecipeError, "recipe_fixed_evidence"):
            recipe.validate(changed)

    def test_only_four_verified_c_hashes_can_change_no_paths_or_aliases(self):
        self.fixture.install(gate.krb5_inventory.VERSION, tail=b"new synthetic C build bytes")
        facts, _ = gate.verify_archive_backport(self.write_archive(), self.recipe, self.repo)
        self.assertTrue(gate.elf_delta(self.recipe, facts))
        for mutate in (lambda e: e.update({"/usr/lib/new.so": next(iter(e.values()))}),
                       lambda e: e.pop(next(iter(e))),
                       lambda e: e[next(iter(e))].update(type="hardlink", target="other")):
            changed = copy.deepcopy(facts)
            mutate(changed.entries)
            with self.assertRaises(gate.ScanPolicyError):
                gate.elf_delta(self.recipe, changed)

    def test_generated_assets_are_exact_known_client_bytes_not_a_prefix_exclusion(self):
        name = "/app/staticfiles/app.js"
        data = b"/* synthetic client code */"
        self.recipe["generated_assets"] = {name: recipe.sha(data)}
        _, report = gate.verify_archive_backport(self.write_archive(extra={name[1:]: data}),
                                                self.recipe, self.repo)
        self.assertEqual(report["source_coverage"]["generated_assets"], {name: recipe.sha(data)})
        for extra in ({name[1:]: data + b"changed"}, {name[1:]: data,
                      "app/staticfiles/new.js": b"new client script"}):
            with self.assertRaisesRegex(gate.ScanPolicyError, "source_archive_changed"):
                gate.verify_archive_backport(self.write_archive(extra=extra),
                                            self.recipe, self.repo)
        for path in ("/app/staticfiles/server.py", "/app/staticfiles/a.so",
                     "/app/staticfiles/template.html", "/app/staticfiles/../a.js",
                     "/app/staticfiles/shell.sh.gz", "/app/staticfiles/a.pth",
                     "/app/staticfiles/a.js.map", "/app/staticfiles/a.png"):
            with self.subTest(path=path), self.assertRaises(recipe.RecipeError):
                recipe.generated_assets({path: "a" * 64})

    def test_archive_two_pass_mutation_and_current_abi_tampering_fail(self):
        archive = self.write_archive()
        original = gate.archive_facts
        calls = []

        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(True)
            if len(calls) == 1:
                with archive.open("ab") as stream:
                    stream.write(b"synthetic post-read substitution")
            return result

        with patch.object(gate, "archive_facts", side_effect=changed), self.assertRaisesRegex(
                gate.ScanPolicyError, "backport_archive_changed"):
            gate.verify_archive_backport(archive, self.recipe, self.repo)
        item = self.fixture.manifest()["libraries"][0]
        raw = (self.fixture.root / item["path"].lstrip("/")).read_bytes()
        with self.assertRaises(ValueError):
            gate.verify_archive_backport(self.write_archive(extra={
                item["path"].lstrip("/"): raw.replace(b"synthetic_export", b"different_export")}),
                self.recipe, self.repo)

    def test_recipe_cli_capture_verify_and_archive_do_not_approve_a_build(self):
        manifest = self.repo / "manifest.json"
        manifest.write_text(recipe.canonical(self.fixture.manifest()), encoding="utf8")
        entries = self.repo / "entries.json"
        entries.write_text(recipe.canonical(self.elf_entries), encoding="utf8")
        candidate = self.repo / "candidate.json"
        self.assertEqual(recipe.main(["capture", "--root", str(self.repo),
            "--backport-manifest", str(manifest), "--elf-reference", str(entries),
            "--external-evidence", ".github/qualification/evidence/test.json",
            "--output", str(candidate)]), 0)
        for operation, extra in (("verify", []), ("verify-archive", [
                "--archive", str(self.write_archive())])):
            output = self.repo / (operation + ".json")
            self.assertEqual(recipe.main([operation, "--root", str(self.repo), "--recipe",
                str(candidate), "--output", str(output), *extra]), 0)
            report = recipe.read_json(output)
            self.assertTrue(report["verified"])
            self.assertFalse(report["build_verified"])

    def test_recipe_policy_result_binds_archive_and_rejects_other_image_config(self):
        fixture = policytest.ImageScanPolicyTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.repo = self.repo
        (self.repo / "docs").mkdir(exist_ok=True)
        entry = fixture.add_exception()
        fixture.os["matches"] = [fixture.match("CVE-2026-119079", name="libkrb5-3",
            source="krb5", version=gate.krb5_inventory.VERSION)]
        key, finding = next(iter(gate.high_groups(fixture.os, "os").items()))
        entry.update(fingerprint=key, finding=finding, disposition="fixed_by_backport")
        folder = self.repo / ".github/qualification"
        folder.mkdir(parents=True)
        path = folder / "build-recipe.v1.json"
        path.write_text(recipe.canonical(self.recipe), encoding="utf8")
        proof = {"path": ".github/qualification/build-recipe.v1.json",
                 "sha256": gate.hash_file(path)}
        entry.update(build_recipe=proof,
                     conditions=[{"kind": "backport_recipe", "sha256": proof["sha256"]}])
        entry["local_evidence"].append(proof)

        def evaluate():
            return gate.qualify(fixture.os, fixture.compiled, fixture.positive, fixture.sbom,
                fixture.policy, config_id=fixture.config_id, config_bytes=fixture.config,
                facts=(set(), {}), repo=self.repo, now=fixture.now, archive=self.archive)

        self.write_archive()
        fixture.config = self.config
        fixture.config_id = "sha256:" + recipe.sha(self.config)
        fixture.os["source"]["target"].update(imageID=fixture.config_id,
            config=base64.b64encode(fixture.config).decode())
        fixture.sbom["metadata"]["properties"][1]["value"] = fixture.config_id
        report = evaluate()
        self.assertTrue(report["passed"])
        self.assertFalse(report["all_findings_clear"])
        self.assertFalse(report["build_verified"])
        self.assertEqual(report["artifact_qualifications"][0]["archive_sha256"],
                         gate.hash_file(self.archive))
        self.write_archive(config=b'{"synthetic":"other image"}')
        with self.assertRaisesRegex(gate.ScanPolicyError, "recipe_image_config_changed"):
            evaluate()

    def test_gcc_recipe_keeps_27_real_current_consumer_hashes_and_only_four_c_deltas(self):
        fixture = policytest.ImageScanPolicyTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.repo = self.repo
        (self.repo / "docs").mkdir(exist_ok=True)
        entry, _ = fixture.add_gcc("code_not_present")
        evidence_path = self.repo / entry["gcc_evidence"]["path"]
        evidence = json.loads(evidence_path.read_bytes())
        extra = {}
        for consumer in evidence["consumers"]:
            raw = krbtest.synthetic_elf("libsynthetic.so", tail=consumer["path"].encode())
            consumer["sha256"] = recipe.sha(raw)
            extra[consumer["path"].lstrip("/")] = raw
            self.recipe["elf_reference"].append({"path": consumer["path"], "type": "elf",
                "sha256": recipe.sha(raw), "class": 64, "machine": 62})
        self.recipe["elf_reference"].sort(key=lambda row: row["path"])
        evidence["elf_set"] = gate.elf_set_summary({row["path"]: row
                                                    for row in self.recipe["elf_reference"]})
        evidence_path.write_text(recipe.canonical(evidence), encoding="utf8")
        entry["gcc_evidence"]["sha256"] = gate.hash_file(evidence_path)
        path = self.repo / ".github/qualification/build-recipe.v1.json"
        path.parent.mkdir(parents=True)
        path.write_text(recipe.canonical(self.recipe), encoding="utf8")
        proof = {"path": ".github/qualification/build-recipe.v1.json",
                 "sha256": gate.hash_file(path)}
        entry["build_recipe"] = proof
        entry["local_evidence"].append(proof)
        entry["conditions"] = gate.gcc_conditions(entry, entry["finding"],
            proofs=entry["local_evidence"], repo=self.repo)

        def evaluate():
            return gate.reviewed_exception(entry, entry["finding"], facts=(set(), {}),
                repo=self.repo, now=fixture.now, archive=self.archive)

        self.write_archive(extra=extra)
        self.assertTrue(evaluate())
        self.fixture.install(gate.krb5_inventory.VERSION, tail=b"another honest C build")
        self.write_archive(extra=extra)
        self.assertTrue(evaluate())
        first = next(iter(extra))
        self.write_archive(extra={**extra, first: extra[first] + b"changed C++ consumer"})
        with self.assertRaisesRegex(gate.ScanPolicyError, "gcc_delta_unreviewed_change"):
            evaluate()
        self.write_archive(extra={**extra, "usr/lib/unknown-extension.so": extra[first]})
        with self.assertRaisesRegex(gate.ScanPolicyError, "gcc_delta_paths"):
            evaluate()

    def test_duplicate_recipe_json_and_existing_output_refuse(self):
        path = self.repo / "duplicate.json"
        path.write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaises(gate.krb5_inventory.Krb5Error):
            recipe.read_json(path)
        original = path.read_bytes()
        self.assertEqual(recipe.main(["verify", "--root", str(self.repo), "--recipe", "missing",
                                      "--output", str(path)]), 1)
        self.assertEqual(path.read_bytes(), original)
