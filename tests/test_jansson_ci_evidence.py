"""Synthetic DATA and actual consumers; no Docker, native oracle or compiler."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from deploy import jansson_ci_evidence as receive
from deploy import jansson_oracle_identity as identity
from deploy import qualified_image
from deploy import qualify_image_scan as gate
from tests import test_jansson_image_absence as absence_fixture
from tests.test_native_inventory import elf


def raw(value):
    return (json.dumps(value) + "\n").encode()


def oracle_buffers():
    rows = [
        {"case": i, "cjson": True, "jansson_default": False, "winpr_guarded": i in {0, 9}}
        for i in range(15)
    ]
    rows += [
        {"case": "embedded_NUL", "cjson": True, "winpr_guarded": False},
        {"case": "depth64", "cjson": True, "winpr_guarded": True},
        {"case": "depth4096", "winpr_guarded_rejected": True},
    ]
    native = raw(
        {
            "schema": "pamolive.winpr-jansson-regression.v1",
            "passed": True,
            "backend": "jansson 2.14",
            "network": False,
        }
    )
    return {
        "json-reference.jsonl": b"".join(raw(row) for row in rows),
        "winpr-jansson-build.json": native,
        "winpr-jansson-runtime.json": native,
    }


def identity_buffers(buffers, provider):
    result = {}
    for case, name in (
        ("build", "winpr-jansson-build.json"),
        ("runtime", "winpr-jansson-runtime.json"),
        ("reference", "json-reference.jsonl"),
    ):
        result[case + "-identity.json"] = raw(
            {
                "schema": "pamolive.jansson-oracle-identity/1",
                "case": case,
                "provider_files": provider,
                "jansson_files": {"/usr/lib/x86_64-linux-gnu/libjansson.so.4": receive.sha(elf())},
                "aliases": {path: path for path in provider},
                "binary_sha256": "b" * 64,
                "oracle_sha256": receive.sha(buffers[name]),
            }
        )
    return result


class JanssonCiEvidenceTests(unittest.TestCase):
    def test_settings_null_oracle_establishes_ownership_safe_premise_before_serializing(self):
        root = Path(__file__).resolve().parents[1]
        body = (root / "tests/fixtures/winpr_jansson_regression.c").read_text(encoding="utf-8")
        created = body.index("rdpSettings* settings = freerdp_settings_new(0);")
        serialized = body.index("encoded = freerdp_settings_serialize(settings, FALSE, &length);")
        setup = body[created:serialized]
        self.assertEqual(setup.count("const FreeRDP_Settings_Keys_Pointer keys[]"), 1)
        for key in (
            "FreeRDP_RedirectionTargetCertificate",
            "FreeRDP_RdpServerCertificate",
            "FreeRDP_RdpServerRsaKey",
        ):
            self.assertEqual(setup.count(key), 1)
        self.assertIn("CHECK(freerdp_settings_set_pointer_len(settings, keys[i], NULL, 0));", setup)
        self.assertIn("CHECK(!freerdp_settings_get_pointer(settings, keys[i]));", setup)
        for unsafe in (
            "freerdp_settings_set_pointer(",
            "freerdp_certificate_free(",
            "freerdp_key_free(",
            "freerdp_certificate_new(",
            "freerdp_key_new(",
        ):
            self.assertNotIn(unsafe, setup)

    def test_settings_null_oracle_keeps_post_serialize_assertions_and_native_guards(self):
        root = Path(__file__).resolve().parents[1]
        body = (root / "tests/fixtures/winpr_jansson_regression.c").read_text(encoding="utf-8")
        serialized = body.index("encoded = freerdp_settings_serialize(settings, FALSE, &length);")
        result = body[serialized:]
        self.assertIn("CHECK(!freerdp_settings_get_pointer(settings, keys[i]));", result)
        self.assertIn(
            "CHECK(WINPR_JSON_IsArray(array) && WINPR_JSON_GetArraySize(array) == 0);", result
        )
        self.assertLess(result.index("WINPR_JSON_Delete(obj);"), result.index("free(encoded);"))
        self.assertLess(
            result.index("free(encoded);"), result.index("freerdp_settings_free(settings);")
        )
        for retained in (
            "CHECK(setrlimit(RLIMIT_CPU, &cpu) == 0);",
            "CHECK(setrlimit(RLIMIT_AS, &memory) == 0);",
            "alarm(5);",
            "CHECK(!WINPR_JSON_Parse(deep));",
            "CHECK(!WINPR_JSON_CreateNumber(NAN));",
            'CHECK(!WINPR_JSON_Parse("{\\"k\\":1,\\"k\\":2}"));',
        ):
            self.assertIn(retained, body)

    def test_finite_oracles_refuse_extra_missing_wrongguard_and_boolean_alias(self):
        buffers = oracle_buffers()
        self.assertEqual(set(receive.validate_oracles(buffers)), receive.ORACLES)
        bad = dict(buffers, extra=b"not exported")
        with self.assertRaisesRegex(gate.ScanPolicyError, "oracle_closure"):
            receive.validate_oracles(bad)
        for index, field, value in (
            (6, "winpr_guarded", True),
            (16, "winpr_guarded", 1),
            (17, "winpr_guarded_rejected", False),
        ):
            bad = dict(buffers)
            rows = [json.loads(line) for line in bad["json-reference.jsonl"].splitlines()]
            rows[index][field] = value
            bad["json-reference.jsonl"] = b"".join(raw(row) for row in rows)
            with self.subTest(index=index), self.assertRaises(gate.ScanPolicyError):
                receive.validate_oracles(bad)
        bad = dict(buffers)
        bad["winpr-jansson-runtime.json"] = buffers["winpr-jansson-runtime.json"].replace(
            b'"passed": true', b'"passed": 1'
        )
        with self.assertRaises(gate.ScanPolicyError):
            receive.validate_oracles(bad)

    def test_provider_is_exact_not_version_or_tag_equivalence(self):
        buffers = oracle_buffers()
        provider = {"/opt/pamolive-freerdp/lib/libwinpr3.so.3": "a" * 64}
        native = raw(
            {"files": [{"path": path, "sha256": digest} for path, digest in provider.items()]}
        )
        identities = identity_buffers(buffers, provider)
        receive.provider_binding(identities, buffers, native)
        for field, replacement in (
            ("provider_files", {next(iter(provider)): "c" * 64}),
            ("oracle_sha256", "c" * 64),
            ("aliases", {"/etc/passwd": next(iter(provider))}),
            ("binary_sha256", "c" * 64),
        ):
            bad = dict(identities)
            value = json.loads(bad["runtime-identity.json"])
            value[field] = replacement
            bad["runtime-identity.json"] = raw(value)
            with self.subTest(field=field), self.assertRaises(gate.ScanPolicyError):
                receive.provider_binding(bad, buffers, native)

    def test_projection_retains_inventory_and_refuses_ambiguous_dpkg(self):
        status = (
            b"Package: libjansson4\nStatus: install ok installed\n"
            b"Version: 2.14-2+b3\nArchitecture: amd64\n"
        )
        meta = {"image_id": "sha256:" + "a" * 64, "archive_sha256": "b" * 64}
        value = receive.dpkg_projection(status, meta)
        self.assertEqual(value["components"][0]["name"], "libjansson4")
        self.assertIn("not-scanner", value["metadata"]["properties"][0]["value"])
        for bad in (
            status + b"Package: other\n",
            status + b"\n" + status,
            status.replace(b"amd64", b"arm64"),
            status.replace(b"2.14-2+b3", b"2.14-2"),
        ):
            with self.subTest(bad=bad), self.assertRaises(gate.ScanPolicyError):
                receive.dpkg_projection(bad, meta)

    def test_source_context_receipt_and_executed_code_must_all_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            revision = "a" * 40
            files = {}
            for name in receive.PRODUCT_PATHS | receive.WIRING_PATHS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic public source")
                files[name] = receive.sha(path.read_bytes())
            pin_path = root / "deploy/jansson-ci-product-pins.json"
            pin_path.write_bytes(raw({name: files[name] for name in receive.PRODUCT_PATHS}))
            files["deploy/jansson-ci-product-pins.json"] = receive.sha(pin_path.read_bytes())
            receipt = root / "context.json"
            receipt.write_bytes(
                raw(
                    {
                        "schema": "pamolive.committed-build-context.v1",
                        "revision": revision,
                        "files": files,
                    }
                )
            )
            value = receive.source_binding(root, receipt, revision, executed_root=root)
            self.assertEqual(value["revision"], revision)
            (root / "deploy/build-freerdp.sh").write_bytes(b"different script")
            with self.assertRaisesRegex(gate.ScanPolicyError, "context_source"):
                receive.source_binding(root, receipt, revision, executed_root=root)
            with self.assertRaisesRegex(gate.ScanPolicyError, "context_receipt"):
                receive.source_binding(root, receipt, "b" * 40, executed_root=root)

    def data_fixture(self):
        fixture = absence_fixture.JanssonAbsenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = fixture.archive.parent
        revision = "a" * 40
        provider_path = "/opt/pamolive-freerdp/lib/libwinpr3.so.3"
        provider = {provider_path: receive.sha(elf())}
        native = raw({"files": [{"path": provider_path, "sha256": receive.sha(elf())}]})
        fixture.status += b"Architecture: amd64\n"
        fixture.make(
            [
                (provider_path.lstrip("/"), elf()),
                ("var/lib/dpkg/status", fixture.status),
                ("opt/pamolive-native-manifest.json", native),
                ("usr/lib/x86_64-linux-gnu/libjansson.so.4", elf()),
            ]
        )
        with tarfile.open(fixture.archive) as source:
            members = {row.name: source.extractfile(row).read() for row in source}
        config = json.loads(members["config.json"])
        config["config"] = {
            "Labels": {
                "org.opencontainers.image.source": qualified_image.SOURCE,
                "org.opencontainers.image.revision": revision,
                "io.pamolive.source.license": "AGPL-3.0-or-later",
            }
        }
        members["config.json"] = raw(config)
        config_name = receive.sha(members["config.json"]) + ".json"
        members[config_name] = members.pop("config.json")
        archive_manifest = json.loads(members["manifest.json"])
        archive_manifest[0]["RepoTags"] = [qualified_image.TAG]
        archive_manifest[0]["Config"] = config_name
        members["manifest.json"] = raw(archive_manifest)
        with tarfile.open(fixture.archive, "w") as output:
            for name, body in members.items():
                row = tarfile.TarInfo(name)
                row.size = len(body)
                output.addfile(row, io.BytesIO(body))
        bundle = root / "bundle"
        bundle.mkdir()
        fixture.archive.rename(bundle / qualified_image.ARCHIVE)
        metadata = {
            "schema": qualified_image.FORMAT,
            "source": qualified_image.SOURCE,
            "revision": revision,
            "platform": "linux/amd64",
            "image_id": "sha256:" + receive.sha(members[config_name]),
            "archive_sha256": receive.sha((bundle / qualified_image.ARCHIVE).read_bytes()),
        }
        (bundle / qualified_image.METADATA).write_bytes(raw(metadata))
        proof = root / "proof"
        proof.mkdir()
        (proof / "native-manifest.json").write_bytes(native)
        oracles = root / "oracles"
        oracles.mkdir()
        buffers = oracle_buffers()
        for name, body in {**buffers, **identity_buffers(buffers, provider)}.items():
            (oracles / name).write_bytes(body)
        return root, bundle, oracles, proof, revision

    def test_actual_archive_parser_full_receiver_closes_data_bindings(self):
        root, bundle, oracles, proof, revision = self.data_fixture()
        with mock.patch.object(receive, "source_binding", return_value={"revision": revision}):
            result = receive.receive(
                root, root / "receipt", bundle, oracles, proof / "jansson", revision
            )
        self.assertTrue(result["physical_absence"]["physical_checks_passed"])
        self.assertFalse(result["CVE_closed"])
        self.assertFalse(result["Docker_H1_inferred"])
        self.assertEqual(
            result["physical_absence"]["archive_sha256"],
            result["qualified_image"]["archive_sha256"],
        )
        self.assertEqual(len(list((proof / "jansson").iterdir())), 8)

    def test_exported_native_manifest_cannot_name_different_archive_bytes(self):
        root, bundle, oracles, proof, revision = self.data_fixture()
        native = json.loads((proof / "native-manifest.json").read_bytes())
        native["synthetic"] = "different bytes with same provider claims"
        (proof / "native-manifest.json").write_bytes(raw(native))
        with mock.patch.object(receive, "source_binding", return_value={"revision": revision}):
            with self.assertRaisesRegex(gate.ScanPolicyError, "archived_native_manifest"):
                receive.receive(
                    root, root / "receipt", bundle, oracles, proof / "jansson", revision
                )
        self.assertFalse((proof / "jansson/report.json").exists())

    def test_same_parser_claim_in_three_oracles_must_match_actual_image_bytes(self):
        root, bundle, oracles, proof, revision = self.data_fixture()
        for name in receive.IDENTITIES:
            path = oracles / name
            value = json.loads(path.read_bytes())
            value["jansson_files"] = {"/usr/lib/x86_64-linux-gnu/libjansson.so.4": "c" * 64}
            path.write_bytes(raw(value))
        with mock.patch.object(receive, "source_binding", return_value={"revision": revision}):
            with self.assertRaisesRegex(gate.ScanPolicyError, "archived_parser"):
                receive.receive(
                    root, root / "receipt", bundle, oracles, proof / "jansson", revision
                )
        self.assertFalse((proof / "jansson/report.json").exists())

    def test_oracle_identity_has_no_unknown_case_or_escape(self):
        with self.assertRaises(ValueError), mock.patch.object(Path, "stat") as stats:
            identity.snapshot("unknown")
        stats.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            directory = root / identity.PREFIX.lstrip("/")
            directory.mkdir(parents=True)
            (directory / "libwinpr3.so.3").write_bytes(b"DATA, not executed")
            parser = root / "usr/lib/x86_64-linux-gnu/libjansson.so.4"
            parser.parent.mkdir(parents=True)
            parser.write_bytes(b"DATA, not executed")
            with mock.patch.object(identity, "captured", return_value="a" * 64):
                value = identity.snapshot("build", root=root)
            self.assertEqual(set(value["provider_files"]), {identity.PREFIX + "/libwinpr3.so.3"})

    def test_actual_checkout_wiring_executes_disjoint_data_before_unchanged_scan(self):
        root = Path(__file__).resolve().parents[1]
        ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        name = "      - name: Exercise Jansson differential and receive exact-image absence DATA\n"
        self.assertEqual(ci.count(name), 1)
        step = ci.partition(name)[2].partition("      - name:")[0]
        self.assertIn("python -m deploy.build_context", step)
        self.assertIn("--build-target json-reference-data", step)
        self.assertIn('--oracle-output "$oracles"', step)
        self.assertIn('--sealed-archive "$RUNNER_TEMP/pamolive-context-input/context.tar"', step)
        self.assertIn('--sealed-receipt "$RUNNER_TEMP/pamolive-context-input/receipt.json"', step)
        self.assertIn('--source-manifest "$RUNNER_TEMP/pamolive-committed-context.json"', step)
        self.assertIn('--probe-receipt "$RUNNER_TEMP/pamolive-context-input/probe.json"', step)
        self.assertNotIn("docker build", step)
        self.assertIn("python -m deploy.jansson_ci_evidence", step)
        # Once the product uses Jansson, its evidence is mandatory on every
        # Platform run, including the composed candidate and main.
        self.assertNotIn("        if:", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("--push", step)
        self.assertNotIn("ghcr.io", step)
        self.assertLess(ci.index("--build-target native-test"), ci.index(name))
        self.assertLess(ci.index("python -m deploy.native_sbom"), ci.index(name))
        self.assertLess(ci.index(name), ci.index("run: bash deploy/check_image_scan_ci.sh"))
        self.assertIn("tests.test_jansson_ci_evidence", ci)
        docker = (root / "Dockerfile").read_text(encoding="utf-8")
        scratch = docker.partition("FROM scratch AS json-reference-data\n")[2]
        scratch = scratch.partition("\nFROM runtime AS production")[0]
        self.assertNotIn("RUN ", scratch)
        lines = [line for line in scratch.splitlines() if line]
        self.assertEqual(len(lines), 6)
        self.assertTrue(all(line.startswith("COPY --from=") for line in lines))
        self.assertTrue(all(line.endswith((".json", ".jsonl")) for line in lines))
        self.assertTrue(all("libcjson" not in line for line in lines))
        self.assertEqual(docker.count("RUN --network=none /tmp/json-backend-reference"), 1)
        self.assertEqual(
            docker.count("RUN --network=none /opt/pamolive-test/winpr-jansson-regression"), 2
        )
