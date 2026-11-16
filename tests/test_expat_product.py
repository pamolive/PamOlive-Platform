"""Synthetic archives/filesystems only; no compiler, Docker, XML or signatures."""

import copy
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy import expat_image as expat
from deploy import expat_snapshot as snapshot
from deploy import native_sbom as sbom
from deploy import qualified_image as image
from deploy import qualify_image_scan as gate


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def elf(mark):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = (62).to_bytes(2, "little")
    return bytes(header) + mark


def tar_bytes(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, raw in files.items():
            row = tarfile.TarInfo(name.lstrip("/"))
            if isinstance(raw, tuple):
                row.type = tarfile.SYMTYPE
                row.linkname = raw[1]
                archive.addfile(row)
            else:
                row.size = len(raw)
                archive.addfile(row, io.BytesIO(raw))
    return out.getvalue()


def fixture(extra_layers=(), mutate=None):
    active, before, files = {}, {}, {}
    for key in expat.KEYS:
        alias = expat.MODULES.get(key, "/usr/lib/x86_64-linux-gnu/" + key)
        target = alias if key in expat.MODULES else alias + ".13.1"
        raw = elf(key.encode())
        files[target] = raw
        if target != alias:
            files[alias] = ("symlink", target.rsplit("/", 1)[-1])
        active[key] = {
            "alias": alias,
            "target": target,
            "sha256": digest(raw),
            "soname": None if key in expat.MODULES else key,
            "rpath": [],
            "runpath": [],
            "needed": ["libc.so.6", "libexpat.so.1"] if key == "pyexpat" else ["libc.so.6"],
        }
        before[key] = {"sha256": digest(elf(b"old-" + key.encode()))}
    source = {
        "packages": [
            {
                "package": name,
                "version": "2.10.0-1+pamolive1",
                "sha256": ("a" if name == "libexpat1" else "b") * 64,
                "bytes": 100,
            }
            for name in ("libexpat1", "libexpat1-dev")
        ]
    }
    proof = {
        expat.PATHS[0]: before,
        expat.PATHS[1]: active,
        expat.PATHS[2]: {"optimization": {"policy": "xml-local-no-pgo-v1"}},
        expat.PATHS[3]: source,
        expat.PATHS[4]: {"metadata_equal": True, "base_origin_attested": False},
        expat.PATHS[5]: {"package_version": "2.10.0-1+pamolive1", "fixed4_admitted": False},
    }
    if mutate:
        mutate(proof, files)
    for name, value in proof.items():
        files[name] = json.dumps(value).encode()
    files[expat.PATHS[-1]] = (
        b"Package: libexpat1\nStatus: install ok installed\n"
        b"Architecture: amd64\nVersion: 2.10.0-1+pamolive1\n\n"
    )
    layers = [*extra_layers, tar_bytes(files)]
    config = {
        "os": "linux",
        "architecture": "amd64",
        "config": {
            "Env": expat.RUNTIME_ENV,
            "User": "root",
            "WorkingDir": "/app",
            "Cmd": ["python", "deploy/runtime.py"],
            "ExposedPorts": {"8000/tcp": {}},
            "Healthcheck": {
                "Test": [
                    "CMD-SHELL",
                    'python -c "import urllib.request; '
                    "urllib.request.urlopen('http://localhost:8000/health/', timeout=4)\"",
                ],
                "Interval": 20_000_000_000,
                "Timeout": 5_000_000_000,
                "StartPeriod": 20_000_000_000,
            },
        },
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(raw) for raw in layers]},
    }
    config_raw = json.dumps(config).encode()
    outer = {"config.json": config_raw}
    outer.update({f"{i}/layer.tar": raw for i, raw in enumerate(layers)})
    outer["manifest.json"] = json.dumps(
        [{"Config": "config.json", "Layers": [f"{i}/layer.tar" for i in range(len(layers))]}]
    ).encode()
    return tar_bytes(outer), "sha256:" + digest(config_raw)


class ExpatProductTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def examine(self, raw, image_id):
        path = self.root / "image.tar"
        path.write_bytes(raw)
        return expat.examine(path, image_id)

    def test_same_archive_hash_and_active_bytes_are_bound(self):
        raw, image_id = fixture()
        result = self.examine(raw, image_id)
        self.assertEqual(result["archive_sha256"], digest(raw))
        self.assertEqual(result["image_id"], image_id)
        self.assertEqual(len(result["old_ELF_hashes_absent_all_layers"]), 4)
        self.assertFalse(result["fixed4_admitted"])
        self.assertFalse(result["product_qualified"])

    def test_old_hidden_ELF_refuses_before_logical_overwrite(self):
        hidden = tar_bytes({expat.MODULES["pyexpat"]: elf(b"old-pyexpat")})
        raw, image_id = fixture([hidden])
        with self.assertRaisesRegex(ValueError, "forbidden_physical_elf"):
            self.examine(raw, image_id)

    def test_extra_physical_provider_refuses_even_if_name_would_be_removed(self):
        hidden = tar_bytes({"/old/libexpat.so.1.9.3": elf(b"different-old-provider")})
        raw, image_id = fixture([hidden])
        with self.assertRaisesRegex(ValueError, "expat_other_physical_provider"):
            self.examine(raw, image_id)

    def test_mismatched_config_or_active_hash_refuses(self):
        raw, image_id = fixture()
        with self.assertRaisesRegex(ValueError, "expat_configuration_changed"):
            self.examine(raw, "sha256:" + "0" * 64)
        raw, image_id = fixture(
            mutate=lambda proof, _: proof[expat.PATHS[1]]["pyexpat"].update(sha256="c" * 64)
        )
        with self.assertRaisesRegex(ValueError, "expat_active_bytes"):
            self.examine(raw, image_id)

    def test_duplicate_old_hashes_wrong_policy_and_snapshot_refuse(self):
        changes = (
            lambda p, _: p[expat.PATHS[0]].update(
                {key: {"sha256": "0" * 64} for key in expat.KEYS}
            ),
            lambda p, _: p[expat.PATHS[2]]["optimization"].update(policy="automatic"),
            lambda p, _: p[expat.PATHS[4]].update(metadata_equal=False),
            lambda p, _: p[expat.PATHS[5]].update(fixed4_admitted=True),
        )
        for mutate in changes:
            with self.subTest(mutate=mutate):
                raw, image_id = fixture(mutate=mutate)
                with self.assertRaises(ValueError):
                    self.examine(raw, image_id)

    def test_archive_rewrite_between_passes_refuses(self):
        raw, image_id = fixture()
        path = self.root / "image.tar"
        path.write_bytes(raw)
        original, calls = gate.archive_facts, []

        def change(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(True)
            if len(calls) == 1:
                path.write_bytes(raw[:-1] + b"X")
            return result

        with patch.object(gate, "archive_facts", side_effect=change):
            with self.assertRaisesRegex(ValueError, "expat_archive_changed"):
                expat.examine(path, image_id)

    def test_physical_hash_seam_default_unchanged_and_stream_matches_path(self):
        raw, _ = fixture()
        path = self.root / "image.tar"
        path.write_bytes(raw)
        a = gate.archive_facts(path, [{"kind": "elf_set"}])
        b = gate.archive_facts(None, [{"kind": "elf_set"}], archive_stream=io.BytesIO(raw))
        self.assertEqual(a, b)
        self.assertEqual(a.elf_set, b.elf_set)
        for values in (["bad"], [False], ["a" * 64] * 17):
            with self.assertRaisesRegex(ValueError, "forbidden_elf_hashes"):
                gate.archive_facts(path, [], forbidden_elf_sha256=values)

    def test_fd_hash_budget_matches_path_hash(self):
        path = self.root / "data"
        path.write_bytes(b"public")
        self.assertEqual(
            image.archive_hash(path), image.archive_hash(None, archive_stream=io.BytesIO(b"public"))
        )
        with patch.object(image, "MAX_ARCHIVE_SIZE", 3):
            with self.assertRaises(ValueError):
                image.archive_hash(None, archive_stream=io.BytesIO(b"oversize"))

    def test_snapshot_metadata_equal_and_mode_or_alias_drift_refuses(self):
        source, target = self.root / "source", self.root / "target"
        source.mkdir()
        (source / "public").write_bytes(b"data")
        shutil.copytree(source, target)
        self.assertTrue(snapshot.compare(source, target)["metadata_equal"])
        before = snapshot.metadata(source)
        after = copy.deepcopy(before)
        after["/public"]["uid"] += 1
        with patch.object(snapshot, "metadata", side_effect=[before, after]):
            with self.assertRaisesRegex(ValueError, "snapshot_metadata_changed"):
                snapshot.compare(source, target)
        after = copy.deepcopy(before)
        after["/public"]["mode"] ^= 0o020
        with patch.object(snapshot, "metadata", side_effect=[before, after]):
            with self.assertRaises(ValueError):
                snapshot.compare(source, target)

    def test_dpkg_types_duplicates_and_old_version_refuse(self):
        good = (
            b"Package: libexpat1\nStatus: install ok installed\n"
            b"Architecture: amd64\nVersion: 2.10.0-1+pamolive1\n\n"
        )
        expat.check_package(good)
        for bad in (
            good + good,
            good.replace(b"2.10.0", b"2.9.0"),
            good.replace(b"amd64", b"arm64"),
            good.replace(b"Version:", b"Status:"),
        ):
            with self.assertRaises(ValueError):
                expat.check_package(bad)

    def test_config_keeps_exact_ENV_roles_entrypoint_and_health(self):
        raw, _ = fixture()
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            config = json.loads(archive.extractfile("config.json").read())
        expat.check_config(config)
        for key, value in (
            ("Env", [*expat.RUNTIME_ENV, "LD_PRELOAD=evil"]),
            ("User", "1000"),
            ("Cmd", ["sh"]),
            ("Entrypoint", ["sh"]),
            ("WorkingDir", "/"),
        ):
            bad = copy.deepcopy(config)
            bad["config"][key] = value
            with self.assertRaises(ValueError):
                expat.check_config(bad)

    def test_sbom_component_graph_tied_to_actual_config_not_authority(self):
        raw, image_id = fixture()
        report = self.examine(raw, image_id)
        components, edges, roots = sbom.expat_components(report, image_id, "image_config")
        self.assertEqual(len(components), 5)
        refs = {row["bom-ref"] for row in components}
        self.assertTrue(set(roots) <= refs)
        self.assertTrue(all(set(row.get("dependsOn", [])) <= refs for row in edges))
        self.assertEqual(components[0]["version"], "2.10.0")
        for bad in (
            report | {"image_id": "sha256:" + "0" * 64},
            report | {"fixed4_admitted": True},
        ):
            with self.assertRaises(ValueError):
                sbom.expat_components(bad, image_id, "image_config")

    def test_sbom_full_merge_retains_native_graph_and_strict_schema(self):
        from tests import test_native_sbom as existing

        native = existing.NativeSbomTests()
        native.setUp()
        raw, image_id = fixture()
        report = self.examine(raw, image_id)
        result = sbom.merge(
            native.app,
            native.manifest,
            native.report,
            image_digest=image_id,
            image_digest_kind="image_config",
            input_hashes={**native.hashes, "expat": "e" * 64},
            expat_report=report,
        )
        sbom.references(result)
        self.assertEqual(sum(c.get("name") == "expat" for c in result["components"]), 1)
        self.assertEqual(sum("cpe" in c for c in result["components"]), 2)

    def test_alias_search_override_and_wrong_DSO_need_refuse(self):
        changes = (
            lambda p, f: f.update(
                {"/usr/lib/x86_64-linux-gnu/libexpat.so.1": ("symlink", "/other")}
            ),
            lambda p, _: p[expat.PATHS[1]]["pyexpat"].update(rpath=["/tmp"]),
            lambda p, _: p[expat.PATHS[1]]["_elementtree"].update(needed=["libexpat.so.1"]),
        )
        for mutate in changes:
            with self.subTest(mutate=mutate):
                raw, image_id = fixture(mutate=mutate)
                with self.assertRaises(ValueError):
                    self.examine(raw, image_id)

    def test_docker_product_uses_received_builders_both_modules_and_clean_final_root(self):
        docker = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf8")
        self.assertIn("--optimization-policy xml-local-no-pgo-v1", docker)
        self.assertEqual(docker.count("FROM scratch AS runtime\n"), 1)
        runtime = docker.split("FROM scratch AS runtime\n")[1].split("FROM guacd-builder")[0]
        self.assertIn("COPY --from=runtime-build / /", runtime)
        self.assertNotIn("--chown", runtime.split("COPY --from=runtime-build / /", 1)[1])
        for name in (
            "build_debian.py",
            "check_sanitizer.py",
            "source_audit.py",
            "abi_gate.py compare",
            "qualify_linux.py",
        ):
            self.assertIn(name, docker)
        self.assertIn("FROM expat-sdk AS freerdp-builder", docker)
        self.assertIn("FROM expat-sdk AS directory-builder", docker)
        self.assertIn("FROM runtime AS native-test", docker)
        self.assertIn("FROM runtime AS production", docker)


if __name__ == "__main__":
    unittest.main()
