"""Pure stdlib tests; no acquired backend, network, Docker, or application import."""

import copy
import gzip
import hashlib
import io
import os
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

from deploy import python_materials as pm

ROOT = Path(__file__).resolve().parents[1]


def manifest():
    return pm.load_manifest(ROOT / "deploy/python-materials.linux-amd64.json")[0]


def source_fixture(row, *, extra=None, mismatch=False):
    """Independent small source tar, never relying on a downloaded source tree."""
    out = io.BytesIO()
    row["source_files"] = {
        name: hashlib.sha256(b"source").hexdigest() for name in pm.SOURCE_PATHS[row["name"]]
    }
    prefix = row["filename"][:-7]
    with tarfile.open(fileobj=out, mode="w") as archive:
        for index, relative in enumerate(sorted(row["source_files"])):
            name = prefix + "/" + relative
            data = b"bad" if mismatch and index == 0 else b"source"
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        if extra:
            entry = tarfile.TarInfo(prefix + "/" + extra)
            entry.size = 0
            archive.addfile(entry, io.BytesIO())
    data = gzip.compress(out.getvalue(), mtime=0)
    row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    return data


def wheel_fixture(
    directory,
    name,
    version,
    *,
    metadata_name=None,
    tag="cp312-cp312-linux_x86_64",
    extra=None,
    omit_extension=False,
):
    prefix = name.replace("-", "_") + "-" + version
    path = Path(directory) / (prefix + "-cp312-cp312-linux_x86_64.whl")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            prefix + ".dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {metadata_name or name}\nVersion: {version}\n",
        )
        archive.writestr(
            prefix + ".dist-info/WHEEL", f"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: {tag}\n"
        )
        for index, item in enumerate(sorted(pm.SO_PATHS[name])):
            if omit_extension and index == 0:
                continue
            header = bytearray(64)
            header[:7] = b"\x7fELF\x02\x01\x01"
            header[16:20] = b"\x03\x00\x3e\x00"
            archive.writestr(item, bytes(header) + name.encode())
        if extra:
            archive.writestr(extra, b"extra")
    return path


class Response:
    def __init__(self, data, url, status=200, headers=None):
        self.body = io.BytesIO(data)
        self.status, self.url = status, url
        self.headers = headers if headers is not None else {"Content-Length": str(len(data))}
        self.read_sizes = []

    def geturl(self):
        return self.url

    def read(self, size):
        self.read_sizes.append(size)
        return self.body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class PythonMaterialsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_closed_reviewed_sets_locks_and_prior_pins(self):
        m = manifest()
        pm.check_locks(m, ROOT)
        sets = {
            role: {r["name"] for r in m["materials"] if role in r["roles"]} for role in pm.LOCKS
        }
        self.assertEqual(sets["runtime"], set(pm.RUNTIME))
        self.assertEqual(len(sets["runtime"]), 26)
        self.assertEqual(sets["build-tools"], {"setuptools", "wheel", "packaging"})
        self.assertEqual(sets["sources"], {"psycopg-c", "python-ldap"})
        self.assertEqual(sets["bootstrap"], {"pip"})
        self.assertEqual(sets["native-test"], {"pillow"})
        self.assertEqual(
            next(r for r in m["materials"] if r["name"] == "psycopg-c")["sha256"],
            "30183897f5fe7ff4375b7dfcec9d44dfe8a5e009080addc1626889324a9eb1ed",
        )
        for old in (
            "requirements-bootstrap.lock",
            "requirements-native-build.lock",
            "requirements-database-build.lock",
        ):
            data = (ROOT / old).read_text()
            for line in data.splitlines():
                if "--hash=sha256:" not in line:
                    continue
                name = line.split("==")[0].lower()
                row = next(r for r in m["materials"] if r["name"] == name)
                self.assertIn(row["sha256"], line)

    def test_original_linux_markers_versions_and_native_test_unchanged(self):
        # Closed marker grammar avoids silently evaluating this Windows host.
        declarations = {}
        for line in (ROOT / "requirements.lock").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            pin, _, marker = line.partition(";")
            if marker:
                self.assertIn(
                    marker.strip(), ('platform_system == "Linux"', 'platform_system != "Linux"')
                )
                if marker.strip() == 'platform_system != "Linux"':
                    self.assertEqual(pin, "psycopg-binary==3.2.10")
                    continue
            name, version = pin.split("==")
            declarations[name.lower()] = version
        self.assertEqual(declarations, pm.RUNTIME | pm.SOURCES)
        self.assertIn("Pillow==13.0.0", (ROOT / "requirements-native-test.lock").read_text())
        for old in (
            "requirements-directory.lock",
            "requirements-native-build.lock",
            "requirements-database-build.lock",
            "requirements-bootstrap.lock",
        ):
            for line in (ROOT / old).read_text().splitlines():
                if not line or line.startswith("#"):
                    continue
                pin = line.split(";")[0].split(" --hash")[0]
                name, version = pin.split("==")
                self.assertEqual(pm.EXPECTED[name], version)

    def test_manifest_substitutions_fail(self):
        changes = (
            lambda m: m["materials"].pop(),
            lambda m: m["materials"].append(copy.deepcopy(m["materials"][0])),
            lambda m: m["materials"][0].update(name="unknown"),
            lambda m: m["materials"][0].update(roles=["runtime", "native-test"]),
            lambda m: m["materials"][0].update(version="1"),
            lambda m: m["materials"][0].update(size=True),
            lambda m: m["materials"][0].update(size=pm.MAX_FILE + 1),
            lambda m: m["materials"][0].update(sha256="0"),
            lambda m: m.update(build_verified=True),
            lambda m: m.update(attestation_verified=True),
            lambda m: m["target"].update(os="win32"),
            lambda m: m.update(extra="unknown"),
            lambda m: next(r for r in m["materials"] if r["name"] == "psycopg-c")[
                "source_files"
            ].pop("psycopg_c/pq.c"),
        )
        for change in changes:
            with self.subTest(change=change):
                m = manifest()
                change(m)
                with self.assertRaises(pm.MaterialsError):
                    pm.validate_manifest(m)

    def test_manifest_duplicate_keys_and_byte_budget(self):
        for value in (b'{"schema":1,"schema":2}', b" " * (pm.MAX_JSON + 1), b"{" * 2000):
            path = self.root / "manifest.json"
            path.write_bytes(value)
            with self.assertRaises(pm.MaterialsError):
                pm.load_manifest(path)

    def test_url_origin_path_and_filename_refusals(self):
        row = manifest()["materials"][0]
        bad = (
            "http://files.pythonhosted.org/packages/x/" + row["filename"],
            "https://files.pythonhosted.org.evil.test/packages/x/" + row["filename"],
            "https://x@files.pythonhosted.org/packages/x/" + row["filename"],
            "https://files.pythonhosted.org:443/packages/x/" + row["filename"],
            row["url"] + "?token=1",
            row["url"] + "#f",
            row["url"].replace("/packages/", "/packages/../"),
            row["url"].replace("/packages/", "/packages/%2e%2e/"),
            row["url"].replace(row["filename"], "other.whl"),
            "\t" + row["url"],
            row["url"] + "\n",
            row["url"].replace("packages", "pack\tages"),
        )
        for value in bad:
            with self.subTest(url=value), self.assertRaises(pm.MaterialsError):
                pm.valid_url(value, row["filename"])
        for value in ("../x", "a/b", "C:x", "a\\b", "/x", "a\x00b", ".", "..", "é.whl"):
            with self.subTest(path=value), self.assertRaises(pm.MaterialsError):
                pm.safe_path(value, basename=True)

    def test_wheel_tags_use_explicit_linux_cp312(self):
        for filename in (
            "x-1-cp312-cp312-win_amd64.whl",
            "x-1-cp313-cp313-manylinux_2_28_x86_64.whl",
            "x-1-cp312-cp312-manylinux_2_42_x86_64.whl",
            "x-1-cp312-cp312-manylinux_2_28_aarch64.whl",
            "x-1-py2-none-any.whl",
        ):
            with self.subTest(filename=filename), self.assertRaises(pm.MaterialsError):
                pm.compatible_wheel(filename)
        for row in manifest()["materials"]:
            if row["kind"] == "wheel":
                pm.compatible_wheel(row["filename"])

    def transport(
        self, *, body=b"bytes", expected=b"bytes", status=200, headers=None, different_url=False
    ):
        row = copy.deepcopy(manifest()["materials"][0])
        row.update(size=len(expected), sha256=hashlib.sha256(expected).hexdigest())
        response = Response(
            body, "https://evil.test/" if different_url else row["url"], status, headers
        )
        opener = mock.Mock()
        opener.open.return_value = response
        return row, opener, response

    def test_download_success_bounded_requests_and_no_credentials(self):
        row, opener, response = self.transport()
        pm.download(row, self.root, opener)
        self.assertEqual((self.root / row["filename"]).read_bytes(), b"bytes")
        request = opener.open.call_args.args[0]
        self.assertNotIn("Authorization", request.headers)
        self.assertNotIn("Cookie", request.headers)
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 30})
        self.assertLessEqual(max(response.read_sizes), pm.CHUNK)

    def test_transport_rejects_redirect_status_encoding_size_and_sha(self):
        cases = (
            dict(status=302),
            dict(different_url=True),
            dict(headers={"Content-Length": "999"}),
            dict(headers={"Content-Encoding": "gzip"}),
            dict(body=b"truncated", expected=b"long expected body", headers={}),
            dict(body=b"other"),
            dict(body=b"bytes-extra", headers={}),
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                row, opener, _ = self.transport(**kwargs)
                with self.assertRaises(pm.MaterialsError):
                    pm.download(row, self.root, opener)
                self.assertFalse((self.root / row["filename"]).exists())
                self.assertEqual(opener.open.call_count, 1)

    def test_download_does_not_delete_existing_and_deadline(self):
        row, opener, _ = self.transport()
        path = self.root / row["filename"]
        path.write_bytes(b"keep")
        with self.assertRaises(pm.MaterialsError):
            pm.download(row, self.root, opener)
        self.assertEqual(path.read_bytes(), b"keep")
        opener.open.assert_not_called()
        path.unlink()
        with (
            mock.patch.object(pm.time, "monotonic", side_effect=[0, 301]),
            self.assertRaisesRegex(pm.MaterialsError, "download_deadline"),
        ):
            pm.download(row, self.root, opener)
        self.assertFalse(path.exists())

    def test_default_tls_and_redirect_are_closed_before_second_request(self):
        with mock.patch.dict("os.environ", {"HTTPS_PROXY": "http://localhost:9"}):
            opener = pm.https_opener()
        self.assertFalse(
            any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers)
        )
        handler = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler))
        self.assertTrue(handler._context.check_hostname)
        self.assertEqual(handler._context.verify_mode, pm.ssl.CERT_REQUIRED)
        with self.assertRaisesRegex(pm.MaterialsError, "redirect_forbidden"):
            pm.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.test")

    def test_regular_files_refuse_hardlinks_and_size_overrun(self):
        path = self.root / "file"
        path.write_bytes(b"bytes")
        with self.assertRaises(pm.MaterialsError):
            pm.regular(path, 4)
        alias = self.root / "alias"
        os.link(path, alias)
        with self.assertRaises(pm.MaterialsError):
            pm.regular(path)
        with self.assertRaises(pm.MaterialsError):
            pm.regular(alias)

    def test_upstream_pth_pyc_and_entry_budget_require_review(self):
        for extra in ("inject.pth", "__pycache__/inject.pyc", "../outside"):
            with self.subTest(extra=extra):
                path = self.root / "wheel.whl"
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(extra, b"raise AssertionError('never execute')")
                with self.assertRaises(pm.MaterialsError):
                    pm.inspect_upstream(path)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("large.py", b"bounded")
        with mock.patch.object(pm, "MAX_TOTAL", 3), self.assertRaises(pm.MaterialsError):
            pm.inspect_upstream(path)

    def test_acquisition_exact_directories_without_executing_sources(self):
        m = manifest()
        bodies = {}
        for row in m["materials"]:
            if row["kind"] == "sdist":
                data = source_fixture(row)
            else:
                memory = io.BytesIO()
                with zipfile.ZipFile(memory, "w") as archive:
                    archive.writestr("fixture.py", "raise AssertionError('never execute')")
                data = memory.getvalue()
            row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            bodies[row["url"]] = data
        opener = mock.Mock()
        opener.open.side_effect = lambda req, **kw: Response(bodies[req.full_url], req.full_url)
        with mock.patch.object(
            pm,
            "wheel_inventory",
            side_effect=AssertionError("acquisition must not execute/prepare wheels"),
        ):
            pm.acquire(m, self.root / "fresh", opener)
        for role, count in (
            ("runtime", 26),
            ("runtime-inputs", 27),
            ("build-tools", 3),
            ("bootstrap", 1),
            ("sources", 2),
            ("native-test", 1),
        ):
            self.assertEqual(len(list((self.root / "fresh" / role).iterdir())), count)
        self.assertFalse(
            any(
                p.name.startswith(("setuptools-", "wheel-", "pillow-"))
                or p.name.endswith(".tar.gz")
                for p in (self.root / "fresh/runtime-inputs").iterdir()
            )
        )
        with self.assertRaises(FileExistsError):
            pm.acquire(m, self.root / "fresh", opener)

    def derived_fixture(self):
        m = manifest()
        inputs = self.root / "inputs"
        (inputs / "sources").mkdir(parents=True)
        wheels = self.root / "wheels"
        wheels.mkdir()
        for row in m["materials"]:
            if row["name"] in pm.SOURCES:
                (inputs / "sources" / row["filename"]).write_bytes(source_fixture(row))
                wheel_fixture(wheels, row["name"], row["version"])
        return m, inputs, wheels

    def test_derived_per_run_hashes_and_source_c_mapping(self):
        m, inputs, wheels = self.derived_fixture()
        report = pm.capture_derived(m, "0" * 64, inputs, wheels, self.root / "proof")
        self.assertIs(report["build_verified"], False)
        for row in report["materials"]:
            raw = (wheels / row["wheel_filename"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["wheel_sha256"])
            self.assertNotEqual(row["wheel_sha256"], row["source_sha256"])
            self.assertEqual(set(row["extensions"]), pm.SO_PATHS[row["name"]])
            self.assertIn(
                row["wheel_sha256"],
                (self.root / "proof/requirements-python-derived-linux.lock").read_text(),
            )
            self.assertNotIn(
                row["source_sha256"],
                (self.root / "proof/requirements-python-derived-linux.lock").read_text(),
            )

    def test_hash_and_parse_use_same_buffers_despite_path_substitution(self):
        m, inputs, wheels = self.derived_fixture()
        row = next(r for r in m["materials"] if r["name"] == "psycopg-c")
        source_path = inputs / "sources" / row["filename"]
        original_verify = pm.verify_file

        def substitute_source(path, source_row):
            data = original_verify(path, source_row)
            Path(path).write_bytes(b"substituted after verified read")
            return data

        with mock.patch.object(pm, "verify_file", side_effect=substitute_source):
            self.assertEqual(pm.source_inventory(source_path, row), row["source_files"])
        # Restore for capture, then substitute each wheel immediately after its
        # sole bounded read. The record must still describe those exact bytes.
        source_path.write_bytes(source_fixture(row))
        original_regular, seen = pm.regular, {}

        def substitute_wheel(path, limit=pm.MAX_FILE):
            data = original_regular(path, limit)
            if Path(path).suffix == ".whl":
                self.assertNotIn(Path(path).name, seen)
                seen[Path(path).name] = hashlib.sha256(data).hexdigest()
                Path(path).write_bytes(b"substituted after bounded read")
            return data

        with mock.patch.object(pm, "regular", side_effect=substitute_wheel):
            report = pm.capture_derived(m, "0" * 64, inputs, wheels, self.root / "proof")
        for entry in report["materials"]:
            self.assertEqual(entry["wheel_sha256"], seen[entry["wheel_filename"]])
        self.assertEqual(len(seen), 2)

    def test_output_extra_source_substitution_and_forged_identity_fail(self):
        for case in (
            "extra-wheel",
            "extra-source",
            "source-sha",
            "source-c",
            "name",
            "tag",
            "extension",
            "omit",
            "path",
            "duplicate",
            "machine",
            "pth",
            "pyc",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                old_root, self.root = self.root, Path(tmp)
                try:
                    m, inputs, wheels = self.derived_fixture()
                    row = next(r for r in m["materials"] if r["name"] == "psycopg-c")
                    if case == "extra-wheel":
                        (wheels / "extra.whl").write_bytes(b"extra")
                    elif case == "extra-source":
                        (inputs / "sources/extra.tar.gz").write_bytes(b"extra")
                    elif case == "source-sha":
                        (inputs / "sources" / row["filename"]).write_bytes(b"substitution")
                    elif case == "source-c":
                        (inputs / "sources" / row["filename"]).write_bytes(
                            source_fixture(row, mismatch=True)
                        )
                    elif case == "duplicate":
                        path = next(wheels.glob("psycopg_c-*.whl"))
                        with zipfile.ZipFile(path, "a") as archive:
                            with self.assertWarns(UserWarning):
                                archive.writestr("psycopg_c-3.2.10.dist-info/METADATA", "duplicate")
                    elif case == "machine":
                        # Valid magic/class/endian with an ARM64 machine field.
                        path = next(wheels.glob("psycopg_c-*.whl"))
                        with zipfile.ZipFile(path) as archive:
                            contents = {i.filename: archive.read(i) for i in archive.infolist()}
                        with zipfile.ZipFile(path, "w") as archive:
                            for name, data in contents.items():
                                if name.endswith(".so"):
                                    data = data[:18] + b"\xb7\x00" + data[20:]
                                archive.writestr(name, data)
                    else:
                        extras = {
                            "extension": "unknown.so",
                            "path": "../outside",
                            "pth": "inject.pth",
                            "pyc": "inject.pyc",
                        }
                        wheel_fixture(
                            wheels,
                            "psycopg-c",
                            "3.2.10",
                            metadata_name="other" if case == "name" else None,
                            tag="cp312-cp312-win_amd64"
                            if case == "tag"
                            else "cp312-cp312-linux_x86_64",
                            extra=extras.get(case),
                            omit_extension=case == "omit",
                        )
                    with self.assertRaises((pm.MaterialsError, OSError)):
                        pm.capture_derived(m, "0" * 64, inputs, wheels, self.root / "proof")
                    self.assertFalse((self.root / "proof").exists())
                finally:
                    self.root = old_root

    def test_source_inventory_requires_pregenerated_c_and_bounded_archive(self):
        row = next(r for r in manifest()["materials"] if r["name"] == "psycopg-c")
        self.assertTrue(
            {"psycopg_c/_psycopg.c", "psycopg_c/pq.c", "psycopg_c/types/numutils.c"}.issubset(
                row["source_files"]
            )
        )
        for case in ("pyx", "traversal", "budget"):
            with self.subTest(case=case):
                data = source_fixture(
                    row,
                    extra="x.pyx"
                    if case == "pyx"
                    else "../outside"
                    if case == "traversal"
                    else None,
                )
                path = self.root / row["filename"]
                path.write_bytes(data)
                with (
                    mock.patch.object(pm, "MAX_TOTAL", 128 if case == "budget" else pm.MAX_TOTAL),
                    self.assertRaises(pm.MaterialsError),
                ):
                    pm.source_inventory(path, row)

    def test_cli_and_docker_contract_no_network_fallback(self):
        self.assertEqual(
            pm.main(
                [
                    "check-locks",
                    "--manifest",
                    str(ROOT / "deploy/python-materials.linux-amd64.json"),
                    "--locks",
                    str(ROOT),
                ]
            ),
            0,
        )
        docker = (ROOT / "Dockerfile").read_text()
        directory = docker.split(" AS directory-builder\n", 1)[1].split(
            "FROM krb5-runtime AS runtime", 1
        )[0]
        self.assertLess(
            directory.index("libpq-dev=${LIBPQ_DEBIAN_VERSION}"),
            directory.index("python_materials.py acquire"),
        )
        self.assertIn("RUN --network=none export", directory)
        self.assertIn(
            "--no-build-isolation --check-build-dependencies --no-deps --require-hashes", directory
        )
        self.assertIn("--find-links=/opt/python-inputs/sources --no-binary=:all:", directory)
        runtime = docker.split("FROM krb5-runtime AS runtime", 1)[1].split(
            "FROM guacd-builder AS native-test-builder", 1
        )[0]
        self.assertNotIn("COPY --from=directory-builder /opt/python-inputs/build-tools", runtime)
        self.assertNotIn("COPY --from=directory-builder /opt/python-inputs/sources", runtime)
        self.assertIn("requirements-python-derived-linux.lock", runtime)
        self.assertNotIn("psycopg_c-3.2.10-*.whl", runtime)
        self.assertEqual(runtime.count("pip install --no-compile"), 3)
        for line in docker.splitlines():
            if "pip install" in line or " -m pip " in line:
                self.assertIn("RUN --network=none", line)
                self.assertIn("--no-index", line)
                self.assertIn("--require-hashes", line)


if __name__ == "__main__":
    unittest.main()
