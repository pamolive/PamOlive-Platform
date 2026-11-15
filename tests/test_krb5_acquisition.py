"""Live build-script PYCHECK, real SHA256/XZ, virtual FS/curl/time only.
Fixtures model two repository versions; no CI builder bytes or GPG are claimed.
"""

import builtins
import datetime as dt
import hashlib
import lzma
import re
import subprocess
import types
import unittest
from email.utils import format_datetime
from pathlib import Path

from deploy.krb5_inventory import SOURCES

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "deploy/build-krb5.sh").read_text(encoding="utf8")
CANDIDATE = SCRIPT.split("python - <<'PYCHECK'\n", 1)[1].split("\nPYCHECK\n", 1)[0] + "\n"

PROOF = "/usr/share/pamolive/krb5-backport"
BASE = "https://security.debian.org/debian-security/dists/trixie-security/"
BY_HASH = BASE + "main/source/by-hash/SHA256/"
MAX = 33554432
NOW = dt.datetime(2026, 11, 15, 19, 45, tzinfo=dt.UTC)
EXPECTED = dict(SOURCES)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(extra=""):
    rows = [(value, "100", name) for name, value in EXPECTED.items()]
    rows.extend(
        [
            ("1" * 64, "100", "krb5_1.21.3-5+deb13u1.dsc"),
            ("2" * 64, "100", "krb5_1.21.3.orig.tar.gz.asc"),
        ]
    )
    return (
        "Package: krb5\nVersion: 1.21.3-5+deb13u1\nDirectory: pool/updates/main/k/krb5\n"
        + extra
        + "Checksums-Sha256:\n"
        + "".join(" " + " ".join(row) + "\n" for row in rows)
    )


A = lzma.compress(record().encode())
B = lzma.compress(record("Description: PUBLIC_SYNTHETIC_SECOND_INDEX\n").encode())


class Fixture:
    def __init__(self, index=A):
        self.index = index
        self.origin = "Debian"
        self.codename = "trixie-security"
        self.acquire = "yes"
        self.date = NOW - dt.timedelta(minutes=5)
        self.expiry = NOW + dt.timedelta(minutes=30)
        self.rows = [f"{sha(index)} {len(index)} main/source/Sources.xz"]
        self.sha_field = True
        self.status = "[GNUPG:] VALIDSIG PUBLIC_SYNTHETIC_STATUS_ONLY\n"
        self.clock = [NOW, NOW]
        self.calls = []
        self.reads = []
        self.writes = []
        self.decompressions = 0
        self.remote = {sha(A): A, sha(B): B}
        self.body_override = None
        self.curl_error = False
        self.stat_size = None
        self.files = {}

    def release(self):
        result = (
            f"Origin: {self.origin}\nCodename: {self.codename}\n"
            f"Date: {format_datetime(self.date)}\n"
            f"Valid-Until: {format_datetime(self.expiry)}\n"
        )
        if self.acquire is not None:
            result += "Acquire-By-Hash: " + self.acquire + "\n"
        if self.sha_field:
            result += "SHA256:\n" + "".join(" " + row + "\n" for row in self.rows)
        return result

    def execute(self):
        fixture = self
        self.files.update(
            {
                PROOF + "/Release": self.release().encode(),
                PROOF + "/gpgv.status": self.status.encode(),
            }
        )
        self.files[PROOF + "/Sources.xz"] = B  # Canonical path rotated after the signed Release.

        class VirtualPath:
            def __init__(self, path):
                self.path = str(path)

            def __truediv__(self, name):
                return VirtualPath(self.path + "/" + str(name))

            def __str__(self):
                return self.path

            def read_bytes(self):
                fixture.reads.append(self.path)
                return fixture.files[self.path]

            def read_text(self):
                return self.read_bytes().decode()

            def write_text(self, value):
                fixture.writes.append(self.path)
                fixture.files[self.path] = value.encode()
                return len(value)

            def stat(self):
                return types.SimpleNamespace(
                    st_size=fixture.stat_size
                    if fixture.stat_size is not None
                    else len(fixture.files[self.path])
                )

        class Clock:
            @classmethod
            def now(cls, zone):
                assert zone is dt.UTC
                return fixture.clock.pop(0)

        def run(argv, **kwargs):
            fixture.calls.append(argv)
            assert kwargs == {"check": True}
            assert argv[:-1] == [
                "curl",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "120",
                "--max-filesize",
                "33554432",
                "--output",
                PROOF + "/Sources.xz",
            ]
            assert argv[-1].startswith(BY_HASH) and re.fullmatch(
                "[0-9a-f]{64}", argv[-1][len(BY_HASH) :]
            )
            digest = argv[-1][len(BY_HASH) :]
            if fixture.curl_error or digest not in fixture.remote:
                raise subprocess.CalledProcessError(22, argv)
            fixture.files[PROOF + "/Sources.xz"] = (
                fixture.body_override
                if fixture.body_override is not None
                else fixture.remote[digest]
            )
            return types.SimpleNamespace(returncode=0)

        def decompressor():
            fixture.decompressions += 1
            return lzma.LZMADecompressor()

        real_import = builtins.__import__

        def imports(name, *args, **kwargs):
            if name == "pathlib":
                return types.SimpleNamespace(Path=VirtualPath)
            if name == "datetime":
                return types.SimpleNamespace(datetime=Clock, timezone=dt.timezone)
            if name == "subprocess":
                return types.SimpleNamespace(run=run)
            if name == "lzma":
                return types.SimpleNamespace(LZMADecompressor=decompressor)
            return real_import(name, *args, **kwargs)

        namespace = {"__builtins__": {**vars(builtins), "__import__": imports}}
        try:
            exec(compile(CANDIDATE, "<real-deploy-PYCHECK-synthetic-IO>", "exec"), namespace)
        except Exception as error:
            return error
        return None


class ByHashAcquisitionTests(unittest.TestCase):
    def assert_refused(self, f, *, code=None, before_fetch=False, before_xz=True):
        error = f.execute()
        self.assertIsNotNone(error)
        if code is not None:
            self.assertIsInstance(error, AssertionError)
            self.assertEqual(str(error), code)
        if before_fetch:
            self.assertEqual(f.calls, [])
        if before_xz:
            self.assertEqual(f.decompressions, 0)
        self.assertNotIn("/build/krb5-input/downloads.sha256", f.writes)
        return error

    def test_01_SYNTHETIC_rotation_old_mutable_refused_byhash_picks_A(self):
        fixed = Fixture()
        self.assertIsNone(fixed.execute())
        self.assertEqual(fixed.files[PROOF + "/Sources.xz"], A)
        self.assertEqual(fixed.calls[0][-1], BY_HASH + sha(A))
        self.assertIn("/build/krb5-input/downloads.sha256", fixed.writes)

    def test_02_second_signed_fixture_version_selects_its_own_B_hash(self):
        f = Fixture(B)
        self.assertIsNone(f.execute())
        self.assertEqual(f.files[PROOF + "/Sources.xz"], B)
        self.assertEqual(f.calls[0][-1], BY_HASH + sha(B))

    def test_03_mismatch_at_byhash_is_still_refused_before_XZ(self):
        f = Fixture()
        f.body_override = B
        self.assert_refused(f, code="sources_index_hash")
        self.assertEqual(len(f.calls), 1)

    def test_04_declared_size_mismatch_has_closed_size_error(self):
        f = Fixture()
        f.rows = [f"{sha(A)} {len(A) + 1} main/source/Sources.xz"]
        self.assert_refused(f, code="sources_index_size")

    def test_05_missing_or_duplicate_matching_entry_refused_before_fetch(self):
        for rows in ([], [Fixture().rows[0]] * 2, [f"{sha(A)} {len(A)} other/Sources.xz"]):
            f = Fixture()
            f.rows = rows
            self.assert_refused(f, code="sources_index_entry_count", before_fetch=True)

    def test_06_hash_absent_or_malformed_row_is_refused(self):
        f = Fixture()
        f.sha_field = False
        self.assert_refused(f, code="sources_index_entry_count", before_fetch=True)
        for row in (
            "123 main/source/Sources.xz",
            f"{sha(A)} {len(A)} extra main/source/Sources.xz",
        ):
            f = Fixture()
            f.rows = [row]
            self.assert_refused(f, code="sources_index_row", before_fetch=True)

    def test_07_invalid_digest_never_becomes_URL(self):
        for digest in ("A" * 64, "0" * 63, "../../bad", "https://foreign.invalid", "g" * 64):
            f = Fixture()
            f.rows = [f"{digest} {len(A)} main/source/Sources.xz"]
            self.assert_refused(f, code="sources_index_hash_format", before_fetch=True)

    def test_08_absent_zero_invalid_or_oversize_size_refused_before_fetch(self):
        for size in ("0", "-1", "1e4", "33554433", "999999999999999999", "+123"):
            f = Fixture()
            f.rows = [f"{sha(A)} {size} main/source/Sources.xz"]
            self.assert_refused(f, code="sources_index_size", before_fetch=True)

    def test_09_AcquireByHash_must_be_exact_yes(self):
        for value in (None, "no", "YES", "yes no", ""):
            f = Fixture()
            f.acquire = value
            self.assert_refused(f, code="sources_index_by_hash", before_fetch=True)

    def test_10_expired_or_future_release_refused_before_fetch(self):
        for mode in ("expired", "future"):
            f = Fixture()
            if mode == "expired":
                f.expiry = NOW - dt.timedelta(seconds=1)
            else:
                f.date = NOW + dt.timedelta(seconds=1)
            self.assert_refused(f, before_fetch=True)

    def test_11_expiry_during_fetch_refused_after_fetch_before_XZ(self):
        f = Fixture()
        f.clock = [NOW, f.expiry]
        self.assert_refused(f)
        self.assertEqual(len(f.calls), 1)

    def test_12_wrong_origin_or_codename_cannot_reroute(self):
        for field, value in (("origin", "Foreign"), ("codename", "sid")):
            f = Fixture()
            setattr(f, field, value)
            self.assert_refused(f, before_fetch=True)

    def test_13_missing_or_bad_signature_status_refused_before_fetch(self):
        for status in (
            "",
            "[GNUPG:] VALIDSIG fixture\n[GNUPG:] BADSIG fixture\n",
            "[GNUPG:] VALIDSIG fixture\n[GNUPG:] EXPKEYSIG fixture\n",
        ):
            f = Fixture()
            f.status = status
            self.assert_refused(f, before_fetch=True)

    def test_14_curl_failure_has_one_call_and_no_mutable_fallback(self):
        f = Fixture()
        f.curl_error = True
        self.assertIsInstance(self.assert_refused(f), subprocess.CalledProcessError)
        self.assertEqual(len(f.calls), 1)
        self.assertTrue(f.calls[0][-1].startswith(BY_HASH))

    def test_15_missing_byhash_object_does_not_use_other_cached_index(self):
        f = Fixture()
        f.remote = {sha(B): B}
        self.assertIsInstance(self.assert_refused(f), subprocess.CalledProcessError)
        self.assertEqual(len(f.calls), 1)

    def test_16_wrong_canonical_path_or_injected_hash_refuses_no_request(self):
        f = Fixture()
        f.rows = [f"{sha(A)} {len(A)} https://foreign.invalid/main/source/Sources.xz"]
        self.assert_refused(f, code="sources_index_entry_count", before_fetch=True)

    def test_17_download_stat_over_budget_refused_before_read_and_XZ(self):
        f = Fixture()
        f.stat_size = MAX + 1
        self.assert_refused(f, code="sources_index_size")
        self.assertNotIn(PROOF + "/Sources.xz", f.reads)

    def test_18_invalid_truncated_or_concatenated_XZ_refused(self):
        for data in (b"not_xz", A[:-4], A + B):
            f = Fixture(data)
            f.remote[sha(data)] = data
            self.assert_refused(f, before_xz=False)
            self.assertEqual(f.decompressions, 1)

    def test_19_decompression_budget_is_unchanged_32MiB(self):
        data = lzma.compress(b"x" * (MAX + 1))
        f = Fixture(data)
        f.remote[sha(data)] = data
        self.assert_refused(f, before_xz=False)

    def test_20_source_version_directory_and_original_pins_unchanged(self):
        for text in (
            record().replace("Version: 1.21.3-5+deb13u1", "Version: FOREIGN"),
            record().replace("pool/updates/main/k/krb5", "pool/foreign"),
            record().replace(next(iter(EXPECTED.values())), "f" * 64),
        ):
            data = lzma.compress(text.encode())
            f = Fixture(data)
            f.remote[sha(data)] = data
            self.assert_refused(f, before_xz=False)

    def test_21_duplicate_release_field_preserves_existing_parser_guard(self):
        f = Fixture()
        original = f.release
        f.release = lambda: original() + "Acquire-By-Hash: yes\n"
        error = self.assert_refused(f, before_fetch=True)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(str(error), "duplicate_control_field")

    def test_22_positive_curl_argv_budgets_origin_and_output_exact(self):
        f = Fixture()
        self.assertIsNone(f.execute())
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(f.calls[0][f.calls[0].index("--max-time") + 1], "120")
        self.assertEqual(f.calls[0][f.calls[0].index("--max-filesize") + 1], "33554432")
        self.assertNotIn("--location", f.calls[0])
        self.assertNotIn("--retry", f.calls[0])
