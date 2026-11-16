"""Preparation-PC tests: Core Python, fake IO, no subprocess/native/XML execution."""

# ruff: noqa: E402 -- deliberate isolated sibling imports after fixed HERE bootstrap
import copy
import json
import stat
import sys
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import abi_gate
import authenticate
import build_python_xml as build_pyexpat
import check_sanitizer
import common
import download
import python_cases
import source_audit
import verify_runtime

MATERIALS = HERE.parent / "materials"

P = "3176EF7DB2367F1FCA4F306B1F9B0E909AF37285"
S = "CB8DE70A90CFBF6C3BF5CC5696262ACFFBD3AEC6"


def status(primary=P, signer=S):
    return (
        f"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {signer[-16:]} Public fixture\n"
        f"[GNUPG:] VALIDSIG {signer} 2026-11-02 1793577600 0 4 0 1 10 00 {primary}\n"
    ).encode()


class SignatureTests(unittest.TestCase):
    def test_formfeed_trailing_and_multisignature_refuse(self):
        raw = (MATERIALS / "expat-2.10.0-1.dsc").read_bytes()
        authenticate.cleartext_envelope(raw)
        for changed in (
            raw + b"injected",
            raw.replace(b"Source: expat", b"Source: expat\x0c"),
            raw + raw,
        ):
            with self.assertRaises(ValueError):
                authenticate.cleartext_envelope(changed)

    def test_full_primary_and_signer(self):
        self.assertEqual(authenticate.valid_status(status(), P, S, 1794787200)["signing_key"], S)

    def test_no_bad_status_overrides_good(self):
        for bad in authenticate.BAD:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                authenticate.valid_status(
                    status() + f"[GNUPG:] {bad} x\n".encode(), P, S, 1794787200
                )

    def test_multiple_wrong_partial(self):
        for raw in (
            status() * 2,
            status(primary="A" * 40),
            status().replace(b"VALIDSIG", b"NO_VALID"),
            b"garbage\n" + status(),
            status().replace(b"1793577600", b"9999999999"),
        ):
            with self.subTest(raw=raw[:24]), self.assertRaises(ValueError):
                authenticate.valid_status(raw, P, S, 1794787200)

    def test_one_primary_key_purpose(self):
        row = ("pub:-:4096:1:x:0:0:::::scESC:\n" + "fpr:::::::::" + P + ":\n").encode()
        authenticate.one_primary(row, P)
        for raw in (row * 2, row.replace(P.encode(), b"A" * 40), row.replace(b"pub:-", b"pub:r")):
            with self.assertRaises(ValueError):
                authenticate.one_primary(raw, P)

    def test_actual_signer_capability_and_period(self):
        key = {"validity": "-", "created": "1", "expires": "0", "caps": "sc"}
        keys = {P: dict(key), S: key | {"caps": "s"}}
        authenticate.signing_capability(keys, P, S, 1000)
        for delta in (
            {"caps": "e"},
            {"caps": "sD"},
            {"validity": "r"},
            {"expires": "900"},
            {"created": "9999"},
        ):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                authenticate.signing_capability(keys | {S: key | delta}, P, S, 1000)


class RootPurposeTests(unittest.TestCase):
    def decision(self):
        return json.loads((HERE / "Root-bootstrap-decision.json").read_bytes())

    def test_three_exact_Root_purposes(self):
        rows = authenticate.approved_authorities()
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0].primary, "A0DF7E0D3851E0EE45C00BC8ACE1F33CB933BBBB")
        self.assertNotEqual(rows[0].primary, rows[0].signer)
        self.assertEqual(rows[2].primary, rows[2].signer)
        for a in rows:
            raw = (MATERIALS / a.key).read_bytes()
            self.assertEqual((common.sha(raw), len(raw)), (a.bundle_sha256, a.bundle_bytes))

    def test_wrong_primary_right_signer_refused(self):
        for a in authenticate.AUTHORITIES:
            with self.subTest(purpose=a.purpose), self.assertRaises(ValueError):
                authenticate.valid_status(
                    status(primary="A" * 40, signer=a.signer), a.primary, a.signer, 1794787200
                )

    def test_right_primary_wrong_signer_refused(self):
        for a in authenticate.AUTHORITIES:
            with self.subTest(purpose=a.purpose), self.assertRaises(ValueError):
                authenticate.valid_status(
                    status(primary=a.primary, signer="B" * 40), a.primary, a.signer, 1794787200
                )

    def test_primary_as_signer_not_substitute_and_Python_self_signer_allowed(self):
        for a in authenticate.AUTHORITIES:
            raw = status(primary=a.primary, signer=a.primary)
            if a.purpose == "python":
                self.assertEqual(
                    authenticate.valid_status(raw, a.primary, a.signer, 1794787200)["signing_key"],
                    a.primary,
                )
            else:
                with self.assertRaises(ValueError):
                    authenticate.valid_status(raw, a.primary, a.signer, 1794787200)

    def test_cross_purpose_overlap_refused(self):
        rows = list(authenticate.AUTHORITIES)
        rows[1] = rows[1]._replace(signer=rows[0].signer)
        with self.assertRaisesRegex(ValueError, "authority_overlap"):
            authenticate.validate_authorities(rows, self.decision())
        with self.assertRaises(ValueError):
            authenticate.validate_authorities((rows[0], rows[0], rows[2]), self.decision())

    def test_label_bundle_and_artifact_scope_cannot_be_reassigned(self):
        original = authenticate.AUTHORITIES
        for delta in (
            {"purpose": "upstream"},
            {"key": original[1].key},
            {"signature": original[1].signature},
            {"data": "expat_2.10.0.orig.tar.gz"},
            {"bundle_sha256": "0" * 64},
            {"bundle_bytes": 1},
            {"primary": original[0].signer},
        ):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                authenticate.validate_authorities(
                    (original[0]._replace(**delta), *original[1:]), self.decision()
                )

    def test_expat_signature_never_admits_Debian_or_Python_purpose(self):
        a = authenticate.AUTHORITIES[1]
        raw = status(primary=a.primary, signer=a.signer)
        authenticate.valid_status(raw, a.primary, a.signer, 1794787200)
        for target in (authenticate.AUTHORITIES[0], authenticate.AUTHORITIES[2]):
            with self.assertRaises(ValueError):
                authenticate.valid_status(raw, target.primary, target.signer, 1794787200)

    def test_changed_Root_decision_refused_before_material_IO_or_command(self):
        with (
            mock.patch.object(authenticate, "read", return_value=b"{}") as read,
            mock.patch.object(authenticate, "check_materials") as materials,
            mock.patch.object(authenticate, "command") as command,
        ):
            with self.assertRaisesRegex(ValueError, "Root_bootstrap_bytes"):
                authenticate.main("unused", "unused")
            self.assertEqual(read.call_count, 1)
            materials.assert_not_called()
            command.assert_not_called()

    def test_missing_binding_listing_and_signature_outside_key_period_refused(self):
        a = authenticate.AUTHORITIES[0]
        primary = ("pub:-:4096:1:x:1:0:::::c:\n" + f"fpr:::::::::{a.primary}:\n").encode()
        keys = authenticate.one_primary(primary, a.primary)
        with self.assertRaises(ValueError):
            authenticate.signing_capability(keys, a.primary, a.signer, 1000, 900)
        with self.assertRaises(ValueError):
            authenticate.one_primary(primary + b"sub:-:4096:1:x:1:0:::::s:\n", a.primary)
        key = {"validity": "-", "created": "1", "expires": "0", "caps": "s"}
        keys = {a.primary: key, a.signer: key | {"created": "950"}}
        with self.assertRaisesRegex(ValueError, "signature_before_key"):
            authenticate.signing_capability(keys, a.primary, a.signer, 1000, 900)

    def main_model(self, wrong_signer=False):
        authorities = authenticate.approved_authorities()
        captured, receipts = [], []

        class FakePath:
            def __init__(self, value):
                self.value = str(value)

            def __truediv__(self, name):
                return FakePath(self.value + "/" + name)

            def __str__(self):
                return self.value

            def resolve(self):
                return self

            def mkdir(self, **kwargs):
                pass

        data = {a.key: (MATERIALS / a.key).read_bytes() for a in authorities}
        data.update(
            {
                "expat_2.10.0.orig.tar.gz": b"Debian orig fixture",
                "expat_2.10.0-1.debian.tar.xz": b"Debian packaging fixture",
            }
        )
        text = b"Source: expat\nVersion: 2.10.0-1\nChecksums-Sha256:\n"
        for name in ("expat_2.10.0.orig.tar.gz", "expat_2.10.0-1.debian.tar.xz"):
            text += f" {common.sha(data[name])} {len(data[name])} {name}\n".encode()
        data["expat-2.10.0-1.dsc"] = (
            b"-----BEGIN PGP SIGNED MESSAGE-----\n\n"
            + text
            + b"-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n"
        )

        def fake_command(args, cwd, log, **kwargs):
            captured.append((args, str(log), kwargs))
            a = next(
                a
                for a in authorities
                if str(log).endswith(
                    (a.purpose + "-import", a.purpose + "-keys", a.purpose + "-verify")
                )
            )
            if "--import" in args:
                return b""
            if "--list-keys" in args:
                rows = f"pub:-:4096:1:x:1:0:::::sc:\nfpr:::::::::{a.primary}:\n"
                if a.signer != a.primary:
                    rows += f"sub:-:4096:1:x:1:0:::::s:\nfpr:::::::::{a.signer}:\n"
                return rows.encode()
            return status(primary=a.primary, signer="B" * 40 if wrong_signer else a.signer)

        with (
            mock.patch.multiple(
                authenticate,
                Path=FakePath,
                approved_authorities=lambda: authorities,
                check_materials=lambda folder: None,
                material_rows=lambda: [{"name": n} for n in data],
                material=lambda folder, name: data[name],
                write_new=lambda *args: None,
                read=lambda path, cap: data.get(str(path).split("/")[-1], text),
                record=lambda path, value: receipts.append((str(path), value)),
                command=fake_command,
            ),
            mock.patch.object(authenticate.time, "time", return_value=1794787200),
        ):
            if wrong_signer:
                with self.assertRaisesRegex(ValueError, "signature_authority"):
                    authenticate.main("/materials", "/authentication")
            else:
                authenticate.main("/materials", "/authentication")
        return captured, receipts

    def test_real_main_wires_three_offline_GPG_purposes_with_bounds(self):
        calls, receipts = self.main_model()
        self.assertEqual(len(calls), 9)
        for args, log, kwargs in calls:
            self.assertEqual(args[0], "/usr/bin/gpg")
            self.assertIn("--require-cross-certification", args)
            self.assertIn("--no-auto-key-retrieve", args)
            self.assertEqual(kwargs["seconds"], 30)
            self.assertEqual(kwargs["env"]["GNUPGHOME"], args[args.index("--homedir") + 1])
            if "--list-keys" in args:
                self.assertIn("--with-subkey-fingerprint", args)
        self.assertEqual(len(receipts), 1)
        proof = receipts[0][1]
        self.assertEqual(proof["Root_bootstrap_sha256"], authenticate.ROOT_BOOTSTRAP_SHA256)
        self.assertEqual([s["purpose"] for s in proof["signatures"]], ["debian", "expat", "python"])

    def test_real_main_wrong_signer_cannot_write_AUTHENTICATED(self):
        calls, receipts = self.main_model(wrong_signer=True)
        self.assertEqual(len(calls), 3)
        self.assertEqual(receipts, [])


class BuildModelTests(unittest.TestCase):
    def config(self):
        return {
            "SOABI": "cpython-312-x86_64-linux-gnu",
            "EXT_SUFFIX": build_pyexpat.SUFFIX,
            "MULTIARCH": "x86_64-linux-gnu",
            "Py_DEBUG": 0,
            "Py_ENABLE_SHARED": 1,
            "CC": "gcc",
            "LDSHARED": "gcc -shared",
            "CFLAGS": "-O3 -fwrapv",
            "CCSHARED": "-fPIC",
            "LDFLAGS": "",
            "PY_STDMODULE_CFLAGS": (
                "-O3 -fwrapv -fprofile-use -fprofile-correction -I./Include/internal"
            ),
            "LIBS": "-ldl",
            "SYSLIBS": "-lm",
            "PY_LDFLAGS": "",
            "PY_LDFLAGS_NODIST": "",
        }

    def test_exact_python_abi(self):
        self.assertEqual(
            build_pyexpat.abi(
                self.config(), (3, 12, 16), optimization_policy=build_pyexpat.OPTIMIZATION_POLICY
            )[0],
            "/usr/bin/gcc",
        )
        for version in ((3, 14, 0), (3, 12, 15)):
            with self.assertRaises(ValueError):
                build_pyexpat.abi(
                    self.config(), version, optimization_policy=build_pyexpat.OPTIMIZATION_POLICY
                )
        for field, value in (
            ("SOABI", "cpython-314"),
            ("CC", "ccache gcc"),
            ("EXT_SUFFIX", ".so"),
            ("Py_DEBUG", 1),
            ("MULTIARCH", "aarch64-linux-gnu"),
        ):
            row = self.config() | {field: value}
            with self.assertRaises(ValueError):
                build_pyexpat.abi(
                    row, (3, 12, 16), optimization_policy=build_pyexpat.OPTIMIZATION_POLICY
                )

    def test_compiler_injection_and_missing_profiles(self):
        for flag in (
            "@file",
            "-fplugin=x",
            "-specs=x",
            "--sysroot=/x",
            "-fprofile-use",
            "-Wl,-rpath,/x",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                build_pyexpat.flags(flag)
        self.assertIn("-fuse-linker-plugin", build_pyexpat.flags("-flto -fuse-linker-plugin"))
        with self.assertRaises(ValueError):
            build_pyexpat.stdmodule_flags("-O3 -I/unreviewed")

    def test_consumed_headers_not_declared_header_names_only(self):
        include = PurePosixPath("/usr/local/include/python3.12")
        trace = "\n".join(
            ". " + path
            for path in (
                str(include / "Python.h"),
                str(include / "pyexpat.h"),
                "/usr/include/expat.h",
                "/usr/include/x86_64-linux-gnu/expat_config.h",
            )
        )
        self.assertEqual(len(build_pyexpat.header_trace(trace, "pyexpat", include)), 64)
        for wrong in (
            trace.replace("/usr/include/expat.h", "/usr/local/include/expat.h"),
            trace.replace("/usr/include/expat.h", "/usr/include/python3.14/expat.h"),
            trace.replace(". /usr/include/x86_64-linux-gnu/expat_config.h", ""),
        ):
            with self.assertRaises(ValueError):
                build_pyexpat.header_trace(wrong, "pyexpat", include)

    def test_python_source_selected_without_bundled_sources(self):
        raw = (MATERIALS / "Python-3.12.16.tar.xz").read_bytes()
        result = build_pyexpat.source_parts(raw)
        self.assertEqual(
            set(result),
            {"pyexpat.c", "clinic/pyexpat.c.h", "_elementtree.c", "clinic/_elementtree.c.h"},
        )
        self.assertIn(b'#include "expat_config.h"', result["pyexpat.c"])
        self.assertIn(b'"expat.h"', result["_elementtree.c"])
        for field in ("MAJOR", "MINOR", "MICRO"):
            changed = result | {
                "_elementtree.c": result["_elementtree.c"].replace(
                    f"st->expat_capi->{field}_VERSION != XML_{field}_VERSION".encode(), b"0"
                )
            }
            with self.assertRaises(ValueError):
                build_pyexpat.capsule_contract(changed)

    def test_pinned_material_corruption(self):
        rows = common.material_rows()
        self.assertEqual(sum(r["name"].endswith(".asc") for r in rows), 5)
        row = next(r for r in rows if r["name"] == "expat_2.10.0.orig.tar.gz")
        raw = (MATERIALS / row["name"]).read_bytes()
        self.assertEqual(common.sha(raw), row["sha256"])
        self.assertNotEqual(common.sha(raw[:-1] + bytes([raw[-1] ^ 1])), row["sha256"])


class AbiTests(unittest.TestCase):
    def test_nondefault_does_not_satisfy_unversioned(self):
        hidden = abi_gate.symbols("  1: 0001 8 FUNC GLOBAL DEFAULT 12 XML_Parse@V1\n")[0]
        default = abi_gate.symbols("  2: 0001 8 FUNC GLOBAL DEFAULT 12 XML_Parse@@V2\n")[0]
        required = {"name": "XML_Parse", "version": None}
        self.assertFalse(abi_gate.resolves(required, [hidden]))
        self.assertTrue(abi_gate.resolves(required, [default]))
        self.assertFalse(abi_gate.resolves(required | {"version": "V1"}, [default]))
        self.assertFalse(abi_gate.resolves(hidden | {"default": True}, [hidden]))
        self.assertTrue(abi_gate.resolves(hidden | {"defined": False}, [hidden]))

    def model(self):
        exports = [
            {
                "name": f"XML_F{i}",
                "version": None,
                "default": True,
                "defined": True,
                "weak": False,
                "kind": "FUNC",
            }
            for i in range(20)
        ]
        old = {
            name: {"soname": name, "symbols": copy.deepcopy(exports)}
            for name in ("libexpat.so.1", "libexpatw.so.1")
        }
        after = {
            name: value | {"rpath": [], "runpath": []} for name, value in copy.deepcopy(old).items()
        }
        after["pyexpat"] = {
            "needed": ["libexpat.so.1"],
            "rpath": [],
            "runpath": [],
            "symbols": [s | {"defined": False} for s in exports],
        }
        old["pyexpat"] = {"sha256": "old-pyexpat"}
        old["_elementtree"] = {"sha256": "old-elementtree"}
        for module in ("pyexpat", "_elementtree"):
            after.setdefault(module, {"symbols": [], "rpath": [], "runpath": []})
            after[module]["sha256"] = "new-" + module
            after[module]["symbols"].append(
                {
                    "name": "PyInit_" + module,
                    "defined": True,
                    "version": None,
                    "default": True,
                    "weak": False,
                    "kind": "FUNC",
                }
            )
        return old, after

    def test_missing_export_soname_vendored_or_rpath(self):
        old, new = self.model()
        abi_gate.compare(old, new)
        for mutate in (
            lambda r: r["libexpat.so.1"]["symbols"].pop(),
            lambda r: r["libexpatw.so.1"].update(soname="libexpatw.so.2"),
            lambda r: r["pyexpat"].update(needed=["libc.so.6"]),
            lambda r: r["pyexpat"].update(rpath=["/tmp"]),
            lambda r: r["_elementtree"].update(sha256="old-elementtree"),
            lambda r: r["pyexpat"]["symbols"].append(r["libexpat.so.1"]["symbols"][0]),
        ):
            value = copy.deepcopy(new)
            mutate(value)
            with self.assertRaises(ValueError):
                abi_gate.compare(old, value)


class DataTests(unittest.TestCase):
    def test_package_state_and_duplicates(self):
        valid = (
            "Package: libexpat1\nVersion: 2.10.0-1+pamolive1\nArchitecture: amd64\n"
            "Status: install ok installed\n"
        )
        self.assertEqual(verify_runtime.package_version(valid), "2.10.0-1+pamolive1")
        for raw in (
            valid.replace("2.10.0-1+pamolive1", "2.9.0-1~deb13u1"),
            valid + "Version: 2.10.0-1+pamolive1\n",
            valid + "\n" + valid,
            valid.replace("install ok installed", "deinstall ok config-files"),
        ):
            with self.assertRaises(ValueError):
                verify_runtime.package_version(raw)

    def test_readonly_https_redirects_closed(self):
        request = download.urllib.request.Request(
            "https://github.com/libexpat/libexpat/releases/download/R_2_10_0/expat-2.10.0.tar.gz"
        )
        for url in (
            "http://release-assets.githubusercontent.com/x",
            "https://attacker.example/x",
            "https://user@release-assets.githubusercontent.com/x",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                download.Redirect().redirect_request(request, None, 302, "", {}, url)
        gate = download.Redirect()
        next_request = gate.redirect_request(
            request, None, 302, "", {}, "https://release-assets.githubusercontent.com/x"
        )
        self.assertEqual(next_request.host, "release-assets.githubusercontent.com")
        with self.assertRaises(ValueError):
            gate.redirect_request(
                request, None, 302, "", {}, "https://release-assets.githubusercontent.com/y"
            )

    def test_instrument_actual_counter_not_proxy(self):
        fixed = (
            b"size_t attIndex = 0;\nsize_t nPrefixes = 0;\nif (attIndex > INT_MAX) return error;"
        )
        instrumented = check_sanitizer.instrument(fixed)
        self.assertIn(b"_Generic(attIndex, size_t:", instrumented)
        for invalid in (
            fixed.replace(b"size_t attIndex", b"int attIndex"),
            fixed + fixed,
            fixed.replace(b"attIndex > INT_MAX", b"attIndex > 0"),
        ):
            with self.assertRaises(ValueError):
                check_sanitizer.instrument(invalid)

    def test_payloads_are_small_no_parser_run(self):
        for name in python_cases.CASES:
            if name.startswith("capsule-") or name == "external":
                continue
            self.assertLessEqual(len(python_cases.payload(name)), python_cases.INPUT_CAP)
        with self.assertRaises(ValueError):
            python_cases.payload("arbitrary-command")

    def test_real_signed_candidates_have_equal_complete_code(self):
        # DATA ONLY: hashes/contents, not signature verification or correction admission.
        evidence = source_audit.audit(MATERIALS)
        self.assertEqual(
            evidence["equal_source_hashes"]["lib/xmlparse.c"],
            "9443794afe78dfab5cccf27e803b30359a55dbf9eaadbd54297522b72356833c",
        )
        self.assertFalse(evidence["crypto_or_runtime_proved"])


class CommandTests(unittest.TestCase):
    def model(self, mode):
        journal = {}

        class FakePath:
            def __init__(self, value):
                self.value = str(value)

            def __truediv__(self, other):
                return FakePath(self.value + "/" + str(other))

            def __str__(self):
                return self.value

            def __eq__(self, other):
                return str(self) == str(other)

            def is_absolute(self):
                return True

            def stat(self):
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)

            def mkdir(self, **kwargs):
                pass

            def resolve(self, **kwargs):
                return self

        def record(path, value):
            self.assertNotIn(str(path), journal)
            journal[str(path)] = value

        def runner(args, **kwargs):
            self.assertEqual(journal["/log/intent.json"]["state"], "PENDING")
            self.assertTrue(kwargs["owned_session"])
            self.assertEqual(kwargs["timeout"] - kwargs["work_timeout"], 5)
            kwargs["on_spawn"](1234)
            if mode == "raise":
                raise KeyboardInterrupt()
            return SimpleNamespace(
                ok=mode != "nonreap",
                stdout=b"public",
                stderr=b"",
                facts=lambda: {
                    "returncode": 0,
                    "owned_child_reaped": mode != "nonreap",
                    "drains_complete": mode != "nonreap",
                },
            )

        hashes = iter((b"tool", b"changed" if mode == "changed" else b"tool"))
        with (
            mock.patch.multiple(
                common,
                Path=FakePath,
                os=SimpleNamespace(name="posix"),
                read=lambda *args: next(hashes),
                record=record,
                write_new=lambda *args: None,
            ),
            mock.patch.object(common.bounded_io, "run_capped", runner),
        ):
            if mode == "ok":
                self.assertEqual(common.command(["/tool"], "/cwd", "/log"), b"public")
            else:
                with self.assertRaises((ValueError, KeyboardInterrupt)):
                    common.command(["/tool"], "/cwd", "/log")
        return journal

    def test_real_command_pending_pid_and_actual_facts(self):
        journal = self.model("ok")
        self.assertEqual(journal["/log/pid.json"], {"pid": 1234})
        self.assertTrue(journal["/log/result.json"]["owned_child_reaped"])
        self.assertNotIn("/log/unknown.json", journal)

    def test_toolchanged_nonreap_and_exception_durable_unknown(self):
        for mode in ("changed", "nonreap", "raise"):
            with self.subTest(mode=mode):
                journal = self.model(mode)
                self.assertEqual(journal["/log/unknown.json"], {"state": "UNKNOWN"})
                if mode != "raise":
                    self.assertIn("/log/result.json", journal)


if __name__ == "__main__":
    unittest.main()
