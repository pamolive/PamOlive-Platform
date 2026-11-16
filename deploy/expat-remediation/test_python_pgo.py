"""Pure policy/ABI/argv tests. No compiler, GPG, XML parser or downloaded binary runs."""

import copy
import io
import json
import shlex
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

import build_python_xml as builder

OBSERVED = json.loads(
    '{"sysconfig": {"CC": "gcc", "CCSHARED": '
    '"-fPIC", "CFLAGS": "-fno-strict-overflow'
    ' -Wsign-compare -DNDEBUG -g -O3 -Wall", '
    '"CFLAGSFORSHARED": "-fPIC", "CONFIG_ARGS'
    "\": \"'--build=x86_64-linux-gnu' '--enable"
    "-loadable-sqlite-extensions' '--enable-o"
    "ptimizations' '--enable-option-checking="
    "fatal' '--enable-shared' '--with-lto' '-"
    "-with-ensurepip' 'build_alias=x86_64-lin"
    'ux-gnu\'", "EXT_SUFFIX": ".cpython-312-x8'
    '6_64-linux-gnu.so", "LDFLAGS": "", "LDSH'
    'ARED": "gcc -shared", "LIBS": "-ldl", "M'
    'ULTIARCH": "x86_64-linux-gnu", "PY_CFLAG'
    'S": "-fno-strict-overflow -Wsign-compare'
    ' -DNDEBUG -g -O3 -Wall", "PY_CFLAGS_NODI'
    'ST": "-fno-semantic-interposition -flto '
    "-fuse-linker-plugin -ffat-lto-objects -f"
    "lto-partition=none -g -std=c11 -Wextra -"
    "Wno-unused-parameter -Wno-missing-field-"
    "initializers -Wstrict-prototypes -Werror"
    "=implicit-function-declaration -fvisibil"
    "ity=hidden -fprofile-use -fprofile-corre"
    'ction -I./Include/internal", "PY_CPPFLAG'
    'S": "-I. -I./Include", "PY_LDFLAGS": "",'
    ' "PY_LDFLAGS_NODIST": "-fno-semantic-int'
    "erposition -flto -fuse-linker-plugin -ff"
    'at-lto-objects -flto-partition=none -g",'
    ' "PY_STDMODULE_CFLAGS": "-fno-strict-ove'
    "rflow -Wsign-compare -DNDEBUG -g -O3 -Wa"
    "ll -fno-semantic-interposition -flto -fu"
    "se-linker-plugin -ffat-lto-objects -flto"
    "-partition=none -g -std=c11 -Wextra -Wno"
    "-unused-parameter -Wno-missing-field-ini"
    "tializers -Wstrict-prototypes -Werror=im"
    "plicit-function-declaration -fvisibility"
    "=hidden -fprofile-use -fprofile-correcti"
    "on -I./Include/internal -I. -I./Include "
    '-fPIC", "Py_DEBUG": 0, "Py_ENABLE_SHARED'
    '": 1, "SOABI": "cpython-312-x86_64-linux'
    '-gnu", "SYSLIBS": "-lm"}, "version": "3.'
    "12.16 (main, Nov  5 2026, 07:58:20) [GCC"
    ' 14.2.0]"}\n'
)["sysconfig"]
EXPECTED_BASE = [
    "/usr/bin/gcc",
    "-shared",
    "-fno-strict-overflow",
    "-Wsign-compare",
    "-DNDEBUG",
    "-g",
    "-O3",
    "-Wall",
    "-fno-semantic-interposition",
    "-flto",
    "-fuse-linker-plugin",
    "-ffat-lto-objects",
    "-flto-partition=none",
    "-g",
    "-std=c11",
    "-Wextra",
    "-Wno-unused-parameter",
    "-Wno-missing-field-initializers",
    "-Wstrict-prototypes",
    "-Werror=implicit-function-declaration",
    "-fvisibility=hidden",
    "-I/usr/local/include/python3.12/internal",
    "-I/usr/local/include/python3.12",
    "-I/usr/local/include/python3.12",
    "-fPIC",
    "-fPIC",
    "-fno-semantic-interposition",
    "-flto",
    "-fuse-linker-plugin",
    "-ffat-lto-objects",
    "-flto-partition=none",
    "-g",
]
POLICY = "xml-local-no-pgo-v1"


class PythonOptimizationTests(unittest.TestCase):
    def abi(self, config=None, policy=POLICY):
        return builder.abi(
            copy.deepcopy(OBSERVED if config is None else config),
            (3, 12, 16),
            optimization_policy=policy,
        )

    def test_received699_abi_exact_vector_and_original_config(self):
        config = copy.deepcopy(OBSERVED)
        self.assertEqual(self.abi(config), EXPECTED_BASE)
        self.assertEqual(config, OBSERVED)
        receipt = builder.optimization_receipt(config["PY_STDMODULE_CFLAGS"], POLICY)
        original = shlex.split(config["PY_STDMODULE_CFLAGS"])
        index = original.index("-fprofile-use")
        self.assertEqual(receipt["effective_tokens"], original[:index] + original[index + 2 :])
        self.assertEqual(receipt["removed_tokens"], ["-fprofile-use", "-fprofile-correction"])
        self.assertEqual(receipt["original_tokens"], original)
        self.assertEqual(len(receipt["header_aliases"]), 3)
        for key in ("profiles_generated", "profiles_imported", "performance_qualified"):
            self.assertIs(receipt[key], False)
        # Recorded original provenance is retained; this role is not consumed twice.
        self.assertIn("-fprofile-use", config["PY_CFLAGS_NODIST"])

    def test_missing_partial_duplicate_reversed_separated_parameterized_pair(self):
        text = OBSERVED["PY_STDMODULE_CFLAGS"]
        pair = "-fprofile-use -fprofile-correction"
        cases = [
            text.replace(pair, ""),
            text.replace("-fprofile-use", ""),
            text.replace("-fprofile-correction", ""),
            text + " -fprofile-use",
            text + " -fprofile-correction",
            text.replace(pair, pair + " " + pair),
            text.replace(pair, "-fprofile-correction -fprofile-use"),
            text.replace(pair, "-fprofile-use -O3 -fprofile-correction"),
            text.replace("-fprofile-use", "-fprofile-use=/tmp/foreign"),
            text.replace("-fprofile-correction", "-fprofile-correction=1"),
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.abi(OBSERVED | {"PY_STDMODULE_CFLAGS": value})
        with self.assertRaises(ValueError):
            self.abi(policy="")
        with self.assertRaises(ValueError):
            self.abi(policy="automatic")
        with self.assertRaises(TypeError):
            builder.abi(OBSERVED, (3, 12, 16))

    def test_foreign_profile_and_coverage_families_fail_real_abi(self):
        flags = (
            "-fauto-profile",
            "-fauto-profile=/tmp/foreign.afdo",
            "-fbranch-probabilities",
            "-fno-branch-probabilities",
            "-fvpt",
            "-fprofile-generate=/tmp/foreign",
            "-fprofile-arcs",
            "-fprofile-dir=/tmp/foreign",
            "-fprofile-use",
            "-fprofile-correction",
            "-fcs-profile-generate",
            "--coverage",
            "-ftest-coverage",
            "-fcondition-coverage",
            "-fpath-coverage",
            "-Wno-error=coverage-mismatch",
            "-p",
            "-pg",
        )
        for flag in flags:
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                self.abi(
                    OBSERVED | {"PY_STDMODULE_CFLAGS": OBSERVED["PY_STDMODULE_CFLAGS"] + " " + flag}
                )
        roles = (
            "CC",
            "LDSHARED",
            "CCSHARED",
            "PY_LDFLAGS",
            "PY_LDFLAGS_NODIST",
            "LIBS",
            "SYSLIBS",
        )
        for role in roles:
            for flag in flags:
                with self.subTest(role=role, flag=flag), self.assertRaises(ValueError):
                    self.abi(OBSERVED | {role: (OBSERVED[role] or "") + " " + flag})

    def test_generic_flags_do_not_admit_the_pair_or_similar_plugin(self):
        for value in (
            "-fprofile-use -fprofile-correction",
            "-fauto-profile=/tmp/foreign",
            "-pg",
            "-fuse-linker-plugin=/tmp/plugin",
            "-fplugin=/tmp/plugin",
            "@response",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                builder.flags(value)
        self.assertEqual(
            builder.flags("-flto -fuse-linker-plugin"), ["-flto", "-fuse-linker-plugin"]
        )

    def test_other_abi_and_header_guards_still_refuse(self):
        for key, value in (
            ("CC", "ccache gcc"),
            ("SOABI", "cpython-314-x86_64-linux-gnu"),
            ("MULTIARCH", "aarch64-linux-gnu"),
            ("Py_DEBUG", 1),
            ("PY_STDMODULE_CFLAGS", OBSERVED["PY_STDMODULE_CFLAGS"] + " -I/unreviewed"),
            (
                "PY_STDMODULE_CFLAGS",
                OBSERVED["PY_STDMODULE_CFLAGS"] + " -fplugin=/tmp/plugin",
            ),
            ("PY_STDMODULE_CFLAGS", OBSERVED["PY_STDMODULE_CFLAGS"] + " @response"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.abi(OBSERVED | {key: value})
        with self.assertRaises(ValueError):
            builder.abi(OBSERVED, (3, 14, 0), optimization_policy=POLICY)

    def test_cli_requires_explicit_policy_before_main(self):
        for args in (
            ["materials", "output"],
            ["--optimization-policy", "automatic", "materials", "output"],
            ["--optimization-p", POLICY, "materials", "output"],
        ):
            with (
                mock.patch.object(builder, "main") as main,
                mock.patch("sys.stderr", new=io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as exit_:
                    builder.cli(args)
                self.assertEqual(exit_.exception.code, 2)
                main.assert_not_called()
        with mock.patch.object(builder, "main") as main:
            builder.cli(["--optimization-policy", POLICY, "materials", "output"])
            main.assert_called_once_with("materials", "output", optimization_policy=POLICY)

    def test_main_wrong_policy_before_material_auth_or_files(self):
        with (
            mock.patch.object(builder, "check_materials") as check,
            mock.patch.object(builder, "authenticate") as auth,
        ):
            with self.assertRaises(ValueError):
                builder.main("never-materials", "never-output", optimization_policy="automatic")
            check.assert_not_called()
            auth.assert_not_called()

    def fake_main(self, fail_compile=False, config=None):
        from contextlib import ExitStack

        config = copy.deepcopy(OBSERVED if config is None else config)
        files, commands, records = {}, [], []
        real_header_trace = builder.header_trace
        old = {name: ("old-" + name).encode() for name in ("pyexpat", "_elementtree")}
        hashes = {name: builder.sha(raw) for name, raw in old.items()}
        for name, raw in old.items():
            files[Path("/usr/local/lib/python3.12/lib-dynload/" + name + builder.SUFFIX)] = raw
        include = Path("/usr/local/include/python3.12")
        for name in (
            "Python.h",
            "pyconfig.h",
            "pyexpat.h",
            "internal/pycore_ceval.h",
            "internal/pycore_runtime.h",
        ):
            files[include / name] = ("synthetic-header-" + name).encode()
        files[Path("/usr/include/expat.h")] = (
            b"#define XML_MAJOR_VERSION 2\n#define XML_"
            b"MINOR_VERSION 10\n#define XML_MICRO_VERSI"
            b"ON 0\n"
        )
        files[Path("/usr/include/x86_64-linux-gnu/expat_config.h")] = (
            b"#define XML_GE 1\n#define XML_DTD 1\n#define XML_NS 1\n"
        )

        def read(path, cap):
            raw = files[Path(path)]
            self.assertLessEqual(len(raw), cap)
            return raw

        def write(path, raw, *args):
            self.assertNotIn(Path(path), files)
            files[Path(path)] = raw

        def command(argv, cwd, log, **kwargs):
            self.assertEqual(argv[0], "/usr/bin/gcc")
            self.assertEqual(kwargs, {"seconds": 180})
            commands.append(argv)
            if fail_compile:
                raise ValueError("synthetic_compile_failure")
            target = Path(argv[argv.index("-o") + 1])
            files[target] = b"synthetic-output-not-an-ELF"
            paths = [
                (include / "Python.h").as_posix(),
                (include / "pyexpat.h").as_posix(),
                "/usr/include/expat.h",
            ]
            if target.name.startswith("pyexpat."):
                paths.append("/usr/include/x86_64-linux-gnu/expat_config.h")
            files[Path(log) / "stderr"] = ("\n".join(". " + path for path in paths) + "\n").encode()

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            for name, value in {
                "OLD_MODULE_SHAS": hashes,
                "check_materials": lambda p: None,
                "authenticate": lambda *a: None,
                "read": read,
                "write_new": write,
                "command": command,
                "material": lambda *a: b"synthetic-source-input",
                "source_parts": lambda raw: {
                    "pyexpat.c": b"model",
                    "_elementtree.c": b"model",
                    "clinic/pyexpat.c.h": b"model",
                    "clinic/_elementtree.c.h": b"model",
                },
                "record": lambda path, value: records.append((Path(path), value)),
                # Model only: feed POSIX include spelling to the unchanged Linux guard.
                "header_trace": lambda trace, name, include: real_header_trace(
                    trace, name, PurePosixPath(include.as_posix())
                ),
            }.items():
                stack.enter_context(mock.patch.object(builder, name, value))
            stack.enter_context(
                mock.patch.object(
                    builder.sysconfig,
                    "get_config_var",
                    side_effect=lambda name: config[name],
                )
            )
            stack.enter_context(mock.patch.object(builder.sys, "version_info", (3, 12, 16)))
            try:
                builder.main(
                    Path(temporary) / "materials",
                    Path(temporary) / "new-output",
                    optimization_policy=POLICY,
                )
            except ValueError:
                if not fail_compile:
                    raise
        return commands, records, config

    def test_real_main_builds_exact_pair_argv_and_truthful_receipt(self):
        commands, records, config = self.fake_main()
        self.assertEqual(len(commands), 2)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0][0].name, "BUILD.json")
        receipt = records[0][1]
        self.assertEqual(receipt["sysconfig"], OBSERVED)
        self.assertEqual(config, OBSERVED)
        self.assertEqual(receipt["optimization"]["policy"], POLICY)
        self.assertFalse(receipt["optimization"]["performance_qualified"])
        for command in commands:
            self.assertEqual(command[: len(EXPECTED_BASE)], EXPECTED_BASE)
            self.assertFalse(any("profile" in word or "coverage" in word for word in command))
        self.assertIn("-lexpat", commands[0])
        self.assertNotIn("-lexpat", commands[1])
        self.assertEqual(set(receipt["modules"]), {"pyexpat", "_elementtree"})
        self.assertFalse(receipt["fixed4_admitted"])

    def test_compile_failure_propagates_without_fallback_or_BUILD(self):
        commands, records, _ = self.fake_main(fail_compile=True)
        self.assertEqual(len(commands), 1)
        self.assertEqual(records, [])

    def test_main_rejects_other_role_feedback_before_any_compile(self):
        for role in ("LIBS", "SYSLIBS", "PY_LDFLAGS_NODIST"):
            commands, records, _ = self.fake_main(
                fail_compile=True,
                config=OBSERVED | {role: OBSERVED[role] + " -fauto-profile=/tmp/foreign"},
            )
            self.assertEqual(commands, [])
            self.assertEqual(records, [])
