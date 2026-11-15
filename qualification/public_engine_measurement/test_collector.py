"""Pure fake-runner tests; never calls main or a real executable."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import collector as c


def version():
    return {
        "client_version": "29.6.1",
        "client_api": "1.55",
        "client_os": "linux",
        "client_arch": "amd64",
        "server_version": "29.6.1",
        "server_api_min": "1.44",
        "server_api_max": "1.55",
        "server_os": "linux",
        "server_arch": "amd64",
    }


def image():
    value = {
        "Id": "sha256:" + "a" * 64,
        "Os": "linux",
        "Architecture": "amd64",
        "RootFS": {"Type": "layers", "Layers": ["sha256:" + "b" * 64]},
        "RepoDigests": None,
    }
    value.update({key: {"present": False, "value": None} for key in c.CONFIG_FIELDS})
    return value


class Result:
    def __init__(self, data=None, error=b"", code=0, **changes):
        self.stdout = json.dumps(data).encode() if data is not None else b""
        self.stderr, self.ok = error, code == 0
        self.data = {
            "spawn_attempted": True,
            "pid": 123,
            "returncode": code,
            "reason": "nonzero_exit" if code else None,
            "exception_type": None,
            "killed_owned_child": False,
            "owned_child_reaped": True,
            "drains_complete": True,
            "cleanup_exception_type": None,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(error),
        }
        self.data.update(changes)

    def facts(self):
        return copy.deepcopy(self.data)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="public-pure-", dir=c.HERE)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "new"
        self.tool = {"path": "/usr/bin/docker", "bytes": 123, "sha256": "c" * 64}

    def good(self, calls):
        def run(argv, **options):
            calls.append((argv, options))
            self.assertEqual(set(options["env"]), {"PATH", "HOME", "LANG", "LC_ALL"})
            self.assertEqual(argv[:3], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"])
            self.assertEqual(options["stdout_cap"], 32768)
            self.assertEqual(options["stderr_cap"], 4096)
            self.assertEqual(options["timeout"], 15)
            args = argv[5:]
            if args[0] == "version":
                return Result(version())
            if args[0] == "info":
                return Result(
                    {
                        "driver": "overlayfs",
                        "driver_status": [["driver-type", "io.containerd.snapshotter.v1"]],
                        "root": "/var/lib/docker",
                    }
                )
            return Result(image())

        return run

    def test_four_fixed_read_queries_no_intermediate_report(self):
        calls = []
        report = c.collect(self.work, self.good(calls), self.tool)
        self.assertEqual(len(calls), 4)
        self.assertFalse((self.work / "public-report.json").exists())
        self.assertEqual([args[5] for args, _ in calls], ["version", "info", "image", "image"])
        self.assertEqual(c.finalize(self.work, report, self.tool), 0)
        written = json.loads((self.work / "public-report.json").read_bytes())
        self.assertTrue(written["four_queries_received"])
        self.assertFalse(written["profile_accepted"])
        self.assertFalse(written["getent_executed"])

    def test_unknown_reap_drain_cleanup_stops_new_queries(self):
        for changes in (
            {"owned_child_reaped": False},
            {"drains_complete": False},
            {"cleanup_exception_type": "TimeoutError"},
            {"pid": None},
        ):
            with self.subTest(changes=changes):
                path = Path(self.temporary.name) / (
                    "case" + str(len(list(Path(self.temporary.name).iterdir())))
                )
                calls = []
                report = c.collect(
                    path,
                    lambda *_a, **_k: calls.append(1) or Result(version(), **changes),
                    self.tool,
                )
                self.assertEqual(calls, [1])
                self.assertFalse(report["four_queries_projected"])
                self.assertIsNone(report["queries"]["application"]["process"])

    def test_confirmed_nonzero_does_not_hide_other_read_queries(self):
        calls = []
        good = self.good(calls)

        def run(argv, **options):
            if not calls:
                calls.append((argv, options))
                return Result(error=b"Error response from daemon: No such image: SYNTHETIC", code=1)
            return good(argv, **options)

        report = c.collect(self.work, run, self.tool)
        self.assertEqual(len(calls), 4)
        self.assertEqual(report["queries"]["version"]["stderr_class"], "local_image_absent")
        self.assertEqual(c.finalize(self.work, report, self.tool), 42)

    def test_changed_or_missing_tool_never_persists_complete_receipt(self):
        for index, after in enumerate((dict(self.tool, sha256="d" * 64), None)):
            path = Path(self.temporary.name) / ("tool-case" + str(index))
            report = c.collect(path, self.good([]), self.tool)
            self.assertEqual(c.finalize(path, report, after), 42)
            written = json.loads((path / "public-report.json").read_bytes())
            self.assertFalse(written["four_queries_received"])
            self.assertFalse(written["tool_unchanged"])

    def test_unexpected_values_have_no_value_hash_or_length_or_label_name(self):
        secret = "SYNTHETIC_UNEXPECTED_PRIVATE_MARKER"
        for name in c.CONFIG_FIELDS:
            result = c.safe_field(
                name, {secret: secret} if name in {"Labels", "Volumes"} else secret
            )
            self.assertEqual(result, {"redacted": True})
        value = image()
        value["RepoDigests"] = ["private.invalid/" + secret + "@sha256:" + "a" * 64]
        value["Labels"] = {"present": True, "value": {secret: secret}}
        text = json.dumps(c.project("application", value))
        self.assertNotIn(secret, text)
        self.assertNotIn(c.sha(secret.encode()), text)
        changed = dict(version(), client_version=secret, server_api_max=secret)
        self.assertEqual(c.project("version", changed)["client_version"], {"redacted": True})

    def test_closed_shapes_duplicate_and_overflow_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b"x" * 32769):
            with self.assertRaises(ValueError):
                c.parse(raw)
        bad = dict(version(), extra="PRIVATE")
        with self.assertRaises(ValueError):
            c.project("version", bad)
        value = image()
        value["User"] = {"present": False, "value": "postgres"}
        with self.assertRaises(ValueError):
            c.project("postgres", value)

    def test_no_env_or_container_or_mutation_command_is_produced(self):
        self.assertEqual(len(c.COMMANDS), 4)
        for _name, args in c.COMMANDS:
            self.assertNotIn(".Config.Env", " ".join(args))
            self.assertNotIn(
                args[0], {"create", "start", "pull", "load", "stop", "exec", "container"}
            )
        self.assertIn("range $k,$v := .Config", c.image_template())
        self.assertEqual(c.stderr_class(b"UNEXPECTED_SYNTHETIC_SECRET"), "unclassified")


if __name__ == "__main__":
    unittest.main()
