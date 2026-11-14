"""Pure effective-profile checks; no service, Docker daemon, database or NAS started."""

import os
import runpy
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from deploy import check_runtime as probe
from deploy import runtime
from deploy.runtime import (
    APP_HOME,
    APPLICATION_PATH,
    NATIVE_LIBRARIES,
    application_environment,
    validate_launch_environment,
)


class RuntimeEnvironmentTests(TestCase):
    def init_processes(self):
        root = {"Uid": "0 0 0 0", "Gid": "0 0 0 0", "NoNewPrivs": "1"}
        command = ["python", "deploy/runtime.py"]
        return {
            "1": ({**root, "PPid": "0"}, ["/sbin/docker-init", "--", *command]),
            "2": ({**root, "PPid": "1"}, command),
        }

    @contextmanager
    def init_files(self, *, target=None, executable=None, resolved=None):
        target = target or SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0, st_dev=7, st_ino=19
        )
        with (
            patch.object(Path, "lstat", return_value=target),
            patch.object(Path, "stat", return_value=executable or target),
            patch.object(Path, "resolve", return_value=resolved or Path(probe.DOCKER_INIT_PATH)),
        ):
            yield

    def init_mounts(self):
        return self.mounts() + (
            "3 1 0:3 / /usr/sbin/docker-init ro,relatime - overlay overlay rw\n"
        )

    def test_init_mount_requires_actual_pid1_executable_and_readonly_unique_mount(self):
        with self.init_files():
            probe.check_mounts(self.init_mounts(), processes=self.init_processes(), supervisor="2")
            for command in ("/sbin/docker-init", "/usr/sbin/docker-init"):
                processes = self.init_processes()
                processes["1"][1][0] = command
                probe.check_mounts(self.init_mounts(), processes=processes, supervisor="2")
            for text in (
                self.init_mounts().replace("ro,relatime - overlay", "rw,relatime - overlay"),
                self.init_mounts().replace("ro,relatime - overlay", "ro,rw - overlay"),
                self.init_mounts() + self.init_mounts().splitlines(keepends=True)[-1],
                self.mounts(),
            ):
                with self.subTest(mounts=text), self.assertRaises(RuntimeError):
                    probe.check_mounts(text, processes=self.init_processes(), supervisor="2")

    def test_init_path_or_missing_and_wrong_process_arguments_do_not_authorize_mount(self):
        with self.init_files():
            with self.assertRaises(RuntimeError):
                probe.check_mounts(self.init_mounts())
            for pid, field, value in (
                ("1", "Uid", "1000 1000 1000 1000"),
                ("1", "Gid", "0 1000 0 0"),
                ("1", "NoNewPrivs", "0"),
                ("1", "PPid", "3"),
                ("2", "Uid", "0 1000 0 0"),
                ("2", "Gid", "1000 1000 1000 1000"),
                ("2", "NoNewPrivs", "0"),
                ("2", "PPid", "9"),
            ):
                processes = self.init_processes()
                processes[pid][0][field] = value
                with self.subTest(pid=pid, field=field), self.assertRaises(RuntimeError):
                    probe.check_mounts(self.init_mounts(), processes=processes, supervisor="2")
            for command in (
                ["docker-init", "--", "python", "deploy/runtime.py"],
                ["/usr/bin/tini", "--", "python", "deploy/runtime.py"],
                ["/tmp/docker-init", "--", "python", "deploy/runtime.py"],
                ["/sbin/docker-init", "-g", "--", "python", "deploy/runtime.py"],
                ["/sbin/docker-init", "--", "python", "deploy/runtime.py", "extra"],
                ["/sbin/docker-init", "--", "python", "manage.py"],
            ):
                processes = self.init_processes()
                processes["1"] = (processes["1"][0], command)
                with self.subTest(command=command), self.assertRaises(RuntimeError):
                    probe.check_mounts(self.init_mounts(), processes=processes, supervisor="2")
            for processes, supervisor in ((None, "2"), ({}, "2"), (self.init_processes(), "9")):
                with self.subTest(supervisor=supervisor), self.assertRaises(RuntimeError):
                    probe.check_mounts(
                        self.init_mounts(), processes=processes, supervisor=supervisor
                    )
            direct = {"1": self.init_processes()["2"]}
            with self.assertRaises(RuntimeError):
                probe.check_mounts(self.init_mounts(), processes=direct, supervisor="1")

    def test_init_real_file_root_owner_modes_and_kernel_executable_identity_are_required(self):
        good = dict(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0, st_dev=7, st_ino=19)
        for field, value in (
            ("st_mode", stat.S_IFDIR | 0o755),
            ("st_mode", stat.S_IFLNK | 0o755),
            ("st_mode", stat.S_IFIFO | 0o755),
            ("st_mode", stat.S_IFREG | 0o775),
            ("st_mode", stat.S_IFREG | 0o757),
            ("st_mode", stat.S_IFREG | 0o4755),
            ("st_mode", stat.S_IFREG | 0o2755),
            ("st_mode", stat.S_IFREG | 0o1755),
            ("st_mode", stat.S_IFREG | 0o644),
            ("st_uid", 1000),
            ("st_gid", 1000),
        ):
            target = SimpleNamespace(**{**good, field: value})
            with self.subTest(target_field=field, value=value), self.init_files(target=target):
                with self.assertRaises(RuntimeError):
                    probe.check_mounts(
                        self.init_mounts(), processes=self.init_processes(), supervisor="2"
                    )
        for field, value in (
            ("st_dev", 8),
            ("st_ino", 20),
            ("st_uid", 1000),
            ("st_gid", 1000),
            ("st_mode", stat.S_IFREG | 0o777),
        ):
            actual = SimpleNamespace(**{**good, field: value})
            with self.subTest(executable_field=field), self.init_files(executable=actual):
                with self.assertRaises(RuntimeError):
                    probe.check_mounts(
                        self.init_mounts(), processes=self.init_processes(), supervisor="2"
                    )
        with (
            self.init_files(resolved=Path("/usr/sbin/other-init")),
            self.assertRaises(RuntimeError),
        ):
            probe.check_mounts(self.init_mounts(), processes=self.init_processes(), supervisor="2")
        with self.init_files(), patch.object(Path, "resolve", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                probe.check_mounts(
                    self.init_mounts(), processes=self.init_processes(), supervisor="2"
                )

    def test_verified_init_does_not_allow_any_other_code_or_ancestor_shadow(self):
        with self.init_files():
            for path in (
                "/usr",
                "/usr/sbin",
                "/sbin",
                "/usr/sbin/docker-init.evil",
                "/usr/sbin/docker-init/child",
                "/usr/lib",
                "/app",
                "/etc/fonts",
            ):
                text = self.init_mounts() + f"4 1 0:4 / {path} ro - tmpfs tmpfs rw\n"
                with self.subTest(path=path), self.assertRaises(RuntimeError):
                    probe.check_mounts(text, processes=self.init_processes(), supervisor="2")

    def application(self):
        return application_environment(
            {
                "SECRET_KEY": "synthetic signing value",
                "DATABASE_URL": "postgresql://synthetic",
                "PAMOLIVE_ENCRYPTION_KEY": "synthetic encryption value",
                "PAMOLIVE_OIDC_CLIENT_ID": "synthetic-client",
                "PAMOLIVE_EVENT_MANUAL_DAILY_LIMIT": "5",
                "PAMOLIVE_MFA_REQUIRED": "true",
                "LDAPTLS_CACERT": "/etc/ssl/certs/ca-certificates.crt",
                "PAMOLIVE_SCIM_TOKEN": "synthetic-scim-token",
                "LANGUAGE": "synthetic",
                "LANG": "fr_FR.UTF-8",
                "LC_MESSAGES": "synthetic",
                "FONTCONFIG_FILE": "/tmp/fonts.conf",
                "XDG_CONFIG_HOME": "/tmp",
                "DISPLAY": ":99",
                "XAUTHORITY": "/tmp/xauth",
                "LOCPATH": "/tmp",
                "NLSPATH": "/tmp/%N",
            }
        )

    def test_web_jobs_locale_and_font_cleanup_preserves_application_values_exactly(self):
        result = self.application()
        probe.check_environment(result, "application")
        self.assertEqual(result["SECRET_KEY"], "synthetic signing value")
        self.assertEqual(result["PAMOLIVE_ENCRYPTION_KEY"], "synthetic encryption value")
        self.assertEqual(result["DATABASE_URL"], "postgresql://synthetic")
        self.assertEqual(result["PAMOLIVE_OIDC_CLIENT_ID"], "synthetic-client")
        self.assertEqual(result["PAMOLIVE_EVENT_MANUAL_DAILY_LIMIT"], "5")
        self.assertEqual(result["PAMOLIVE_MFA_REQUIRED"], "true")
        self.assertEqual(result["LDAPTLS_CACERT"], "/etc/ssl/certs/ca-certificates.crt")
        self.assertEqual(result["PAMOLIVE_SCIM_TOKEN"], "synthetic-scim-token")
        self.assertEqual(result["LANG"], "C.UTF-8")
        self.assertEqual(result["LC_ALL"], "C.UTF-8")
        self.assertEqual(result["HOME"], APP_HOME)
        self.assertEqual(result["LD_LIBRARY_PATH"], NATIVE_LIBRARIES)

    def test_loader_and_interpreter_overrides_are_not_silently_sanitized(self):
        for name in (
            "LD_PRELOAD",
            "LD_AUDIT",
            "PYTHONPATH",
            "PYTHONHOME",
            "GCONV_PATH",
            "LD_LIBRARY_PATH",
            "LD_FUTURE_LOADER_FLAG",
            "PYTHONINSPECT",
            "PYTHONUSERBASE",
            "PYTHONSTARTUP",
            "PYTHONWARNINGS",
            "PYTHON_FUTURE_SWITCH",
            "GLIBC_TUNABLES",
            "GIO_EXTRA_MODULES",
        ):
            with self.subTest(name=name), self.assertRaises(SystemExit):
                application_environment({name: "/tmp/synthetic"})

    def test_unknown_loader_names_are_refused_even_when_empty(self):
        for name in ("LD_UNKNOWN", "PYTHONUNKNOWN", "LD_PRELOAD"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_launch_environment({name: ""})
        for environment in ({"PYTHONUNBUFFERED": "0"}, {"PYTHONDONTWRITEBYTECODE": "0"}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                validate_launch_environment(environment)
        validate_launch_environment({"PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"})

    def test_preflight_environment_types_and_safe_values_are_explicit(self):
        for environment in ([], None, {"LANG": None}, {"LANG": 1}):
            with self.subTest(type=type(environment).__name__), self.assertRaises(ValueError):
                validate_launch_environment(environment)
        validate_launch_environment(
            {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "LD_LIBRARY_PATH": NATIVE_LIBRARIES,
                "PAMOLIVE_CONNECTOR_HOSTS": "synthetic.invalid",
            }
        )

    def fields(self):
        return {
            "Uid": "1000 1000 1000 1000",
            "Gid": "1000 1000 1000 1000",
            "Groups": "",
            "NoNewPrivs": "1",
            **dict.fromkeys(("CapEff", "CapPrm", "CapInh", "CapAmb"), "0"),
        }

    def test_effective_uid_gid_nonewprivileges_and_all_capability_sets_are_required(self):
        fields = self.fields()
        probe.check_privileges(fields, 1000)
        for field, value in (
            ("Uid", "0 1000 1000 1000"),
            ("Gid", "0 1000 1000 1000"),
            ("Groups", "1000 1001"),
            ("NoNewPrivs", "0"),
            ("CapEff", "1"),
            ("CapPrm", "1"),
            ("CapInh", "1"),
            ("CapAmb", "1"),
        ):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                probe.check_privileges({**fields, field: value}, 1000)

    def test_effective_environment_rejects_new_display_font_locale_or_loader_names(self):
        environment = self.application()
        for field, value in (
            ("LANG", "fr_FR.UTF-8"),
            ("LC_ALL", "C"),
            ("DISPLAY", ""),
            ("FONTCONFIG_FILE", "/tmp/f"),
            ("LD_PRELOAD", ""),
            ("XDG_CONFIG_HOME", "/tmp"),
            ("LC_TIME", "C.UTF-8"),
        ):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                probe.check_environment({**environment, field: value}, "application")

    def test_native_environment_remains_small_without_application_secrets(self):
        environment = {
            "PATH": APPLICATION_PATH,
            "LANG": "C.UTF-8",
            "LD_LIBRARY_PATH": NATIVE_LIBRARIES,
            "PYTHONUNBUFFERED": "1",
            "HOME": "/tmp/pamolive-engine-synthetic",
            "GUACAMOLE_HOME": "/tmp/pamolive-engine-synthetic",
        }
        probe.check_environment(environment, "native")
        for name in ("DATABASE_URL", "SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY", "FONTCONFIG_PATH"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                probe.check_environment({**environment, name: "synthetic"}, "native")
        with self.assertRaises(RuntimeError):
            probe.check_environment(
                {**environment, "HOME": "/tmp/pamolive-engine-a/../bad"}, "native"
            )

    def test_native_home_requires_private_mode_owner_and_real_directory(self):
        path = SimpleNamespace(
            lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1001, st_gid=1001)
        )
        probe.check_private_home(path, 1001)
        for mode, uid, gid in (
            (stat.S_IFDIR | 0o755, 1001, 1001),
            (stat.S_IFDIR | 0o700, 1000, 1001),
            (stat.S_IFDIR | 0o700, 1001, 1000),
            (stat.S_IFLNK | 0o700, 1001, 1001),
        ):
            path = SimpleNamespace(
                lstat=lambda: SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)
            )
            with self.subTest(mode=mode, uid=uid), self.assertRaises(RuntimeError):
                probe.check_private_home(path, 1001)

    def mounts(self):
        return (
            "1 0 0:1 / / ro,relatime - overlay overlay rw\n"
            "2 1 0:2 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,size=65536k,mode=1777\n"
        )

    def test_font_and_application_home_anchors_cannot_be_symlinks_or_writable_by_other_roles(self):
        for mode, uid in (
            (stat.S_IFLNK | 0o755, 0),
            (stat.S_IFDIR | 0o777, 0),
            (stat.S_IFDIR | 0o755, 1000),
        ):
            path = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=mode, st_uid=uid))
            with self.subTest(mode=mode, uid=uid), self.assertRaises(RuntimeError):
                probe.check_readonly_directory(path, 0)

    def test_effective_mounts_require_readonly_root_bounded_tmpfs_and_no_shadows(self):
        probe.check_mounts(self.mounts())
        for changed in (
            self.mounts().replace("ro,relatime", "rw,relatime"),
            self.mounts().replace("size=65536k", "size=65537k"),
            self.mounts().replace("rw,nosuid,nodev", "ro,nosuid,nodev"),
            self.mounts().replace("- tmpfs tmpfs", "- ext4 /dev/synthetic"),
            self.mounts()
            .replace("ro,relatime", "rw,relatime")
            .replace("- overlay overlay rw", "- overlay overlay ro"),
        ):
            with self.subTest(mount=changed), self.assertRaises(RuntimeError):
                probe.check_mounts(changed)
        for target in (
            "/etc/fonts",
            "/etc",
            "/home",
            "/var",
            "/etc/fonts/conf.d",
            "/usr/lib",
            "/app",
            "/opt",
            "/bin",
            "/home/pamolive",
            "/tmp/hidden",
        ):
            added = f"3 1 0:3 / {target} rw - tmpfs tmpfs rw,size=1024k\n"
            with self.subTest(target=target), self.assertRaises(RuntimeError):
                probe.check_mounts(self.mounts() + added)

    def services(self):
        return {
            "11": (
                {"Uid": "1000 1000 1000 1000", "PPid": "2"},
                [
                    "/usr/local/bin/python",
                    "-m",
                    "uvicorn",
                    "config.asgi:application",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "8000",
                    "--workers",
                    "3",
                    "--no-proxy-headers",
                    "--ws-max-size",
                    "65536",
                    "--ws-per-message-deflate",
                    "false",
                    "--limit-concurrency",
                    "256",
                    "--timeout-graceful-shutdown",
                    "10",
                ],
            ),
            "12": (
                {"Uid": "1000 1000 1000 1000", "PPid": "2"},
                ["/usr/local/bin/python", "manage.py", "runjobs"],
            ),
            "13": (
                {"Uid": "1001 1001 1001 1001", "PPid": "2"},
                [
                    "/opt/pamolive-guac/sbin/guacd",
                    "-f",
                    "-b",
                    "127.0.0.1",
                    "-l",
                    "4822",
                    "-p",
                    "/tmp/pamolive-engine-synthetic/guacd.pid",
                    "-L",
                    "error",
                ],
            ),
        }

    def test_probe_requires_actual_web_jobs_native_children_of_supervisor(self):
        probe.check_service_commands(self.services(), "2")
        for pid in self.services():
            processes = self.services()
            del processes[pid]
            with self.subTest(missing=pid), self.assertRaises(RuntimeError):
                probe.check_service_commands(processes, "2")
            processes = self.services()
            processes[pid][0]["PPid"] = "99"
            with self.subTest(reparented=pid), self.assertRaises(RuntimeError):
                probe.check_service_commands(processes, "2")
        processes = self.services()
        processes["13"][1][3] = "0.0.0.0"
        with self.assertRaises(RuntimeError):
            probe.check_service_commands(processes, "2")

    def test_web_command_allows_only_exact_arguments_and_bounded_positive_worker_count(self):
        for workers in ("1", "3", "256"):
            processes = self.services()
            processes["11"][1][9] = workers
            with self.subTest(workers=workers):
                probe.check_service_commands(processes, "2")
        original = self.services()["11"][1]
        mutations = [
            original + extra
            for extra in (
                ["--app-dir", "/tmp"],
                ["--factory"],
                ["--host", "127.0.0.1"],
                ["--workers", "2"],
                ["unreviewed-suffix"],
            )
        ]
        mutations.append(original[:4])
        for workers in ("0", "257", "-1", "+1", "01", "1.5", "1 ", "synthetic", "9999"):
            command = list(original)
            command[9] = workers
            mutations.append(command)
        for index, value in ((5, "127.0.0.1"), (7, "8080"), (14, "true"), (16, "512")):
            command = list(original)
            command[index] = value
            mutations.append(command)
        for command in mutations:
            processes = self.services()
            processes["11"] = (processes["11"][0], command)
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                probe.check_service_commands(processes, "2")

    def test_supervisor_launches_only_isolated_children_with_sanitized_environments(self):
        child = Mock()
        child.poll.return_value = 0
        environment = self.application()
        environment["SECRET_KEY"] = "s" * 64
        environment["PAMOLIVE_ENCRYPTION_KEY"] = "e" * 64
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(os, "geteuid", return_value=0, create=True),
            patch.object(runtime, "children", []),
            patch.object(runtime, "stopping", False),
            patch("signal.signal"),
            patch.object(runtime.subprocess, "Popen", return_value=child) as launch,
        ):
            self.assertEqual(runtime.main(), 1)
        self.assertEqual(launch.call_count, 3)
        actual_web = list(launch.call_args_list[1].args[0])
        # The supervisor uses sys.executable; this pure test also runs on Windows.
        actual_web[0] = "/usr/local/bin/python"
        processes = self.services()
        processes["11"] = (processes["11"][0], actual_web)
        probe.check_service_commands(processes, "2")
        for call, uid in zip(launch.call_args_list, (1001, 1000, 1000), strict=True):
            self.assertEqual(call.kwargs["user"], uid)
            self.assertEqual(call.kwargs["group"], uid)
            self.assertEqual(call.kwargs["extra_groups"], [])
            if uid == 1000:
                probe.check_environment(call.kwargs["env"], "application")
                self.assertEqual(call.kwargs["env"]["PAMOLIVE_SCIM_TOKEN"], "synthetic-scim-token")
            else:
                self.assertEqual(
                    set(call.kwargs["env"]), {"PATH", "LANG", "LD_LIBRARY_PATH", "PYTHONUNBUFFERED"}
                )

    def test_importing_both_modules_performs_no_runtime_or_network_actions(self):
        root = Path(__file__).resolve().parents[1]
        with (
            patch("subprocess.Popen") as launch,
            patch("urllib.request.urlopen") as network,
            patch.object(Path, "iterdir") as processes,
        ):
            for name in ("runtime.py", "check_runtime.py"):
                runpy.run_path(str(root / "deploy" / name), run_name="runtime_import_only")
        launch.assert_not_called()
        network.assert_not_called()
        processes.assert_not_called()

    def test_proc_read_budget_and_environment_duplicates_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-proc"
            path.write_bytes(b"x" * 129)
            with self.assertRaises(RuntimeError):
                probe.read_bounded(path, 128)
        with self.assertRaises(RuntimeError):
            probe.environment_fields(b"LANG=C.UTF-8\x00LANG=C\x00")
        self.assertEqual(probe.environment_fields(b"TEST=a=b\x00"), {"TEST": "a=b"})

    def test_importing_runtime_does_not_start_services_or_require_secrets(self):
        import subprocess
        import sys

        child = subprocess.run(
            [sys.executable, "-c", "import deploy.runtime, deploy.check_runtime"],
            env={
                key: value
                for key, value in os.environ.items()
                if key not in {"SECRET_KEY", "PAMOLIVE_ENCRYPTION_KEY", "DATABASE_URL"}
            },
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(child.returncode, 0)
        self.assertEqual(child.stdout, b"")
        self.assertEqual(child.stderr, b"")

    def test_probe_script_and_module_import_without_pythonpath(self):
        import subprocess
        import sys

        root = Path(__file__).resolve().parents[1]
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        for folder, invocation in (
            (root / "deploy", "runpy.run_path('check_runtime.py', run_name='__main__')"),
            (root, "runpy.run_module('deploy.check_runtime', run_name='__main__')"),
        ):
            child = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import runpy,sys; sys.platform='import-only'; " + invocation,
                ],
                cwd=folder,
                env=environment,
                capture_output=True,
                timeout=10,
                check=False,
            )
            with self.subTest(invocation=invocation):
                self.assertEqual(child.returncode, 1)
                self.assertEqual(child.stdout, b"")
                self.assertEqual(
                    child.stderr.decode().strip(),
                    "Runtime profile check failed; inspect the isolated laboratory privately.",
                )
