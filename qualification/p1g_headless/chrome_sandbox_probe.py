"""Measure the relocated Chrome 158 sandbox on an isolated GitHub runner."""

import argparse
import importlib.metadata
import os
import re
import socket
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from qualification.p1g_headless import (  # noqa: E402
    chrome_bootstrap as bootstrap,
)
from qualification.p1g_headless import (  # noqa: E402
    chrome_bundle,
    chrome_key_scope,
    chrome_metadata,
    chrome_probe_stage,
)
from qualification.p1g_headless import (  # noqa: E402
    lab_support as support,
)

BRANCH = "refs/heads/agent/p1g-chrome158-sandbox-probe"
PURPOSE = "RELOCATED_SANDBOX_MEASUREMENT_ONLY"
PACKAGE_VERSION = "158.0.8127.36-1"
BROWSER_VERSION = PACKAGE_VERSION.removesuffix("-1")
CHROME_SHA = "08d5a3fba3197010b28113da201bd31a49b4439619dbf558f8040e4015c787bb"
CHROME_BYTES = 309615944
PROFILE = {
    "package_sha256": "4696bce00b128f385a870ba2eb6eede61698f22374ea0d8e09af8a1c6543d397",
    "tree_sha256": "e8545b0a610999293b90f1a10eaadf51ba517c6fb41b71557ed16934305e5664",
    "privileged_roles": {
        "chrome-sandbox": {
            "mode": 0o4755,
            "role": "setuid-sandbox-helper",
            "sha256": "c6733ac7189cd66d34b0dc5715d58b7ae30b01984a7cc814a7cd8f824f81ea7a",
        },
    },
}
WORK_PREFIX = "pamolive-sandbox-private-"
CAP_FIELDS = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}


def run_identity(env):
    support.need(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REPOSITORY") == chrome_metadata.REPOSITORY
        and env.get("GITHUB_EVENT_NAME") == "push"
        and env.get("GITHUB_REF") == BRANCH,
        "sandbox_probe_scope",
    )
    fields = {"revision": "GITHUB_SHA", "run": "GITHUB_RUN_ID", "attempt": "GITHUB_RUN_ATTEMPT"}
    result = {name: env.get(var, "") for name, var in fields.items()}
    support.need(
        re.fullmatch(r"[0-9a-f]{40}", result["revision"])
        and all(re.fullmatch(r"[1-9][0-9]{0,19}", result[name]) for name in ("run", "attempt")),
        "sandbox_probe_identity",
    )
    return result


def check_isolation(status, interfaces, inherited_net, current_net, socket_descriptors, uid):
    """Require a private IP network and no privilege in the browser process tree."""
    fields = {}
    checked = CAP_FIELDS | {"NoNewPrivs", "Groups", "Uid"}
    for line in status.decode("ascii").splitlines():
        name, _, value = line.partition(":")
        if name in checked:
            support.need(name not in fields, "sandbox_probe_status_duplicate")
            fields[name] = value.split()
    expected = {
        **{name: ["0000000000000000"] for name in CAP_FIELDS},
        "NoNewPrivs": ["1"],
        "Groups": [],
        "Uid": [str(uid)] * 4,
    }
    support.need(fields == expected and uid > 0, "sandbox_probe_privileges")
    support.need(
        inherited_net > 0
        and current_net > 0
        and inherited_net != current_net
        and interfaces == [(1, "lo")],
        "sandbox_probe_network_namespace",
    )
    support.need(not socket_descriptors, "sandbox_probe_inherited_socket")


def isolated_worker_status(inherited_net):
    with open("/proc/self/status", "rb") as stream:
        status = stream.read(16385)
    support.need(0 < len(status) <= 16384, "sandbox_probe_status_budget")
    # The owned subprocess starts with only the runner pipes and a null input.
    sockets = [fd for fd in (0, 1, 2) if stat.S_ISSOCK(os.fstat(fd).st_mode)]
    check_isolation(
        status,
        socket.if_nameindex(),
        inherited_net,
        os.stat("/proc/self/ns/net").st_ino,
        sockets,
        os.getuid(),
    )


def worker(work, inherited_net):
    try:
        isolated_worker_status(inherited_net)
    except (OSError, ValueError) as exc:
        return refused_worker("isolation", exc)
    try:
        return browser_probe(work)
    except (ImportError, OSError, ValueError) as exc:
        return refused_worker("prerequisites", exc)


def browser_probe(work):
    binary = work / "chrome" / "chrome"
    before = support.tool_pin(binary, root_owner=False)
    support.need(
        before["sha256"] == CHROME_SHA and before["bytes"] == CHROME_BYTES,
        "sandbox_probe_executable_pin",
    )
    home = work / "browser-home"
    home.mkdir(mode=0o700)
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    os.environ.clear()
    os.environ.update(env)
    from playwright.sync_api import sync_playwright

    distribution = importlib.metadata.distribution("playwright")
    support.need(distribution.version == support.SDK_VERSION, "sandbox_probe_playwright_version")
    driver = Path(distribution.locate_file("playwright/driver/node"))
    driver_before = support.playwright_node_pin(driver)
    phase = "launch"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=str(binary),
                headless=True,
                chromium_sandbox=True,
                timeout=20000,
                env=env,
                args=["--disable-crash-reporter", "--disable-crashpad-for-testing"],
            )
            try:
                phase = "observe"
                support.need(browser.version == BROWSER_VERSION, "sandbox_probe_browser_version")
                active = support.observe_browser_sandbox(browser, binary, namespace_only=True)
            finally:
                browser.close()
    except Exception as exc:
        return refused_worker(phase, exc)
    support.need(
        support.tool_pin(binary, root_owner=False) == before, "sandbox_probe_binary_changed"
    )
    support.need(
        support.playwright_node_pin(driver) == driver_before,
        "sandbox_probe_driver_changed",
        "playwright_driver_identity",
    )
    return {
        "state": "SANDBOX_OBSERVED",
        "ip_network_isolated": True,
        "version": BROWSER_VERSION,
        "layer_one": "Namespace",
        "renderer_evidence": active,
    }


MEASUREMENT_REFUSALS = {
    "isolation": {
        "sandbox_probe_status_budget",
        "sandbox_probe_status_duplicate",
        "sandbox_probe_privileges",
        "sandbox_probe_network_namespace",
        "sandbox_probe_inherited_socket",
        "sandbox_probe_worker_path",
    },
    "prerequisites": {
        "sandbox_probe_executable_pin",
        "sandbox_probe_playwright_version",
        "sandbox_probe_binary_changed",
        "sandbox_probe_driver_changed",
        "tool_alias_refused",
        "tool_type_owner_mode",
        "tool_fd_identity",
        "tool_byte_budget",
        "tool_changed_or_not_ELF",
    },
    "launch": {"namespace_startup_refused", "browser_dependencies_unavailable"},
    "observe": {"sandbox_namespace_required", "chromium_sandbox_not_active"},
}


def failure_code(phase, error):
    detail = str(error)[-8192:]
    if isinstance(error, ValueError) and detail in MEASUREMENT_REFUSALS[phase]:
        return detail
    if phase == "launch":
        if any(
            text in detail
            for text in (
                "No usable sandbox",
                "Failed to move to new namespace",
                "zygote_host_impl_linux",
            )
        ):
            return "namespace_startup_refused"
        if "error while loading shared libraries" in detail:
            return "browser_dependencies_unavailable"
    return "browser_measurement_refused"


def refused_worker(phase, error):
    return {
        "state": "REFUSED",
        "phase": phase,
        "code": failure_code(phase, error),
        "ip_network_isolated": phase != "isolation",
    }


def worker_command(work, scratch, identity, inherited_net):
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": chrome_metadata.REPOSITORY,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": BRANCH,
        "GITHUB_SHA": identity["revision"],
        "GITHUB_RUN_ID": identity["run"],
        "GITHUB_RUN_ATTEMPT": identity["attempt"],
        "RUNNER_TEMP": str(scratch),
    }
    return [
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/bin/unshare",
        "--net",
        "--",
        "/usr/bin/setpriv",
        "--reuid",
        str(os.getuid()),
        "--regid",
        str(os.getgid()),
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--",
        "/usr/bin/env",
        "-i",
        *(f"{name}={value}" for name, value in env.items()),
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--worker",
        str(work),
        "--host-net",
        str(inherited_net),
    ]


def prepare(commands, private, receipt):
    materials = private / "metadata"
    materials.mkdir(mode=0o700)
    original = bootstrap.read(
        ROOT / "qualification/p1g_headless/chrome_materials/google-key.asc", chrome_key_scope.LIMIT
    )
    support.need(
        bootstrap.sha(original) == chrome_key_scope.ORIGINAL_SHA256, "sandbox_probe_key_pin"
    )
    pins = chrome_bundle.json_bytes(bootstrap.read(ROOT / bootstrap.PIN_PATH, 131072))
    expected = pins["package"]
    support.need(
        expected["Version"] == PACKAGE_VERSION and expected["SHA256"] == PROFILE["package_sha256"],
        "sandbox_probe_package_pin",
    )
    _, facts = chrome_metadata.acquire(commands, materials, private, original, expected)
    support.need(facts["package"] == expected, "sandbox_probe_metadata_changed")
    with chrome_metadata.authenticated_payload(commands, private, expected, receipt) as stream:
        tree = chrome_bundle.inventory(stream, expected["SHA256"], until=commands.until - 120)
        names = chrome_bundle._admitted_tree(tree, PROFILE)
        chrome_probe_stage.materialize(
            stream, names, private / "chrome", until=commands.until - 120
        )
    receipt.update(
        {
            "package_sha256": expected["SHA256"],
            "tree_sha256": tree["tree_sha256"],
            "chrome_sha256": CHROME_SHA,
            "signer": facts["signature"],
        }
    )
    return names


def valid_worker_result(result):
    if type(result) is not dict:
        return False
    if result.get("state") == "REFUSED":
        phase, code = result.get("phase"), result.get("code")
        return (
            set(result) == {"state", "phase", "code", "ip_network_isolated"}
            and type(phase) is str
            and phase in MEASUREMENT_REFUSALS
            and type(code) is str
            and code in MEASUREMENT_REFUSALS[phase] | {"browser_measurement_refused"}
            and result["ip_network_isolated"] is (phase != "isolation")
        )
    return (
        set(result) == {"state", "version", "ip_network_isolated", "layer_one", "renderer_evidence"}
        and result["state"] == "SANDBOX_OBSERVED"
        and result["ip_network_isolated"] is True
        and result["version"] == BROWSER_VERSION
        and result["layer_one"] == "Namespace"
        and support.sandbox_receipt(result["renderer_evidence"])
    )


def launcher_status(journals, number):
    note = journals / ("command-" + str(number)) / "process.json"
    try:
        facts = chrome_bundle.json_bytes(bootstrap.read(note, 8192))
        status = facts.get("returncode")
        if type(status) is int and -255 <= status <= 255:
            return status
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def supervisor(scratch, identity):
    public = scratch / ("pamolive-sandbox-" + identity["run"] + "-" + identity["attempt"] + ".json")
    report = {
        "schema": "pamolive.chrome-sandbox-probe/1",
        **identity,
        "purpose": PURPOSE,
        "state": "REFUSED",
        "operational_GO": False,
        "ui_executed": False,
    }
    phase = "source"
    try:
        with tempfile.TemporaryDirectory(dir=scratch, prefix=WORK_PREFIX) as temporary:
            private = Path(temporary)
            journals = private / "journals"
            journals.mkdir(mode=0o700)
            commands = bootstrap.Commands(
                support, support.bounded(ROOT), private, journals, horizon=540
            )
            phase = "authenticated_stage"
            names = prepare(commands, private, report)
            phase = "isolated_worker"
            inherited = os.stat("/proc/self/ns/net").st_ino
            try:
                response = commands.run(
                    worker_command(private, scratch, identity, inherited),
                    seconds=75,
                    cap=8192,
                    sudo=True,
                )
            except (OSError, ValueError):
                status = launcher_status(journals, commands.number)
                if status is not None:
                    report["launcher_exit_status"] = status
                raise
            result = chrome_bundle.json_bytes(response)
            support.need(valid_worker_result(result), "sandbox_probe_worker_receipt")
            phase = "tree_recheck"
            chrome_probe_stage.verify_tree(names, private / "chrome", until=commands.until - 10)
        report.update(result, workspace_cleaned=True)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        code = str(exc) if type(exc) is ValueError else ""
        report.update(
            phase=phase,
            code=code if re.fullmatch(r"[A-Za-z0-9_]{1,70}", code) else "sandbox_probe_refused",
        )
    support.fresh_write(public, chrome_bundle.canonical(report))
    return 0 if report["state"] == "SANDBOX_OBSERVED" else 42


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--host-net", type=int)
    args = parser.parse_args()
    support.need(
        sys.platform == "linux" and os.getuid() == os.geteuid() > 0, "sandbox_probe_nonroot"
    )
    identity = run_identity(os.environ)
    scratch = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if args.worker is None:
        support.need(args.host_net is None, "sandbox_probe_args")
        return supervisor(scratch, identity)
    work = args.worker
    try:
        support.need(
            args.host_net is not None
            and work.parent == scratch
            and work.name.startswith(WORK_PREFIX)
            and work.resolve(strict=True) == work
            and work.stat().st_uid == os.getuid()
            and stat.S_IMODE(work.stat().st_mode) == 0o700,
            "sandbox_probe_worker_path",
        )
        result = worker(work, args.host_net)
    except (OSError, ValueError) as exc:
        result = refused_worker("isolation", exc)
    print(chrome_bundle.canonical(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
