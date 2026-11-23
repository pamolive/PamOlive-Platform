"""Run a synthetic native portal case in a GitHub-owned loopback."""

import argparse
import asyncio
import hashlib
import os
import re
import secrets
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from qualification.p1g_headless import (  # noqa: E402
    chrome_bootstrap,
    chrome_bundle,
    chrome_probe_stage,
    guacd_namespace,
    postgres_namespace,
    rdp_namespace,
    run_lab,
)
from qualification.p1g_headless import (  # noqa: E402
    chrome_sandbox_probe as chrome,
)
from qualification.p1g_headless import (  # noqa: E402
    lab_support as support,
)

REF = "refs/heads/" + support.NATIVE_BRANCH
RDP_REF = "refs/heads/" + support.NATIVE_RDP_BRANCH
MANDATE_REF = "refs/heads/" + support.NATIVE_MANDATE_BRANCH
PREFIX = "pamolive-native-private-"
PARAMETERS = {
    "ssh": {"hostname", "port", "username", "password", "host-key"},
    "rdp": {
        "hostname", "port", "username", "password", "domain", "cert-fingerprints",
        "ignore-cert", "cert-tofu", "security",
    },
}


async def verify_guacd(protocol):
    from deploy.check_guacd import plugin_arguments

    for _ in range(40):
        try:
            arguments = await plugin_arguments(guacd_namespace.PORT, protocol)
        except ConnectionRefusedError:
            await asyncio.sleep(0.25)
        else:
            support.need(PARAMETERS[protocol] <= arguments, "native_plugin_parameters")
            return
    raise ValueError("native_guacd_readiness")


def worker(private, inherited, expected, protocol):
    chrome.isolated_worker_status(inherited)
    support.need(os.stat("/proc/self/ns/net").st_ino == expected, "native_namespace_identity")
    support.need(not os.access("/var/run/docker.sock", os.W_OK), "native_docker_socket_access")
    database = postgres_namespace.read_loopback(private)
    asyncio.run(verify_guacd(protocol))
    password = (private / "postgres-password").read_text(encoding="ascii")
    support.need(re.fullmatch(r"[A-Za-z0-9_-]{32}", password), "native_database_password_shape")
    home = private / "worker-home"
    home.mkdir(mode=0o700)
    os.environ.update(
        HOME=str(home),
        DATABASE_URL=f"postgresql://p1g:{password}@127.0.0.1:5432/pamolive_p1g",
        PAMOLIVE_TEST_DATABASE_NAME="test_pamolive_p1g_browser",
        PAMOLIVE_P1G_DISPOSABLE="1",
        SECRET_KEY=secrets.token_urlsafe(48),
        PAMOLIVE_ENCRYPTION_KEY=secrets.token_urlsafe(48),
    )
    support.guard(os.environ, native_lab=True)
    support.fresh_write(private / "transport.json", chrome_bundle.canonical({
        "database": database, "owned_loopback": True, "plugin": protocol,
        "plugin_parameters_verified": True,
    }))
    return run_lab.worker(private, native_protocol=protocol, isolated=True)


def acceptable(packet, revision, protocol="ssh"):
    stop_phase = run_lab.RDP_STOP_PHASE if protocol == "rdp" else run_lab.STOP_PHASE
    return (
        packet.get("schema") == "pamolive.p1g-browser-worker/1"
        and packet.get("case") == "native_" + protocol
        and packet.get("state") == "OBSERVED_SYNTHETIC_INCREMENT_ONLY"
        and packet.get("full_P1G_qualified") is False
        and packet.get("source", {}).get("revision") == revision
        and packet.get("tests") == 1
        and all(packet.get(field) == 0 for field in ("failures", "errors", "skips"))
        and all(packet.get(field) is True for field in (
            "native_PAM_transport_observed", "browser_E2E_executed", "SDK_cleanup_completed",
            "live_server_thread_closed", "fresh_test_database_absent_after_runner",
            "base_database_OID_preserved",
        ))
        and stop_phase in packet.get("observed_UI_phases", [])
        and support.NATIVE_MANDATE_PHASE in packet.get("observed_UI_phases", [])
        and (protocol != "rdp" or packet.get("native_RDP_display_and_NLA_observed") is True)
        and support.sandbox_receipt(packet.get("browser_sandbox"))
    )


def read_packet(io, path):
    packet = chrome_bundle.json_bytes(io.read_regular(path, 65536))
    support.need(type(packet) is dict, "native_worker_packet")
    return packet


def run_isolated(commands, command, private, report, revision, protocol):
    try:
        commands.run(command, seconds=660, cap=262144, sudo=True)
    finally:
        if (private / "transport.json").exists():
            report["transport"] = read_packet(commands.io, private / "transport.json")
        if (private / "worker-report.json").exists():
            report["portal"] = read_packet(commands.io, private / "worker-report.json")
    support.need(report.get("transport") == {
        "database": {
            "server_version_num": postgres_namespace.VERSION, "verified_loopback_SQL": True,
        },
        "owned_loopback": True, "plugin": protocol, "plugin_parameters_verified": True,
    }, "native_transport_receipt")
    support.need(acceptable(report["portal"], revision, protocol), "native_portal_receipt")


def supervisor(scratch, identity, image, protocol, branch):
    public = scratch / f"pamolive-native-{protocol}-{identity['run']}-{identity['attempt']}.json"
    report = {
        "schema": "pamolive.native-portal-ci/1",
        **identity,
        "protocol": protocol,
        "state": "REFUSED",
        "full_P1G_qualified": False,
    }
    phase = "runner"
    try:
        report["runner_facts"] = chrome.runner_facts(identity["runner"])
        with tempfile.TemporaryDirectory(dir=scratch, prefix=PREFIX) as name:
            private = Path(name)
            journals = private / "journals"
            journals.mkdir(mode=0o700)
            commands = chrome_bootstrap.Commands(
                support, support.bounded(ROOT), private, journals, horizon=1100,
            )
            manifest = commands.io.read_regular(scratch / "p1g-source.json", 2 * 1024**2)
            report["source_manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
            source = chrome_bundle.json_bytes(manifest)
            support.need(source["revision"] == identity["revision"], "native_source_revision")
            for filename in ("receipt.json", "probe.json"):
                public_input = commands.io.read_regular(scratch / "p1g-context" / filename, 65536)
                report["context_" + filename.removesuffix(".json") + "_sha256"] = (
                    hashlib.sha256(public_input).hexdigest()
                )
            phase = "authenticated_chrome"
            names = chrome.prepare(commands, private, report)
            phase = "postgres"
            with postgres_namespace.service(private, identity, report) as (namespace, database_id):
                inherited = os.stat("/proc/self/ns/net").st_ino
                expected = chrome.read_namespace_inode(commands, namespace, identity["runner"])
                support.need(expected > 0 and expected != inherited, "native_namespace_identity")
                phase = "guacd"
                with ExitStack() as services:
                    services.enter_context(
                        guacd_namespace.service(private, identity, image, database_id, report)
                    )
                    if protocol == "rdp":
                        phase = "rdp_peer"
                        services.enter_context(rdp_namespace.service(
                            private, identity, image, database_id, report,
                            wrapper_sha256=source["files"][run_lab.RDP_INPUTS[0]],
                        ))
                    phase = "portal_worker"
                    command = chrome.worker_command(
                        private, scratch, identity, inherited, namespace, expected,
                        script=Path(__file__).resolve(), branch=branch,
                    )
                    run_isolated(
                        commands, [*command, "--protocol", protocol],
                        private, report, identity["revision"], protocol,
                    )
                    support.need(
                        report["portal"]["source"]["context_receipt_SHA256"]
                        == report["source_manifest_sha256"],
                        "native_portal_manifest_binding",
                    )
            phase = "tree_recheck"
            chrome_probe_stage.verify_tree(names, private / "chrome", until=commands.until - 10)
            support.need(
                report.get("guacd_container_removed") is True
                and report.get("postgres_container_removed") is True,
                "native_container_cleanup",
            )
            if protocol == "rdp":
                support.need(
                    report.get("rdp_container_removed") is True
                    and report.get("rdp_fixture_reaped") is True,
                    "native_rdp_cleanup",
                )
        report.update(
            state=f"NATIVE_{protocol.upper()}_PORTAL_OBSERVED", workspace_cleaned=True,
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        code = str(exc) if type(exc) is ValueError else ""
        report.update(
            phase=phase,
            code=code if re.fullmatch(r"[A-Za-z0-9_]{1,70}", code) else "native_lab_refused",
        )
    support.fresh_write(public, chrome_bundle.canonical(report))
    return 0 if report["state"] == f"NATIVE_{protocol.upper()}_PORTAL_OBSERVED" else 42


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--worker", type=Path)
    mode.add_argument("--image")
    parser.add_argument("--host-net", type=int)
    parser.add_argument("--expected-net", type=int)
    parser.add_argument("--protocol", choices=("ssh", "rdp"), default="ssh")
    args = parser.parse_args()
    os.umask(0o077)
    branch = os.environ.get("GITHUB_REF")
    support.need(branch in (REF, RDP_REF, MANDATE_REF), "native_branch_scope")
    support.need(args.protocol == "ssh" or branch in (RDP_REF, MANDATE_REF),
                 "native_rdp_branch_scope")
    identity = chrome.run_identity(os.environ, branch=branch)
    scratch = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    support.need(
        identity["runner"] == "ubuntu-22.04"
        and sys.platform == "linux" and os.getuid() > 0
        and ROOT == scratch / "p1g-source",
        "native_lab_scope",
    )
    if args.worker is not None:
        private = args.worker.resolve(strict=True)
        support.need(
            private == args.worker and private.parent == scratch and private.name.startswith(PREFIX)
            and args.host_net is not None and args.expected_net is not None,
            "native_worker_scope",
        )
        try:
            return worker(private, args.host_net, args.expected_net, args.protocol)
        except (OSError, ValueError, RuntimeError, ImportError):
            return 42
    support.need(
        re.fullmatch(guacd_namespace.IMAGE_ID, args.image)
        and args.host_net is None and args.expected_net is None,
        "native_image_scope",
    )
    return supervisor(scratch, identity, args.image, args.protocol, branch)


if __name__ == "__main__":
    raise SystemExit(main())
