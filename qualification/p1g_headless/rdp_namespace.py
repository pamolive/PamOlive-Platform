"""Own the headless RDP fixture in the same loopback as the portal and guacd."""

import hashlib
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path

from qualification.p1g_headless import guacd_namespace, rdp_peer
from qualification.p1g_headless.lab_support import need
from qualification.p1g_headless.postgres_namespace import CONTAINER_ID, docker

OWNER_LABEL = "io.pamolive.p1g-rdp"
BINARY = "/opt/pamolive-test/rdp-fixture"
ENTRYPOINT = "/usr/local/bin/python3.12"
SCRIPT = "/run/p1g-rdp-peer.py"
COMMAND = ["-I", "-B", SCRIPT]
INSPECT = (
    guacd_namespace.INSPECT[:-1]
    + ',"mounts":{{json .Mounts}},"exit_code":{{json .State.ExitCode}}}'
)


def admit(row, *, cid, owner, image, network, user, state, script):
    need(
        isinstance(row, dict) and row.get("id") == cid and row.get("name") == "/" + owner
        and row.get("image") == image and row.get("mode") == network
        and row.get("ports") in (None, {}) and row.get("publish_all") is False
        and row.get("privileged") is False and row.get("read_only") is True
        and row.get("running") is True and row.get("caps") in (["ALL"], ["CAP_ALL"])
        and row.get("security") in (["no-new-privileges"], ["no-new-privileges:true"])
        and row.get("user") == user and row.get("entrypoint") == [ENTRYPOINT]
        and row.get("cmd") == COMMAND and type(row.get("mounts")) is list,
        "rdp_container_identity",
    )
    mounts = {
        (item["Type"], item["Source"], item["Destination"], item["RW"])
        for item in row["mounts"]
        if not (item["Type"] == "tmpfs" and item["Destination"] == "/tmp" and item["RW"] is True)
    }
    need(mounts == {
        ("bind", str(state), str(rdp_peer.STATE), True),
        ("bind", str(script), SCRIPT, False),
    }, "rdp_container_mounts")


@contextmanager
def service(private, identity, image, database_id, receipt, *, wrapper_sha256):
    need(guacd_namespace.IMAGE_ID.fullmatch(image) and CONTAINER_ID.fullmatch(database_id),
         "rdp_fixture_identity")
    user = f"{os.getuid()}:{os.getgid()}"
    profile = ["--user", user, *guacd_namespace.NATIVE_LIMITS]
    raw = docker(
        private, ["run", "--rm", "--network", "none", *profile,
                  "--entrypoint", "/usr/bin/sha256sum", image, BINARY],
        timeout=25, code="rdp_executable_inspect",
    ).decode("ascii").split()
    need(len(raw) == 2 and re.fullmatch(r"[0-9a-f]{64}", raw[0]) and raw[1] == BINARY,
         "rdp_executable_identity")
    state = private / "rdp-state"
    state.mkdir(mode=0o700)
    script = Path(rdp_peer.__file__).resolve(strict=True)
    script_sha = hashlib.sha256(script.read_bytes()).hexdigest()
    need(script_sha == wrapper_sha256, "rdp_wrapper_source_binding")
    owner = "pamolive-p1g-rdp-" + identity["run"] + "-" + identity["attempt"]
    label = f"{OWNER_LABEL}={identity['revision']}-{identity['run']}-{identity['attempt']}"
    network = "container:" + database_id
    cidfile = private / "rdp.cid"
    cid = None
    try:
        docker(private, [
            "run", "--detach", "--init", "--network", network, *profile,
            "--name", owner, "--label", label, "--cidfile", str(cidfile),
            "--mount", f"type=bind,src={state},dst={rdp_peer.STATE}",
            "--mount", f"type=bind,src={script},dst={SCRIPT},readonly",
            "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp",
            "--entrypoint", ENTRYPOINT, image, *COMMAND,
        ], timeout=30, code="rdp_container_start")
        received = cidfile.read_text(encoding="ascii").strip()
        need(CONTAINER_ID.fullmatch(received), "rdp_container_id")
        cid = received
        inspect = ["inspect", "--type", "container", "--format", INSPECT, cid]

        def verify():
            row = docker(private, inspect, timeout=8, code="rdp_container_inspect")
            admit(json.loads(row), cid=cid, owner=owner, image=image, network=network,
                  user=user, state=state, script=script)

        verify()
        receipt["rdp_container"] = {
            "config_id": image, "executable_sha256": raw[0], "wrapper_sha256": script_sha,
        }
        yield
        verify()
        need(hashlib.sha256(script.read_bytes()).hexdigest() == script_sha,
             "rdp_wrapper_changed")
        docker(private, ["stop", "--time", "9", cid], timeout=15, code="rdp_container_stop")
        row = json.loads(docker(private, inspect, timeout=8, code="rdp_container_inspect"))
        need(row["id"] == cid and row["running"] is False and row["exit_code"] == 0,
             "rdp_fixture_graceful_stop")
        receipt["rdp_fixture_reaped"] = True
    finally:
        if cid is not None:
            removed = docker(private, ["rm", "--force", cid], timeout=15,
                             code="rdp_container_cleanup").decode("ascii").strip()
            need(removed in (cid, owner), "rdp_container_cleanup")
            remaining = docker(private, ["ps", "--all", "--quiet", "--no-trunc",
                                         "--filter", "id=" + cid],
                               timeout=8, code="rdp_container_cleanup")
            need(not remaining.strip(), "rdp_container_cleanup")
            receipt["rdp_container_removed"] = True
