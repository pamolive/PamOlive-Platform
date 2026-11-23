"""Own an exact native-test guacd process inside the synthetic database network."""

import json
import re
from contextlib import contextmanager

from qualification.p1g_headless.lab_support import need
from qualification.p1g_headless.postgres_namespace import CONTAINER_ID, docker

PORT = 4822
BINARY = "/opt/pamolive-guac/sbin/guacd"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
OWNER_LABEL = "io.pamolive.p1g-guacd"
COMMAND = ["-f", "-b", "127.0.0.1", "-l", str(PORT), "-p", "/tmp/guacd.pid", "-L", "error"]
INSPECT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
    '"mode":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
    '"publish_all":{{json .HostConfig.PublishAllPorts}},"running":{{json .State.Running}},'
    '"privileged":{{json .HostConfig.Privileged}},"read_only":{{json .HostConfig.ReadonlyRootfs}},'
    '"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},'
    '"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},'
    '"cmd":{{json .Config.Cmd}}}'
)
PROFILE = [
    "--user", "1001:1001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--read-only", "--no-healthcheck", "--pull", "never",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
    "--memory", "256m", "--memory-swap", "256m", "--cpus", "1", "--pids-limit", "64",
    "--log-driver", "none",
]


def admit(row, *, cid, owner, image, network):
    need(
        isinstance(row, dict) and row.get("id") == cid and row.get("name") == "/" + owner
        and row.get("image") == image and row.get("mode") == network
        and row.get("ports") in (None, {}) and row.get("publish_all") is False
        and row.get("privileged") is False and row.get("read_only") is True
        and row.get("running") is True and row.get("caps") in (["ALL"], ["CAP_ALL"])
        and row.get("security") in (["no-new-privileges"], ["no-new-privileges:true"])
        and row.get("user") == "1001:1001" and row.get("entrypoint") == [BINARY]
        and row.get("cmd") == COMMAND,
        "guacd_container_identity",
    )


@contextmanager
def service(private, identity, image, database_id, receipt):
    need(IMAGE_ID.fullmatch(image) and CONTAINER_ID.fullmatch(database_id),
         "guacd_fixture_identity")
    platform = docker(
        private, ["image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", image],
        timeout=10, code="guacd_image_inspect",
    )
    need(platform.decode("ascii").strip() == image + " linux/amd64", "guacd_image_identity")
    executable = docker(
        private, ["run", "--rm", "--network", "none", *PROFILE,
                  "--entrypoint", "/usr/bin/sha256sum", image, BINARY],
        timeout=25, code="guacd_executable_inspect",
    ).decode("ascii").split()
    need(len(executable) == 2 and re.fullmatch(r"[0-9a-f]{64}", executable[0])
         and executable[1] == BINARY, "guacd_executable_identity")

    owner = "pamolive-p1g-guacd-" + identity["run"] + "-" + identity["attempt"]
    label = f"{OWNER_LABEL}={identity['revision']}-{identity['run']}-{identity['attempt']}"
    network = "container:" + database_id
    cidfile = private / "guacd.cid"
    cid = None
    try:
        docker(private, [
            "run", "--detach", "--init", "--network", network, *PROFILE,
            "--name", owner, "--label", label, "--cidfile", str(cidfile),
            "--env", "HOME=/tmp", "--env", "GUACAMOLE_HOME=/tmp",
            "--entrypoint", BINARY, image, *COMMAND,
        ], timeout=30, code="guacd_container_start")
        received = cidfile.read_text(encoding="ascii").strip()
        need(CONTAINER_ID.fullmatch(received), "guacd_container_id")
        cid = received
        inspect = ["inspect", "--type", "container", "--format", INSPECT, cid]

        def verify():
            raw = docker(private, inspect, timeout=8, code="guacd_container_inspect")
            admit(json.loads(raw), cid=cid, owner=owner, image=image, network=network)

        verify()
        receipt["guacd_container"] = {"config_id": image, "executable_sha256": executable[0]}
        yield
        verify()
    finally:
        if cid is not None:
            removed = docker(private, ["rm", "--force", cid], timeout=15,
                             code="guacd_container_cleanup").decode("ascii").strip()
            need(removed in (cid, owner), "guacd_container_cleanup")
            remaining = docker(private, ["ps", "--all", "--quiet", "--no-trunc",
                                         "--filter", "id=" + cid],
                               timeout=8, code="guacd_container_cleanup")
            need(not remaining.strip(), "guacd_container_cleanup")
            receipt["guacd_container_removed"] = True
