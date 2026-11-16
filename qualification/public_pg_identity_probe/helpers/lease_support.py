import os
import uuid

import protocol as m
from support import safe_file

PG_FIELDS = {
    "id": ".Id",
    "name": ".Name",
    "image": ".Image",
    "config_image": ".Config.Image",
    "config_user": ".Config.User",
    "config_working_dir": ".Config.WorkingDir",
    "running": ".State.Running",
    "started_at": ".State.StartedAt",
    "restarting": ".State.Restarting",
    "networks": ".NetworkSettings.Networks",
    "ports": ".NetworkSettings.Ports",
    "mounts": ".Mounts",
    "readonly_rootfs": ".HostConfig.ReadonlyRootfs",
    "network_mode": ".HostConfig.NetworkMode",
    "port_bindings": ".HostConfig.PortBindings",
    "cpu": ".HostConfig.NanoCpus",
    "memory": ".HostConfig.Memory",
    "swap": ".HostConfig.MemorySwap",
    "restart_policy": ".HostConfig.RestartPolicy",
}


def template(fields):
    return "{" + ",".join(('"' + k + '":{{json ' + v + "}}" for k, v in fields.items())) + "}"


class Lease:
    """Cooperating-runner lease, not an attestation or adversarial OS lock."""

    def __init__(self, path, reservation):
        self.path = path
        self.token = ("ZLIB_CONTROL:" + reservation + ":" + uuid.uuid4().hex).encode("ascii")
        self.held, self.identity = (False, None)

    def acquire(self):
        m.need(len(self.token) <= 256, "lease_token_budget")
        try:
            file = self.path.open("xb")
        except FileExistsError:
            raise m.Refusal("shared_lease_busy") from None
        self.held = True
        with file:
            info = os.fstat(file.fileno())
            self.identity = (info.st_dev, info.st_ino)
            file.write(self.token)
            file.flush()
            os.fsync(file.fileno())

    def release(self, safe):
        if not self.held or not safe:
            return {"state": "UNKNOWN", "released": False}
        try:
            raw = safe_file(self.path, 256)
            info = self.path.lstat()
            m.need(
                raw == self.token and (info.st_dev, info.st_ino) == self.identity,
                "lease_owner_changed",
            )
            self.path.unlink()
            self.held = False
            return {"state": "RELEASED", "released": True}
        except BaseException as error:
            return {"state": "UNKNOWN", "released": False, "reason_type": type(error).__name__}


def mount_order(values):
    m.need(type(values) is list, "mount_list")
    seen = set()
    for row in values:
        m.need(
            type(row) is dict
            and type(row.get("Destination")) is str
            and (row["Destination"] not in seen),
            "mount_duplicate_or_type",
        )
        seen.add(row["Destination"])
    return sorted(values, key=lambda row: row["Destination"])


def pg_value(row):
    m.need(type(row) is dict and set(row) == set(PG_FIELDS), "pg_fields")
    return {**row, "mounts": mount_order(row["mounts"])}
