"""Typed phase2 host consumer composed with reviewed lifecycle/H1; no CLI."""

import copy
import time

import host_seam
import schema
import wheel_transfer
import workload_schema
from support import load, need
from workload_prepare import s0_pins


def client_class(entry_raw, entry_sha):
    control, legacy = load("controller.py"), load("legacy_controller.py")
    parent = host_seam.client_class(entry_raw, entry_sha)

    class Labelled(parent):
        def command(self, *args, **options):
            if args and args[0] == "create":
                need(len(args) > 5 and args[1] == "--name" and args[3] == "--label")
                need(args[4] == legacy.LABEL + "=" + self.state["run"])
                need(args.count("--label") == 1 and args.count(args[4]) == 1)
                args = (*args[:4], control.LABEL + "=" + self.state["run"], *args[5:])
            return super().command(*args, **options)

    return Labelled


def accept_attach(result, **bindings):
    control = load("controller.py")
    facts = result.facts()
    need(control.io_record_released({"operation": "start", **facts}))
    need(result.spawn_attempted and not result.killed_owned_child)
    need(result.exception_type is None and result.cleanup_exception_type is None)
    need(
        (result.returncode == 0 and result.reason is None)
        or (result.returncode == 42 and result.reason == "nonzero_exit")
    )
    need(not result.stderr and 0 < len(result.stdout) <= schema.MAX_PACKET)
    value = schema.parse(result.stdout, schema.MAX_PACKET)
    workload_schema.accept(value, result.returncode, **bindings)
    return {"ok": value["ok"], "packet": copy.deepcopy(value), "IO": copy.deepcopy(facts)}


def pull_owned(work, pins, state, entry_raw, entry_sha, *, factory=None):
    s0_pins(pins)
    control, legacy = load("controller.py"), load("legacy_controller.py")
    control.ci_guard(work)
    need(state["type"] == host_seam.STATE and state["phase"] == host_seam.PHASE)
    need(state["image_config"] == pins["image_config"] and state["user"] == "1000:1000")
    need(state["pull"] == "not_attempted" and state["started"] is False)
    control.check_inputs(work, state)
    cls = factory if factory is not None else client_class(entry_raw, entry_sha)
    client = cls(work, pins, state, time.monotonic() + 300)
    original = None
    try:
        code, active, stderr = client.command("ps", "--format", "{{.ID}}")
        need(code == 0 and not active.strip() and not stderr)
        storage = {}
        legacy.storage_observation(client, 4096, storage)
        legacy.memory_guard(2048)
        state["pull"] = "pending"
        control.atomic(work / "state.json", state)
        need(client.pull(pins) == 0)
        client.image(pins)
        state["pull"] = "ready"
    except BaseException as error:
        original = error
        state["pull"] = "unknown"
        state["failure"] = state.get("failure") or "PULL_FAILED_OR_UNKNOWN"
        raise
    finally:
        control.io_history_released(state)
        try:
            control.atomic(work / "state.json", state)
        except BaseException:
            state["pull"] = "unknown"
            state["IO_uncertain"] = True
            if original is not None:
                raise original from None
            raise
    return state


def run_owned(
    work,
    pins,
    state,
    entry_raw,
    entry_sha,
    *,
    bindings,
    factory=None,
):
    """Caller supplies verified/staged RO inputs and prior pinned S0 pull receipt."""
    control, legacy = load("controller.py"), load("legacy_controller.py")
    s0_pins(pins)
    control.ci_guard(work)
    transfer_verified_wheels = state.get("transfer_verified_wheels", False)
    need(type(transfer_verified_wheels) is bool)
    need(state["type"] == host_seam.STATE and state["phase"] == host_seam.PHASE)
    need(state["image_config"] == pins["image_config"] and state["user"] == "1000:1000")
    need(bindings == state["bindings"])
    need(
        set(bindings) == {"expected_source", "expected_input", "expected_sql", "expected_materials"}
    )
    need(all(schema.digest(value) for value in bindings.values()))
    need(state["pull"] == "ready" and state["started"] is False)
    cls = factory if factory is not None else client_class(entry_raw, entry_sha)
    client = cls(work, pins, state, time.monotonic() + 900)

    def save():
        control.io_history_released(state)
        control.atomic(work / "state.json", state)

    original = None
    packet = None
    transfer = None
    try:
        control.check_inputs(work, state)
        code, active, stderr = client.command("ps", "--format", "{{.ID}}")
        need(code == 0 and not active.strip() and not stderr)
        storage = {}
        legacy.storage_observation(client, 4096, storage)
        legacy.memory_guard(2048)
        client.image(pins)
        state["started"] = True
        save()
        cid = legacy.reserve_create(
            client, state, save, host_seam.create_arguments(work, pins, entry_raw, entry_sha)
        )
        row = client.inspect(cid)
        need(legacy.owns(row, state["create"]) and row["Running"] is False)
        code, raw, stderr = client.command("start", "--attach", cid, timeout=900)
        need(not stderr and 0 < len(raw) <= schema.MAX_PACKET)
        if transfer_verified_wheels and code == 0:
            value, _, _ = wheel_transfer.decode(raw, bindings=bindings)
            transfer = raw
        else:
            value = schema.parse(raw, schema.MAX_PACKET)
            workload_schema.accept(value, code, **bindings)
        packet = value
        state["workload_packet"] = {
            "ok": value["ok"],
            "execution_sha256": value["execution_sha256"],
        }
        need(code == 0 and value["ok"])
    except BaseException as error:
        original = error
        state["failure"] = state.get("failure") or "VAULT_WORKLOAD_FAILED_OR_UNKNOWN"
    finally:
        try:
            save()
        except BaseException:
            state["IO_uncertain"] = True
            state["failure"] = state.get("failure") or "JOURNAL_UNCONFIRMED"
        try:
            control.check_inputs(work, state)
        except BaseException:
            state["failure"] = state.get("failure") or "INPUTS_CHANGED_OR_UNKNOWN"
        client.cleaning = True
        try:
            cleanup = legacy.reconcile(client, state, save)
        except BaseException:
            cleanup = {"released": False, "outcome": "unknown"}
            state["failure"] = state.get("failure") or "CLEANUP_UNCONFIRMED"
        state["cleanup"] = cleanup
        try:
            control.check_inputs(work, state)
        except BaseException:
            state["failure"] = state.get("failure") or "INPUTS_CHANGED_OR_UNKNOWN"
        try:
            save()
        except BaseException:
            state["IO_uncertain"] = True
            state["failure"] = state.get("failure") or "JOURNAL_UNCONFIRMED"
    released = (
        cleanup.get("released") is True
        and control.io_history_released(state)
        and state.get("pull") == "ready"
    )
    result = {
        "schema": "pamolive.vault-installed-host-reception/2",
        "ok": original is None
        and not state.get("failure")
        and packet is not None
        and packet["ok"] is True
        and released
        and type(cleanup.get("exit_code")) is int
        and cleanup["exit_code"] == 0
        and cleanup.get("OOMKilled") is False,
        "packet": packet,
        "container_released": cleanup.get("released") is True,
        "container_exit_code": cleanup.get("exit_code"),
        "container_OOMKilled": cleanup.get("OOMKilled"),
        "clients_released": control.io_history_released(state),
        "resources_released": released,
        "failure": state.get("failure"),
        "authority": False,
        "attestation_verified": False,
    }
    if result["ok"] and transfer_verified_wheels:
        try:
            wheel_transfer.keep_private(work, transfer)
        except OSError:
            result["ok"] = False
            result["failure"] = "WHEEL_TRANSFER_PERSISTENCE_FAILED"
    return result


def cleanup_owned(work, pins, state, entry_raw, entry_sha, *, factory=None):
    """Independent always-step; a second cleanup never heals old IO uncertainty."""
    control, legacy = load("controller.py"), load("legacy_controller.py")
    s0_pins(pins)
    control.ci_guard(work)
    need(state["type"] == host_seam.STATE and state["phase"] == host_seam.PHASE)
    need(state["image_config"] == pins["image_config"] and state["user"] == "1000:1000")
    cls = factory if factory is not None else client_class(entry_raw, entry_sha)
    client = cls(work, pins, state, time.monotonic())
    client.cleaning = True

    def save():
        control.io_history_released(state)
        control.atomic(work / "state.json", state)

    previous = state.get("cleanup")
    try:
        cleanup = legacy.reconcile(client, state, save)
    except BaseException:
        cleanup = {"released": False, "status": "unknown"}
    if (
        cleanup.get("released") is True
        and (state.get("create") or {}).get("outcome") == "removed"
        and previous
        and previous.get("released") is True
    ):
        for key in ("exit_code", "OOMKilled"):
            if key not in cleanup and key in previous:
                cleanup[key] = previous[key]
    state["cleanup"] = cleanup
    try:
        save()
    except BaseException:
        state["IO_uncertain"] = True
        state["failure"] = state.get("failure") or "JOURNAL_UNCONFIRMED"
    clients = control.io_history_released(state)
    return {
        "container_released": cleanup.get("released") is True,
        "clients_released": clients,
        "resources_released": cleanup.get("released") is True
        and clients
        and state.get("pull") == "ready",
        "failure": state.get("failure"),
        "authority": False,
    }


def bootstrap(entry_sha, bindings, *, transfer_verified_wheels=False):
    """Hash/compile the same bounded FD buffer. No runpy re-open or globals patch."""
    need(schema.digest(entry_sha) and all(schema.digest(value) for value in bindings.values()))
    arguments = ["/controller/workload_entry.py"]
    for name in ("source", "input", "sql", "materials"):
        arguments.extend(["--expected-" + name, bindings["expected_" + name]])
    if transfer_verified_wheels:
        arguments.append("--transfer-verified-wheels")
    return (
        "import os,stat,hashlib,types,sys\n"
        "p='/controller/workload_entry.py'\n"
        "a=os.lstat(p);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<a.st_size<=262144\n"
        "f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n"
        "try:\n"
        " b=os.fstat(f);assert (a.st_dev,a.st_ino,a.st_size)==(b.st_dev,b.st_ino,b.st_size)\n"
        " with os.fdopen(f,'rb',closefd=False) as s:r=s.read(262145)\n"
        " c=os.fstat(f);d=os.lstat(p)\n"
        " assert len(r)==a.st_size and "
        "(b.st_dev,b.st_ino,b.st_mode,b.st_nlink,b.st_size,b.st_mtime_ns,b.st_ctime_ns)=="
        "(c.st_dev,c.st_ino,c.st_mode,c.st_nlink,c.st_size,c.st_mtime_ns,c.st_ctime_ns)\n"
        " assert (a.st_dev,a.st_ino,a.st_mode,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)=="
        "(d.st_dev,d.st_ino,d.st_mode,d.st_nlink,d.st_size,d.st_mtime_ns,d.st_ctime_ns)\n"
        "finally:os.close(f)\n"
        + "assert hashlib.sha256(r).hexdigest()=="
        + repr(entry_sha)
        + "\n"
        + "m=types.ModuleType('_vault_workload_entry');m.__file__=p;sys.argv="
        + repr(arguments)
        + "\n"
        + "exec(compile(r,p,'exec'),m.__dict__);m.main()\n"
    ).encode()
