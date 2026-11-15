"""Thin composition seam only: no Docker lifecycle or main is duplicated."""

import copy

import schema
from support import load, need, sha

STATE = "pamolive.vault-runtime-installed-ci-state/1"
PHASE = "installed_vault_reservation_pure_only"


def client_class(entry_raw, expected_sha, *, controller=None, legacy=None, bounded=None):
    need(
        type(entry_raw) is bytes
        and 0 < len(entry_raw) <= 1024**2
        and sha(entry_raw) == expected_sha
    )
    controller = controller if controller is not None else load("controller.py")
    legacy = legacy if legacy is not None else load("legacy_controller.py")
    bounded = bounded if bounded is not None else load("bounded_io.py")
    parent = controller.docker_class(legacy, bounded)

    class VaultDocker(parent):
        def __init__(self, work, pins, state, work_deadline=None):
            need(state.get("type") == STATE and state.get("phase") == PHASE)
            super().__init__(work, pins, state, work_deadline)
            self.entry_raw = entry_raw

    return VaultDocker


def create_arguments(work, pins, entry_raw, expected_sha, *, controller=None):
    need(type(entry_raw) is bytes and sha(entry_raw) == expected_sha)
    controller = controller if controller is not None else load("controller.py")
    return controller.create_arguments(work, pins, entry_raw)


def accept_attach(
    result,
    expected_distributions,
    source_sha256,
    expected_child_input_sha256,
    expected_sql_sha256,
):
    controller = load("controller.py")
    facts = result.facts()
    need(controller.io_record_released({"operation": "start", **facts}))
    need(facts["spawn_attempted"] is True and facts["killed_owned_child"] is False)
    need(facts["exception_type"] is None and facts["cleanup_exception_type"] is None)
    need(
        (result.returncode == 0 and result.reason is None)
        or (result.returncode == 42 and result.reason == "nonzero_exit")
    )
    need(result.stderr == b"" and 0 < len(result.stdout) <= schema.MAX_PACKET)
    value = schema.parse(result.stdout, schema.MAX_PACKET)
    schema.packet(
        value,
        expected_distributions,
        result.returncode,
        expected_input_sha256=expected_child_input_sha256,
        expected_sql_sha256=expected_sql_sha256,
    )
    need(value["source_sha256"] == source_sha256)
    return {"ok": value["ok"], "packet": copy.deepcopy(value), "IO": copy.deepcopy(facts)}
