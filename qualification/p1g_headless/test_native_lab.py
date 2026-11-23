"""Local contracts for the isolated native portal supervisor and inputs."""

import asyncio
import threading
import unittest
from contextvars import ContextVar
from unittest.mock import patch

from qualification.p1g_headless import guacd_namespace, native_lab, rdp_namespace, rdp_peer

REVISION = "a" * 40
IMAGE = "sha256:" + "2" * 64
CONTAINER = "3" * 64


class NativeLabContracts(unittest.TestCase):
    def test_fixture_operations_run_without_browser_loop_and_keep_scope(self):
        scope = ContextVar("synthetic_scope", default=None)
        scope.set("synthetic-organization")
        observed = []

        def sync_operation(*, label):
            with self.assertRaises(RuntimeError):
                asyncio.get_running_loop()
            return label, scope.get(), threading.get_ident()

        async def browser():
            with native_lab.support.SyncFixture(lambda: observed.append(
                ("closed", threading.get_ident()),
            )) as fixture:
                label, organization, fixture_thread = fixture.run(sync_operation, label="query")
                self.assertEqual((label, organization), ("query", "synthetic-organization"))
                self.assertNotEqual(fixture_thread, threading.get_ident())
                with self.assertRaisesRegex(ValueError, "synthetic_fixture_error"):
                    fixture.run(lambda: int("synthetic_fixture_error"))
                self.assertEqual(fixture.run(sync_operation, label="next")[-1], fixture_thread)
            self.assertEqual(observed, [("closed", fixture_thread)])

        asyncio.run(browser())

    def test_receipt_requires_browser_stop_and_database_cleanup(self):
        packet = {
            "schema": "pamolive.p1g-browser-worker/1",
            "case": "native_ssh",
            "state": "OBSERVED_SYNTHETIC_INCREMENT_ONLY",
            "full_P1G_qualified": False,
            "source": {"revision": REVISION},
            "tests": 1, "failures": 0, "errors": 0, "skips": 0,
            "native_PAM_transport_observed": True, "browser_E2E_executed": True,
            "SDK_cleanup_completed": True, "live_server_thread_closed": True,
            "fresh_test_database_absent_after_runner": True, "base_database_OID_preserved": True,
            "observed_UI_phases": [native_lab.run_lab.STOP_PHASE],
        }
        with patch.object(native_lab.support, "sandbox_receipt", return_value=True):
            self.assertTrue(native_lab.acceptable(packet, REVISION))
            for key in ("source", "native_PAM_transport_observed", "observed_UI_phases",
                        "full_P1G_qualified",
                        "fresh_test_database_absent_after_runner"):
                with self.subTest(key=key):
                    self.assertFalse(native_lab.acceptable(
                        {item: value for item, value in packet.items() if item != key}, REVISION
                    ))
            self.assertFalse(native_lab.acceptable({**packet, "skips": 1}, REVISION))

    def test_guacd_is_bound_to_one_image_and_network_without_public_ports(self):
        network = "container:" + "4" * 64
        owner = "owned-guacd"
        row = {
            "id": CONTAINER, "name": "/" + owner, "image": IMAGE, "mode": network,
            "ports": None, "publish_all": False, "privileged": False, "read_only": True,
            "running": True, "caps": ["ALL"], "security": ["no-new-privileges"],
            "user": "1001:1001", "entrypoint": [guacd_namespace.BINARY],
            "cmd": guacd_namespace.COMMAND,
        }
        kwargs = {"cid": CONTAINER, "owner": owner, "image": IMAGE, "network": network}
        guacd_namespace.admit(row, **kwargs)
        for key, value in {"mode": "host", "publish_all": True, "user": "0",
                           "image": "sha256:" + "5" * 64, "caps": []}.items():
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "guacd_container"):
                guacd_namespace.admit({**row, key: value}, **kwargs)

    def test_rdp_observations_must_belong_to_one_authenticated_peer(self):
        rows = [{"event": event, "connection": 7} for event in rdp_peer.EVENTS]
        self.assertEqual(rdp_peer.connection_events(rows), 7)
        self.assertEqual(rdp_peer.connection_events(rows[:3], required=rdp_peer.EVENTS[:3]), 7)
        self.assertIsNone(rdp_peer.connection_events(rows, required=rdp_peer.EVENTS[:4]))
        self.assertIsNone(rdp_peer.connection_events(rows[:4], required=rdp_peer.EVENTS[:3]))
        self.assertIsNone(rdp_peer.connection_events([*rows[:3], rows[4], rows[3]]))
        for foreign in (rows[0], rows[-1]):
            with self.subTest(foreign=foreign), self.assertRaisesRegex(
                ValueError, "rdp_peer_multiple_connections",
            ):
                rdp_peer.connection_events([*rows, {**foreign, "connection": 8}])

    def test_rdp_receipt_requires_real_display_NLA_and_rdp_stop(self):
        packet = {
            "schema": "pamolive.p1g-browser-worker/1",
            "case": "native_rdp",
            "state": "OBSERVED_SYNTHETIC_INCREMENT_ONLY",
            "full_P1G_qualified": False,
            "source": {"revision": REVISION},
            "tests": 1, "failures": 0, "errors": 0, "skips": 0,
            "native_PAM_transport_observed": True, "browser_E2E_executed": True,
            "SDK_cleanup_completed": True, "live_server_thread_closed": True,
            "fresh_test_database_absent_after_runner": True, "base_database_OID_preserved": True,
            "observed_UI_phases": [native_lab.run_lab.RDP_STOP_PHASE],
            "native_RDP_display_and_NLA_observed": True,
        }
        with patch.object(native_lab.support, "sandbox_receipt", return_value=True):
            self.assertTrue(native_lab.acceptable(packet, REVISION, "rdp"))
            self.assertFalse(native_lab.acceptable(packet, REVISION, "ssh"))
            self.assertFalse(native_lab.acceptable(
                {**packet, "native_RDP_display_and_NLA_observed": False}, REVISION, "rdp"
            ))
            self.assertFalse(native_lab.acceptable(
                {**packet, "observed_UI_phases": [native_lab.run_lab.STOP_PHASE]}, REVISION, "rdp"
            ))

    def test_rdp_peer_mounts_only_private_state_and_readonly_wrapper(self):
        network = "container:" + "4" * 64
        owner, user = "owned-rdp", "1001:1001"
        script, state = "/lab/source/rdp_peer.py", "/lab/private/rdp"
        mounts = [
            {"Type": "bind", "Source": state, "Destination": str(rdp_peer.STATE), "RW": True},
            {"Type": "bind", "Source": script, "Destination": rdp_namespace.SCRIPT, "RW": False},
        ]
        row = {
            "id": CONTAINER, "name": "/" + owner, "image": IMAGE, "mode": network,
            "ports": None, "publish_all": False, "privileged": False, "read_only": True,
            "running": True, "caps": ["ALL"], "security": ["no-new-privileges"],
            "user": user, "entrypoint": [rdp_namespace.ENTRYPOINT], "cmd": rdp_namespace.COMMAND,
            "mounts": mounts,
        }
        params = dict(cid=CONTAINER, owner=owner, image=IMAGE, network=network,
                      user=user, state=state, script=script)
        rdp_namespace.admit(row, **params)
        with self.assertRaisesRegex(ValueError, "rdp_container_mounts"):
            rdp_namespace.admit({**row, "mounts": [mounts[0], {**mounts[1], "RW": True}]}, **params)
