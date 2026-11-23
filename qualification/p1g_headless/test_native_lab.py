"""Local contracts for the isolated native portal supervisor and inputs."""

import unittest
from unittest.mock import patch

from qualification.p1g_headless import guacd_namespace, native_lab

REVISION = "a" * 40
IMAGE = "sha256:" + "2" * 64
CONTAINER = "3" * 64


class NativeLabContracts(unittest.TestCase):
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
