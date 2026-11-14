"""Presentation-only regression: lease and relay dates belong to distinct rows."""

from django.template.loader import render_to_string
from django.test import SimpleTestCase


class AccessContractPamRenderingTests(SimpleTestCase):
    def test_lease_pending_and_connected_relay_rows_render_without_invented_dates(self):
        lease_time = "2026-11-14T10:11:12+00:00"
        connection_time = "2026-11-14T10:12:13+00:00"
        contract = {
            "schema": "pamolive.access-contract/1",
            "intention": {"id": "00000000-0000-4000-8000-000000000001", "reference": "render-only"},
            "pam_sessions": {
                "availability": "available",
                "items": [
                    {"lease_id": "render-lease", "state": "open", "started_at": lease_time},
                    {"connection_id": "render-pending", "state": "pending", "connected_at": None},
                    {
                        "connection_id": "render-connected",
                        "state": "connected",
                        "connected_at": connection_time,
                    },
                ],
            },
        }
        rendered = render_to_string(
            "governance/access_contract.html",
            {"contract": contract, "csrf_token": "NOTPROVIDED"},
        )
        self.assertIn("bail render-lease", rendered)
        self.assertIn("relais render-pending", rendered)
        self.assertIn("relais render-connected", rendered)
        self.assertEqual(rendered.count(lease_time), 1)
        self.assertEqual(rendered.count(connection_time), 1)
        self.assertEqual(rendered.count("Connexion non enregistrée"), 1)
        self.assertIn("Un bail local ne prouve pas à lui seul une connexion distante", rendered)
