"""Adversarial directory protocol tests, never a real organization or secret."""

import hashlib
import secrets
import sys
import tempfile
import threading
import types
from dataclasses import asdict
from unittest.mock import Mock, patch
from uuid import uuid4

from django.test import SimpleTestCase, override_settings

from platform_modules.connectors.directory_adapters import (
    DirectoryFailure,
    _ldap_rows,
    normalize_destination,
    normalize_directory_records,
    read_directory,
)
from tests.fixtures.directory import GraphPeer


class DestinationTests(SimpleTestCase):
    def test_normalization_is_offline_and_binds_scope_principal_and_pin(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS in normalizer")):
            one = normalize_destination(
                "ldap",
                "ldap://LOCALHOST",
                "a" * 64,
                {"base_dn": "dc=lab", "bind_dn": "cn=reader,dc=lab"},
            )
        self.assertEqual(one["endpoint"], "ldap://localhost:389")
        changed = normalize_destination(
            "ldap",
            "ldap://localhost",
            "a" * 64,
            {"base_dn": "dc=lab", "bind_dn": "cn=other,dc=lab"},
        )
        self.assertNotEqual(one, changed)

    def test_ambiguous_destinations_and_missing_pins_are_refused(self):
        scope = {"tenant_id": str(uuid4())}
        for url in (
            "http://localhost/v1.0/users",
            "https://u:p@localhost/v1.0/users",
            "https://localhost/v1.0/../users",
            "https://localhost/v1.0/users?x=y",
            "https://localhost/v1.0/users#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(DirectoryFailure):
                normalize_destination("entra", url, "a" * 64, scope)
        with self.assertRaises(DirectoryFailure):
            normalize_destination("entra", "https://localhost/v1.0/users", "", scope)

    def test_real_execution_disabled_before_transport_and_credential_access(self):
        secret = Mock()
        with self.assertRaisesMessage(DirectoryFailure, "directory_real_execution_disabled"):
            read_directory(provider="ldap", destination={}, secret=secret, synthetic=False)
        self.assertFalse(secret.mock_calls)


class GraphHttpsTests(SimpleTestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="pamolive-graph-")
        self.addCleanup(self.folder.cleanup)
        self.tenant = str(uuid4())
        self.peer = GraphPeer(self.folder.name, self.tenant)
        self.addCleanup(self.peer.close)
        self.destination = normalize_destination(
            "entra", self.peer.url, self.peer.pin, {"tenant_id": self.tenant}
        )
        self.policy = override_settings(
            CONNECTOR_ALLOWED_HOSTS=(f"localhost:{self.peer.server.server_port}",),
            CONNECTOR_ALLOWED_NETWORKS=("127.0.0.1/32", "::1/128"),
            CONNECTOR_CA_BUNDLE=self.peer.ca_file,
        )
        self.policy.enable()
        self.addCleanup(self.policy.disable)
        self.token = secrets.token_urlsafe(32)

    def user(self, identifier=None):
        return {
            "id": identifier or str(uuid4()),
            "userPrincipalName": "synthetic@example.invalid",
            "accountEnabled": True,
        }

    def read(self, **kwargs):
        return read_directory(
            provider="entra", destination=self.destination, secret={"token": self.token}, **kwargs
        )

    def test_real_tls_pagination_verifies_realm_but_does_not_claim_groups_complete(self):
        cursor = (
            self.peer.url
            + "?$select=id,userPrincipalName,accountEnabled&$top=100&$skiptoken=opaque"
        )
        self.peer.pages = [
            {"value": [self.user()], "@odata.nextLink": cursor},
            {"value": [self.user()]},
        ]
        before = Mock()
        result = self.read(before_auth=before)
        self.assertEqual(len(result.records), 2)
        self.assertEqual(result.page_count, 2)
        self.assertFalse(result.complete)
        self.assertEqual(result.transport_identity["realm_id"], self.tenant)
        self.assertEqual(before.call_count, 3)
        self.assertNotIn("opaque", repr(asdict(result)))
        self.assertNotIn(self.token, repr(asdict(result)))

    def test_wrong_pin_prevents_any_authorization_from_being_sent(self):
        self.destination["certificate_sha256"] = "0" * 64
        with self.assertRaisesMessage(DirectoryFailure, "directory_certificate_mismatch"):
            self.read()
        self.assertEqual(self.peer.requests, [])

    def test_untrusted_ca_prevents_authorization(self):
        with override_settings(CONNECTOR_CA_BUNDLE=""):
            with self.assertRaisesMessage(DirectoryFailure, "directory_tls_verification_failed"):
                self.read()
        self.assertEqual(self.peer.requests, [])

    def test_revalidation_failure_after_tls_prevents_authorization(self):
        def revoked():
            raise DirectoryFailure("source_revoked")

        with self.assertRaisesMessage(DirectoryFailure, "source_revoked"):
            self.read(before_auth=revoked)
        self.assertEqual(self.peer.requests, [])

    def test_different_authenticated_tenant_with_same_remote_ids_is_refused(self):
        self.peer.tenant_id = str(uuid4())
        self.peer.pages = [{"value": [self.user()]}]
        with self.assertRaisesMessage(DirectoryFailure, "directory_realm_mismatch"):
            self.read()
        self.assertEqual(len(self.peer.requests), 1)
        self.assertEqual(len(self.peer.pages), 1)

    def test_next_link_other_origin_path_or_scope_is_not_followed(self):
        for link in (
            "https://attacker.invalid/v1.0/users?$skiptoken=secret",
            self.peer.url.replace("/users", "/groups") + "?$skiptoken=secret",
            self.peer.url + "?$select=password&$top=100&$skiptoken=secret",
            self.peer.url + "?$select=id,userPrincipalName,accountEnabled&$top=100&tenant=other",
        ):
            self.peer.requests = []
            self.peer.pages = [{"value": [self.user()], "@odata.nextLink": link}]
            with (
                self.subTest(link=link),
                self.assertRaisesMessage(DirectoryFailure, "directory_next_link_invalid"),
            ):
                self.read()
            self.assertEqual(len(self.peer.requests), 2)

    def test_redirect_is_refused_without_followup(self):
        self.peer.redirect = "https://attacker.invalid/collect"
        with self.assertRaisesMessage(DirectoryFailure, "directory_http_failed"):
            self.read()
        self.assertEqual(len(self.peer.requests), 1)

    def test_raw_body_size_is_bounded_before_parsing(self):
        self.peer.pages = [{"value": [self.user()], "padding": "x" * 1_048_576}]
        with self.assertRaisesMessage(DirectoryFailure, "directory_response_too_large"):
            self.read()

    def test_duplicate_object_ids_do_not_overwrite_an_earlier_observation(self):
        row = self.user()
        self.peer.pages = [{"value": [row, {**row, "accountEnabled": False}]}]
        with self.assertRaisesMessage(DirectoryFailure, "directory_duplicate_identifier"):
            self.read()

    def test_cursor_cycle_is_refused(self):
        next_link = (
            self.peer.url
            + "?$select=id,userPrincipalName,accountEnabled&$top=100&$skiptoken=repeat"
        )
        self.peer.pages = [
            {"value": [self.user()], "@odata.nextLink": next_link},
            {"value": [self.user()], "@odata.nextLink": next_link},
        ]
        with self.assertRaisesMessage(DirectoryFailure, "directory_cursor_cycle"):
            self.read()

    def test_page_and_record_caps_return_incomplete_without_exporting_cursor(self):
        with patch("platform_modules.connectors.directory_adapters.MAX_PAGES", 1):
            self.peer.pages = [
                {
                    "value": [self.user()],
                    "@odata.nextLink": self.peer.url
                    + "?$select=id,userPrincipalName,accountEnabled&$top=100&$skiptoken=private",
                }
            ]
            result = self.read()
        self.assertFalse(result.complete)
        self.assertIn("directory_page_limit", result.limitations)

    def test_synthetic_policy_refuses_nonloopback_resolved_address(self):
        with patch(
            "platform_modules.connectors.directory_adapters.resolve_destination",
            return_value="192.0.2.10",
        ):
            with self.assertRaisesMessage(DirectoryFailure, "directory_synthetic_address_required"):
                self.read()
        self.assertEqual(self.peer.requests, [])


class LdapProtocolTests(SimpleTestCase):
    def setUp(self):
        self.cert = b"synthetic-certificate-used-only-by-the-protocol-mock"
        self.pin = hashlib.sha256(self.cert).hexdigest()
        self.destination = normalize_destination(
            "ad",
            "ldap://localhost:389",
            self.pin,
            {"base_dn": "dc=lab", "bind_dn": "cn=reader,dc=lab"},
        )
        self.secret = {"bind_dn": "cn=reader,dc=lab", "password": secrets.token_urlsafe(32)}
        self.module, self.controls = types.ModuleType("ldap"), types.ModuleType("ldap.controls")
        for constant in (
            "INIT_FD_AVAIL",
            "OPT_X_TLS_PEERCERT",
            "OPT_X_TLS_PROTOCOL_MIN",
            "OPT_X_TLS_PROTOCOL_TLS1_2",
            "OPT_X_TLS_REQUIRE_SAN",
            "OPT_DEBUG_LEVEL",
            "OPT_PROTOCOL_VERSION",
            "OPT_REFERRALS",
            "OPT_DEREF",
            "DEREF_NEVER",
            "OPT_NETWORK_TIMEOUT",
            "OPT_TIMEOUT",
            "OPT_X_TLS_REQUIRE_CERT",
            "OPT_X_TLS_DEMAND",
            "OPT_X_TLS_CACERTFILE",
            "OPT_X_TLS_NEWCTX",
            "SCOPE_BASE",
            "SCOPE_SUBTREE",
        ):
            setattr(self.module, constant, constant)
        self.module.LDAPError = type("SyntheticLdapError", (Exception,), {})
        self.connection, self.raw = Mock(), Mock()
        self.module.initialize = Mock(return_value=self.connection)
        self.module.set_option = Mock()
        self.connection.get_option.return_value = self.cert

        class Control:
            controlType = "1.2.840.113556.1.4.319"

            def __init__(self, criticality, size, cookie):
                self.cookie = cookie

        self.controls.SimplePagedResultsControl = Control
        self.control = Control(True, 100, b"")
        self.identifier = uuid4()
        self.attrs = {
            "objectGUID": [self.identifier.bytes_le],
            "sAMAccountName": [b"fixture"],
            "userAccountControl": [b"512"],
            "memberOf": [b"cn=group,dc=lab"],
        }
        self.connection.result3.return_value = (
            None,
            [("cn=fixture,dc=lab", self.attrs)],
            None,
            [self.control],
        )
        for context in (
            patch.dict(sys.modules, {"ldap": self.module, "ldap.controls": self.controls}),
            patch(
                "platform_modules.connectors.directory_adapters.socket.create_connection",
                return_value=self.raw,
            ),
            override_settings(
                CONNECTOR_ALLOWED_HOSTS=("localhost:389", "localhost:636"),
                CONNECTOR_ALLOWED_NETWORKS=("127.0.0.1/32", "::1/128"),
            ),
        ):
            context.__enter__()
            self.addCleanup(context.__exit__, None, None, None)

    def read(self, **kwargs):
        return read_directory(
            provider="ad", destination=self.destination, secret=self.secret, **kwargs
        )

    def test_starttls_pin_and_revalidation_precede_bind_on_the_pinned_fd(self):
        sequence = []
        self.connection.start_tls_s.side_effect = lambda: sequence.append("tls")
        self.connection.get_option.side_effect = lambda _: (sequence.append("pin") or self.cert)
        self.connection.simple_bind_s.side_effect = lambda *args: sequence.append("bind")
        result = self.read(before_auth=lambda: sequence.append("revalidate"))
        self.assertEqual(sequence, ["tls", "pin", "revalidate", "bind", "revalidate"])
        self.assertEqual(result.records[0]["objectGUID"], str(self.identifier))
        self.assertTrue(result.complete)
        self.connection.set_option.assert_any_call(self.module.OPT_REFERRALS, 0)
        self.connection.set_option.assert_any_call(self.module.OPT_DEREF, self.module.DEREF_NEVER)
        self.raw.detach.assert_called_once()

    def test_ldaps_is_refused_before_any_network_or_credential_send(self):
        with self.assertRaisesMessage(DirectoryFailure, "directory_ldaps_not_qualified"):
            normalize_destination(
                "ad", "ldaps://localhost:636", self.pin, self.destination["scope"]
            )
        self.module.initialize.assert_not_called()
        self.connection.simple_bind_s.assert_not_called()

    def test_wrong_pin_or_revocation_never_emits_bind_credentials(self):
        self.connection.get_option.return_value = b"other-server-certificate"
        with self.assertRaisesMessage(DirectoryFailure, "directory_certificate_mismatch"):
            self.read()
        self.connection.simple_bind_s.assert_not_called()

    def test_changed_bind_identity_cannot_reuse_existing_credentials(self):
        self.secret["bind_dn"] = "cn=attacker,dc=lab"
        with self.assertRaisesMessage(DirectoryFailure, "directory_credential_identity_mismatch"):
            self.read()
        self.module.initialize.assert_not_called()

    def test_referred_and_ranged_membership_data_remain_incomplete(self):
        self.attrs["memberOf;range=0-1499"] = [b"cn=partial,dc=lab"]
        self.connection.result3.return_value = (
            None,
            [(None, ["ldap://attacker.invalid"]), ("cn=fixture,dc=lab", self.attrs)],
            None,
            [self.control],
        )
        result = self.read()
        self.assertFalse(result.complete)
        self.assertIn("ldap_referral_not_followed", result.limitations)
        self.assertIn("ad_ranged_membership_incomplete", result.limitations)

    def test_missing_paging_control_cannot_claim_a_complete_snapshot(self):
        self.connection.result3.return_value = (None, [], None, [])
        with self.assertRaisesMessage(DirectoryFailure, "directory_paging_control_missing"):
            self.read()

    def test_bounded_inventory_and_group_truncation_never_claim_completeness(self):
        second = {**self.attrs, "objectGUID": [uuid4().bytes_le]}
        self.connection.result3.return_value = (
            None,
            [("cn=one,dc=lab", self.attrs), ("cn=two,dc=lab", second)],
            None,
            [self.control],
        )
        with patch("platform_modules.connectors.directory_adapters.MAX_RECORDS", 1):
            result = self.read()
        self.assertEqual(len(result.records), 1)
        self.assertFalse(result.complete)
        self.assertIn("directory_record_limit", result.limitations)
        self.attrs["memberOf"] = [f"cn=group{i},dc=lab".encode() for i in range(40)]
        self.connection.result3.return_value = (
            None,
            [("cn=one,dc=lab", self.attrs)],
            None,
            [self.control],
        )
        result = self.read()
        self.assertFalse(result.complete)
        self.assertEqual(len(result.records[0]["memberOf"]), 32)
        self.assertIn("directory_group_limit", result.limitations)

    def test_byte_budget_failure_exports_no_unbounded_page(self):
        with patch("platform_modules.connectors.directory_adapters.MAX_BYTES", 1):
            result = self.read()
        self.assertEqual(result.records, [])
        self.assertFalse(result.complete)
        self.assertIn("directory_byte_limit", result.limitations)

    def test_revalidation_failure_after_starttls_prevents_secret_bind(self):
        def revoked():
            raise DirectoryFailure("source_revoked")

        with self.assertRaisesMessage(DirectoryFailure, "source_revoked"):
            self.read(before_auth=revoked)
        self.connection.simple_bind_s.assert_not_called()

    def test_revocation_between_ldap_pages_stops_before_next_search(self):
        self.control.cookie = b"opaque-next-page"
        calls = []

        def revalidate():
            calls.append(True)
            if len(calls) == 3:  # Before bind, before first search, before next search.
                raise DirectoryFailure("source_revoked")

        with self.assertRaisesMessage(DirectoryFailure, "source_revoked"):
            self.read(before_auth=revalidate)
        self.connection.simple_bind_s.assert_called_once()
        self.connection.search_ext.assert_called_once()
        self.connection.unbind_s.assert_called_once()

    def test_repeated_ldap_cookie_is_refused_and_not_in_public_error(self):
        self.control.cookie = b"private-cookie"
        with self.assertRaisesMessage(DirectoryFailure, "directory_cursor_cycle") as caught:
            self.read()
        self.assertNotIn("private-cookie", str(caught.exception))

    def test_invalid_binary_guid_does_not_fall_back_to_dn_or_login(self):
        self.attrs["objectGUID"] = [b"not-a-guid"]
        with self.assertRaisesMessage(DirectoryFailure, "directory_attribute_invalid"):
            self.read()

    def test_standard_ldap_uses_entry_uuid_and_never_invents_account_state(self):
        identifier = uuid4()
        rows, limits = _ldap_rows(
            "ldap",
            [
                (
                    "uid=test,dc=lab",
                    {
                        "entryUUID": [str(identifier).encode()],
                        "uid": [b"test"],
                    },
                )
            ],
        )
        self.assertEqual(rows[0]["entryUUID"], str(identifier))
        self.assertIsNone(rows[0]["enabled"])
        self.assertIn("directory_enabled_state_unknown", limits)
        self.assertIn("ldap_group_memberships_unknown", limits)


class NullableDirectoryTests(SimpleTestCase):
    def test_fixture_default_uses_private_temporary_parent_without_host_changes(self):
        from tests.fixtures.ldap_directory import fixture_directory_parent

        self.assertEqual(fixture_directory_parent("posix"), "/var/tmp")
        self.assertIsNone(fixture_directory_parent("nt"))

    def test_explicit_fixture_parent_cannot_select_an_existing_directory_or_arbitrary_path(self):
        from tests.fixtures.ldap_directory import fixture_directory_parent

        for parent in ("", "/tmp", "/var/tmp", "/var/lib/ldap", "relative",
                       "/var/lib/ldap/other-directory",
                       "/var/lib/ldap/../ldap/pamolive-fixtures-1-1"):
            with self.subTest(parent=parent), self.assertRaises(RuntimeError):
                fixture_directory_parent("posix", parent)

    def test_fixture_startup_codes_never_echo_private_diagnostic_text(self):
        from tests.fixtures.ldap_directory import startup_failure_code

        marker = secrets.token_urlsafe(32)
        for text, expected in (
            ("Permission denied " + marker, "fixture_permission_refused"),
            ("TLS init def ctx failed " + marker, "fixture_tls_context_failed"),
            ("moduleload failed " + marker, "fixture_module_unavailable"),
            ("Address already in use " + marker, "fixture_port_in_use"),
            ("unclassified " + marker, "fixture_startup_failed"),
        ):
            self.assertEqual(startup_failure_code(text), expected)
            self.assertNotIn(marker, startup_failure_code(text))

    def test_v2_unknown_does_not_change_p1_strict_preview_contract(self):
        from django.core.exceptions import ValidationError

        from platform_modules.identity.directory_simulation import normalize_fixture

        row = {"entryUUID": str(uuid4()), "uid": "fixture", "enabled": None, "memberOf": []}
        normalized = normalize_directory_records("ldap", [row])
        self.assertIsNone(normalized[0]["enabled"])
        with self.assertRaises(ValidationError):
            normalize_fixture("ldap", [row])

    def test_graph_omitted_account_state_stays_unknown(self):
        row = {"id": str(uuid4()), "userPrincipalName": "synthetic@example.invalid", "groups": []}
        self.assertIsNone(normalize_directory_records("entra", [row])[0]["enabled"])

    def test_ascii_bearer_required_before_any_network(self):
        destination = normalize_destination(
            "entra", "https://localhost/v1.0/users", "a" * 64, {"tenant_id": str(uuid4())}
        )
        for token in ("contains space", "non-ascii-é", "tab\tvalue"):
            with self.subTest(token=token), patch("socket.getaddrinfo") as dns:
                with self.assertRaisesMessage(DirectoryFailure, "directory_credential_invalid"):
                    read_directory(
                        provider="entra", destination=destination, secret={"token": token}
                    )
                dns.assert_not_called()

    def test_dns_deadline_aborts_before_auth_and_does_not_release_busy_slot(self):
        from platform_modules.connectors import directory_adapters as adapter

        entered, release = threading.Event(), threading.Event()

        def slow_dns(*args):
            entered.set()
            release.wait(2)
            return "127.0.0.1"

        try:
            with patch.object(adapter, "resolve_destination", side_effect=slow_dns):
                with self.assertRaisesMessage(DirectoryFailure, "directory_dns_deadline_exceeded"):
                    adapter._bounded_resolve("localhost", 443, adapter.time.monotonic() + 0.03)
                self.assertTrue(entered.is_set())
        finally:
            release.set()

    def test_dns_has_no_unbounded_queue_when_four_resolvers_are_busy(self):
        from platform_modules.connectors import directory_adapters as adapter

        for _ in range(4):
            self.assertTrue(adapter._DNS_SLOTS.acquire(timeout=1))
        try:
            with self.assertRaisesMessage(DirectoryFailure, "directory_dns_capacity_exceeded"):
                adapter._bounded_resolve("localhost", 443, adapter.time.monotonic() + 1)
        finally:
            for _ in range(4):
                adapter._DNS_SLOTS.release()
