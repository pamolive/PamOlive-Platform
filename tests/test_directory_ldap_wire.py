"""Actual OpenLDAP/TLS qualification. Run in Dockerfile.directory-test.

Optional native prerequisites are explicit skips elsewhere, never successes.
"""

from unittest import skipUnless
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from platform_modules.connectors.directory_adapters import (
    DirectoryFailure,
    normalize_destination,
    read_directory,
)
from tests.fixtures.ldap_directory import LdapDirectoryPeer, available


@skipUnless(available(), "Linux OpenLDAP/python-ldap isolated qualification image required")
class DirectoryLdapWireTests(SimpleTestCase):
    def setUp(self):
        self.peer = LdapDirectoryPeer()
        self.addCleanup(self.peer.close)
        self.policy = override_settings(
            CONNECTOR_ALLOWED_HOSTS=(
                f"directory.invalid:{self.peer.port}",
                f"directory.invalid:{self.peer.tls_port}",
            ),
            CONNECTOR_ALLOWED_NETWORKS=("127.0.0.1/32", "::1/128"),
            CONNECTOR_CA_BUNDLE=self.peer.ca_file,
        )
        self.policy.enable()
        self.addCleanup(self.policy.disable)
        resolver = patch(
            "platform_modules.connectors.directory_adapters.resolve_destination",
            return_value="127.0.0.1",
        )
        resolver.start()
        self.addCleanup(resolver.stop)

    def read(self, url=None, pin=None, **kwargs):
        destination = normalize_destination(
            "ldap",
            url or self.peer.url,
            pin or self.peer.pin,
            {"base_dn": self.peer.base_dn, "bind_dn": self.peer.bind_dn},
        )
        return read_directory(
            provider="ldap",
            destination=destination,
            secret={"bind_dn": self.peer.bind_dn, "password": self.peer.password},
            **kwargs,
        )

    def test_actual_starttls_pinned_socket_and_stable_entry_uuid(self):
        result = self.read()
        self.assertEqual(len(result.records), 1)
        self.assertFalse(result.complete)
        self.assertIsNone(result.records[0]["enabled"])
        self.assertIn("ldap_group_memberships_unknown", result.limitations)
        self.assertEqual(result.records[0]["uid"], "fixture")
        repeated = self.read()
        self.assertEqual(result.records[0]["entryUUID"], repeated.records[0]["entryUUID"])

    def test_ldaps_is_explicitly_refused_before_credential_emission(self):
        before = self.peer.authenticated_bind_count()
        with self.assertRaisesMessage(DirectoryFailure, "directory_ldaps_not_qualified"):
            self.read(url=self.peer.tls_url)
        self.assertEqual(self.peer.authenticated_bind_count(), before)

    def test_starttls_wrong_leaf_pin_never_sends_authenticated_bind(self):
        before = self.peer.authenticated_bind_count()
        with self.assertRaisesMessage(DirectoryFailure, "directory_certificate_mismatch"):
            self.read(pin="0" * 64)
        self.assertEqual(self.peer.authenticated_bind_count(), before)

    def test_hostname_mismatch_with_trusted_ca_never_sends_authenticated_bind(self):
        before = self.peer.authenticated_bind_count()
        with override_settings(CONNECTOR_ALLOWED_HOSTS=(f"wrong.invalid:{self.peer.port}",)):
            with self.assertRaises(DirectoryFailure):
                self.read(url=self.peer.url.replace("directory.invalid", "wrong.invalid"))
        self.assertEqual(self.peer.authenticated_bind_count(), before)

    def test_untrusted_ca_does_not_fall_back_to_cleartext_or_send_bind(self):
        before = self.peer.authenticated_bind_count()
        with override_settings(CONNECTOR_CA_BUNDLE=""):
            with self.assertRaises(DirectoryFailure):
                self.read()
        self.assertEqual(self.peer.authenticated_bind_count(), before)

    def test_revocation_after_handshake_does_not_send_bind(self):
        before = self.peer.authenticated_bind_count()

        def revoked():
            raise DirectoryFailure("source_revoked")

        with self.assertRaisesMessage(DirectoryFailure, "source_revoked"):
            self.read(before_auth=revoked)
        self.assertEqual(self.peer.authenticated_bind_count(), before)
