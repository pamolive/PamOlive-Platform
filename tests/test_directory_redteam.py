"""Independent adversarial checks of the directory inventory authority boundary.

All credentials, organizations and records are synthetic. No network or remote
provisioning is needed: directory observations must never become IAM/PAM rights.
"""
import copy
import json
import secrets
import time
from threading import Event, Lock
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

import pyotp
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings

from platform_core.authorization import recent_authentication
from platform_core.models import (
    AccountSecurity,
    AuditEvent,
    ModuleActivation,
    OrganizationMembership,
)
from platform_core.security import cipher
from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvent, AccessIntent
from platform_modules.connectors import directory_adapters
from platform_modules.connectors import directory_inventory as directory
from platform_modules.connectors.directory_adapters import DirectoryFailure
from platform_modules.connectors.directory_models import (
    DirectoryFact,
    DirectoryMapping,
    DirectoryRun,
    DirectorySource,
)
from platform_modules.connectors.models import ExternalChange
from platform_modules.identity.models import ExternalAccount, Grant, Identity
from platform_modules.pam.models import SessionLease

from . import test_platform as baseline


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryInventoryRedTeamTests(TestCase):
    def setUp(self):
        baseline.PlatformTests.setUp(self)
        self.secret = secrets.token_urlsafe(32)
        AccountSecurity.objects.create(
            account=self.admin,
            encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode(),
        )

    def source(self, *, actor=None, endpoint="ldap://directory.invalid:389", **changes):
        actor = actor or self.admin
        values = dict(name="Synthetic collector-shaped display name", provider="ldap",
                      endpoint=endpoint, certificate_sha256="1" * 64,
                      scope={"base_dn": "dc=example,dc=invalid",
                             "bind_dn": "cn=reader,dc=example,dc=invalid"},
                      credential={"bind_dn": "cn=reader,dc=example,dc=invalid",
                                  "password": self.secret}, synthetic=True)
        values.update(changes)
        with recent_authentication(actor, self.org, time.time()):
            source = directory.configure_directory_source(
                actor=actor, organization=self.org, **values)
            directory.set_directory_source_enabled(
                source.pk, enabled=True, actor=actor, organization=self.org)
        source.refresh_from_db()
        return source

    def row(self, remote=None, **changes):
        result = dict(entryUUID=str(remote or uuid4()), uid=self.account.username,
                      enabled=True, memberOf=["Synthetic administrators"])
        result.update(changes)
        return result

    def ingest(self, source, records, *, key="synthetic-redteam-request", actor=None,
               complete=False):
        actor = actor or self.admin
        with recent_authentication(actor, self.org, time.time()):
            return directory.import_directory_fixture(
                source.pk, records=records, idempotency_key=key, complete=complete,
                actor=actor, organization=self.org)

    def test_same_remote_uuid_in_two_sources_has_no_shared_identity_or_authority(self):
        first = self.source()
        second = self.source(endpoint="ldap://other-directory.invalid:389")
        row = self.row(remote=self.account.pk)
        before = {model._meta.label: model.unscoped.count() for model in
                  (Grant, ExternalChange, AccessIntent, AccessEvent, SessionLease)}
        left, right = self.ingest(first, [row]), self.ingest(second, [row])
        self.assertNotEqual(left.pk, right.pk)
        self.assertEqual(DirectoryFact.unscoped.filter(remote_id=self.account.pk).count(), 2)
        self.assertEqual(DirectoryMapping.unscoped.count(), 0)
        for model in (Grant, ExternalChange, AccessIntent, AccessEvent, SessionLease):
            self.assertEqual(model.unscoped.count(), before[model._meta.label])

    def test_manual_fixture_cannot_inherit_authenticated_collector_provenance(self):
        run = self.ingest(self.source(), [self.row()])
        self.assertEqual(run.provenance, "synthetic_fixture")
        self.assertEqual(AccessEvent.unscoped.count(), 0)
        self.assertNotIn("authenticated_lab_directory", run.provenance)

    def test_identical_replay_returns_original_without_duplicate_facts(self):
        source, row = self.source(), self.row()
        first = self.ingest(source, [row])
        second = self.ingest(source, [copy.deepcopy(row)])
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(DirectoryRun.unscoped.count(), 1)
        self.assertEqual(DirectoryFact.unscoped.count(), 1)

    def test_divergent_replay_keeps_original_and_audits_the_conflict(self):
        source, row = self.source(), self.row()
        run = self.ingest(source, [row])
        previous = DirectoryRun.unscoped.values().get(pk=run.pk)
        before = AuditEvent.objects.count()
        changed = dict(row, enabled=False)
        with self.assertRaises(directory.DirectoryConflict) as error:
            self.ingest(source, [changed])
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(DirectoryRun.unscoped.values().get(pk=run.pk), previous)
        self.assertEqual(DirectoryFact.unscoped.get(run=run).enabled, True)
        self.assertGreater(AuditEvent.objects.count(), before)

    def test_completeness_flag_is_not_silently_rewritten_on_replay(self):
        source, row = self.source(), self.row()
        run = self.ingest(source, [row], complete=False)
        with self.assertRaises(directory.DirectoryConflict):
            self.ingest(source, [row], complete=True)
        run.refresh_from_db()
        self.assertFalse(run.complete)

    def test_duplicate_uuid_spellings_are_rejected_before_any_run_is_written(self):
        source = self.source()
        remote = uuid4()
        with self.assertRaises((ValidationError, DirectoryFailure)):
            self.ingest(source, [self.row(remote), self.row(str(remote).upper())])
        self.assertEqual(DirectoryRun.unscoped.count(), 0)
        self.assertEqual(DirectoryFact.unscoped.count(), 0)

    def test_destination_change_preserves_original_source_and_credential(self):
        source = self.source()
        before = DirectorySource.unscoped.values().get(pk=source.pk)
        source.destination = dict(source.destination, endpoint="ldap://attacker.invalid:389")
        with self.assertRaises(ValidationError):
            source.save()
        self.assertEqual(DirectorySource.unscoped.values().get(pk=source.pk), before)

    def test_disabled_source_and_module_cannot_accept_fixture_indirectly(self):
        source = self.source()
        with recent_authentication(self.admin, self.org, time.time()):
            directory.set_directory_source_enabled(
                source.pk, enabled=False, actor=self.admin, organization=self.org)
        with self.assertRaises((PermissionDenied, ValidationError)):
            self.ingest(source, [self.row()])
        self.assertEqual(DirectoryRun.unscoped.count(), 0)
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False)
        with self.assertRaises(PermissionDenied):
            directory.directory_inventory(
                source_id=source.pk, actor=self.admin, organization=self.org)

    def test_reader_receives_neither_credentials_nor_ciphertext(self):
        source = self.source()
        self.ingest(source, [self.row()])
        result = directory.directory_inventory(
            source_id=source.pk, actor=self.operator, organization=self.org)
        serialized = json.dumps(result, default=str)
        source.refresh_from_db()
        self.assertNotIn(self.secret, serialized)
        self.assertNotIn(source.encrypted_credential, serialized)
        for forbidden in ("encrypted_credential", "credential_seal", "Authorization"):
            self.assertNotIn(forbidden, serialized)

    def test_matching_username_cannot_create_an_implicit_local_binding(self):
        source = self.source()
        self.ingest(source, [self.row(remote=self.account.pk)])
        self.assertEqual(DirectoryMapping.unscoped.count(), 0)
        self.account.refresh_from_db()
        self.assertEqual(self.account.identity_id, self.identity.pk)

    def test_foreign_account_mapping_is_refused(self):
        source, remote = self.source(), uuid4()
        self.ingest(source, [self.row(remote)])
        identity = Identity.objects.create(organization=self.other, name="Foreign synthetic person")
        foreign = ExternalAccount.objects.create(
            organization=self.other, identity=identity, username="same-name", system="Synthetic")
        with recent_authentication(self.admin, self.org, time.time()):
            with self.assertRaises(
                (PermissionDenied, ValidationError, ExternalAccount.DoesNotExist)
            ):
                directory.map_directory_account(source.pk, remote_id=str(remote),
                    account_id=foreign.pk, actor=self.admin, organization=self.org)
        self.assertEqual(DirectoryMapping.unscoped.count(), 0)

    def test_missing_object_in_complete_or_partial_snapshot_never_retires_account(self):
        source, remote = self.source(), uuid4()
        self.ingest(source, [self.row(remote)])
        with recent_authentication(self.admin, self.org, time.time()):
            directory.map_directory_account(source.pk, remote_id=str(remote),
                account_id=self.account.pk, actor=self.admin, organization=self.org)
        mapping_count = DirectoryMapping.unscoped.count()
        account_before = ExternalAccount.unscoped.values().get(pk=self.account.pk)
        for complete in (False, True):
            self.ingest(source, [], key="empty-"+str(complete), complete=complete)
            result = directory.directory_inventory(
                source_id=source.pk, actor=self.operator, organization=self.org)
            self.assertIn("not_observed", result)
            self.assertEqual(
                ExternalAccount.unscoped.values().get(pk=self.account.pk), account_before)
            self.assertEqual(DirectoryMapping.unscoped.count(), mapping_count)
            self.assertEqual(ExternalChange.unscoped.count(), 0)

    def test_stale_local_administrator_is_rechecked_after_role_revocation(self):
        admin = get_user_model().objects.create_user("directory-local-admin")
        member = OrganizationMembership.objects.create(
            organization=self.org, account=admin, role="admin")
        AccountSecurity.objects.create(account=admin,
            encrypted_secret=cipher().encrypt(pyotp.random_base32().encode()).decode())
        source = self.source(actor=admin)
        member.role = "auditor"
        member.save(update_fields=["role"])
        with self.assertRaises(PermissionDenied):
            self.ingest(source, [self.row()], actor=admin)
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_wrong_current_organization_cannot_use_a_source_from_another_context(self):
        source = self.source()
        with organization_context(self.other), self.assertRaises(PermissionDenied):
            self.ingest(source, [self.row()])

    def test_revocation_during_tls_handshake_prevents_credential_emission(self):
        source = self.source()
        emitted = []

        def simulated_tls_then_authenticate(**values):
            # No socket: this transport boundary models a blocked TLS handshake
            # completing just after a real administrative revocation.
            ModuleActivation.objects.filter(
                organization=self.org, module_key="connectors").update(enabled=False)
            before_auth = values.get("before_auth")
            if before_auth is not None:
                before_auth()
            emitted.append(True)
            return SimpleNamespace(records=[], complete=True, page_count=1, synthetic=True,
                                   transport_identity={})

        with patch("platform_modules.connectors.directory_adapters.read_directory",
                   side_effect=simulated_tls_then_authenticate):
            with recent_authentication(self.admin, self.org, time.time()):
                with self.assertRaises(PermissionDenied):
                    directory.collect_directory_inventory(source.pk,
                        idempotency_key="revoke-before-bind", actor=self.admin,
                        organization=self.org)
        self.assertEqual(emitted, [], "A post-read guard cannot undo credential disclosure.")
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    def test_cursor_cannot_be_replayed_for_another_source_with_identical_remote_ids(self):
        first = self.source()
        second = self.source(endpoint="ldap://other-directory.invalid:389")
        rows = [self.row() for _ in range(3)]
        self.ingest(first, rows)
        self.ingest(second, rows)
        result = directory.directory_inventory(source_id=first.pk, limit=1,
            actor=self.operator, organization=self.org)
        self.assertTrue(result["next_cursor"])
        with self.assertRaises(ValidationError):
            directory.directory_inventory(source_id=second.pk, limit=1,
                cursor=result["next_cursor"], actor=self.operator, organization=self.org)

    def test_rotation_during_tls_handshake_prevents_old_credential_emission(self):
        source = self.source()
        emitted = []

        def simulated_tls_then_authenticate(**values):
            with recent_authentication(self.admin, self.org, time.time()):
                directory.rotate_directory_credential(source.pk, actor=self.admin,
                    organization=self.org, credential={
                        "bind_dn": "cn=reader,dc=example,dc=invalid",
                        "password": secrets.token_urlsafe(32)})
            before_auth = values.get("before_auth")
            if before_auth is not None:
                before_auth()
            emitted.append(True)
            return SimpleNamespace(records=[], complete=True, page_count=1, synthetic=True,
                                   transport_identity={})

        with patch("platform_modules.connectors.directory_adapters.read_directory",
                   side_effect=simulated_tls_then_authenticate):
            with recent_authentication(self.admin, self.org, time.time()):
                with self.assertRaises(PermissionDenied):
                    directory.collect_directory_inventory(source.pk,
                        idempotency_key="rotate-before-bind", actor=self.admin,
                        organization=self.org)
        self.assertEqual(emitted, [])
        self.assertEqual(DirectoryRun.unscoped.count(), 0)

    @skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL constraints")
    def test_postgresql_rejects_destination_rewrite_even_via_direct_sql(self):
        source = self.source()
        before = DirectorySource.unscoped.values().get(pk=source.pk)
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("UPDATE connectors_directorysource SET destination=%s::jsonb "
                               "WHERE id=%s", [json.dumps({"endpoint": "ldap://attacker.invalid"}),
                                               source.pk])
        self.assertEqual(DirectorySource.unscoped.values().get(pk=source.pk), before)

    @skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL constraints")
    def test_postgresql_refuses_cross_tenant_fact_even_via_direct_sql(self):
        source = self.source()
        run = self.ingest(source, [self.row()])
        fact = DirectoryFact.unscoped.get(run=run)
        fields = [field.column for field in DirectoryFact._meta.concrete_fields]
        quoted = [connection.ops.quote_name(field) for field in fields]
        selected = ["%s" if field in ("id", "organization_id") else 'f.'+name
                    for field, name in zip(fields, quoted, strict=True)]
        values = [uuid4() if field == "id" else self.other.pk
                  for field in fields if field in ("id", "organization_id")]
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO connectors_directoryfact ("+','.join(quoted)+") "
                    "SELECT "+','.join(selected)+" FROM connectors_directoryfact f WHERE f.id=%s",
                    values+[fact.pk])
        self.assertEqual(DirectoryFact.unscoped.count(), 1)

    def test_unknown_ldap_enabled_state_is_preserved_without_disabling_local_account(self):
        source = self.source()
        before = ExternalAccount.unscoped.values().get(pk=self.account.pk)
        grants = Grant.unscoped.count()
        run = self.ingest(source, [self.row(enabled=None)])
        self.assertIsNone(DirectoryFact.unscoped.get(run=run).enabled)
        result = directory.directory_inventory(source_id=source.pk,
            actor=self.operator, organization=self.org)
        self.assertEqual(len(result["items"]), 1)
        self.assertIsNone(result["items"][0]["enabled"])
        self.assertEqual(result["items"][0]["enabled_assurance"], "unknown")
        self.assertEqual(ExternalAccount.unscoped.values().get(pk=self.account.pk), before)
        self.assertEqual(Grant.unscoped.count(), grants)
        self.assertEqual(ExternalChange.unscoped.count(), 0)


    def test_graph_bearer_whitespace_unicode_and_del_control_are_rejected_at_configuration(self):
        for kind, value in (("whitespace", "x y"), ("unicode", "x\u00e9y"), ("DEL", "x\x7fy")):
            with self.subTest(kind=kind):
                with self.assertRaises((ValidationError, DirectoryFailure)):
                    self.source(provider="entra", endpoint="https://graph.invalid/v1.0/users",
                        scope={"tenant_id": str(uuid4())}, credential={"token": value})
        self.assertEqual(DirectorySource.unscoped.count(), 0)

    def test_missing_mapping_pages_are_complete_even_before_any_inventory_run(self):
        source = self.source()
        expected = set()
        for number in range(3):
            remote = uuid4()
            expected.add(str(remote))
            account = ExternalAccount.objects.create(organization=self.org,
                identity=self.identity, username="synthetic-unobserved-"+str(number),
                system="Synthetic")
            with recent_authentication(self.admin, self.org, time.time()):
                directory.map_directory_account(source.pk, remote_id=str(remote),
                    account_id=account.pk, actor=self.admin, organization=self.org)
        seen, cursor = set(), None
        for _ in range(4):
            result = directory.directory_inventory(source_id=source.pk, limit=1, cursor=cursor,
                actor=self.operator, organization=self.org)
            self.assertEqual(result["items"], [])
            self.assertLessEqual(len(result["not_observed"]), 1)
            for item in result["not_observed"]:
                self.assertNotIn(item["remote_id"], seen)
                self.assertEqual(item["state"], "not_observed_requires_review_never_delete")
                seen.add(item["remote_id"])
            cursor = result["next_cursor"]
            if cursor is None:
                break
        self.assertIsNone(cursor, "Missing-observation pagination did not terminate.")
        self.assertEqual(seen, expected)
        self.assertEqual(ExternalChange.unscoped.count(), 0)

class DirectoryResolverRedTeamTests(SimpleTestCase):
    def test_timed_out_resolvers_keep_their_slots_and_excess_work_is_refused(self):
        release, finished = Event(), Event()
        lock = Lock()
        counters = {"started": 0, "finished": 0}

        def blocked_resolver(_host, _port):
            with lock:
                counters["started"] += 1
            try:
                if not release.wait(timeout=3):
                    raise AssertionError("Synthetic resolver was not released.")
                return "127.0.0.1"
            finally:
                with lock:
                    counters["finished"] += 1
                    if counters["finished"] == 4:
                        finished.set()

        try:
            with patch.object(directory_adapters, "resolve_destination",
                              side_effect=blocked_resolver):
                for _ in range(4):
                    with self.assertRaises(DirectoryFailure) as error:
                        directory_adapters._bounded_resolve(
                            "synthetic.invalid", 636, time.monotonic()+0.03)
                    self.assertIn(
                        error.exception.code,
                        ("directory_dns_deadline_exceeded", "directory_deadline_exceeded"))
                started = time.monotonic()
                with self.assertRaises(DirectoryFailure) as error:
                    directory_adapters._bounded_resolve(
                        "synthetic.invalid", 636, time.monotonic()+1)
                self.assertEqual(error.exception.code, "directory_dns_capacity_exceeded")
                self.assertLess(time.monotonic()-started, 0.5)
                self.assertEqual(counters["started"], 4)
        finally:
            release.set()
            self.assertTrue(finished.wait(timeout=2), "Synthetic resolver threads did not drain.")
