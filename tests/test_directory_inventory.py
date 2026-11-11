"""Synthetic persistent directory acceptance, authority and evidence regressions."""

import importlib
import json
import secrets
import time
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.test import TestCase, override_settings

from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, AuditEvent, ModuleActivation
from platform_core.security import cipher
from platform_modules.connectors import directory_inventory as inventory
from platform_modules.connectors.directory_adapters import ReadResult
from platform_modules.connectors.directory_models import (
    DirectoryFact,
    DirectoryMapping,
    DirectoryRun,
    DirectorySource,
)
from platform_modules.identity.models import ExternalAccount, Grant

from . import test_platform as fixture


class DirectoryInventoryFixture:
    def setUp(self):
        fixture.PlatformTests.setUp(self)
        for user in (self.admin, self.operator):
            AccountSecurity.objects.get_or_create(
                account=user,
                defaults={
                    "encrypted_secret": cipher().encrypt(secrets.token_bytes(24)).decode(),
                },
            )
        self.scope = {
            "base_dn": "dc=example,dc=invalid",
            "bind_dn": "cn=reader,dc=example,dc=invalid",
        }
        self.credential = {"bind_dn": self.scope["bind_dn"], "password": secrets.token_urlsafe(32)}
        self.source = self.create_source()
        self.mutate(inventory.set_directory_source_enabled, self.source.pk, enabled=True)
        self.remote_id = str(uuid4())
        self.records = [self.fact(self.remote_id)]

    def mutate(self, fn, *args, operator=False, **kwargs):
        actor = self.operator if operator else self.admin
        with recent_authentication(actor, self.org, time.time()):
            return fn(*args, actor=actor, organization=self.org, **kwargs)

    def create_source(self, **kwargs):
        values = dict(
            name="Synthetic directory",
            provider="ldap",
            endpoint="ldap://directory.invalid:389",
            certificate_sha256="1" * 64,
            scope=self.scope,
            credential=self.credential,
            synthetic=True,
        )
        values.update(kwargs)
        return self.mutate(inventory.configure_directory_source, **values)

    def fact(self, remote_id=None, username="reader"):
        return {
            "entryUUID": remote_id or str(uuid4()),
            "uid": username,
            "enabled": True,
            "memberOf": [],
        }

    def accept(self, *, key="snapshot-1", records=None, **kwargs):
        return self.mutate(
            inventory.import_directory_fixture,
            self.source.pk,
            records=self.records if records is None else records,
            idempotency_key=key,
            operator=True,
            **kwargs,
        )

    def read(self, **kwargs):
        return inventory.directory_inventory(
            actor=self.operator, organization=self.org, source_id=self.source.pk, **kwargs
        )


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class DirectoryInventoryTests(DirectoryInventoryFixture, TestCase):
    def test_signed_acceptance_and_facts_preserve_synthetic_provenance(self):
        run = self.accept()
        self.assertTrue(inventory.verify_directory_run(run))
        self.assertEqual(run.provenance, "synthetic_fixture")
        self.assertEqual(DirectoryFact.objects.count(), 1)
        result = self.read()
        self.assertEqual(result["provenance"], "synthetic_fixture")
        self.assertFalse(result["can_apply"])
        self.assertIn("group_observation_incomplete", result["items"][0]["warnings"])
        self.assertNotIn(self.credential["password"], json.dumps(result))
        self.assertNotIn("encrypted_credential", json.dumps(result))

    def test_same_key_same_canonical_content_returns_original(self):
        run = self.accept()
        again = self.accept(records=[dict(self.records[0], entryUUID=self.remote_id.upper())])
        self.assertEqual(run.pk, again.pk)
        self.assertEqual(DirectoryRun.objects.count(), 1)

    def test_conflict_commits_audit_and_leaves_original_unchanged(self):
        run = self.accept()
        with self.assertRaises(inventory.DirectoryConflict):
            self.accept(records=[self.fact(self.remote_id, username="different")])
        self.assertEqual(DirectoryRun.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="directory.import_conflict").count(), 1)
        run.refresh_from_db()
        self.assertTrue(inventory.verify_directory_run(run))
        self.assertEqual(run.facts.get().username, "reader")

    def test_mapping_requires_admin_and_never_creates_a_right(self):
        self.accept()
        before = Grant.objects.count()
        with self.assertRaises(PermissionDenied):
            self.mutate(
                inventory.map_directory_account,
                self.source.pk,
                operator=True,
                remote_id=self.remote_id,
                account_id=self.account.pk,
            )
        mapping = self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        self.assertTrue(inventory.verify_directory_mapping(mapping))
        self.assertEqual(self.read()["items"][0]["account_id"], str(self.account.pk))
        revoked = self.mutate(inventory.revoke_directory_mapping, mapping.pk)
        self.assertTrue(inventory.verify_directory_mapping(revoked))
        self.assertIsNone(self.read()["items"][0]["account_id"])
        self.assertEqual(DirectoryMapping.objects.count(), 2)
        self.assertEqual(Grant.objects.count(), before)

    def test_missing_even_complete_snapshot_never_revokes_mapping_or_account(self):
        self.accept()
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        self.accept(key="snapshot-2", records=[], complete=True)
        self.assertEqual(DirectoryMapping.objects.count(), 1)
        self.account.refresh_from_db()
        self.assertTrue(self.account.active)
        self.assertEqual(self.read()["not_observed"][0]["remote_id"], self.remote_id)

    def test_rotation_preserves_source_identity_and_old_verifiable_run(self):
        run = self.accept()
        changed = dict(self.credential, password=secrets.token_urlsafe(32))
        rotated = self.mutate(
            inventory.rotate_directory_credential, self.source.pk, credential=changed
        )
        self.assertEqual(rotated.pk, self.source.pk)
        self.assertTrue(inventory.verify_directory_run(run))
        self.assertTrue(inventory.verify_directory_source(rotated))
        self.assertEqual(self.accept().pk, run.pk)

    def test_destination_change_needs_new_source(self):
        self.source.refresh_from_db()
        self.source.destination = dict(
            self.source.destination, endpoint="ldaps://other.invalid:636"
        )
        with self.assertRaises(ValidationError):
            self.source.save()

    def test_disabled_source_preserves_history_but_hides_active_mapping(self):
        run = self.accept()
        self.mutate(
            inventory.map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        self.mutate(inventory.set_directory_source_enabled, self.source.pk, enabled=False)
        with self.assertRaises(PermissionDenied):
            self.accept(key="another")
        self.assertTrue(inventory.verify_directory_run(run))
        self.assertIsNone(self.read()["items"][0]["account_id"])

    def test_services_enforce_mfa_modules_and_fresh_actor(self):
        with self.assertRaises(PermissionDenied):
            inventory.import_directory_fixture(
                self.source.pk,
                records=self.records,
                idempotency_key="nomfa",
                actor=self.operator,
                organization=self.org,
            )
        self.operator.__class__.objects.filter(pk=self.operator.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            self.accept()
        self.operator.__class__.objects.filter(pk=self.operator.pk).update(is_active=True)
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        with self.assertRaises(PermissionDenied):
            self.read()

    def test_page_cursor_pins_immutable_run_and_source(self):
        self.accept(records=[self.fact(username=str(n)) for n in range(3)])
        first = self.read(limit=1)
        second = self.read(limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["items"][0]["remote_id"], second["items"][0]["remote_id"])
        self.assertEqual(first["run_id"], second["run_id"])
        with self.assertRaises(ValidationError):
            self.read(cursor=first["next_cursor"] + "tamper")

    def test_missing_observation_pages_are_complete_without_repeating_facts(self):
        records = [self.fact(username=f"synthetic-{number}") for number in range(3)]
        self.accept(records=records)
        for number, row in enumerate(records):
            account = ExternalAccount.objects.create(
                organization=self.org,
                identity=self.identity,
                username=f"mapped-{number}",
                system="Synthetic LDAP",
            )
            self.mutate(
                inventory.map_directory_account,
                self.source.pk,
                remote_id=row["entryUUID"],
                account_id=account.pk,
            )
        self.accept(records=[], key="missing-all", complete=True)
        cursor, observed = None, []
        for _ in range(4):
            page = self.read(limit=1, cursor=cursor)
            self.assertEqual(page["items"], [])
            observed.extend(item["remote_id"] for item in page["not_observed"])
            cursor = page["next_cursor"]
            if not cursor:
                break
        self.assertEqual(set(observed), {row["entryUUID"] for row in records})
        self.assertEqual(len(observed), 3)
        self.assertIsNone(cursor)

    def test_unknown_ldap_enabled_is_not_a_disabled_account_observation(self):
        row = dict(self.records[0], enabled=None)
        run = self.accept(records=[row])
        self.assertTrue(inventory.verify_directory_run(run))
        self.assertIsNone(run.facts.get().enabled)
        result = self.read()["items"][0]
        self.assertIsNone(result["enabled"])
        self.assertEqual(result["enabled_assurance"], "unknown")
        self.account.refresh_from_db()
        self.assertTrue(self.account.active)

    def test_before_auth_blocks_credential_emission_after_revocation(self):
        emitted = []

        def read(**kwargs):
            self.mutate(inventory.set_directory_source_enabled, self.source.pk, enabled=False)
            kwargs["before_auth"]()
            emitted.append(True)

        with patch(
            "platform_modules.connectors.directory_adapters.read_directory", side_effect=read
        ):
            with self.assertRaises(PermissionDenied):
                self.mutate(
                    inventory.collect_directory_inventory,
                    self.source.pk,
                    idempotency_key="network",
                    operator=True,
                )
        self.assertEqual(emitted, [])
        self.assertEqual(DirectoryRun.objects.count(), 0)

    def test_collector_revalidates_module_after_fetch_and_commits_no_facts(self):
        def read(**kwargs):
            kwargs["before_auth"]()
            ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
                enabled=False
            )
            return ReadResult(self.records, False, 1, True, {}, ("partial_lab_fixture",))

        with patch(
            "platform_modules.connectors.directory_adapters.read_directory", side_effect=read
        ):
            with self.assertRaises(PermissionDenied):
                self.mutate(
                    inventory.collect_directory_inventory,
                    self.source.pk,
                    idempotency_key="network",
                    operator=True,
                )
        self.assertEqual(DirectoryRun.objects.count(), 0)

    def test_authenticated_lab_read_preserves_partial_limits_and_transport_identity(self):
        self.source.refresh_from_db()
        identity = {
            key: self.source.destination[key]
            for key in ("provider", "endpoint", "certificate_sha256", "scope")
        }
        identity.update(self.source.destination["scope"])

        def read(**kwargs):
            kwargs["before_auth"]()
            return ReadResult(
                self.records, False, 1, True, identity, ("directory_groups_not_collected",)
            )

        with patch(
            "platform_modules.connectors.directory_adapters.read_directory", side_effect=read
        ):
            run = self.mutate(
                inventory.collect_directory_inventory,
                self.source.pk,
                idempotency_key="authenticated",
                operator=True,
            )
        self.assertTrue(inventory.verify_directory_run(run))
        self.assertEqual(run.provenance, "authenticated_lab_directory")
        self.assertEqual(run.limitations, ["directory_groups_not_collected"])
        result = self.read()
        self.assertIn("group_observation_incomplete", result["items"][0]["warnings"])
        self.assertEqual(result["limitations"], run.limitations)

    def test_lab_read_cannot_accept_an_identity_from_another_destination(self):
        def read(**kwargs):
            kwargs["before_auth"]()
            return ReadResult(
                self.records, True, 1, True, {"endpoint": "ldaps://attacker.invalid:636"}, ()
            )

        with patch(
            "platform_modules.connectors.directory_adapters.read_directory", side_effect=read
        ):
            with self.assertRaises(ValidationError):
                self.mutate(
                    inventory.collect_directory_inventory,
                    self.source.pk,
                    idempotency_key="wrong-destination",
                    operator=True,
                )
        self.assertFalse(DirectoryRun.objects.exists())

    def test_snapshot_quota_does_not_delete_old_evidence(self):
        run = self.accept()
        with patch.object(inventory, "MAX_RUNS", 1):
            with self.assertRaises(ValidationError):
                self.accept(key="quota-overflow")
        self.assertEqual(DirectoryRun.objects.count(), 1)
        self.assertTrue(inventory.verify_directory_run(run))

    def test_mapping_quota_reserves_capacity_for_explicit_revocation(self):
        records = [self.fact(username=str(number)) for number in range(2)]
        self.accept(records=records)
        account = ExternalAccount.objects.create(
            organization=self.org,
            identity=self.identity,
            username="another",
            system="Synthetic LDAP",
        )
        with patch.object(inventory, "MAX_MAPPINGS", 2):
            mapping = self.mutate(
                inventory.map_directory_account,
                self.source.pk,
                remote_id=records[0]["entryUUID"],
                account_id=self.account.pk,
            )
            with self.assertRaises(ValidationError):
                self.mutate(
                    inventory.map_directory_account,
                    self.source.pk,
                    remote_id=records[1]["entryUUID"],
                    account_id=account.pk,
                )
            revoked = self.mutate(inventory.revoke_directory_mapping, mapping.pk)
        self.assertEqual(revoked.kind, "revoke")
        self.assertTrue(inventory.verify_directory_mapping(revoked))

    def test_populated_migration_reverse_is_refused_without_deleting_rows(self):
        migration = importlib.import_module(
            "platform_modules.connectors.migrations.0012_directory_inventory"
        )
        from django.apps import apps

        with self.assertRaises(RuntimeError):
            migration.refuse_populated_reverse(apps, connection.schema_editor())
        self.assertEqual(DirectorySource.objects.count(), 1)

    def test_postgresql_trigger_preserves_fact_and_source_identity(self):
        if connection.vendor != "postgresql":
            self.skipTest("Requires PostgreSQL immutable and composite-tenant triggers")
        self.accept()
        from django.db import DatabaseError

        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("UPDATE connectors_directoryfact SET username='tampered'")
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("UPDATE connectors_directorysource SET synthetic=false")
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO connectors_directoryfact "
                    "(id,organization_id,run_id,remote_id,username,enabled,groups,signature) "
                    "VALUES (%s,%s,%s,%s,'foreign',true,'[]','invalid')",
                    [uuid4(), self.other.pk, DirectoryRun.objects.get().pk, uuid4()],
                )
