"""Adversarial trust transitions and the independent rollback witness."""

import json
import secrets
import uuid
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from unittest import skipUnless
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from platform_modules.pam import trust_auth, trust_registry
from platform_modules.pam.trust_auth_models import PAMTrustAuthorization, PAMTrustChallenge
from platform_modules.pam.trust_models import PAMAuthenticatorState, PAMTrustRevision

from .pam_trust_fixtures import VirtualAuthenticator, public
from .test_pam_sessions import PamSessionFixtureMixin


@override_settings(PAM_ALLOWED_HOSTS={"ssh.example.test:22"})
class PAMTrustRegistryTests(PamSessionFixtureMixin, TestCase):
    def publish(self, body, *, signers=None):
        envelope = self.trust.envelope(body, signers=signers)
        row = trust_registry.publish_registry(envelope)
        self.trust.body, self.trust.row = deepcopy(body), row
        self.trust.checkpoint()
        return row

    def assert_rejected(self, envelope, **options):
        before = PAMTrustRevision.unscoped.count()
        with self.assertRaises((PermissionDenied, ValidationError, ObjectDoesNotExist)):
            trust_registry.publish_registry(envelope, **options)
        self.assertEqual(PAMTrustRevision.unscoped.count(), before)

    def checkpoint(self, mutate):
        document = self.trust.checkpoint()
        mutate(document["body"])
        document["signature"] = trust_auth.b64encode(
            self.trust.witness.sign(trust_registry.checkpoint_message(document["body"]))
        )
        self.write_checkpoint(document)

    def write_checkpoint(self, document):
        path = Path(self.trust.directory.name) / (str(self.org.pk) + ".json")
        path.write_text(json.dumps(document), encoding="utf-8")

    def commissioning_body(self, *, organization=None, previous=None):
        organization = organization or self.org
        now = timezone.now()
        body = deepcopy(self.trust.body)
        body.update(
            organization=str(organization.pk), generation=str(uuid.uuid4()),
            revision=previous.revision + 1 if previous else 1,
            previous_hash=previous.revision_hash if previous else "",
            operation="recommission" if previous else "bootstrap",
            issued_at=now.isoformat(), expires_at=(now + timedelta(hours=23)).isoformat(),
        )
        for person in body["persons"].values():
            person["authenticators"] = []
        return body

    def recommissioning_envelope(self):
        body = self.commissioning_body(previous=self.trust.row)
        new_keys = {person: Ed25519PrivateKey.generate() for person in self.trust.custodians}
        body["custodians"] = {
            person: {"public_key": public(key), "active": True}
            for person, key in new_keys.items()
        }
        message = trust_registry.signature_message(body)
        envelope = {
            "body": body,
            "signatures": {
                person: trust_auth.b64encode(new_keys[person].sign(message))
                for person in list(new_keys)[:2]
            },
            "commissioning_signatures": {
                "commissioner": trust_auth.b64encode(self.trust.commissioner.sign(message))
            },
        }
        return envelope, new_keys

    def test_two_current_custodians_authorize_a_change_and_witness_must_advance(self):
        previous = self.trust.row
        body = self.trust.next_body()
        body["policy"] = {"standard_min": 2, "critical_min": 3}
        envelope = self.trust.envelope(body)
        one = deepcopy(envelope)
        one["signatures"].pop(next(iter(one["signatures"])))
        self.assert_rejected(one)
        row = trust_registry.publish_registry(envelope)
        with self.assertRaises(PermissionDenied):
            trust_registry.recognized_registry(self.org)
        self.trust.row, self.trust.body = row, body
        self.trust.checkpoint()
        self.assertEqual(trust_registry.recognized_registry(self.org).pk, row.pk)
        self.assertEqual(
            trust_registry.historical_registry(self.org, previous.revision_hash).pk, previous.pk
        )

    def test_new_custodian_cannot_authorize_its_own_admission(self):
        old, second, third = self.trust.custodians
        newcomer, key = str(uuid.uuid4()), Ed25519PrivateKey.generate()
        self.trust.custodians[newcomer] = key
        body = self.trust.next_body()
        body["persons"][newcomer] = {
            "active": True, "identity_ids": [], "account_ids": [], "endpoint_ids": [],
            "roles": [], "authenticators": [],
        }
        body["custodians"][old]["active"] = False
        body["custodians"][newcomer] = {"public_key": public(key), "active": True}
        self.assert_rejected(self.trust.envelope(body, signers=[newcomer, second]))
        self.assert_rejected(self.trust.envelope(body, signers=[old, second]))
        row = self.publish(body, signers=[second, third])
        self.assertEqual(trust_registry.recognized_registry(self.org).pk, row.pk)
        body = self.trust.next_body()
        body["policy"]["critical_min"] = 3
        self.assert_rejected(self.trust.envelope(body, signers=[old, second]))

    def test_self_habilitation_and_union_of_batch_subjects_are_excluded(self):
        first, second, third = self.trust.custodians
        body = self.trust.next_body()
        body["persons"][first]["roles"] = ["reviewer"]
        self.assert_rejected(self.trust.envelope(body, signers=[first, second]))
        self.publish(body, signers=[second, third])
        batch = self.trust.next_body()
        batch["persons"][first]["roles"] = ["reviewer", "requester"]
        batch["persons"][second]["roles"] = ["reviewer"]
        for signers in ([first, second], [first, third], [second, third]):
            with self.subTest(signers=signers):
                self.assert_rejected(self.trust.envelope(batch, signers=signers))

    def test_sponsor_nomination_cannot_hide_inside_a_target_mutation(self):
        first, second, _ = self.trust.custodians
        endpoint_id = str(self.configured_endpoint.pk)
        body = self.trust.next_body()
        body["persons"][first]["roles"] = ["sponsor"]
        body["persons"][first]["endpoint_ids"] = [endpoint_id]
        body["targets"][endpoint_id]["sponsor_person"] = first
        self.assert_rejected(self.trust.envelope(body, signers=[first, second]))

    def test_custodian_key_recovery_uses_the_two_other_current_keys(self):
        first, second, third = self.trust.custodians
        previous, old_key = self.trust.row, self.trust.custodians[first]
        new_key = Ed25519PrivateKey.generate()
        body = self.trust.next_body()
        body["custodians"][first]["public_key"] = public(new_key)
        self.assert_rejected(self.trust.envelope(body, signers=[first, second]))
        self.publish(body, signers=[second, third])
        followup = self.trust.next_body()
        followup["policy"]["critical_min"] = 3
        self.assert_rejected(self.trust.envelope(followup, signers=[first, second]))
        self.trust.custodians[first] = new_key
        self.publish(followup, signers=[first, second])
        self.assertNotEqual(public(old_key), public(new_key))
        self.assertEqual(
            trust_registry.historical_registry(self.org, previous.revision_hash).pk, previous.pk
        )

    def test_aliases_cannot_be_assigned_to_two_canonical_people_or_recycled(self):
        operator = self.trust.people[self.operator.pk]
        reviewer = self.trust.people[self.admin.pk]
        for field in ("identity_ids", "account_ids"):
            with self.subTest(field=field, mode="duplicate"):
                body = self.trust.next_body()
                alias = body["persons"][operator][field][0]
                body["persons"][reviewer][field].append(alias)
                self.assert_rejected(self.trust.envelope(body))
            with self.subTest(field=field, mode="reassign"):
                body = self.trust.next_body()
                alias = body["persons"][operator][field].pop()
                body["persons"][reviewer][field].append(alias)
                self.assert_rejected(self.trust.envelope(body))

    def test_reencoded_cose_key_cannot_be_enrolled_as_a_second_person(self):
        operator = self.trust.people[self.operator.pk]
        reviewer = self.trust.people[self.admin.pk]
        body = self.trust.next_body()
        credential = deepcopy(body["persons"][operator]["authenticators"][0])
        cose = cbor2.loads(trust_auth.b64decode(credential["public_key"]))
        credential.update(
            id=trust_auth.b64encode(secrets.token_bytes(32)), enrollment_id=str(uuid.uuid4()),
            public_key=trust_auth.b64encode(cbor2.dumps(dict(reversed(list(cose.items()))))),
        )
        body["persons"][reviewer]["authenticators"].append(credential)
        self.assert_rejected(self.trust.envelope(body))

    def test_new_authenticator_needs_a_verified_unconsumed_enrollment_receipt(self):
        device = VirtualAuthenticator()
        person = self.trust.people[self.operator.pk]
        body = self.trust.next_body()
        body["persons"][person]["authenticators"].append({
            "id": device.id, "public_key": trust_auth.b64encode(device.cose),
            "rp_id": "pam.example.test", "origin": "https://pam.example.test", "active": True,
            "enrollment_id": str(uuid.uuid4()),
        })
        before = PAMAuthenticatorState.unscoped.count()
        self.assert_rejected(self.trust.envelope(body))
        self.assertEqual(PAMAuthenticatorState.unscoped.count(), before)

    def test_revoked_authenticator_stays_revoked_and_historical_proof_remains_valid(self):
        previous = self.trust.row
        person = self.trust.people[self.operator.pk]
        credential = self.trust.body["persons"][person]["authenticators"][0]
        state = PAMAuthenticatorState.unscoped.get(
            organization=self.org, credential_id=credential["id"]
        )
        self.trust.update(
            lambda body: body["persons"][person]["authenticators"][0].update(active=False)
        )
        request = self.trust.request(self.operator)
        with self.assertRaises(PermissionDenied):
            trust_auth.begin_action(request, "launch", {"synthetic": "request"})
        body = self.trust.next_body()
        body["persons"][person]["authenticators"][0]["active"] = True
        self.assert_rejected(self.trust.envelope(body))
        state.refresh_from_db()
        self.assertEqual(state.sign_count, 0)
        self.assertEqual(
            trust_registry.historical_registry(self.org, previous.revision_hash).pk, previous.pk
        )
        self.assertTrue(trust_auth.verify_authorization_evidence(
            self.intent.pam_trust["request"], actor=self.operator,
            organization=self.org, action="request",
        ))

    def test_standard_and_critical_policy_floors_cannot_be_lowered(self):
        for policy in (
            {"standard_min": 0, "critical_min": 2},
            {"standard_min": 1, "critical_min": 1},
            {"standard_min": 3, "critical_min": 2},
        ):
            with self.subTest(policy=policy):
                body = self.trust.next_body()
                body["policy"] = policy
                self.assert_rejected(self.trust.envelope(body))

    def test_registry_lifetime_cannot_exceed_the_bound(self):
        body = self.trust.next_body()
        issued = timezone.now()
        body.update(
            issued_at=issued.isoformat(),
            expires_at=(issued + timedelta(seconds=trust_registry.REGISTRY_TTL + 1)).isoformat(),
        )
        self.assert_rejected(self.trust.envelope(body))

    def test_absent_expired_and_overlong_checkpoints_keep_the_registry_closed(self):
        path = Path(self.trust.directory.name) / (str(self.org.pk) + ".json")
        path.unlink()
        with self.assertRaises(PermissionDenied):
            trust_registry.recognized_registry(self.org)
        now = timezone.now()
        self.checkpoint(lambda body: body.update(
            issued_at=(now - timedelta(seconds=90)).isoformat(),
            expires_at=(now - timedelta(seconds=30)).isoformat(),
        ))
        with self.assertRaises(PermissionDenied):
            trust_registry.recognized_registry(self.org)
        self.checkpoint(lambda body: body.update(
            issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=61)).isoformat(),
        ))
        with self.assertRaises(PermissionDenied):
            trust_registry.recognized_registry(self.org)

    def test_signed_checkpoint_must_match_installation_tenant_generation_and_head(self):
        for field, value in (
            ("installation", "another-installation"), ("organization", str(self.other.pk)),
            ("generation", str(uuid.uuid4())), ("revision", self.trust.row.revision + 1),
            ("registry_hash", "a" * 64),
        ):
            with self.subTest(field=field):
                self.checkpoint(lambda body, f=field, v=value: body.update({f: v}))
                with self.assertRaises(PermissionDenied):
                    trust_registry.recognized_registry(self.org)

    def test_valid_stale_checkpoint_and_restored_database_prefix_are_rejected(self):
        previous = self.trust.row
        self.trust.update(lambda body: body["policy"].update(critical_min=3))
        current = self.trust.row
        self.trust.checkpoint(previous)
        with self.assertRaises(PermissionDenied):
            trust_registry.recognized_registry(self.org)
        self.trust.checkpoint(current)
        manager = PAMTrustRevision._base_manager
        restored = manager.filter(organization=self.org, revision__lte=previous.revision)
        with patch.object(manager, "filter", return_value=restored):
            with self.assertRaises(PermissionDenied):
                trust_registry.recognized_registry(self.org)
        self.assertEqual(trust_registry.recognized_registry(self.org).pk, current.pk)

    def test_retired_commissioning_key_preserves_history_but_cannot_recommission(self):
        current = self.trust.row
        record = {
            "public_key": public(self.trust.commissioner), "active": False,
            "revoked_at": timezone.now().isoformat(),
        }
        keys = {str(self.org.pk): {"commissioner": record}}
        with override_settings(PAM_TRUST_COMMISSIONING_KEYS=keys):
            self.assertEqual(trust_registry.verify_history(self.org).pk, current.pk)
            self.assertEqual(trust_registry.recognized_registry(self.org).pk, current.pk)
            envelope, _ = self.recommissioning_envelope()
            self.assert_rejected(envelope, recommission=True)

    def test_revoked_witness_key_closes_live_authority_without_rewriting_archives(self):
        keys = {str(self.org.pk): {"witness": {
            "public_key": public(self.trust.witness), "active": False,
        }}}
        with override_settings(PAM_TRUST_CHECKPOINT_KEYS=keys):
            with self.assertRaises(PermissionDenied):
                trust_registry.recognized_registry(self.org)
            self.assertEqual(trust_registry.verify_history(self.org).pk, self.trust.row.pk)

    def test_historical_signatures_remain_verifiable_after_registry_and_checkpoint_expiry(self):
        future = timezone.now() + timedelta(days=2)
        with patch("django.utils.timezone.now", return_value=future):
            with self.assertRaises(PermissionDenied):
                trust_registry.recognized_registry(self.org)
            self.assertEqual(trust_registry.verify_history(self.org).pk, self.trust.row.pk)
            self.assertTrue(trust_auth.verify_authorization_evidence(
                self.intent.pam_trust["request"], actor=self.operator, organization=self.org,
            ))

    def test_commissioning_key_must_have_been_valid_at_the_genesis_date(self):
        genesis = PAMTrustRevision.unscoped.filter(organization=self.org, revision=1).get()
        ended = timezone.datetime.fromisoformat(genesis.body["issued_at"]) - timedelta(seconds=1)
        keys = {str(self.org.pk): {"commissioner": {
            "public_key": public(self.trust.commissioner), "revoked_at": ended.isoformat(),
        }}}
        with override_settings(PAM_TRUST_COMMISSIONING_KEYS=keys):
            with self.assertRaises(PermissionDenied):
                trust_registry.verify_history(self.org)

    def test_external_recommissioning_changes_generation_and_requires_fresh_enrollment(self):
        previous = self.trust.row
        envelope, new_keys = self.recommissioning_envelope()
        without_commissioner = deepcopy(envelope)
        without_commissioner["commissioning_signatures"] = {}
        self.assert_rejected(without_commissioner, recommission=True)
        row = trust_registry.publish_registry(envelope, recommission=True)
        self.assertNotEqual(row.generation, previous.generation)
        self.assertGreater(row.revision, previous.revision)
        self.trust.body, self.trust.row, self.trust.custodians = row.body, row, new_keys
        self.trust.checkpoint()
        self.assertEqual(trust_registry.recognized_registry(self.org).pk, row.pk)
        with self.assertRaises(PermissionDenied):
            trust_auth.begin_action(self.trust.request(self.operator), "request", {})
        self.assertEqual(
            trust_registry.historical_registry(self.org, previous.revision_hash).pk, previous.pk
        )
        self.assertTrue(trust_auth.verify_authorization_evidence(self.intent.pam_trust["request"]))

    def test_recommissioning_cannot_reset_the_monotone_revision_or_ignore_the_checkpoint(self):
        envelope, _ = self.recommissioning_envelope()
        envelope["body"].update(revision=1, previous_hash="")
        message = trust_registry.signature_message(envelope["body"])
        envelope["commissioning_signatures"]["commissioner"] = trust_auth.b64encode(
            self.trust.commissioner.sign(message)
        )
        self.assert_rejected(envelope, recommission=True)
        self.checkpoint(lambda body: body.update(registry_hash="f" * 64))
        envelope, _ = self.recommissioning_envelope()
        self.assert_rejected(envelope, recommission=True)

    def test_genesis_requires_the_external_commissioner_and_exactly_three_custodians(self):
        body = self.commissioning_body(organization=self.other)
        body["targets"] = {}
        for person in body["persons"].values():
            person.update(identity_ids=[], account_ids=[], endpoint_ids=[], roles=[])
        keys = {str(self.other.pk): {"commissioner": public(self.trust.commissioner)}}
        with override_settings(PAM_TRUST_COMMISSIONING_KEYS=keys):
            self.assert_rejected(self.trust.envelope(body), bootstrap=True)
            fewer = deepcopy(body)
            fewer["custodians"][next(iter(fewer["custodians"]))]["active"] = False
            self.assert_rejected(self.trust.envelope(fewer, commissioning=True), bootstrap=True)
            envelope = self.trust.envelope(body, commissioning=True)
            row = trust_registry.publish_registry(envelope, bootstrap=True)
            self.assertEqual(row.organization_id, self.other.pk)
            self.assertEqual(trust_registry.verify_history(self.other).pk, row.pk)
            with self.assertRaises(PermissionDenied):
                trust_registry.recognized_registry(self.other)

    def test_genesis_cannot_pre_authorize_a_personal_key_without_its_ceremony(self):
        body = self.commissioning_body(organization=self.other)
        person = self.trust.people[self.operator.pk]
        body["persons"][person]["authenticators"] = deepcopy(
            self.trust.body["persons"][person]["authenticators"]
        )
        keys = {str(self.other.pk): {"commissioner": public(self.trust.commissioner)}}
        with override_settings(PAM_TRUST_COMMISSIONING_KEYS=keys):
            self.assert_rejected(self.trust.envelope(body, commissioning=True), bootstrap=True)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL trust evidence guards")
    def test_database_rejects_raw_update_and_delete_of_registry_evidence(self):
        table = connection.ops.quote_name(PAMTrustRevision._meta.db_table)
        for statement in (
            f"UPDATE {table} SET revision_hash = %s WHERE id = %s",
            f"DELETE FROM {table} WHERE revision_hash = %s AND id = %s",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(DatabaseError), transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute(statement, [self.trust.row.revision_hash, self.trust.row.pk])
        self.assertEqual(trust_registry.verify_history(self.org).pk, self.trust.row.pk)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL authenticator counter guard")
    def test_database_rejects_counter_rollback_and_credential_reassignment(self):
        person = self.trust.people[self.operator.pk]
        credential = self.trust.body["persons"][person]["authenticators"][0]
        state = PAMAuthenticatorState.unscoped.get(
            organization=self.org, credential_id=credential["id"]
        )
        state.sign_count = 7
        state.save(update_fields=["sign_count"])
        table = connection.ops.quote_name(PAMAuthenticatorState._meta.db_table)
        for field, value in (("sign_count", 6), ("organization_id", self.other.pk)):
            with self.subTest(field=field):
                with self.assertRaises(DatabaseError), transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"UPDATE {table} SET {field} = %s WHERE id = %s", [value, state.pk]
                        )
        state.refresh_from_db()
        self.assertEqual(state.sign_count, 7)
        self.assertEqual(state.organization_id, self.org.pk)

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL tenant evidence relationships")
    def test_database_rejects_bulk_challenge_and_authorization_cross_tenant_references(self):
        source = PAMTrustChallenge.unscoped.filter(organization=self.org, action="request").first()
        source.pk = uuid.uuid4()
        source._state.adding = True
        source.used_at = None
        source.nonce = trust_auth.b64encode(secrets.token_bytes(32))
        with self.assertRaises(DatabaseError), transaction.atomic():
            source.organization = self.other
            PAMTrustChallenge.unscoped.bulk_create([source])
        source.organization = self.org
        source.pk = uuid.uuid4()
        source.save(force_insert=True)
        with self.assertRaises(DatabaseError), transaction.atomic():
            PAMTrustAuthorization.unscoped.bulk_create([PAMTrustAuthorization(
                organization=self.other, challenge=source, token_hash=secrets.token_hex(32),
                response={}, sign_count=0, verified_at=timezone.now(), expires_at=source.expires_at,
            )])
