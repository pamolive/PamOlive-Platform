import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from platform_core.attestations import signature
from platform_core.audit import record, verify_chain
from platform_core.authorization import recent_authentication
from platform_core.models import AccountSecurity, ModuleEvent, OrganizationMembership
from platform_core.security import cipher
from platform_core.services import disable_module, install_module
from platform_core.tenancy import organization_context
from platform_modules.identity.models import Grant, Resource
from platform_modules.recertification.evidence import (
    verify_decision,
    verify_manifest,
    verify_recertification,
)
from platform_modules.recertification.models import (
    Campaign,
    CampaignRun,
    Review,
    ReviewDecision,
    ReviewScope,
    Schedule,
    SchedulePublication,
)
from platform_modules.recertification.schedules import (
    process_schedules,
    publish_schedule,
    set_schedule_enabled,
)
from platform_modules.recertification.services import review_grant, start_campaign
from tests import test_platform as fixture


class RecertificationFixture:
    def setUp(self):
        fixture.PlatformTests.setUp(self)
        for actor in (self.admin, self.reviewer, self.operator):
            AccountSecurity.objects.get_or_create(
                account=actor,
                defaults={
                    "encrypted_secret": cipher().encrypt(b"synthetic-enrolled-factor").decode()
                },
            )
        self.grant = Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            account=self.account,
            resource=self.resource,
            entitlement="administrator",
            justification="Approved assignment",
            expires_at=timezone.now() + timedelta(days=100),
        )

    @contextmanager
    def assurance(self, actor=None):
        with recent_authentication(actor or self.admin, self.org, time.time()):
            yield

    @contextmanager
    def clock(self, at):
        with (
            patch("platform_modules.identity.review_contract.database_now", return_value=at),
            patch("platform_modules.recertification.schedules.database_now", return_value=at),
        ):
            yield

    def schedule(self, **overrides):
        data = dict(
            name="Weekly rights",
            first_at=timezone.now() - timedelta(days=1),
            interval_days=7,
            review_window_days=3,
            scope={},
            owner=self.reviewer,
        )
        data.update(overrides)
        with self.assurance():
            draft = publish_schedule(
                data,
                key="weekly-" + str(Schedule.objects.count()),
                actor=self.admin,
                organization=self.org,
            )
            return set_schedule_enabled(
                draft.schedule_id,
                True,
                expected_revision=draft.revision,
                actor=self.admin,
                organization=self.org,
            )

    def login(self, actor=None, *, recent=True):
        self.client.force_login(actor or self.admin)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time() if recent else 0
        session.save()

    def manual(self):
        with self.assurance(self.reviewer):
            start_campaign(
                actor=self.reviewer,
                organization=self.org,
                name="Frozen review",
                due_at=timezone.now() + timedelta(days=2),
            )
        return CampaignRun.objects.get()


class RecertificationTests(RecertificationFixture, TestCase):
    def test_due_campaign_is_unique_signed_and_does_not_grant_or_revoke(self):
        pub = self.schedule()
        with self.clock(pub.published_at + timedelta(seconds=1)):
            self.assertEqual(process_schedules(self.org), 1)
            self.assertEqual(process_schedules(self.org), 0)
        run = CampaignRun.objects.get()
        self.assertEqual(run.review_count, 1)
        self.assertTrue(verify_manifest(run))
        self.assertIsNone(run.opened_by_id)
        self.assertIsNone(run.mfa_verified_at)
        self.grant.refresh_from_db()
        self.assertEqual(self.grant.status, "active")
        self.assertTrue(
            ModuleEvent.unscoped.filter(topic="recertification.campaign.opened.v1").exists()
        )
        self.assertTrue(verify_chain(self.org))

    def test_downtime_creates_only_current_cohort_and_exposes_missed_periods(self):
        pub = self.schedule()
        first = pub.published_at + timedelta(seconds=1)
        with self.clock(first):
            process_schedules(self.org)
        with self.clock(first + timedelta(days=28)):
            process_schedules(self.org)
        runs = list(CampaignRun.objects.order_by("scheduled_for"))
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[1].missed_periods, 3)
        self.assertTrue(verify_manifest(runs[1]))

    def test_scope_filters_are_exact_and_same_reference_outside_org_is_not_included(self):
        other_resource = Resource.objects.create(
            organization=self.org, name="Other app", kind="application"
        )
        Grant.objects.create(
            organization=self.org,
            identity=self.identity,
            resource=other_resource,
            entitlement="reader",
            justification="Other",
        )
        pub = self.schedule(
            scope=dict(
                resource_ids=[str(self.resource.pk)],
                account_kinds=["privileged"],
                identity_kinds=["human"],
            )
        )
        with self.clock(pub.published_at + timedelta(seconds=1)):
            process_schedules(self.org)
        self.assertEqual(CampaignRun.objects.get().review_count, 1)
        self.assertEqual(ReviewScope.objects.get().grant_id, self.grant.pk)

    def test_manual_campaign_and_signed_decision_do_not_extend_access(self):
        original_expiry = self.grant.expires_at
        with self.assurance(self.reviewer):
            campaign = start_campaign(
                actor=self.reviewer,
                organization=self.org,
                name="Manual",
                due_at=timezone.now() + timedelta(days=1),
            )
            review = Review.objects.get(campaign=campaign)
            review_grant(
                review.pk,
                actor=self.reviewer,
                organization=self.org,
                keep=True,
                comment="Still required",
            )
        decision = ReviewDecision.objects.get()
        self.assertTrue(verify_decision(decision))
        self.grant.refresh_from_db()
        self.assertEqual(self.grant.expires_at, original_expiry)
        self.assertEqual(self.grant.state_revision, 1)
        self.assertEqual(decision.local_outcome, "kept")

    def test_decision_requires_personal_mfa_and_assigned_reviewer_or_admin(self):
        pub = self.schedule()
        with self.clock(pub.published_at + timedelta(seconds=1)):
            process_schedules(self.org)
        review = Review.objects.get()
        with self.assertRaises(PermissionDenied):
            review_grant(
                review.pk, actor=self.reviewer, organization=self.org, keep=True, comment="Denied"
            )
        OrganizationMembership.objects.filter(account=self.operator, organization=self.org).update(
            role="reviewer"
        )
        with self.assurance(self.operator), self.assertRaises(PermissionDenied):
            review_grant(
                review.pk,
                actor=self.operator,
                organization=self.org,
                keep=True,
                comment="Not assigned",
            )
        with self.assurance(self.admin):
            review_grant(
                review.pk,
                actor=self.admin,
                organization=self.org,
                keep=False,
                comment="Admin override",
            )
        self.grant.refresh_from_db()
        self.assertEqual(self.grant.status, "revoked")
        self.assertEqual(ReviewDecision.objects.get().local_outcome, "revoked")

    def test_changed_grant_cannot_be_attested_or_withdrawn_from_stale_review(self):
        with self.assurance(self.reviewer):
            campaign = start_campaign(
                actor=self.reviewer,
                organization=self.org,
                name="Snapshot",
                due_at=timezone.now() + timedelta(days=1),
            )
        self.grant.entitlement = "new-privilege"
        self.grant.save()
        for keep in (True, False):
            with self.assurance(self.reviewer), self.assertRaises(ValidationError):
                review_grant(
                    Review.objects.get(campaign=campaign).pk,
                    actor=self.reviewer,
                    organization=self.org,
                    keep=keep,
                    comment="Stale",
                )
        self.assertFalse(ReviewDecision.objects.exists())
        self.assertTrue(verify_manifest(CampaignRun.objects.get()))

    def test_legacy_campaign_is_retained_but_cannot_be_given_a_fake_snapshot(self):
        old = Campaign.objects.create(organization=self.org, name="Legacy", due_at=timezone.now())
        review = Review.objects.create(organization=self.org, campaign=old, grant=self.grant)
        with self.assurance(self.reviewer), self.assertRaises(ValidationError):
            review_grant(
                review.pk, actor=self.reviewer, organization=self.org, keep=False, comment="Old"
            )
        self.assertFalse(ReviewScope.objects.exists())
        self.grant.refresh_from_db()
        self.assertEqual(self.grant.status, "active")

    def test_disabled_module_and_inactive_owner_do_not_create_campaigns(self):
        pub = self.schedule()
        with self.assurance():
            disable_module("recertification", actor=self.admin, organization=self.org)
        self.assertEqual(process_schedules(self.org), 0)
        install_module("recertification", actor=self.admin, organization=self.org)
        OrganizationMembership.objects.filter(account=self.reviewer, organization=self.org).update(
            active=False
        )
        with self.clock(pub.published_at + timedelta(seconds=1)):
            self.assertEqual(process_schedules(self.org), 0)
        self.assertFalse(CampaignRun.objects.exists())
        self.assertEqual(Schedule.objects.get().last_error, "review_owner_unavailable")

    def test_new_configuration_stays_inactive_and_old_button_cannot_activate_it(self):
        pub = self.schedule()
        data = dict(
            name="Changed",
            first_at=pub.first_at,
            interval_days=30,
            review_window_days=5,
            scope={},
            owner=self.reviewer,
        )
        with self.assurance():
            newer = publish_schedule(
                data,
                schedule_id=pub.schedule_id,
                expected_revision=pub.revision,
                actor=self.admin,
                organization=self.org,
            )
            self.assertFalse(newer.active)
            with self.assertRaises(ValidationError):
                set_schedule_enabled(
                    pub.schedule_id,
                    True,
                    expected_revision=pub.revision,
                    actor=self.admin,
                    organization=self.org,
                )
        self.assertEqual(process_schedules(self.org), 0)

    def test_scope_limit_never_publishes_partial_campaign(self):
        pub = self.schedule()
        with (
            override_settings(RECERTIFICATION_MAX_GRANTS=0),
            self.clock(pub.published_at + timedelta(seconds=1)),
        ):
            self.assertEqual(process_schedules(self.org), 0)
        self.assertFalse(Campaign.objects.exists())
        self.assertFalse(ReviewScope.objects.exists())
        self.assertEqual(Schedule.objects.get().last_error, "review_scope_limit")

    def test_offline_verification_does_not_require_active_module_or_tenant_context(self):
        pub = self.schedule()
        with self.clock(pub.published_at + timedelta(seconds=1)):
            process_schedules(self.org)
        with self.assurance(self.reviewer):
            review_grant(
                Review.objects.get().pk,
                actor=self.reviewer,
                organization=self.org,
                keep=False,
                comment="Withdrawn",
            )
        disable_module("recertification", actor=self.admin, organization=self.org)
        with organization_context(None):
            self.assertEqual(verify_recertification(), 5)

    def test_invalid_http_decision_never_means_revoke(self):
        run = self.manual()
        self.login(self.reviewer)
        response = self.client.post(
            reverse("grant-review", args=[Review.objects.get().pk]),
            {"decision": "typo", "comment": "No withdrawal"},
        )
        self.assertRedirects(response, reverse("recertification-run", args=[run.pk]))
        self.grant.refresh_from_db()
        self.assertEqual(self.grant.status, "active")
        self.assertFalse(ReviewDecision.objects.exists())

    def test_native_schedule_form_inactive_activation_and_stale_button(self):
        self.login()
        response = self.client.post(
            reverse("recertification-schedule-new"),
            dict(
                key="native",
                name="Native",
                first_at="2026-01-01T08:00",
                interval_days="30",
                review_window_days="7",
                owner=self.reviewer.pk,
            ),
        )
        self.assertEqual(response.status_code, 302)
        pub = SchedulePublication.objects.get()
        self.assertFalse(pub.active)
        url = reverse("recertification-schedule-toggle", args=[pub.schedule_id])
        self.client.post(url, {"command": "enable", "expected_revision": "1"})
        self.assertEqual(SchedulePublication.objects.count(), 2)
        self.assertTrue(SchedulePublication.objects.order_by("-revision").first().active)
        self.client.post(url, {"command": "disable", "expected_revision": "1"})
        self.assertEqual(SchedulePublication.objects.count(), 2)
        for name, args in (
            ("recertification-home", []),
            ("recertification-schedule", [pub.schedule_id]),
            ("recertification-schedule-edit", [pub.schedule_id]),
        ):
            page = self.client.get(reverse(name, args=args))
            self.assertEqual(page.status_code, 200)
            self.assertNotContains(page, "/django-admin/")
            self.assertEqual(page["Cache-Control"], "no-store")

    def test_proof_requires_recent_mfa_and_is_scoped_no_store(self):
        run = self.manual()
        url = reverse("recertification-export", args=[run.pk])
        self.login(self.reviewer, recent=False)
        self.assertEqual(self.client.get(url).status_code, 302)
        self.login(self.reviewer)
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result["Cache-Control"], "no-store")
        body = result.json()
        self.assertTrue(body["manifest_verified"])
        self.assertTrue(body["complete"])
        self.assertEqual(body["total_scopes"], 1)
        self.assertTrue(body["scopes"][0]["verified"])
        proof = body["run"]
        self.assertEqual(
            signature(
                "pamolive.recertification/1",
                "run",
                {
                    "body": proof["body"],
                    "audit_id": proof["audit_id"],
                    "audit_hash": proof["audit_hash"],
                },
            ),
            proof["signature"],
        )
        self.assertEqual(
            self.client.get(reverse("recertification-run", args=[run.pk])).status_code, 200
        )
        self.login()
        session = self.client.session
        session["organization_id"] = str(self.other.pk)
        session.save()
        install_module("identity", actor=self.admin, organization=self.other)
        install_module("recertification", actor=self.admin, organization=self.other)
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_owner_deactivation_blocks_generation_but_not_explicit_disable(self):
        pub = self.schedule()
        OrganizationMembership.objects.filter(account=self.reviewer).update(active=False)
        with self.assurance():
            disabled = set_schedule_enabled(
                pub.schedule_id,
                False,
                expected_revision=pub.revision,
                actor=self.admin,
                organization=self.org,
            )
        self.assertFalse(disabled.active)

    def test_capture_byte_limit_and_concurrent_deactivation_publish_nothing(self):
        pub = self.schedule()
        with (
            override_settings(RECERTIFICATION_MAX_BYTES=1),
            self.clock(pub.published_at + timedelta(seconds=1)),
        ):
            self.assertEqual(process_schedules(self.org), 0)
        self.assertFalse(CampaignRun.objects.exists())
        Schedule.objects.filter(pk=pub.schedule_id).update(retry_after=None)
        from platform_modules.recertification.campaigns import capture_for_review

        def changed(*args, **kwargs):
            capture = capture_for_review(*args, **kwargs)
            OrganizationMembership.objects.filter(account=self.reviewer).update(active=False)
            return capture

        with (
            patch(
                "platform_modules.recertification.campaigns.capture_for_review", side_effect=changed
            ),
            self.clock(pub.published_at + timedelta(seconds=1)),
        ):
            self.assertEqual(process_schedules(self.org), 0)
        self.assertFalse(CampaignRun.objects.exists())

    def test_foreign_scope_and_owner_are_rejected(self):
        foreign = Resource.unscoped.create(organization=self.other, name="Foreign", kind="server")
        with self.assertRaises(ValidationError):
            self.schedule(scope={"resource_ids": [str(foreign.pk)]})
        OrganizationMembership.objects.filter(account=self.reviewer).update(organization=self.other)
        with self.assertRaises(ValidationError):
            self.schedule()
        self.assertFalse(Schedule.objects.exists())

    def test_replayed_decision_is_refused_and_already_revoked_is_a_noop(self):
        self.manual()
        from platform_modules.identity.services import revoke_grant

        revoke_grant(self.grant, actor=self.admin, organization=self.org, origin="test.withdrawn")
        self.grant.refresh_from_db()
        revision = self.grant.state_revision
        with self.assurance(self.reviewer):
            review_grant(
                Review.objects.get().pk,
                actor=self.reviewer,
                organization=self.org,
                keep=False,
                comment="Already withdrawn",
            )
            with self.assertRaises(ValidationError):
                review_grant(
                    Review.objects.get().pk,
                    actor=self.reviewer,
                    organization=self.org,
                    keep=False,
                    comment="Duplicate",
                )
        self.grant.refresh_from_db()
        self.assertEqual(self.grant.state_revision, revision)
        decision = ReviewDecision.objects.get()
        self.assertEqual(decision.local_outcome, "already_revoked")
        self.assertTrue(verify_decision(decision))

    def test_paged_export_does_not_claim_to_be_complete(self):
        for index in range(26):
            Grant.objects.create(
                organization=self.org,
                identity=self.identity,
                resource=self.resource,
                entitlement=f"role-{index}",
                justification="Test",
            )
        run = self.manual()
        self.login(self.reviewer)
        url = reverse("recertification-export", args=[run.pk])
        first = self.client.get(url).json()
        second = self.client.get(url + "?page=2").json()
        self.assertFalse(first["complete"])
        self.assertFalse(second["complete"])
        self.assertEqual(first["total_scopes"], 27)
        self.assertEqual(len(first["scopes"]), 25)
        self.assertEqual(len(second["scopes"]), 2)
        self.assertEqual(
            first["run"]["body"]["manifest_hash"], second["run"]["body"]["manifest_hash"]
        )


@skipUnless(connection.vendor == "postgresql", "PostgreSQL worker and constraint gates")
class RecertificationPostgresTests(RecertificationFixture, TransactionTestCase):
    def test_database_enforces_append_only_proofs_and_stable_scope(self):
        pub = self.schedule()
        self.manual()
        with self.assurance(self.reviewer):
            review_grant(
                Review.objects.get().pk,
                actor=self.reviewer,
                organization=self.org,
                keep=True,
                comment="Checked",
            )
        for table in (
            "recertification_schedulepublication",
            "recertification_campaignrun",
            "recertification_reviewscope",
            "recertification_reviewdecision",
        ):
            with (
                self.assertRaises(DatabaseError) as error,
                transaction.atomic(),
                connection.cursor() as cursor,
            ):
                cursor.execute(f"DELETE FROM {table}")
            self.assertEqual(error.exception.__cause__.sqlstate, "P0001")
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "UPDATE recertification_schedule SET key='changed' WHERE id=%s", [pub.schedule_id]
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23514")
        # A second organization's schedule cannot be substituted even by raw SQL.
        foreign = Schedule.unscoped.create(organization=self.other, key="foreign")
        audit = record(
            action="test.recertification.scope",
            summary="Synthetic constraint test",
            organization=self.org,
            actor=self.admin,
        )
        fields = list(pub._meta.concrete_fields)
        overrides = {"id": uuid.uuid4(), "schedule_id": foreign.pk, "audit_id": audit.pk}
        values = [overrides.get(field.attname, getattr(pub, field.attname)) for field in fields]
        # Adapt JSON exactly as Django does, without invoking model validation.
        values = [field.get_db_prep_save(value, connection) for field, value in zip(fields, values)]
        columns = ",".join(connection.ops.quote_name(field.column) for field in fields)
        placeholders = ",".join(["%s"] * len(fields))
        with (
            self.assertRaises(DatabaseError) as error,
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(
                f"INSERT INTO recertification_schedulepublication ({columns}) "
                f"VALUES ({placeholders})",
                values,
            )
        self.assertEqual(error.exception.__cause__.sqlstate, "23503")

    def test_two_active_workers_create_one_occurrence(self):
        self.schedule()

        def worker():
            close_old_connections()
            try:
                return process_schedules(self.org)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            counts = list(pool.map(lambda _: worker(), range(2)))
        self.assertEqual(sum(counts), 1)
        self.assertEqual(CampaignRun.objects.count(), 1)
        self.assertEqual(ReviewScope.objects.count(), 1)
        self.assertTrue(verify_manifest(CampaignRun.objects.get()))

    def test_normal_jobs_command_really_dispatches_due_campaigns(self):
        self.schedule()
        call_command("runjobs", once=True)
        self.assertEqual(CampaignRun.objects.count(), 1)
        self.assertTrue(verify_manifest(CampaignRun.objects.get()))
