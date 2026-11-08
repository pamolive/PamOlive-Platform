import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from platform_core.attestations import ImmutableEvidence
from platform_core.tenancy import ScopedModel


class Schedule(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.SlugField(max_length=80)
    created_at = models.DateTimeField(default=timezone.now)
    retry_after = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=80, blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(fields=("organization", "key"), name="recert_schedule_key")
        ]

    def __str__(self):
        return self.key


class SchedulePublication(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    schedule = models.ForeignKey(Schedule, on_delete=models.PROTECT)
    revision = models.PositiveIntegerField()
    name = models.CharField(max_length=140)
    active = models.BooleanField(default=False)
    first_at = models.DateTimeField()
    interval_days = models.PositiveSmallIntegerField()
    review_window_days = models.PositiveSmallIntegerField()
    scope = models.JSONField(default=dict)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="owned_recertification_publications",
    )
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    published_at = models.DateTimeField(default=timezone.now)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.UniqueConstraint(fields=("schedule", "revision"), name="recert_publication_rev"),
            models.CheckConstraint(
                condition=models.Q(revision__gte=1), name="recert_revision_positive"
            ),
            models.CheckConstraint(
                condition=models.Q(interval_days__gte=1, interval_days__lte=3660),
                name="recert_interval_days",
            ),
            models.CheckConstraint(
                condition=models.Q(review_window_days__gte=1, review_window_days__lte=365),
                name="recert_window_days",
            ),
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=(2, 5, 10, 15)),
                name="recert_publication_mfa",
            ),
        ]


class CampaignRun(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.OneToOneField("recertification.Campaign", on_delete=models.PROTECT)
    publication = models.ForeignKey(
        SchedulePublication, on_delete=models.PROTECT, null=True, blank=True
    )
    schedule = models.ForeignKey(Schedule, on_delete=models.PROTECT, null=True, blank=True)
    scheduled_for = models.DateTimeField(null=True, blank=True)
    next_due_at = models.DateTimeField(null=True, blank=True)
    missed_periods = models.PositiveBigIntegerField(default=0)
    capture_started_at = models.DateTimeField()
    snapshot_at = models.DateTimeField()
    opened_at = models.DateTimeField(default=timezone.now)
    due_at = models.DateTimeField()
    name = models.CharField(max_length=180)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="owned_recertification_runs",
    )
    opened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True
    )
    mfa_verified_at = models.DateTimeField(null=True, blank=True)
    mfa_window_minutes = models.PositiveSmallIntegerField(null=True, blank=True)
    review_count = models.PositiveIntegerField()
    selection_scope = models.JSONField(default=dict)
    manifest_hash = models.CharField(max_length=64)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=("publication", "scheduled_for"), name="recert_occurrence_once"
            )
        ]


class ReviewScope(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run = models.ForeignKey(CampaignRun, on_delete=models.PROTECT)
    campaign = models.ForeignKey("recertification.Campaign", on_delete=models.PROTECT)
    review = models.OneToOneField("recertification.Review", on_delete=models.PROTECT)
    grant = models.ForeignKey("identity.Grant", on_delete=models.PROTECT)
    snapshot = models.JSONField(default=dict)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [models.UniqueConstraint(fields=("run", "grant"), name="recert_run_grant")]


class ReviewDecision(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scope = models.OneToOneField(ReviewScope, on_delete=models.PROTECT)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    decided_at = models.DateTimeField(default=timezone.now)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    keep = models.BooleanField()
    comment = models.TextField()
    local_outcome = models.CharField(max_length=32)
    grant_state = models.JSONField(default=dict)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=(2, 5, 10, 15)),
                name="recert_decision_mfa",
            )
        ]
