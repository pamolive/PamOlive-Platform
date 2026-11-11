"""An exception is a tracked justification, never an authorization override."""

import uuid
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.attestations import ImmutableEvidence


class ExceptionCase(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey("identity.Identity", on_delete=models.PROTECT)
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    entitlement = models.CharField(max_length=160)
    reason = models.TextField()
    reference = models.CharField(max_length=180)
    compensating_controls = models.TextField()
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.CheckConstraint(
                condition=models.Q(expires_at__gt=models.F("created_at")),
                name="governance_exception_positive_period",
            ),
            models.CheckConstraint(
                condition=models.Q(expires_at__lte=models.F("created_at") + timedelta(days=30)),
                name="governance_exception_max_period",
            ),
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=(2, 5, 10, 15)),
                name="governance_exception_request_mfa",
            ),
        ]

    def __str__(self):
        return f"{self.reference} · {self.entitlement}"


class ExceptionDecision(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(ExceptionCase, on_delete=models.PROTECT, related_name="decisions")
    decision = models.CharField(
        max_length=10,
        choices=[("accepted", "Acceptée"), ("rejected", "Refusée"), ("closed", "Clôturée")],
    )
    comment = models.TextField()
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    decided_at = models.DateTimeField(default=timezone.now)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(ImmutableEvidence.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=("case",),
                condition=models.Q(decision__in=("accepted", "rejected")),
                name="governance_exception_one_review",
            ),
            models.UniqueConstraint(
                fields=("case",),
                condition=models.Q(decision="closed"),
                name="governance_exception_one_closure",
            ),
            models.CheckConstraint(
                condition=models.Q(decision__in=("accepted", "rejected", "closed")),
                name="governance_exception_known_decision",
            ),
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=(2, 5, 10, 15)),
                name="governance_exception_review_mfa",
            ),
        ]

    def clean(self):
        super().clean()
        if self.decision != "closed" and self.case_id:
            if self.decided_by_id == self.case.requested_by_id:
                raise ValidationError("Le demandeur ne peut pas examiner sa propre exception.")
