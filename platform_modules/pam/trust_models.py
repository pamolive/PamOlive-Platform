"""Public, independently signed PAM authority and authenticator replay state."""

import uuid

from django.db import models
from django.utils import timezone

from platform_core.attestations import ImmutableEvidence
from platform_core.tenancy import ScopedModel


class PAMTrustRevision(ImmutableEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    generation = models.UUIDField(editable=False)
    revision = models.PositiveBigIntegerField(editable=False)
    previous_hash = models.CharField(max_length=64, blank=True, editable=False)
    body = models.JSONField(editable=False)
    signatures = models.JSONField(default=dict, editable=False)
    commissioning_signatures = models.JSONField(default=dict, editable=False)
    revision_hash = models.CharField(max_length=64, unique=True, editable=False)
    accepted_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta(ImmutableEvidence.Meta):
        ordering = ["revision"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "revision"], name="unique_pam_trust_revision"
            ),
        ]


class PAMAuthenticatorState(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential_id = models.CharField(max_length=2048, editable=False)
    sign_count = models.PositiveBigIntegerField(default=0, editable=False)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "credential_id"], name="unique_pam_authenticator_state"
            ),
        ]
