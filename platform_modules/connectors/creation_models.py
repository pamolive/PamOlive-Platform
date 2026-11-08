"""Signed creation authority, one-shot dispatch and inactive-user confirmation."""

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel

from .business_models import BusinessEvidence


class ScimCreationRequest(BusinessEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey("identity.ExternalAccount", on_delete=models.PROTECT)
    intent = models.ForeignKey("access.AccessIntent", on_delete=models.PROTECT)
    connector = models.ForeignKey("connectors.ProvisioningConnector", on_delete=models.PROTECT)
    scope = models.JSONField(default=dict)
    username = models.CharField(max_length=180)
    external_id = models.CharField(max_length=180, unique=True)
    activate_after_grant = models.BooleanField(default=False)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    published_at = models.DateTimeField(default=timezone.now)
    mfa_verified_at = models.DateTimeField()
    mfa_window_minutes = models.PositiveSmallIntegerField()
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)

    class Meta(BusinessEvidence.Meta):
        constraints = [
            models.CheckConstraint(
                condition=models.Q(mfa_window_minutes__in=(2, 5, 10, 15)),
                name="scim_creation_mfa_window",
            )
        ]


class ScimCreationJob(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.OneToOneField("identity.ExternalAccount", on_delete=models.PROTECT)
    request = models.ForeignKey(ScimCreationRequest, on_delete=models.PROTECT)
    binding = models.ForeignKey(
        "connectors.AccountBinding", null=True, blank=True, on_delete=models.PROTECT
    )
    status = models.CharField(
        max_length=20,
        default="queued",
        choices=[
            ("queued", "Création en attente"),
            ("running", "Vérification en cours"),
            ("retry", "Nouvelle lecture prévue"),
            ("created", "Compte désactivé confirmé"),
            ("unconfirmed", "Résultat incertain à vérifier"),
            ("failed", "Échec à traiter"),
            ("cancelled", "Autorisation devenue obsolète"),
        ],
    )
    attempts = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    claim_token = models.UUIDField(null=True, blank=True)
    claim_expires_at = models.DateTimeField(null=True, blank=True)
    result_code = models.CharField(max_length=80, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class ScimCreationDispatch(BusinessEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.OneToOneField(ScimCreationJob, on_delete=models.PROTECT)
    request = models.OneToOneField(ScimCreationRequest, on_delete=models.PROTECT)
    reserved_at = models.DateTimeField(default=timezone.now)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)


class ScimCreationProof(BusinessEvidence):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dispatch = models.OneToOneField(ScimCreationDispatch, on_delete=models.PROTECT)
    binding = models.OneToOneField("connectors.AccountBinding", on_delete=models.PROTECT)
    remote_id = models.CharField(max_length=180)
    confirmed_at = models.DateTimeField(default=timezone.now)
    audit = models.OneToOneField("platform_core.AuditEvent", on_delete=models.PROTECT)
    signature = models.CharField(max_length=64)
