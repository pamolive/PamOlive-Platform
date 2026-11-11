"""Durable WebAuthn ceremonies and their single-use application authorizations."""

import uuid

from django.conf import settings
from django.db import models

from platform_core.tenancy import ScopedModel


class PAMTrustChallenge(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    person_id = models.UUIDField()
    action = models.CharField(max_length=64)
    payload_hash = models.CharField(max_length=64)
    session_hash = models.CharField(max_length=64)
    registry_hash = models.CharField(max_length=64)
    registry_generation = models.UUIDField()
    registry_revision = models.PositiveBigIntegerField()
    policy_hash = models.CharField(max_length=64)
    nonce = models.CharField(max_length=64)
    credential_id = models.CharField(max_length=2048, blank=True)
    public_key = models.TextField(blank=True)
    rp_id = models.CharField(max_length=253)
    origin = models.URLField(max_length=500)
    encrypted_form = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta(ScopedModel.Meta):
        indexes = [models.Index(fields=["organization", "account", "expires_at"])]


class PAMTrustAuthorization(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    challenge = models.OneToOneField(PAMTrustChallenge, on_delete=models.PROTECT)
    token_hash = models.CharField(max_length=64, unique=True)
    response = models.JSONField()
    sign_count = models.PositiveBigIntegerField()
    verified_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)


class PAMTrustEnrollment(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    registration = models.OneToOneField(PAMTrustChallenge, on_delete=models.PROTECT)
    possession = models.OneToOneField(
        PAMTrustChallenge, null=True, blank=True, on_delete=models.PROTECT,
        related_name="possession_enrollment",
    )
    account = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    person_id = models.UUIDField()
    credential_id = models.CharField(max_length=2048)
    public_key = models.TextField()
    rp_id = models.CharField(max_length=253)
    origin = models.URLField(max_length=500)
    registry_generation = models.UUIDField()
    registration_response = models.JSONField()
    possession_response = models.JSONField(default=dict)
    sign_count = models.PositiveBigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)
