import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from platform_core.tenancy import ScopedModel

from .trust_auth_models import (  # noqa: F401
    PAMTrustAuthorization,
    PAMTrustChallenge,
    PAMTrustEnrollment,
)
from .trust_models import PAMAuthenticatorState, PAMTrustRevision  # noqa: F401


class SessionLease(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    intent = models.ForeignKey("access.AccessIntent", on_delete=models.PROTECT)
    opened_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    started_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True)
    status = models.CharField(max_length=16, default="active")
    broker_reference = models.CharField(max_length=180, blank=True)


class SessionEndpoint(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=180)
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    account = models.ForeignKey("identity.ExternalAccount", on_delete=models.PROTECT)
    protocol = models.CharField(max_length=8, choices=[("ssh", "SSH"), ("rdp", "RDP")])
    hostname = models.CharField(max_length=253)
    port = models.PositiveIntegerField()
    domain = models.CharField(max_length=180, blank=True)
    auth_method = models.CharField(
        max_length=16, choices=[("password", "Mot de passe"), ("private_key", "Clé privée SSH")]
    )
    encrypted_secret = models.TextField(editable=False)
    credential_seal = models.CharField(max_length=64, blank=True, editable=False)
    destination_epoch = models.PositiveIntegerField(default=1, editable=False)
    ssh_host_key = models.TextField(blank=True)
    certificate_pin = models.CharField(max_length=64, blank=True)
    revision = models.PositiveIntegerField(default=1)
    verified_revision = models.PositiveIntegerField(null=True, editable=False)
    tested_at = models.DateTimeField(null=True, editable=False)
    test_code = models.CharField(max_length=80, blank=True, editable=False)
    enabled = models.BooleanField(default=False)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "resource", "account", "protocol"],
                name="unique_pam_endpoint",
            )
        ]

    def clean(self):
        super().clean()
        if self.resource_id and self.resource.kind not in ("server", "device", "cloud"):
            raise ValidationError("Une cible PAM doit être un serveur, appareil ou hôte cloud.")
        if self.account_id:
            from .mandates import account_can_use_pam

            if not account_can_use_pam(self.account):
                raise ValidationError("Sélectionnez un compte privilégié ou un service technique.")
        if self.protocol == "rdp" and self.auth_method != "password":
            raise ValidationError("Le relais RDP utilise un mot de passe avec NLA.")

    def __str__(self):
        return self.name


LIVE_CONNECTION_STATES = ("pending", "connecting", "active")


class RelayConnection(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    lease = models.ForeignKey(SessionLease, on_delete=models.PROTECT, related_name="connections")
    endpoint = models.ForeignKey(SessionEndpoint, on_delete=models.PROTECT)
    opened_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    endpoint_revision = models.PositiveIntegerField()
    ticket_hash = models.CharField(max_length=64, blank=True, editable=False)
    ticket_expires_at = models.DateTimeField()
    browser_session_hash = models.CharField(max_length=64, editable=False)
    client_ip = models.GenericIPAddressField()
    owner_token = models.UUIDField(null=True, editable=False)
    instance_id = models.CharField(max_length=80, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    connected_at = models.DateTimeField(null=True, blank=True)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    stop_requested_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=16,
        default="pending",
        choices=[
            ("pending", "Ouverture autorisée"),
            ("connecting", "Connexion du relais"),
            ("active", "Relais ouvert"),
            ("ended", "Terminé"),
            ("failed", "Échec"),
            ("expired", "Expiré"),
        ],
    )
    end_reason = models.CharField(max_length=80, blank=True)
    target_snapshot = models.JSONField(default=dict, editable=False)
    authority_snapshot = models.JSONField(default=dict, editable=False)
    authority_seal = models.CharField(max_length=64, editable=False)
    recording_chunks = models.PositiveIntegerField(default=0, editable=False)
    recording_bytes = models.PositiveBigIntegerField(default=0, editable=False)
    recording_hash = models.CharField(max_length=64, blank=True, editable=False)
    recording_complete = models.BooleanField(default=False, editable=False)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["lease"],
                condition=models.Q(status__in=LIVE_CONNECTION_STATES),
                name="one_live_relay_per_lease",
            )
        ]
        indexes = [models.Index(fields=["organization", "status", "heartbeat_at"])]

    def clean(self):
        super().clean()
        if self.lease_id and self.opened_by_id != self.lease.opened_by_id:
            raise ValidationError(
                "Le demandeur du relais doit être le titulaire de l’autorisation."
            )
        if (
            self.lease_id
            and self.endpoint_id
            and (
                self.endpoint.resource_id != self.lease.intent.resource_id
                or self.endpoint.account_id != self.lease.intent.account_id
                or self.endpoint.protocol != self.lease.intent.method.casefold()
            )
        ):
            raise ValidationError("La cible ne correspond pas au périmètre approuvé.")


class RecordingChunk(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connection = models.ForeignKey(RelayConnection, on_delete=models.PROTECT, related_name="chunks")
    sequence = models.PositiveIntegerField()
    elapsed_ms = models.PositiveBigIntegerField()
    payload_size = models.PositiveIntegerField()
    encrypted_payload = models.BinaryField()
    previous_hash = models.CharField(max_length=64, blank=True)
    chunk_hash = models.CharField(max_length=64)
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["connection", "sequence"],
                name="unique_pam_recording_sequence",
            )
        ]
        ordering = ["sequence"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Les enregistrements sont immuables.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Les enregistrements sont immuables.")
