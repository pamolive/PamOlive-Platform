import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel


class EventSource(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Nom de source", max_length=180)
    token_hash = models.CharField(max_length=64, unique=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class ProvisioningConnector(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Nom", max_length=180)
    adapter = models.CharField(max_length=20, default="scim2", choices=[("scim2", "SCIM 2.0")])
    base_url = models.URLField("URL de base HTTPS SCIM", max_length=500)
    encrypted_token = models.TextField()
    revision = models.PositiveIntegerField(default=1)
    enabled = models.BooleanField(default=False)
    verified_revision = models.PositiveIntegerField(null=True, blank=True)
    tested_at = models.DateTimeField(null=True, blank=True)
    test_code = models.CharField(max_length=80, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class AccountBinding(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connector = models.ForeignKey(ProvisioningConnector, on_delete=models.PROTECT)
    account = models.ForeignKey("identity.ExternalAccount", on_delete=models.PROTECT)
    remote_id = models.CharField("ID SCIM de l’utilisateur", max_length=180)
    claim_token = models.UUIDField(null=True, blank=True, editable=False)
    claim_expires_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "account"], name="unique_provisioned_account"
            ),
            models.UniqueConstraint(
                fields=["organization", "connector", "remote_id"],
                name="unique_connector_remote_account",
            ),
        ]

    def __str__(self):
        return f"{self.account} → {self.connector} · {self.remote_id}"


class GroupBinding(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connector = models.ForeignKey(ProvisioningConnector, on_delete=models.PROTECT)
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    entitlement = models.CharField("Droit / rôle local", max_length=160)
    remote_id = models.CharField("ID SCIM du groupe", max_length=180)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "connector", "resource", "entitlement"],
                name="unique_provisioned_group",
            )
        ]

    def __str__(self):
        return f"{self.resource} · {self.entitlement} → {self.remote_id}"


class ExternalChange(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        "identity.ExternalAccount", null=True, blank=True, on_delete=models.PROTECT
    )
    grant = models.ForeignKey("identity.Grant", null=True, blank=True, on_delete=models.PROTECT)
    binding = models.ForeignKey(AccountBinding, null=True, blank=True, on_delete=models.PROTECT)
    group = models.ForeignKey(GroupBinding, null=True, blank=True, on_delete=models.PROTECT)
    connector_revision = models.PositiveIntegerField(null=True, blank=True)
    kind = models.CharField(
        max_length=24,
        choices=[
            ("disable_account", "Désactiver le compte"),
            ("add_membership", "Attribuer le droit"),
            ("remove_membership", "Retirer le droit"),
        ],
    )
    idempotency_key = models.CharField(max_length=255)
    status = models.CharField(
        max_length=20,
        default="unmapped",
        choices=[
            ("unmapped", "Correspondance à configurer"),
            ("queued", "En attente d’exécution"),
            ("running", "En cours"),
            ("retry", "Nouvelle tentative prévue"),
            ("succeeded", "Confirmé sur le système cible"),
            ("failed", "Échec à traiter"),
            ("blocked", "Bloqué par la configuration"),
            ("cancelled", "Intention devenue obsolète"),
        ],
    )
    authorized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT
    )
    authorization_at = models.DateTimeField(null=True, blank=True)
    attempts = models.PositiveIntegerField(default=0)
    attempt_limit = models.PositiveIntegerField(default=5)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    claim_token = models.UUIDField(null=True, blank=True)
    claim_expires_at = models.DateTimeField(null=True, blank=True)
    result_code = models.CharField(max_length=80, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "idempotency_key"], name="unique_external_change"
            )
        ]
        indexes = [models.Index(fields=["organization", "status", "next_attempt_at"])]

    def __str__(self):
        return f"{self.get_kind_display()} · {self.account} · {self.get_status_display()}"


class ExecutionEvidence(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    change = models.ForeignKey(ExternalChange, on_delete=models.PROTECT, related_name="proofs")
    attempt = models.PositiveIntegerField()
    code = models.CharField(max_length=80)
    confirmed = models.BooleanField(default=False)
    observed = models.JSONField(default=dict)
    recorded_at = models.DateTimeField(auto_now_add=True)


from .teamviewer_access_models import (  # noqa: E402,F401
    TeamViewerAccessCursor,
    TeamViewerAccessObservation,
)
from .teamviewer_mapping_models import TeamViewerMapping, TeamViewerSighting  # noqa: E402,F401
from .teamviewer_models import (  # noqa: E402,F401
    TeamViewerCollector,
    TeamViewerReport,
    TeamViewerRun,
)
from .teamviewer_session_models import (  # noqa: E402,F401
    TeamViewerSession,
    TeamViewerSessionEvidence,
)
