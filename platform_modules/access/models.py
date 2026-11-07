import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from platform_core.tenancy import ScopedModel


class AccessIntent(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey("identity.Identity", on_delete=models.PROTECT)
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    account = models.ForeignKey(
        "identity.ExternalAccount", null=True, blank=True, on_delete=models.PROTECT
    )
    method = models.CharField("Méthode (SSH, RDP, badge…)", max_length=80)
    location = models.CharField("Origine / lieu autorisé", max_length=255, blank=True)
    privilege = models.CharField("Privilège", max_length=160, blank=True)
    reason = models.TextField("Pourquoi ?")
    reference = models.CharField("Ticket / contrat / projet", max_length=180, blank=True)
    contract = models.ForeignKey(
        "governance.SupplierContract", null=True, blank=True, on_delete=models.PROTECT
    )
    country_code = models.CharField("Pays d’origine déclaré (2 lettres)", max_length=2, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)
    approved_at = models.DateTimeField(null=True, blank=True, editable=False)
    fulfillment = models.CharField(
        "Suite après approbation",
        max_length=20,
        default="observe",
        choices=[
            ("observe", "Justification et observation"),
            ("iam_group", "Attribution temporaire d’un droit IAM"),
            ("pam", "Autorisation de session privilégiée"),
        ],
    )
    provisioned_grant = models.ForeignKey(
        "identity.Grant",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="approved_intents",
    )
    starts_at = models.DateTimeField("Début")
    ends_at = models.DateTimeField("Fin")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    status = models.CharField(
        max_length=16,
        default="pending",
        choices=[
            ("pending", "À approuver"),
            ("approved", "Approuvée"),
            ("denied", "Refusée"),
            ("revoked", "Révoquée"),
        ],
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        super().clean()
        if self.fulfillment == "iam_group" and (not self.account_id or not self.privilege):
            raise ValidationError("Une attribution IAM nécessite un compte et un droit précis.")
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValidationError("La fin doit suivre le début.")
        if self.account_id and self.account.identity_id != self.identity_id:
            raise ValidationError("Le compte ne correspond pas à l’identité.")

    def __str__(self):
        return f"{self.identity} → {self.resource} · {self.reference or self.method}"


class AccessEvent(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField("Source", max_length=180)
    external_id = models.CharField("Identifiant source", max_length=180)
    occurred_at = models.DateTimeField("Date source")
    received_at = models.DateTimeField(auto_now_add=True)
    identity = models.ForeignKey(
        "identity.Identity", null=True, blank=True, on_delete=models.PROTECT
    )
    account = models.ForeignKey(
        "identity.ExternalAccount", null=True, blank=True, on_delete=models.PROTECT
    )
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    credential = models.ForeignKey(
        "identity.Credential", null=True, blank=True, on_delete=models.PROTECT
    )
    method = models.CharField("Méthode", max_length=80)
    action = models.CharField("Action", max_length=180)
    location = models.CharField("Origine / lieu observé", max_length=255, blank=True)
    privilege = models.CharField("Privilège observé", max_length=160, blank=True)
    result = models.CharField("Résultat", max_length=80, default="success")
    contract = models.ForeignKey(
        "governance.SupplierContract", null=True, blank=True, on_delete=models.PROTECT
    )
    country_code = models.CharField(
        "Pays observé fourni par la source (2 lettres)", max_length=2, blank=True
    )
    evidence = models.TextField("Référence de preuve", blank=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "source", "external_id"], name="unique_access_source_event"
            )
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Un fait source ne peut pas être réécrit.")
        return super().save(*args, **kwargs)

    def clean(self):
        super().clean()
        if self.account_id and self.identity_id != self.account.identity_id:
            raise ValidationError("Le compte observé ne correspond pas à l’identité.")
        if self.credential_id and self.identity_id != self.credential.identity_id:
            raise ValidationError("Le credential ne correspond pas à l’identité.")

    def __str__(self):
        return f"{self.occurred_at:%d/%m %H:%M} · {self.action} · {self.resource}"


class AccessEvaluation(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.ForeignKey(AccessEvent, on_delete=models.PROTECT, related_name="evaluations")
    intent = models.ForeignKey(AccessIntent, null=True, on_delete=models.PROTECT)
    verdict = models.CharField(
        max_length=20,
        choices=[
            ("expected", "Conforme au périmètre"),
            ("deviation", "Écart à examiner"),
            ("unknown", "Contexte insuffisant"),
        ],
    )
    rule_version = models.CharField(max_length=30, default="access-contract/2")
    findings = models.JSONField(default=list)
    evaluated_at = models.DateTimeField(auto_now_add=True)
