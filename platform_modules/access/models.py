import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from platform_core.tenancy import ScopedModel


class AccessIntent(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(
        "identity.Identity",
        on_delete=models.PROTECT,
        verbose_name="Identité intervenante",
        help_text="L’acteur prévu, distinct du propriétaire éventuel du compte utilisé.",
    )
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    account = models.ForeignKey(
        "identity.ExternalAccount",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        verbose_name="Compte utilisé",
        help_text="Un compte technique partagé nécessite un mandat PAM lié à l’intervenant.",
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
    requester_binding = models.ForeignKey(
        "identity.LoginIdentityBinding",
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
    )
    account_snapshot = models.JSONField(default=dict, blank=True, editable=False)
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
    network_switch = models.ForeignKey(
        "identity.Resource",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="expected_network_intents",
    )
    network_port = models.CharField("Port réseau demandé", max_length=80, blank=True)
    network_vlan = models.CharField("VLAN demandé", max_length=80, blank=True)

    def clean(self):
        super().clean()
        if self.fulfillment == "iam_group" and (not self.account_id or not self.privilege):
            raise ValidationError("Une attribution IAM nécessite un compte et un droit précis.")
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValidationError("La fin doit suivre le début.")
        if (
            self.account_id
            and self.account.identity_id != self.identity_id
            and self.fulfillment == "iam_group"
        ):
            raise ValidationError(
                "Le provisioning IAM exige un compte de l’identité bénéficiaire. "
                "Une utilisation partagée se demande par un mandat PAM, pas un droit SCIM."
            )
        if self.requester_binding_id and (
            self.requester_binding.identity_id != self.identity_id
            or self.requester_binding.login_account_id != self.requested_by_id
        ):
            raise ValidationError("Le lien du demandeur ne correspond pas à l’intervenant.")
        if self.network_switch_id or self.network_port or self.network_vlan:
            if self.fulfillment != "observe":
                raise ValidationError(
                    "Le déplacement réseau précis est actuellement évalué en observation. "
                    "Aucun provisioning NAC/switch n’est exécuté par ce parcours."
                )
            if not self.network_switch_id or not self.network_port or not self.network_vlan:
                raise ValidationError("Un déplacement réseau exige switch, port et VLAN précis.")
            if self.network_switch.kind != "network":
                raise ValidationError("Le switch demandé doit être une ressource réseau.")

    def __str__(self):
        return f"{self.identity} → {self.resource} · {self.reference or self.method}"


class AccessEvent(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField("Source", max_length=180)
    external_id = models.CharField("Identifiant source", max_length=180)
    occurred_at = models.DateTimeField("Date source")
    received_at = models.DateTimeField(auto_now_add=True)
    identity = models.ForeignKey(
        "identity.Identity",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        verbose_name="Acteur rapporté par la source",
        help_text=(
            "Laissez vide si la source ne connaît pas l’acteur. "
            "Le propriétaire d’un compte ou d’un certificat n’est pas déduit comme acteur."
        ),
    )
    account = models.ForeignKey(
        "identity.ExternalAccount",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        verbose_name="Compte observé",
        help_text="Peut appartenir à une autre identité de cette organisation (compte partagé).",
    )
    resource = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    credential = models.ForeignKey(
        "identity.Credential",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        verbose_name="Certificat / badge observé",
        help_text="Son propriétaire reste distinct de l’acteur rapporté ; aucun secret à fournir.",
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
    domain = models.CharField(
        "Domaine d’observation",
        max_length=20,
        blank=True,
        choices=[
            ("physical", "Physique"),
            ("pam", "PAM"),
            ("remote", "Assistance distante"),
            ("network", "Réseau"),
            ("application", "Application"),
            ("certificate", "Certificat"),
            ("directory", "Annuaire"),
            ("cloud", "Cloud"),
        ],
    )
    network_switch = models.ForeignKey(
        "identity.Resource",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="switch_observations",
    )
    network_port = models.CharField("Port réseau observé", max_length=80, blank=True)
    network_vlan = models.CharField("VLAN observé", max_length=80, blank=True)
    credential_observation = models.CharField(
        "Nature de l’observation du credential",
        max_length=30,
        default="identifier_only",
        choices=[
            ("identifier_only", "Identifiant public seulement"),
            ("possession_asserted", "Possession déclarée par la source, non vérifiée ici"),
        ],
    )

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
        if self.network_switch_id and self.network_switch.kind != "network":
            raise ValidationError("Le switch observé doit être une ressource réseau.")

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
    rule_version = models.CharField(max_length=30, default="access-context/5")
    findings = models.JSONField(default=list)
    evaluated_at = models.DateTimeField(auto_now_add=True)
