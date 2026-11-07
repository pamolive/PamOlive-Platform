import uuid
from functools import reduce
from operator import or_

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from platform_core.tenancy import ScopedModel

DOMAINS = [
    ("physical", "Accès physique"),
    ("pam", "PAM"),
    ("remote", "Assistance distante"),
    ("network", "Réseau"),
    ("application", "Applications"),
    ("certificate", "Certificats"),
    ("directory", "Annuaires"),
    ("cloud", "Cloud"),
]
NODE_FIELDS = {
    "identity": "identity.Identity",
    "account": "identity.ExternalAccount",
    "resource": "identity.Resource",
    "credential": "identity.Credential",
    "supplier": "governance.Supplier",
}


class GraphNode(ScopedModel):
    """Typed FK anchors, not an unvalidated generic content-type/id relation."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=20, choices=[(key, key) for key in NODE_FIELDS])
    identity = models.ForeignKey(
        "identity.Identity", null=True, blank=True, on_delete=models.PROTECT
    )
    account = models.ForeignKey(
        "identity.ExternalAccount", null=True, blank=True, on_delete=models.PROTECT
    )
    resource = models.ForeignKey(
        "identity.Resource", null=True, blank=True, on_delete=models.PROTECT
    )
    credential = models.ForeignKey(
        "identity.Credential", null=True, blank=True, on_delete=models.PROTECT
    )
    supplier = models.ForeignKey(
        "governance.Supplier", null=True, blank=True, on_delete=models.PROTECT
    )

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(fields=["organization", key], name=f"graph_unique_{key}")
            for key in NODE_FIELDS
        ] + [
            models.CheckConstraint(
                condition=reduce(
                    or_,
                    [
                        models.Q(
                            kind=key, **{f"{name}__isnull": name != key for name in NODE_FIELDS}
                        )
                        for key in NODE_FIELDS
                    ],
                ),
                name="graph_exact_typed_subject",
            )
        ]

    def clean(self):
        super().clean()
        selected = [key for key in NODE_FIELDS if getattr(self, f"{key}_id")]
        if selected != [self.kind]:
            raise ValidationError("Un nœud doit désigner exactement un objet du type choisi.")

    @property
    def subject(self):
        return getattr(self, self.kind)

    @property
    def key(self):
        return f"{self.kind}:{self.subject.pk}"

    def __str__(self):
        return f"{self.get_kind_display()} · {self.subject}"


RELATIONS = [
    ("owns", "possède"),
    ("runs-on", "s’exécute sur"),
    ("located-in", "se trouve dans"),
    ("managed-by", "est géré par"),
    ("expected-on", "est attendu sur"),
    ("issued-by", "est émis par"),
    ("reaches", "peut joindre (topologie déclarée)"),
]
PAIRS = {
    "owns": ("identity", "resource"),
    "runs-on": ("identity", "resource"),
    "located-in": ("resource", "resource"),
    "managed-by": ("resource", "resource"),
    "expected-on": ("credential", "resource"),
    "issued-by": ("credential", "resource"),
    "reaches": ("resource", "resource"),
}


class ContextLink(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(GraphNode, on_delete=models.PROTECT, related_name="outgoing")
    target = models.ForeignKey(GraphNode, on_delete=models.PROTECT, related_name="incoming")
    relation = models.CharField(max_length=20, choices=RELATIONS)
    evidence = models.CharField("Référence de preuve / provenance", max_length=500)
    confidence = models.CharField(
        "Confiance déclarée",
        max_length=20,
        choices=[("verified", "Vérifiée par le déclarant"), ("declared", "Déclarée, à corroborer")],
        default="declared",
    )
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    recorded_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(null=True, blank=True, editable=False)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)

    def clean(self):
        super().clean()
        if self.source_id and self.target_id:
            if self.source_id == self.target_id or PAIRS.get(self.relation) != (
                self.source.kind,
                self.target.kind,
            ):
                raise ValidationError("Types de relation ou objets incompatibles.")
            if self.relation == "located-in" and self.target.subject.kind != "zone":
                raise ValidationError("Le lieu cible doit être une zone physique.")
            if self.relation == "managed-by" and self.target.subject.kind != "application":
                raise ValidationError("Le gestionnaire doit être une application ressource.")
            if self.relation == "expected-on" and self.source.subject.kind != "certificate":
                raise ValidationError("Cette relation d’hôte attendu concerne les certificats.")
        if self.valid_until and self.valid_until <= self.valid_from:
            raise ValidationError("La fin doit suivre le début.")


class CollectionScope(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey("connectors.EventSource", on_delete=models.PROTECT)
    domain = models.CharField(max_length=20, choices=DOMAINS)
    resource = models.ForeignKey(
        "identity.Resource", null=True, blank=True, on_delete=models.PROTECT
    )
    effective_at = models.DateTimeField(default=timezone.now)
    retired_at = models.DateTimeField(null=True, blank=True, editable=False)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)

    def __str__(self):
        target = self.resource or "organisation entière"
        return f"{self.source} · {self.get_domain_display()} · {target}"


class CollectionReport(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scope = models.ForeignKey(CollectionScope, on_delete=models.PROTECT)
    external_id = models.CharField("Identifiant du rapport chez la source", max_length=180)
    sequence = models.PositiveBigIntegerField(editable=False)
    covered_from = models.DateTimeField()
    covered_until = models.DateTimeField()
    state = models.CharField(
        max_length=20,
        choices=[
            ("complete", "Collecte déclarée complète"),
            ("partial", "Collecte partielle"),
            ("unavailable", "Source indisponible"),
        ],
    )
    clock_uncertainty_seconds = models.PositiveSmallIntegerField(null=True, blank=True)
    detail = models.CharField("Détail non secret", max_length=180, blank=True)
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta(ScopedModel.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "scope", "external_id"], name="unique_collection_report"
            ),
            models.UniqueConstraint(
                fields=["organization", "scope", "sequence"], name="unique_collection_sequence"
            ),
        ]

    def clean(self):
        super().clean()
        if self.covered_from and self.covered_until and self.covered_until <= self.covered_from:
            raise ValidationError("La fin de collecte doit suivre son début.")
        if self.clock_uncertainty_seconds is not None and self.clock_uncertainty_seconds > 3600:
            raise ValidationError(
                "L’incertitude d’horloge doit être comprise entre 0 et 3600 secondes."
            )

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Un rapport source est immuable.")
        return super().save(*args, **kwargs)


class NetworkPlacement(ScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey("identity.Identity", on_delete=models.PROTECT)
    switch = models.ForeignKey("identity.Resource", on_delete=models.PROTECT)
    port = models.CharField("Port attendu", max_length=80)
    vlan = models.CharField("VLAN attendu", max_length=80)
    evidence = models.CharField("Référence de preuve / changement", max_length=500)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    recorded_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(null=True, blank=True, editable=False)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)

    def clean(self):
        super().clean()
        if self.identity_id and self.identity.kind != "machine":
            raise ValidationError("Le placement réseau concerne une identité machine.")
        if self.switch_id and self.switch.kind != "network":
            raise ValidationError("Le switch doit être une ressource réseau.")
        if self.valid_until and self.valid_until <= self.valid_from:
            raise ValidationError("La fin doit suivre le début.")
