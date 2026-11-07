from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone

from platform_core.models import OrganizationMembership
from platform_core.tenancy import current_organization
from platform_modules.identity.models import Resource

from .models import (
    ApprovalPolicyRevision,
    ContractParticipant,
    SeparationRule,
    Supplier,
)


def empty_scoped_field(field, **kwargs):
    if field.is_relation and hasattr(field.related_model, "unscoped"):
        return forms.ModelChoiceField(
            queryset=field.related_model.unscoped.none(),
            required=not field.blank,
            label=field.verbose_name,
        )
    return field.formfield(**kwargs)


class SupplierForm(forms.ModelForm):
    class Meta:
        model = Supplier
        fields = ("name", "reference", "contact")


class ParticipantForm(forms.ModelForm):
    class Meta:
        formfield_callback = empty_scoped_field
        model = ContractParticipant
        fields = ("contract", "identity", "valid_until")


class PolicyForm(forms.ModelForm):
    class Meta:
        model = ApprovalPolicyRevision
        fields = (
            "min_reviewers",
            "critical_reviewers",
            "require_external_contract",
            "supplier_sponsor_required",
        )


class SeparationForm(forms.ModelForm):
    class Meta:
        formfield_callback = empty_scoped_field
        model = SeparationRule
        fields = (
            "name",
            "left_resource",
            "left_entitlement",
            "right_resource",
            "right_entitlement",
        )


class ContractForm(forms.Form):
    supplier = forms.ModelChoiceField(label="Fournisseur", queryset=Supplier.unscoped.none())
    name = forms.CharField(label="Nom du contrat", max_length=180)
    reference = forms.CharField(label="Référence du contrat", max_length=160)
    sponsor = forms.ModelChoiceField(
        label="Responsable approbateur dans l’organisation",
        queryset=get_user_model().objects.none(),
    )
    starts_at = forms.DateTimeField(label="Début du contrat (fuseau de l’installation)")
    ends_at = forms.DateTimeField(label="Fin du contrat (fuseau de l’installation)")
    timezone_name = forms.CharField(
        label="Fuseau des plages horaires (IANA)", initial="Europe/Brussels", max_length=80
    )
    weekdays = forms.MultipleChoiceField(
        label="Jours autorisés",
        choices=list(
            enumerate(["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"])
        ),
        initial=[0, 1, 2, 3, 4],
        widget=forms.CheckboxSelectMultiple,
    )
    daily_start = forms.TimeField(
        label="Ouverture locale", initial="07:00", widget=forms.TimeInput(attrs={"type": "time"})
    )
    daily_end = forms.TimeField(
        label="Fermeture locale",
        initial="19:00",
        widget=forms.TimeInput(attrs={"type": "time"}),
        help_text=(
            "Fin avant début : passage à minuit. "
            "Heures identiques : journée entière pour les jours cochés."
        ),
    )
    allowed_methods = forms.CharField(
        label="Méthodes autorisées",
        initial="SSH, RDP",
        help_text="Séparées par des virgules : SSH, RDP, TeamViewer, badge…",
    )
    allowed_countries = forms.CharField(
        label="Pays autorisés (codes à deux lettres)",
        required=False,
        help_text=(
            "Ex. BE, FR. Vide : aucun contrôle de pays. La source doit fournir le pays observé."
        ),
    )
    resources = forms.ModelMultipleChoiceField(
        label="Ressources autorisées", queryset=Resource.unscoped.none()
    )
    privilege = forms.CharField(
        label="Privilège autorisé sur ces ressources",
        max_length=160,
        required=False,
        help_text="Vide autorise tous les privilèges sur les ressources sélectionnées.",
    )
    locations = forms.CharField(
        label="Origines autorisées",
        required=False,
        help_text=(
            "Valeurs exactes séparées par des virgules. "
            "Vide : toutes les origines. Ce n’est pas un filtre CIDR."
        ),
    )
    physical_allowed = forms.BooleanField(
        label="Autoriser les portes et zones physiques incluses au périmètre", required=False
    )
    require_reference = forms.BooleanField(
        label="Exiger une référence de ticket, changement ou projet", initial=True, required=False
    )

    def __init__(self, *args, contract=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["starts_at"].help_text = (
            f"Dates saisies en {timezone.get_current_timezone_name()}, stockées en UTC. "
            "Le fuseau des plages horaires est indépendant."
        )
        self.fields["supplier"].queryset = Supplier.objects.all()
        self.fields["resources"].queryset = Resource.objects.all()
        self.fields["sponsor"].queryset = get_user_model().objects.filter(
            is_active=True,
            pk__in=OrganizationMembership.objects.filter(
                organization=current_organization(), active=True, role__in=["admin", "reviewer"]
            ).values("account_id"),
        )
        if contract:
            for name in ("supplier", "name", "reference"):
                self.fields[name].initial = getattr(contract, name)
                self.fields[name].disabled = True
            revision = contract.revisions.order_by("-sequence").first()
            if revision:
                for name in (
                    "sponsor",
                    "starts_at",
                    "ends_at",
                    "timezone_name",
                    "weekdays",
                    "daily_start",
                    "daily_end",
                    "physical_allowed",
                    "require_reference",
                ):
                    self.fields[name].initial = getattr(revision, name)
                for name in ("allowed_methods", "allowed_countries"):
                    self.fields[name].initial = ", ".join(getattr(revision, name))
                scopes = list(revision.scopes.all())
                self.fields["resources"].initial = [s.resource_id for s in scopes]
                if scopes:
                    self.fields["privilege"].initial = scopes[0].privilege
                    self.fields["locations"].initial = ", ".join(scopes[0].locations)
        for field in self.fields.values():
            if isinstance(field, forms.DateTimeField):
                field.widget = forms.DateTimeInput(
                    attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"
                )

    def clean_weekdays(self):
        return [int(day) for day in self.cleaned_data["weekdays"]]

    def clean_allowed_methods(self):
        return [v.strip() for v in self.cleaned_data["allowed_methods"].split(",") if v.strip()]

    def clean_allowed_countries(self):
        return [
            v.strip().upper()
            for v in self.cleaned_data["allowed_countries"].split(",")
            if v.strip()
        ]

    def scopes(self):
        return [
            {
                "resource": r,
                "privilege": self.cleaned_data["privilege"],
                "locations": [
                    v.strip() for v in self.cleaned_data["locations"].split(",") if v.strip()
                ],
            }
            for r in self.cleaned_data["resources"]
        ]


def scope_form(form):
    form.instance.organization = current_organization()
    for field in form.fields.values():
        if isinstance(field, forms.ModelChoiceField) and hasattr(
            field.queryset.model, "organization"
        ):
            field.queryset = field.queryset.model.objects.all()
        if isinstance(field, forms.DateTimeField):
            field.widget = forms.DateTimeInput(attrs={"type": "datetime-local"})
    return form
