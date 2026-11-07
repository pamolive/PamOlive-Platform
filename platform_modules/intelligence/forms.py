from datetime import timedelta

from django import forms
from django.apps import apps
from django.utils import timezone

from platform_modules.connectors.models import EventSource
from platform_modules.identity.models import Identity, Resource

from .models import DOMAINS, NODE_FIELDS, RELATIONS
from .services import validate_window


class QueryForm(forms.Form):
    identity = forms.ModelChoiceField(
        label="Identité (graphe / chronologie)", queryset=Identity.unscoped.none(), required=False
    )
    start = forms.DateTimeField(label="Début de période", required=False)
    end = forms.DateTimeField(label="Fin de période / date des droits", required=False)
    question = forms.ChoiceField(
        label="Investigation",
        required=False,
        choices=[
            ("", "Choisir une question"),
            ("physical-admin", "Accès physique ET compte privilégié dans une zone"),
            ("supplier-production", "Fournisseurs ayant un droit vers la production"),
            ("privileged-without-window", "Comptes privilégiés sans intention active rapprochée"),
            ("events-without-reference", "Accès sans référence métier dans l’intention rapprochée"),
        ],
    )
    zone = forms.ModelChoiceField(
        label="Zone physique", queryset=Resource.unscoped.none(), required=False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["identity"].queryset = Identity.objects.all()
        self.fields["zone"].queryset = Resource.objects.filter(kind="zone")
        for key in ("start", "end"):
            self.fields[key].widget = forms.DateTimeInput(
                attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"
            )

    def clean(self):
        data = super().clean()
        data["end"] = data.get("end") or timezone.now()
        data["start"] = data.get("start") or data["end"] - timedelta(days=1)
        validate_window(data["start"], data["end"])
        return data


class LinkForm(forms.Form):
    source = forms.ChoiceField(label="Objet de départ")
    relation = forms.ChoiceField(label="Relation dirigée", choices=RELATIONS)
    target = forms.ChoiceField(label="Objet d’arrivée")
    evidence = forms.CharField(label="Référence de preuve / provenance", max_length=500)
    confidence = forms.ChoiceField(
        label="Confiance déclarée",
        choices=[("declared", "Déclarée, à corroborer"), ("verified", "Vérifiée par le déclarant")],
    )
    valid_until = forms.DateTimeField(
        label="Fin de validité",
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = [("", "Choisissez un objet")]
        for kind, model in NODE_FIELDS.items():
            choices.extend(
                (f"{kind}:{obj.pk}", f"{kind} · {obj}")
                for obj in apps.get_model(model).objects.order_by("pk")[:300]
            )
        self.fields["source"].choices = self.fields["target"].choices = choices
        self.fields[
            "source"
        ].help_text = (
            "Les 300 premiers objets de chaque type sont proposés. Un lien n’accorde aucun droit."
        )


class PlacementForm(forms.Form):
    identity = forms.ModelChoiceField(label="Identité machine", queryset=Identity.unscoped.none())
    switch = forms.ModelChoiceField(label="Switch attendu", queryset=Resource.unscoped.none())
    port = forms.CharField(label="Port attendu", max_length=80)
    vlan = forms.CharField(label="VLAN attendu", max_length=80)
    evidence = forms.CharField(label="Référence de preuve / changement", max_length=500)
    valid_until = forms.DateTimeField(
        label="Fin de validité",
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["identity"].queryset = Identity.objects.filter(kind="machine")
        self.fields["switch"].queryset = Resource.objects.filter(kind="network")


class ScopeForm(forms.Form):
    source = forms.ModelChoiceField(
        label="Source d’événements", queryset=EventSource.unscoped.none()
    )
    domain = forms.ChoiceField(label="Domaine collecté", choices=DOMAINS)
    resource = forms.ModelChoiceField(
        label="Ressource couverte (vide : organisation entière)",
        queryset=Resource.unscoped.none(),
        required=False,
    )
    whole_organization = forms.BooleanField(
        label="Sans ressource, je confirme la couverture de toute l’organisation",
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["source"].queryset = EventSource.objects.filter(active=True)
        self.fields["resource"].queryset = Resource.objects.all()

    def clean(self):
        data = super().clean()
        if not data.get("resource") and not data.get("whole_organization"):
            raise forms.ValidationError(
                "Choisissez une ressource ou confirmez explicitement "
                "la couverture de l’organisation."
            )
        return data


class ReportForm(forms.Form):
    scope = forms.UUIDField()
    external_id = forms.CharField(max_length=180)
    covered_from = forms.DateTimeField()
    covered_until = forms.DateTimeField()
    state = forms.ChoiceField(
        choices=[("complete", "complete"), ("partial", "partial"), ("unavailable", "unavailable")]
    )
    clock_uncertainty_seconds = forms.IntegerField(min_value=0, max_value=3600, required=False)
    detail = forms.CharField(max_length=180, required=False)
