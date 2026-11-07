from django import forms

from .models import AccessAssignment, IdentityApplication


class IdentityApplicationForm(forms.ModelForm):
    class Meta:
        model = IdentityApplication
        fields = ("name", "key", "description", "owner", "active")
        labels = {
            "name": "Nom de l’application",
            "key": "Identifiant technique",
            "description": "Description",
            "owner": "Propriétaire",
            "active": "Application active",
        }
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}


class AccessAssignmentForm(forms.ModelForm):
    class Meta:
        model = AccessAssignment
        fields = (
            "user",
            "application",
            "role",
            "entitlement",
            "status",
            "expires_at",
            "justification",
        )
        labels = {
            "user": "Utilisateur",
            "application": "Application",
            "role": "Rôle métier",
            "entitlement": "Droit ou profil cible",
            "status": "Statut",
            "expires_at": "Expiration",
            "justification": "Justification",
        }
        widgets = {
            "expires_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "justification": forms.Textarea(attrs={"rows": 4}),
        }
