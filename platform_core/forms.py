from django import forms
from django.contrib.auth import get_user_model

from .models import BusinessRole, RolePermission


class PlatformUserForm(forms.ModelForm):
    password = forms.CharField(
        label="Mot de passe",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Obligatoire à la création. Laissez vide pour conserver le mot de passe actuel.",
    )

    class Meta:
        model = get_user_model()
        fields = ("username", "first_name", "last_name", "email", "is_active")
        labels = {
            "username": "Identifiant",
            "first_name": "Prénom",
            "last_name": "Nom",
            "email": "Adresse e-mail",
            "is_active": "Compte actif",
        }

    def clean_password(self):
        password = self.cleaned_data.get("password")
        if not self.instance.pk and not password:
            raise forms.ValidationError("Un mot de passe initial est requis.")
        return password

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.cleaned_data.get("password"):
            user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user


class BusinessRoleForm(forms.ModelForm):
    permission_codes = forms.CharField(
        label="Permissions",
        required=False,
        widget=forms.Textarea(attrs={"rows": 5}),
        help_text="Une permission par ligne, au format module.ressource.action.",
    )

    class Meta:
        model = BusinessRole
        fields = ("name", "key", "description", "members")
        labels = {
            "name": "Nom",
            "key": "Identifiant technique",
            "description": "Description",
            "members": "Membres",
        }
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["permission_codes"].initial = "\n".join(
                self.instance.permission_grants.order_by("code").values_list("code", flat=True)
            )

    def clean_permission_codes(self):
        values = [line.strip() for line in self.cleaned_data["permission_codes"].splitlines()]
        values = [value for value in values if value]
        invalid = [value for value in values if value.count(".") < 1 or " " in value]
        if invalid:
            raise forms.ValidationError("Permissions invalides : " + ", ".join(invalid))
        return sorted(set(values))

    def save(self, commit=True):
        role = super().save(commit=commit)
        if commit:
            role.permission_grants.all().delete()
            RolePermission.objects.bulk_create(
                [
                    RolePermission(role=role, code=code)
                    for code in self.cleaned_data["permission_codes"]
                ]
            )
        return role
