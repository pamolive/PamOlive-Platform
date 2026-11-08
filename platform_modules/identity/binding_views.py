from django import forms
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from platform_core.models import OrganizationMembership
from platform_modules.access.ui import scoped

from .bindings import create_binding, revoke_binding
from .models import Identity, LoginIdentityBinding


@scoped("identity", roles=("admin",))
def login_bindings(request):
    form = forms.Form(request.POST or None)
    member_ids = OrganizationMembership.objects.filter(
        organization=request.organization, active=True
    ).values_list("account_id", flat=True)
    form.fields.update(
        {
            "login_account": forms.ModelChoiceField(
                label="Compte de connexion PAM-olive",
                queryset=get_user_model().objects.filter(pk__in=member_ids, is_active=True),
            ),
            "identity": forms.ModelChoiceField(
                label="Personne IAM",
                queryset=Identity.objects.filter(kind__in=("human", "external"), status="active"),
            ),
            "verification_reference": forms.CharField(
                label="Référence de vérification",
                max_length=255,
                help_text="Référence RH, contrat ou ticket vérifié par vous ; aucun secret.",
            ),
        }
    )
    if request.method == "POST" and form.is_valid():
        try:
            create_binding(
                **form.cleaned_data, actor=request.user, organization=request.organization
            )
            messages.success(request, "Lien de personne créé et audité.")
            return redirect("identity-login-bindings")
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "identity/login_bindings.html",
        {
            "form": form,
            "bindings": LoginIdentityBinding.objects.select_related(
                "login_account", "identity", "created_by", "revoked_by"
            ).order_by("-created_at")[:200],
        },
    )


@scoped("identity", roles=("admin",))
@require_POST
def binding_revoke(request, binding_id):
    get_object_or_404(LoginIdentityBinding.objects, pk=binding_id)
    try:
        revoke_binding(
            binding_id,
            actor=request.user,
            organization=request.organization,
            reason=request.POST.get("reason", ""),
        )
        messages.success(request, "Lien révoqué. Le compte global PAM-olive reste inchangé.")
    except ValidationError as error:
        messages.error(request, str(error))
    return redirect("identity-login-bindings")
