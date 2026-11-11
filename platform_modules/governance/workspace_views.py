"""Native IGA workspace, shared read API and explicit exception registration."""

from datetime import timedelta

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from platform_core.services import authorize
from platform_core.view_access import scoped
from platform_modules.identity.models import Identity, Resource

from .exception_models import ExceptionCase
from .exceptions import decide_exception, request_exception
from .workspace import build_governance_workspace


def _can(request, roles):
    try:
        authorize(request.user, request.organization, roles=roles)
    except PermissionDenied:
        return False
    return True


@require_GET
@scoped("governance")
def workspace(request, *, export=False, api=False):
    contract = build_governance_workspace(actor=request.user, organization=request.organization)
    if api or export:
        response = JsonResponse(contract, json_dumps_params={"ensure_ascii": False})
        if export:
            response["Content-Disposition"] = 'attachment; filename="governance-workspace.json"'
    else:
        response = render(
            request,
            "governance/workspace.html",
            dict(
                workspace=contract,
                can_request=_can(request, ("admin", "operator")),
                can_review=_can(request, ("admin", "reviewer")),
            ),
        )
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


class ExceptionForm(forms.Form):
    identity = forms.ModelChoiceField(label="Identité", queryset=Identity.unscoped.none())
    resource = forms.ModelChoiceField(label="Ressource", queryset=Resource.unscoped.none())
    entitlement = forms.CharField(label="Droit concerné", max_length=160)
    reference = forms.CharField(label="Référence de suivi", max_length=180)
    reason = forms.CharField(label="Motif", max_length=2000, widget=forms.Textarea)
    compensating_controls = forms.CharField(
        label="Mesures compensatoires",
        max_length=2000,
        widget=forms.Textarea,
    )
    days = forms.IntegerField(label="Durée de suivi en jours", min_value=1, max_value=30, initial=7)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["identity"].queryset = Identity.objects.order_by("name", "pk")
        self.fields["resource"].queryset = Resource.objects.order_by("name", "pk")


@scoped("governance", roles=("admin", "operator"))
def exception_create(request):
    form = ExceptionForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        try:
            request_exception(
                actor=request.user,
                organization=request.organization,
                identity_id=data["identity"].pk,
                resource_id=data["resource"].pk,
                entitlement=data["entitlement"],
                reference=data["reference"],
                reason=data["reason"],
                compensating_controls=data["compensating_controls"],
                expires_at=timezone.now() + timedelta(days=data["days"]),
            )
            messages.success(request, "Exception enregistrée pour examen, sans droit accordé.")
            return redirect("governance-workspace")
        except ValidationError as exc:
            form.add_error(None, "; ".join(exc.messages))
    response = render(request, "governance/exception_form.html", {"form": form})
    response["Cache-Control"] = "no-store"
    return response


@require_POST
@scoped("governance", roles=("admin", "operator", "reviewer"))
def exception_decide(request, case_id):
    from django.http import Http404

    try:
        decide_exception(
            case_id,
            actor=request.user,
            organization=request.organization,
            decision=request.POST.get("decision"),
            comment=request.POST.get("comment", ""),
        )
    except ExceptionCase.DoesNotExist:
        raise Http404 from None
    except ValidationError as exc:
        messages.error(request, "; ".join(exc.messages))
    return redirect("governance-workspace")
