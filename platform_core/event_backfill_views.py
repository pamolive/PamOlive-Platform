from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import OperationalError
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from . import event_backfill
from .authorization import recent_authentication
from .security import ensure_recent
from .services import authorize


class BackfillForm(forms.Form):
    selected = forms.ChoiceField(label="Abonnement actif")
    start = forms.DateTimeField(
        label="Début inclus",
        widget=forms.DateTimeInput(format="%Y-%m-%dT%H:%M", attrs={"type": "datetime-local"}),
    )
    end = forms.DateTimeField(
        label="Fin exclue",
        widget=forms.DateTimeInput(format="%Y-%m-%dT%H:%M", attrs={"type": "datetime-local"}),
    )
    token = forms.CharField(required=False, max_length=500, widget=forms.HiddenInput())


@login_required
@require_http_methods(["GET", "POST"])
@never_cache
def backfill(request):
    org = getattr(request, "organization", None)
    if org is None:
        raise PermissionDenied
    authorize(request.user, org, roles=("admin",))
    subscribed = event_backfill.choices(org)
    now = timezone.localtime().replace(second=0, microsecond=0)
    form = BackfillForm(
        request.POST if request.method == "POST" else None,
        initial={"start": now - timedelta(days=1), "end": now},
    )
    form.fields["selected"].choices = subscribed
    plan = None
    if request.method == "POST":
        challenge = ensure_recent(request)
        if challenge is not None:
            return challenge
        if form.is_valid():
            arguments = {
                "actor": request.user,
                "organization": org,
                **{key: form.cleaned_data[key] for key in ("selected", "start", "end")},
            }
            try:
                with recent_authentication(request.user, org, request.session["mfa_verified_at"]):
                    command = request.POST.get("command")
                    if command == "preview":
                        plan, token = event_backfill.preview(**arguments)
                        form.data = form.data.copy()
                        form.data["token"] = token
                    elif command == "submit":
                        count = event_backfill.submit(**arguments, token=form.cleaned_data["token"])
                        messages.success(request, f"{count} notification(s) mise(s) en file.")
                        return redirect("system-status")
                    else:
                        raise ValidationError("Commande non reconnue.")
            except ValidationError as exc:
                form.add_error(None, exc)
            except OperationalError:
                form.add_error(None, "La base n’a pas confirmé le rattrapage. Refaire un aperçu.")
    return render(
        request,
        "governance/event_backfill.html",
        {"form": form, "subscribed": subscribed, "plan": plan},
    )
