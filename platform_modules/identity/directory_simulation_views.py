"""Fixture-only reconciliation preview, with CSRF/session/module controls."""

import json
import re
from functools import wraps

from django import forms
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from platform_core.view_access import scoped

from .directory_simulation import preview_reconciliation
from .identity360_views import _private


class FixtureForm(forms.Form):
    provider = forms.ChoiceField(
        choices=[
            ("ad", "AD synthétique"),
            ("ldap", "LDAP synthétique"),
            ("entra", "Entra ID synthétique"),
        ]
    )
    source_id = forms.CharField(label="Référence de source synthétique", max_length=180)
    records = forms.JSONField(
        label="Enregistrements synthétiques",
        initial=list,
        required=False,
        max_length=65536,
        widget=forms.Textarea(attrs={"rows": 8}),
    )
    mapping = forms.JSONField(
        label="Correspondances explicites UUID distant → UUID compte local",
        initial=dict,
        required=False,
        max_length=65536,
        widget=forms.Textarea(attrs={"rows": 4}),
    )
    synthetic = forms.BooleanField(label="Ces données sont exclusivement synthétiques")

    def clean_records(self):
        value = self.cleaned_data["records"]
        return [] if value is None else value

    def clean_mapping(self):
        value = self.cleaned_data["mapping"]
        return {} if value is None else value


def _preview(request, data):
    return preview_reconciliation(actor=request.user, organization=request.organization, **data)


def _bounded_fixture(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        # Validate syntax before scoped() can ask the MFA resumption helper to
        # parse the length. Only errors return here; every valid request keeps
        # the existing session/module/MFA authorization and CSRF controls.
        raw_length = request.META.get("CONTENT_LENGTH", "")
        if raw_length == "":
            raw_length = "0"
        if not isinstance(raw_length, str) or not re.fullmatch(r"0|[1-9][0-9]{0,8}", raw_length):
            return _private(JsonResponse({"error": "invalid_content_length"}, status=400))
        if int(raw_length) > 131072:
            return _private(JsonResponse({"error": "fixture_too_large"}, status=413))
        return view(request, *args, **kwargs)

    return wrapped


@require_http_methods(["GET", "POST"])
@_bounded_fixture
@scoped("connectors")
def simulation(request):
    if request.method == "POST" and request.content_type == "application/json":
        try:
            data = json.loads(request.body)
            if type(data) is not dict or set(data) != {
                "provider",
                "source_id",
                "records",
                "mapping",
                "synthetic",
            }:
                raise ValidationError("Schéma de simulation invalide.")
            return _private(JsonResponse(_preview(request, data)))
        except (ValidationError, ValueError, UnicodeDecodeError):
            return _private(JsonResponse({"error": "invalid_synthetic_fixture"}, status=400))
    form = FixtureForm(request.POST if request.method == "POST" else None)
    result = None
    if request.method == "POST" and form.is_valid():
        try:
            result = _preview(request, form.cleaned_data)
        except ValidationError as exc:
            form.add_error(None, exc)
    return _private(
        render(
            request,
            "identity/directory_simulation.html",
            {
                "form": form,
                "result": result,
            },
        )
    )
