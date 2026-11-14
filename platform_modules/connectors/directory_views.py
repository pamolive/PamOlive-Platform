"""Session/MFA protected directory inventory; no remote fact grants access."""

import json
import re
from functools import wraps
from io import BytesIO

from django import forms
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from platform_core.services import authorize
from platform_core.view_access import scoped

from .directory_adapters import DirectoryFailure
from .directory_inventory import (
    DirectoryConflict,
    collect_directory_inventory,
    configure_directory_source,
    directory_inventory,
    import_directory_fixture,
    map_directory_account,
    revoke_directory_mapping,
    rotate_directory_credential,
    set_directory_source_enabled,
)


def _private(response):
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _bounded(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        length = request.META.get("CONTENT_LENGTH", "") or "0"
        if not isinstance(length, str) or not re.fullmatch(r"0|[1-9][0-9]{0,8}", length):
            return _private(JsonResponse({"error": "invalid_content_length"}, status=400))
        if int(length) > 65536:
            return _private(JsonResponse({"error": "directory_input_too_large"}, status=413))
        # ASGI may deliver a body without Content-Length. Bound actual bytes
        # before MFA parses POST and retain Django's cached-body contract.
        body = getattr(request, "_body", None)
        if body is None:
            body = request.read(65537)
        if len(body) > 65536:
            return _private(JsonResponse({"error": "directory_input_too_large"}, status=413))
        request._body = body
        request._stream = BytesIO(body)
        return view(request, *args, **kwargs)

    return wrapped


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result


def _data(request, fields):
    if request.content_type == "application/json":
        try:
            value = json.loads(request.body, object_pairs_hook=_pairs)
        except RecursionError:
            raise ValueError("JSON nesting exceeds the accepted parser limit") from None
        if type(value) is not dict or set(value) - set(fields):
            raise ValueError("Unexpected JSON schema")
        for key in ("synthetic", "enabled", "complete"):
            if key in value and type(value[key]) is not bool:
                raise ValueError("Boolean required")
        return value
    return request.POST


def _context(request):
    return {"actor": request.user, "organization": request.organization}


def _permissions(request):
    def can(roles):
        try:
            authorize(request.user, request.organization, roles=roles)
        except PermissionDenied:
            return False
        return True

    return {"can_admin": can(("admin",)), "can_collect": can(("admin", "operator"))}


def _failure(error):
    if isinstance(error, ObjectDoesNotExist):
        status, code = 404, "directory_record_not_found"
    elif isinstance(error, DirectoryConflict):
        status, code = 409, "directory_idempotency_conflict"
    elif isinstance(error, DirectoryFailure):
        status = 503 if error.retryable else 400
        code = (
            "directory_transport_unavailable" if error.retryable else "directory_transport_rejected"
        )
    else:
        status, code = 400, "directory_request_invalid"
    return _private(JsonResponse({"error": code}, status=status))


class SourceForm(forms.Form):
    name = forms.CharField(label="Nom", max_length=180)
    provider = forms.ChoiceField(
        choices=[("ldap", "LDAP"), ("ad", "Active Directory"), ("entra", "Entra / Graph")]
    )
    endpoint = forms.CharField(
        label="Destination exacte du laboratoire", max_length=2048, strip=False
    )
    certificate_sha256 = forms.RegexField(
        r"^[a-f0-9]{64}$", label="Empreinte SHA-256 du certificat (hex minuscule)"
    )
    base_dn = forms.CharField(label="Base DN LDAP/AD", max_length=1024, required=False)
    bind_dn = forms.CharField(label="Principal de lecture LDAP/AD", max_length=1024, required=False)
    password = forms.CharField(
        label="Mot de passe synthétique LDAP/AD",
        max_length=8192,
        required=False,
        strip=False,
        widget=forms.PasswordInput,
    )
    tenant_id = forms.UUIDField(label="Tenant Graph UUID", required=False)
    token = forms.CharField(
        label="Jeton synthétique Graph",
        max_length=8192,
        required=False,
        strip=False,
        widget=forms.PasswordInput,
    )
    synthetic = forms.BooleanField(label="Source et comptes exclusivement synthétiques")

    def clean(self):
        data = super().clean()
        if data.get("provider") == "entra":
            if (
                not data.get("tenant_id")
                or not data.get("token")
                or any(data.get(k) for k in ("base_dn", "bind_dn", "password"))
            ):
                raise forms.ValidationError("Utilisez seulement le tenant UUID et le jeton Graph.")
            if not re.fullmatch(r"[\x21-\x7e]+", data["token"]):
                raise forms.ValidationError("Le jeton Graph doit être ASCII visible, sans espace.")
        elif data.get("provider") in ("ldap", "ad"):
            if (
                not all(data.get(k) for k in ("base_dn", "bind_dn", "password"))
                or data.get("tenant_id")
                or data.get("token")
            ):
                raise forms.ValidationError(
                    "Utilisez seulement la base DN et les identifiants LDAP/AD."
                )
        return data

    def service_data(self):
        d = self.cleaned_data
        graph = d["provider"] == "entra"
        return dict(
            name=d["name"],
            provider=d["provider"],
            endpoint=d["endpoint"],
            certificate_sha256=d["certificate_sha256"],
            synthetic=d["synthetic"],
            scope={"tenant_id": str(d["tenant_id"])}
            if graph
            else {"base_dn": d["base_dn"], "bind_dn": d["bind_dn"]},
            credential={"token": d["token"]}
            if graph
            else {"bind_dn": d["bind_dn"], "password": d["password"]},
        )


class RecordListField(forms.Field):
    """Use the same strict parser for JSON API values and HTML textarea text."""

    widget = forms.Textarea
    empty_values = (None, "")

    def to_python(self, value):
        if isinstance(value, str):
            try:
                value = json.loads(value, object_pairs_hook=_pairs)
            except (ValueError, RecursionError):
                raise forms.ValidationError("Liste JSON invalide ou trop imbriquée.") from None
        if type(value) is not list:
            raise forms.ValidationError("Une liste explicite de faits est requise.")
        return value


class FixtureForm(forms.Form):
    idempotency_key = forms.CharField(label="Clé unique de cette collecte", max_length=180)
    records = RecordListField(
        label="Objets synthétiques au schéma du fournisseur",
        widget=forms.Textarea(attrs={"rows": 8}),
        required=False,
    )
    complete = forms.BooleanField(
        label="Fixture déclarée complète (aucune autorité de retrait)", required=False
    )

    def clean_records(self):
        records = self.cleaned_data["records"]
        if type(records) is not list:
            raise forms.ValidationError("Une liste explicite de faits est requise.")
        return records


class MappingForm(forms.Form):
    remote_id = forms.UUIDField(label="UUID distant stable")
    account_id = forms.UUIDField(label="UUID du compte IAM de cette organisation")


class CredentialForm(forms.Form):
    secret = forms.CharField(
        label="Nouvel identifiant secret synthétique",
        max_length=8192,
        strip=False,
        widget=forms.PasswordInput,
    )


@require_GET
@scoped("connectors")
def index(request, *, api=False):
    data = directory_inventory(**_context(request))
    if api:
        return _private(JsonResponse(data))
    return _private(
        render(request, "connectors/directories.html", {"inventory": data, **_permissions(request)})
    )


@require_http_methods(["GET", "POST"])
@_bounded
@scoped("connectors", roles=("admin",))
def configure(request):
    try:
        values = _data(request, SourceForm.base_fields) if request.method == "POST" else None
        form = SourceForm(values)
        if request.method == "POST" and form.is_valid():
            source = configure_directory_source(**form.service_data(), **_context(request))
            if request.content_type == "application/json":
                return _private(
                    JsonResponse({"source_id": str(source.pk), "enabled": False}, status=201)
                )
            return redirect("directory-detail", source_id=source.pk)
        if request.method == "POST" and request.content_type == "application/json":
            return _failure(ValidationError("Invalid source form"))
        return _private(render(request, "connectors/directory_form.html", {"form": form}))
    except (ValidationError, DirectoryFailure, ValueError, UnicodeDecodeError) as error:
        return _failure(error)


@require_GET
@scoped("connectors")
def detail(request, source_id, *, api=False, export=False):
    try:
        data = directory_inventory(
            source_id=source_id,
            limit=int(request.GET.get("limit", "100")),
            cursor=request.GET.get("cursor") or None,
            **_context(request),
        )
        if api or export:
            response = JsonResponse(data, json_dumps_params={"ensure_ascii": False})
            if export:
                response["Content-Disposition"] = 'attachment; filename="directory-inventory.json"'
            return _private(response)
        return _private(
            render(
                request,
                "connectors/directory_detail.html",
                {
                    "inventory": data,
                    "fixture_form": FixtureForm(),
                    "mapping_form": MappingForm(),
                    **_permissions(request),
                },
            )
        )
    except (ObjectDoesNotExist, ValidationError, ValueError) as error:
        return _failure(error)


@require_POST
@_bounded
@scoped("connectors", roles=("admin", "operator"))
def import_fixture(request, source_id):
    try:
        form = FixtureForm(_data(request, FixtureForm.base_fields))
        if not form.is_valid():
            return _failure(ValidationError("Invalid fixture"))
        run = import_directory_fixture(
            source_id,
            records=form.cleaned_data["records"],
            idempotency_key=form.cleaned_data["idempotency_key"],
            complete=form.cleaned_data["complete"],
            **_context(request),
        )
        return _private(
            JsonResponse(
                {"run_id": str(run.pk), "provenance": run.provenance, "complete": run.complete}
            )
        )
    except (
        ObjectDoesNotExist,
        ValidationError,
        DirectoryFailure,
        ValueError,
        UnicodeDecodeError,
    ) as error:
        return _failure(error)


@require_POST
@_bounded
@scoped("connectors", roles=("admin", "operator"))
def collect(request, source_id):
    try:
        data = _data(request, ("idempotency_key",))
        run = collect_directory_inventory(
            source_id, idempotency_key=data.get("idempotency_key"), **_context(request)
        )
        return _private(
            JsonResponse(
                {"run_id": str(run.pk), "provenance": run.provenance, "complete": run.complete}
            )
        )
    except (
        ObjectDoesNotExist,
        ValidationError,
        DirectoryFailure,
        ValueError,
        UnicodeDecodeError,
    ) as error:
        return _failure(error)


@require_POST
@_bounded
@scoped("connectors", roles=("admin",))
def enabled(request, source_id):
    try:
        data = _data(request, ("enabled",))
        flag = data.get("enabled")
        if request.content_type != "application/json":
            if flag not in ("true", "false"):
                raise ValueError
            flag = flag == "true"
        source = set_directory_source_enabled(source_id, enabled=flag, **_context(request))
        return _private(JsonResponse({"source_id": str(source.pk), "enabled": source.enabled}))
    except (ObjectDoesNotExist, ValidationError, ValueError, UnicodeDecodeError) as error:
        return _failure(error)


@require_POST
@_bounded
@scoped("connectors", roles=("admin",))
def mapping(request, source_id):
    try:
        form = MappingForm(_data(request, MappingForm.base_fields))
        if not form.is_valid():
            return _failure(ValidationError("Invalid mapping"))
        decision = map_directory_account(source_id, **form.cleaned_data, **_context(request))
        return _private(
            JsonResponse({"mapping_id": str(decision.pk), "kind": decision.kind}, status=201)
        )
    except (ObjectDoesNotExist, ValidationError, ValueError, UnicodeDecodeError) as error:
        return _failure(error)


@require_POST
@_bounded
@scoped("connectors", roles=("admin",))
def revoke(request, mapping_id):
    try:
        if request.content_type == "application/json":
            _data(request, ())
        decision = revoke_directory_mapping(mapping_id, **_context(request))
        return _private(JsonResponse({"mapping_id": str(decision.pk), "kind": decision.kind}))
    except (ObjectDoesNotExist, ValidationError, ValueError, UnicodeDecodeError) as error:
        return _failure(error)


@require_http_methods(["GET", "POST"])
@_bounded
@scoped("connectors", roles=("admin",))
def rotate(request, source_id):
    try:
        if request.content_type == "application/json" and request.method == "POST":
            credential = _data(request, ("credential",)).get("credential")
        else:
            source = directory_inventory(source_id=source_id, **_context(request))["source"]
            form = CredentialForm(request.POST if request.method == "POST" else None)
            if request.method == "GET" or not form.is_valid():
                return _private(
                    render(
                        request,
                        "connectors/directory_credential.html",
                        {
                            "source": source,
                            "form": form,
                        },
                    )
                )
            secret = form.cleaned_data["secret"]
            credential = (
                {"token": secret}
                if source["provider"] == "entra"
                else {
                    "bind_dn": source["destination"]["scope"]["bind_dn"],
                    "password": secret,
                }
            )
        source = rotate_directory_credential(source_id, credential=credential, **_context(request))
        return _private(
            JsonResponse(
                {"source_id": str(source.pk), "credential_revision": source.credential_revision}
            )
        )
    except (
        ObjectDoesNotExist,
        ValidationError,
        DirectoryFailure,
        ValueError,
        UnicodeDecodeError,
    ) as error:
        return _failure(error)
