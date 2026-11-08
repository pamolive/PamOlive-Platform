import base64
import hashlib
import json
import secrets
import time
from datetime import timedelta

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils import timezone

from .audit import record
from .models import AccountSecurity, LoginThrottle


def cipher():
    # A separate key can be rotated independently from Django's session signing key.
    material = settings.PAMOLIVE_ENCRYPTION_KEY.encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(material).digest()))


@transaction.atomic
def verify_mfa(account, code):
    profile = AccountSecurity.objects.select_for_update().filter(account=account).first()
    if not profile or not profile.encrypted_secret:
        return False
    now = timezone.now()
    if profile.blocked_until and now < profile.blocked_until:
        return False
    secret = cipher().decrypt(profile.encrypted_secret.encode()).decode()
    totp = pyotp.TOTP(secret)
    counter = int(now.timestamp()) // 30
    accepted = False
    if code.isdigit() and len(code) == 6:
        for candidate in [counter - 1, counter, counter + 1]:
            if candidate > profile.last_counter and secrets.compare_digest(
                totp.at(candidate * 30), code
            ):
                profile.last_counter = candidate
                accepted = True
                break
    if not accepted:
        for index, hashed in enumerate(profile.recovery_hashes):
            if check_password(code, hashed):
                profile.recovery_hashes.pop(index)
                accepted = True
                break
    profile.failures = 0 if accepted else profile.failures + 1
    profile.blocked_until = now + timedelta(minutes=5) if profile.failures >= 5 else None
    profile.save()
    return accepted


@transaction.atomic
def throttle(username, *, failure=False, success=False, limit=10):
    key = hashlib.sha256(username.casefold().encode()).hexdigest()
    row, _ = LoginThrottle.objects.get_or_create(
        key=key, defaults={"window_started": timezone.now()}
    )
    row = LoginThrottle.objects.select_for_update().get(pk=key)
    if timezone.now() - row.window_started > timedelta(minutes=5):
        row.failures, row.window_started = 0, timezone.now()
    blocked = row.failures >= limit
    if failure:
        row.failures += 1
    if success:
        row.failures = 0
    row.save()
    return blocked


class MFALoginForm(AuthenticationForm):
    otp = forms.CharField(label="Code MFA ou récupération", required=False)

    def clean(self):
        username = self.cleaned_data.get("username", "")
        if throttle(username):
            raise forms.ValidationError("Trop de tentatives. Réessayez dans cinq minutes.")
        try:
            data = super().clean()
            profile = AccountSecurity.objects.filter(account=self.user_cache).first()
            if profile and profile.encrypted_secret:
                if not verify_mfa(self.user_cache, self.cleaned_data.get("otp", "").strip()):
                    raise forms.ValidationError("Connexion ou code MFA invalide.")
                self.request.session["mfa_verified_at"] = time.time()
            throttle(username, success=True)
            return data
        except forms.ValidationError:
            throttle(username, failure=True)
            raise


def ensure_recent(request):
    profile = AccountSecurity.objects.filter(account=request.user).first()
    verified = request.session.get("mfa_verified_at", 0)
    if (
        profile
        and profile.encrypted_secret
        and 0 <= time.time() - verified < profile.freshness_minutes * 60
    ):
        return None
    if int(request.META.get("CONTENT_LENGTH") or 0) > 65536:
        raise forms.ValidationError("Requête trop volumineuse pour la reprise sécurisée.")
    action = {
        "path": request.path,
        "organization_id": str(request.organization.pk) if request.organization else "",
        "fields": [
            (k, v)
            for k, values in request.POST.lists()
            if k != "csrfmiddlewaretoken"
            for v in values
        ],
    }
    request.session["post_mfa_action"] = cipher().encrypt(json.dumps(action).encode()).decode()
    return redirect("account-security")


@login_required
def security_settings(request):
    profile, _ = AccountSecurity.objects.get_or_create(account=request.user)
    enabled = bool(profile.encrypted_secret)
    form = forms.Form(request.POST or None)
    form.fields["password"] = forms.CharField(
        label="Votre mot de passe", widget=forms.PasswordInput
    )
    form.fields["code"] = forms.CharField(label="Code MFA ou récupération", max_length=64)
    form.fields["freshness_minutes"] = forms.TypedChoiceField(
        label="Durée personnelle de validation",
        coerce=int,
        choices=AccountSecurity._meta.get_field("freshness_minutes").choices,
        initial=profile.freshness_minutes,
    )
    secret = None
    if not enabled:
        encrypted = request.session.get("mfa_enrollment")
        if not encrypted:
            encrypted = cipher().encrypt(pyotp.random_base32().encode()).decode()
            request.session["mfa_enrollment"] = encrypted
        try:
            secret = cipher().decrypt(encrypted.encode(), ttl=900).decode()
        except InvalidToken:
            request.session.pop("mfa_enrollment", None)
            return redirect("account-security")
    if request.method == "POST" and form.is_valid():
        enrollment_time = timezone.now()
        valid = request.user.check_password(form.cleaned_data["password"])
        if enabled:
            valid = valid and verify_mfa(request.user, form.cleaned_data["code"].strip())
        else:
            valid = valid and pyotp.TOTP(secret).verify(
                form.cleaned_data["code"].strip(), for_time=enrollment_time
            )
        if valid:
            codes = []
            # Refresh after the verifier's locked update to preserve its replay counter.
            profile.refresh_from_db()
            if not enabled:
                codes = [secrets.token_hex(8) for _ in range(8)]
                profile.encrypted_secret = cipher().encrypt(secret.encode()).decode()
                # Persist the exact counter actually verified, even if hashing
                # the recovery codes crosses the next 30-second boundary.
                profile.last_counter = int(enrollment_time.timestamp()) // 30
                profile.recovery_hashes = [make_password(code) for code in codes]
            profile.freshness_minutes = form.cleaned_data["freshness_minutes"]
            profile.save()
            request.session.pop("mfa_enrollment", None)
            request.session["mfa_verified_at"] = time.time()
            record(
                action="core.mfa.verified.v1",
                summary="MFA personnelle validée",
                actor=request.user,
                request=request,
            )
            pending = request.session.pop("post_mfa_action", None)
            action = None
            if pending:
                try:
                    action = json.loads(cipher().decrypt(pending.encode(), ttl=600))
                    organization_id = str(request.organization.pk) if request.organization else ""
                    if action.get("organization_id") != organization_id:
                        request.session["post_mfa_action"] = pending
                        action = None
                        messages.warning(
                            request,
                            "L’organisation a changé. Sélectionnez l’organisation d’origine "
                            "et reprenez votre action ; aucune modification n’a été appliquée.",
                        )
                except (InvalidToken, ValueError):
                    pass
            response = render(request, "security/resume.html", {"action": action, "codes": codes})
            response["Cache-Control"] = "no-store"
            return response
        form.add_error(None, "Mot de passe ou code invalide. Un code déjà utilisé est refusé.")
    response = render(
        request,
        "security/settings.html",
        {
            "form": form,
            "enabled": enabled,
            "secret": secret,
            "uri": pyotp.TOTP(secret).provisioning_uri(
                request.user.username, issuer_name="PAM-olive"
            )
            if secret
            else None,
        },
    )
    response["Cache-Control"] = "no-store"
    return response
