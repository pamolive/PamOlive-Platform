"""Shared organization, module and interactive assurance checks for native forms."""

from functools import wraps

from django.contrib.auth.decorators import login_required

from .authorization import recent_authentication
from .security import ensure_recent
from .services import authorize, require_module
from .tenancy import current_organization


def scoped(module=None, roles=("admin", "operator", "reviewer", "auditor")):
    def decorator(view):
        @login_required
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            organization = current_organization()
            authorize(request.user, organization, roles=roles)
            if module:
                require_module(organization, module)
            if request.method == "POST":
                challenge = ensure_recent(request)
                if challenge is not None:
                    return challenge
                with recent_authentication(
                    request.user, organization, request.session.get("mfa_verified_at", 0)
                ):
                    from platform_modules.pam.trust_auth import (
                        PAMActionRequired,
                        action_authentication,
                    )
                    from platform_modules.pam.trust_views import challenge_response

                    try:
                        with action_authentication(request):
                            return view(request, *args, **kwargs)
                    except PAMActionRequired as exc:
                        return challenge_response(request, exc)
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
