"""Every declared extension HTTP route is mounted through the core guard."""

from functools import wraps

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.urls import include, path
from django.utils.module_loading import import_string
from django.views.decorators.http import require_http_methods

from platform_core.authorization import recent_authentication
from platform_core.security import ensure_recent
from platform_core.services import authorize as authorize_roles
from platform_core.tenancy import current_organization

from .api import authorize, require_delivery


def guarded_view(view, route, manifest):
    permission = next(item for item in manifest.permissions if item.code == route.permission)
    methods = (*route.methods, "HEAD") if "GET" in route.methods else route.methods

    @login_required
    @require_http_methods(methods)
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        current_organization()
        authorize_roles(request.user, request.organization, roles=permission.roles)
        require_delivery(request.organization, manifest.key)
        if permission.sensitive:
            challenge = ensure_recent(request)
            if challenge is not None:
                return challenge
            with recent_authentication(
                request.user, request.organization, request.session.get("mfa_verified_at", 0)
            ):
                authorize(request.user, request.organization, route.permission)
                return view(request, *args, **kwargs)
        authorize(request.user, request.organization, route.permission)
        return view(request, *args, **kwargs)

    # Do not inherit an extension view's accidental csrf_exempt marker via wraps().
    wrapped.csrf_exempt = False
    return wrapped


def extension_patterns():
    result = []
    for release in settings.PAMOLIVE_EXTENSIONS:
        manifest = release.manifest
        routes = [
            path(
                route.path,
                guarded_view(import_string(route.view), route, manifest),
                name=route.name,
            )
            for route in manifest.routes
        ]
        result.append(
            path(
                f"extensions/{manifest.key}/",
                include((routes, manifest.key), namespace=f"ext-{manifest.key}"),
            )
        )
    return result
