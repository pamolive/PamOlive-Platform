"""Native tenant-scoped Identity 360 UI and its session-authenticated API/export."""

from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from platform_core.view_access import scoped

from .identity360 import build_identity360, identity_inventory
from .models import Identity


def _private(response):
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_GET
@scoped("identity")
def inventory(request):
    data = identity_inventory(actor=request.user, organization=request.organization)
    return _private(render(request, "identity/identity360_inventory.html", {"inventory": data}))


def _read(request, identity_id):
    try:
        return build_identity360(identity_id, actor=request.user, organization=request.organization)
    except Identity.DoesNotExist as exc:
        raise Http404 from exc


@require_GET
@scoped("identity")
def detail(request, identity_id):
    return _private(
        render(
            request,
            "identity/identity360.html",
            {
                "profile": _read(request, identity_id),
            },
        )
    )


@require_GET
@scoped("identity")
def api(request, identity_id):
    return _private(JsonResponse(_read(request, identity_id)))


@require_GET
@scoped("identity")
def export(request, identity_id):
    response = _private(JsonResponse(_read(request, identity_id)))
    response["Content-Disposition"] = f'attachment; filename="identity360-{identity_id}.json"'
    return response
