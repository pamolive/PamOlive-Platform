"""Native, session-authenticated readers of the versioned access contract."""

from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from platform_modules.access.models import AccessIntent

from .access_contract import build_access_contract
from .view_access import scoped


@require_GET
@scoped("access")
def detail(request, intent_id, *, export=False, api=False):
    try:
        contract = build_access_contract(
            intent_id, actor=request.user, organization=request.organization
        )
    except AccessIntent.DoesNotExist as error:
        raise Http404 from error
    if export or api:
        response = JsonResponse(contract, json_dumps_params={"ensure_ascii": False})
        if export:
            response["Content-Disposition"] = (
                f'attachment; filename="access-contract-{intent_id}.json"'
            )
    else:
        response = render(request, "governance/access_contract.html", {"contract": contract})
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response
