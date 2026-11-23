"""Native, session-authenticated readers of the versioned access contract."""

from django.core.exceptions import PermissionDenied
from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from platform_modules.access.models import AccessIntent

from .access_contract import build_access_contract
from .services import authorize
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
        intention = contract["intention"]
        may_revoke = False
        if (contract["optional_sections"]["pam"] and intention["fulfillment"] == "pam"
                and intention["status"] in ("pending", "approved")):
            is_requester = intention["requested_by_id"] == request.user.pk
            try:
                authorize(request.user, request.organization,
                          roles=("admin", "operator") if is_requester else ("admin",))
            except PermissionDenied:
                pass
            else:
                may_revoke = True
        response = render(request, "governance/access_contract.html", {
            "contract": contract, "may_revoke_pam_mandate": may_revoke,
        })
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response
