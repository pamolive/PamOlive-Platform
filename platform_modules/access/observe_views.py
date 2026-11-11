"""Session-authenticated Observe readers; no ingestion or execution authority."""

from uuid import UUID

from django.core.exceptions import ValidationError
from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from platform_core.view_access import scoped

from .models import AccessEvent, AccessIntent
from .observe import observation_index, observation_story


@require_GET
@scoped("intelligence")
def index(request):
    try:
        data = observation_index(actor=request.user, organization=request.organization,
                                 verdict=request.GET.get("verdict"))
    except ValidationError as error:
        raise Http404 from error
    response = render(request, "observe/index.html", {"observations": data})
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_GET
@scoped("intelligence")
def detail(request, event_id, *, api=False, export=False):
    comparison = request.GET.get("compare_intent")
    try:
        comparison = UUID(comparison) if comparison else None
        story = observation_story(event_id, actor=request.user, organization=request.organization,
                                  comparison_intent_id=comparison)
    except (AccessEvent.DoesNotExist, AccessIntent.DoesNotExist,
            ValueError, ValidationError) as error:
        raise Http404 from error
    if api or export:
        response = JsonResponse(story, json_dumps_params={"ensure_ascii": False})
        if export:
            response["Content-Disposition"] = f'attachment; filename="observation-{event_id}.json"'
    else:
        response = render(request, "observe/detail.html", {"story": story})
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response
