import json

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from platform_core.tenancy import organization_context
from platform_modules.access.models import AccessEvent
from platform_modules.access.observations import related_event_candidates
from platform_modules.access.ui import scoped
from platform_modules.connectors.services import source_from_token
from platform_modules.identity.models import Identity

from . import services
from .coverage import collection_coverage, event_timeline
from .forms import LinkForm, PlacementForm, QueryForm, ReportForm, ScopeForm
from .models import CollectionReport, CollectionScope, ContextLink, GraphNode, NetworkPlacement
from .projection import graph_for_identity, investigate


@scoped("intelligence")
def index(request):
    form = QueryForm(request.GET)
    context = {"form": form}
    if form.is_valid():
        data = form.cleaned_data
        context["form"] = QueryForm(initial=data)
        start, end, identity = data["start"], data["end"], data["identity"]
        candidate_ids, limited = (
            related_event_candidates(identity, start=start, end=end) if identity else ([], False)
        )
        events = (
            AccessEvent.objects.filter(Q(identity=identity) | Q(pk__in=candidate_ids))
            if identity
            else AccessEvent.objects.all()
        )
        rows, truncated = event_timeline(events, start, end, identity=identity)
        truncated |= limited
        context.update(
            {
                "rows": rows,
                "timeline_truncated": truncated,
                "start": start,
                "end": end,
                "coverage": collection_coverage(start, end),
                "graph": graph_for_identity(identity, at=end) if identity else None,
            }
        )
        if data["question"]:
            results, limited, notice = investigate(
                data["question"], at=end, start=start, end=end, zone=data["zone"]
            )
            context.update({"results": results, "query_notice": notice, "query_truncated": limited})
    return render(request, "intelligence/index.html", context)


@scoped("intelligence")
def graph_export(request, object_id):
    identity = get_object_or_404(Identity.objects, pk=object_id)
    form = QueryForm({"end": request.GET.get("at", "")})
    if not form.is_valid():
        return JsonResponse({"error": "invalid_date"}, status=400)
    response = JsonResponse(graph_for_identity(identity, at=form.cleaned_data["end"]))
    response["Content-Disposition"] = f'attachment; filename="identity-graph-{identity.pk}.json"'
    return response


@scoped("intelligence")
def evidence(request, kind, object_id):
    model = {
        "link": ContextLink,
        "placement": NetworkPlacement,
        "scope": CollectionScope,
        "report": CollectionReport,
        "node": GraphNode,
    }.get(kind)
    if not model:
        raise Http404
    obj = get_object_or_404(model.objects, pk=object_id)
    return JsonResponse(
        {
            "type": kind,
            "fields": {
                field.attname: getattr(obj, field.attname) for field in model._meta.concrete_fields
            },
        }
    )


@scoped("intelligence", roles=("admin",))
def configure(request, kind):
    options = {
        "link": (LinkForm, services.publish_link, "Publier une relation avec sa preuve"),
        "placement": (
            PlacementForm,
            services.publish_placement,
            "Définir le placement réseau attendu",
        ),
        "scope": (ScopeForm, services.publish_scope, "Définir le périmètre de collecte"),
    }
    if kind not in options:
        raise Http404
    form_class, service, title = options[kind]
    form = form_class(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            service(form.cleaned_data, actor=request.user, organization=request.organization)
            messages.success(
                request, "Publication datée et auditée. Les événements passés ne sont pas réécrits."
            )
            return redirect("intelligence-configuration")
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": title, "section": "Graphe et collecte"},
    )


@scoped("intelligence")
def configuration(request):
    return render(
        request,
        "intelligence/configuration.html",
        {
            "links": ContextLink.objects.select_related("source", "target").order_by(
                "-recorded_at"
            )[:100],
            "placements": NetworkPlacement.objects.select_related("identity", "switch").order_by(
                "-recorded_at"
            )[:100],
            "scopes": CollectionScope.objects.select_related("source", "resource").order_by(
                "-effective_at"
            )[:100],
            "reports": CollectionReport.objects.select_related("scope__source").order_by(
                "-received_at"
            )[:100],
        },
    )


@scoped("intelligence", roles=("admin",))
@require_POST
def retire(request, kind, object_id):
    model = {"link": ContextLink, "placement": NetworkPlacement, "scope": CollectionScope}.get(kind)
    if not model:
        raise Http404
    get_object_or_404(model.objects, pk=object_id)
    services.retire(kind, object_id, actor=request.user, organization=request.organization)
    return redirect("intelligence-configuration")


@csrf_exempt
@require_POST
def report_api(request):
    if len(request.body) > 16384:
        return JsonResponse({"error": "payload_too_large"}, status=413)
    header = request.headers.get("Authorization", "")
    source = source_from_token(header[7:]) if header.startswith("Bearer ") else None
    if not source:
        return JsonResponse({"error": "unauthorized"}, status=401)
    try:
        data = json.loads(request.body)
        if not isinstance(data, dict) or set(data) - set(ReportForm.base_fields):
            raise ValueError
        for field in ("covered_from", "covered_until"):
            value = parse_datetime(data[field]) if isinstance(data.get(field), str) else None
            if value is None or not timezone.is_aware(value):
                raise ValueError
        form = ReportForm(data)
        if not form.is_valid():
            return JsonResponse(
                {"error": "invalid_report", "fields": form.errors.get_json_data()}, status=400
            )
        with organization_context(source.organization):
            report, created = services.ingest_report(
                form.cleaned_data, source=source, organization=source.organization
            )
        return JsonResponse(
            {"report_id": str(report.pk), "created": created}, status=201 if created else 200
        )
    except (ValueError, ValidationError, PermissionDenied):
        return JsonResponse({"error": "invalid_report"}, status=400)
