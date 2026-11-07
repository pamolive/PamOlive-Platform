from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render

from platform_core.audit import record
from platform_core.permissions import require_permission
from platform_core.views import installed_module_required

from .forms import AccessAssignmentForm, IdentityApplicationForm
from .models import AccessAssignment, IdentityApplication


@installed_module_required("identity")
def home(request):
    return render(
        request,
        "identity/home.html",
        {
            "user_count": get_user_model().objects.filter(is_active=True).count(),
            "application_count": IdentityApplication.objects.filter(active=True).count(),
            "assignment_count": AccessAssignment.objects.filter(
                status=AccessAssignment.Status.ACTIVE
            ).count(),
            "applications": IdentityApplication.objects.annotate(
                access_count=Count("access_assignments")
            ).order_by("name")[:8],
            "recent_assignments": AccessAssignment.objects.select_related(
                "user", "application", "role"
            ).order_by("-granted_at")[:8],
        },
    )


@installed_module_required("identity")
@require_permission("identity.applications.manage")
def application_create(request):
    form = IdentityApplicationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        application = form.save()
        record(
            action="identity.application.created",
            summary=f"Application {application.name} créée",
            actor=request.user,
            request=request,
            target=application,
        )
        messages.success(request, "Application créée.")
        return redirect("identity-home")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": "Nouvelle application", "section": "Identités"},
    )


@installed_module_required("identity")
@require_permission("identity.applications.manage")
def application_edit(request, application_id):
    application = get_object_or_404(IdentityApplication, pk=application_id)
    form = IdentityApplicationForm(request.POST or None, instance=application)
    if request.method == "POST" and form.is_valid():
        application = form.save()
        record(
            action="identity.application.updated",
            summary=f"Application {application.name} modifiée",
            actor=request.user,
            request=request,
            target=application,
        )
        messages.success(request, "Application mise à jour.")
        return redirect("identity-home")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": f"Application · {application.name}", "section": "Identités"},
    )


@installed_module_required("identity")
@require_permission("identity.assignments.manage")
def assignment_list(request):
    assignments = AccessAssignment.objects.select_related("user", "application", "role").order_by(
        "-granted_at"
    )
    return render(request, "identity/assignments.html", {"assignments": assignments})


@installed_module_required("identity")
@require_permission("identity.assignments.manage")
def assignment_create(request):
    form = AccessAssignmentForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        assignment = form.save()
        record(
            action="identity.assignment.created",
            summary=f"Accès {assignment.entitlement} attribué à {assignment.user}",
            actor=request.user,
            request=request,
            target=assignment,
        )
        messages.success(request, "Accès attribué.")
        return redirect("assignment-list")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": "Nouvelle attribution", "section": "Identités"},
    )


@installed_module_required("identity")
@require_permission("identity.assignments.manage")
def assignment_edit(request, assignment_id):
    assignment = get_object_or_404(AccessAssignment, pk=assignment_id)
    form = AccessAssignmentForm(request.POST or None, instance=assignment)
    if request.method == "POST" and form.is_valid():
        assignment = form.save()
        record(
            action="identity.assignment.updated",
            summary=f"Attribution {assignment.entitlement} modifiée",
            actor=request.user,
            request=request,
            target=assignment,
        )
        messages.success(request, "Attribution mise à jour.")
        return redirect("assignment-list")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": "Modifier l’attribution", "section": "Identités"},
    )
