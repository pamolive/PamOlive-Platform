from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import connection
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from .audit import record
from .forms import BusinessRoleForm, PlatformUserForm
from .models import AuditEvent, BusinessRole
from .permissions import require_permission
from .services import disable_module, install_module, module_catalog


@login_required
def dashboard(request):
    enabled_modules = [
        definition for definition, state in module_catalog() if state and state.enabled
    ]
    return render(
        request,
        "platform_core/dashboard.html",
        {
            "enabled_modules": enabled_modules,
            "module_count": len(enabled_modules),
            "role_count": BusinessRole.objects.count(),
            "user_count": get_user_model().objects.filter(is_active=True).count(),
            "recent_events": AuditEvent.objects.select_related("actor")[:7],
        },
    )


@require_permission("core.users.manage")
def user_list(request):
    users = (
        get_user_model().objects.prefetch_related("pamolive_business_roles").order_by("username")
    )
    return render(request, "platform_core/users.html", {"users": users})


@require_permission("core.users.manage")
def user_create(request):
    form = PlatformUserForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        record(
            action="identity.user.created",
            summary=f"Utilisateur {user.username} créé",
            actor=request.user,
            request=request,
            target=user,
        )
        messages.success(request, "Utilisateur créé.")
        return redirect("user-list")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": "Nouvel utilisateur", "section": "Utilisateurs"},
    )


@require_permission("core.users.manage")
def user_edit(request, user_id):
    user = get_object_or_404(get_user_model(), pk=user_id)
    form = PlatformUserForm(request.POST or None, instance=user)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        record(
            action="identity.user.updated",
            summary=f"Utilisateur {user.username} modifié",
            actor=request.user,
            request=request,
            target=user,
        )
        messages.success(request, "Utilisateur mis à jour.")
        return redirect("user-list")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": f"Utilisateur · {user.username}", "section": "Utilisateurs"},
    )


@require_permission("core.roles.manage")
def role_list(request):
    roles = BusinessRole.objects.prefetch_related("members", "permission_grants")
    return render(request, "platform_core/roles.html", {"roles": roles})


@require_permission("core.roles.manage")
def role_create(request):
    form = BusinessRoleForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        role = form.save()
        record(
            action="identity.role.created",
            summary=f"Rôle {role.name} créé",
            actor=request.user,
            request=request,
            target=role,
        )
        messages.success(request, "Rôle métier créé.")
        return redirect("role-list")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": "Nouveau rôle métier", "section": "Rôles et droits"},
    )


@require_permission("core.roles.manage")
def role_edit(request, role_id):
    role = get_object_or_404(BusinessRole, pk=role_id)
    form = BusinessRoleForm(request.POST or None, instance=role)
    if request.method == "POST" and form.is_valid():
        role = form.save()
        record(
            action="identity.role.updated",
            summary=f"Rôle {role.name} modifié",
            actor=request.user,
            request=request,
            target=role,
        )
        messages.success(request, "Rôle métier mis à jour.")
        return redirect("role-list")
    return render(
        request,
        "platform_core/form.html",
        {"form": form, "title": f"Rôle · {role.name}", "section": "Rôles et droits"},
    )


@require_permission("core.modules.manage")
def module_list(request):
    return render(request, "platform_core/modules.html", {"modules": module_catalog()})


@require_permission("core.modules.manage")
@require_POST
def module_install(request, module_key):
    try:
        install_module(module_key, actor=request.user, request=request)
        messages.success(request, "Module activé.")
    except ValidationError as error:
        messages.error(request, error.message)
    return redirect("module-list")


@require_permission("core.modules.manage")
@require_POST
def module_disable(request, module_key):
    try:
        disable_module(module_key, actor=request.user, request=request)
        messages.success(request, "Module désactivé. Ses données restent conservées.")
    except ValidationError as error:
        messages.error(request, error.message)
    return redirect("module-list")


@require_permission("core.audit.view")
def audit_log(request):
    events = AuditEvent.objects.select_related("actor")[:100]
    return render(request, "platform_core/audit_log.html", {"events": events})


@require_permission("core.system.view")
def system_status(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            database_online = True
    except Exception:  # pragma: no cover - page is a graceful operational fallback
        database_online = False
    return render(
        request,
        "platform_core/system_status.html",
        {
            "database_online": database_online,
            "database_vendor": connection.vendor,
            "module_count": sum(1 for _, state in module_catalog() if state and state.enabled),
        },
    )


def module_is_enabled(module_key):
    from .models import InstalledModule

    return InstalledModule.objects.filter(module_key=module_key, enabled=True).exists()


def installed_module_required(module_key):
    def decorator(view):
        @login_required
        def wrapped(request, *args, **kwargs):
            if not module_is_enabled(module_key):
                messages.warning(request, "Ce module n'est pas activé.")
                return redirect(reverse("module-list"))
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
