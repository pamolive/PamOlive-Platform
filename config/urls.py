from django.contrib.auth import views as auth_views
from django.urls import path

from platform_core.security import MFALoginForm, security_settings
from platform_modules.access import ui

urlpatterns = [
    path("health/", ui.health, name="health"),
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(
            template_name="registration/login.html", authentication_form=MFALoginForm
        ),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("accounts/security/", security_settings, name="account-security"),
    path("", ui.dashboard, name="dashboard"),
    path("organizations/switch/", ui.switch_organization, name="organization-switch"),
    path("modules/", ui.modules, name="module-list"),
    path(
        "modules/<slug:module_key>/install/",
        ui.module_action,
        {"action": "install"},
        name="module-install",
    ),
    path(
        "modules/<slug:module_key>/disable/",
        ui.module_action,
        {"action": "disable"},
        name="module-disable",
    ),
    path("identities/", ui.identity_home, name="identity-home"),
    path("access/", ui.access_home, name="access-home"),
    path("approvals/", ui.approvals_home, name="approvals-home"),
    path("connectors/", ui.connectors_home, name="connectors-home"),
    path("recertification/", ui.recertification_home, name="recertification-home"),
    path("pam/", ui.pam_home, name="pam-home"),
    path("records/<slug:kind>/", ui.record_list, name="record-list"),
    path("records/<slug:kind>/new/", ui.record_create, name="record-create"),
    path("records/<slug:kind>/<uuid:object_id>/", ui.record_detail, name="record-detail"),
    path("identities/<uuid:object_id>/depart/", ui.depart, name="identity-depart"),
    path("approvals/<uuid:object_id>/decide/", ui.decision, name="intent-decide"),
    path("recertification/<uuid:object_id>/review/", ui.review, name="grant-review"),
    path("pam/<uuid:object_id>/lease/", ui.lease, name="pam-lease"),
    path("audit/", ui.audit, name="audit-log"),
    path("system/", ui.system, name="system-status"),
    path("api/v1/events/", ui.api_events, name="api-events"),
    path("api/v1/events/<uuid:object_id>/export/", ui.export_event, name="event-export"),
]
