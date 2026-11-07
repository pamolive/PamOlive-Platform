from django.contrib.auth import views as auth_views
from django.urls import path

from platform_core.security import MFALoginForm, security_settings
from platform_modules.access import ui
from platform_modules.connectors import views as connector_views
from platform_modules.governance import views as governance_views
from platform_modules.intelligence import views as intelligence_views
from platform_modules.pam import views as pam_views

urlpatterns = [
    path("pam/endpoints/", pam_views.endpoints, name="pam-endpoints"),
    path("pam/endpoints/new/", pam_views.configure, name="pam-endpoint-create"),
    path("pam/endpoints/<uuid:endpoint_id>/", pam_views.configure, name="pam-endpoint-edit"),
    path(
        "pam/endpoints/<uuid:endpoint_id>/<slug:action>/",
        pam_views.endpoint_action,
        name="pam-endpoint-action",
    ),
    path("pam/intents/<uuid:intent_id>/open/", pam_views.launch, name="pam-launch"),
    path("pam/connections/<uuid:connection_id>/", pam_views.detail, name="pam-connection"),
    path("pam/connections/<uuid:connection_id>/stop/", pam_views.stop, name="pam-stop"),
    path(
        "pam/connections/<uuid:connection_id>/recording/", pam_views.recording, name="pam-recording"
    ),
    path(
        "pam/connections/<uuid:connection_id>/recording/data/",
        pam_views.recording_data,
        name="pam-recording-data",
    ),
    path(
        "intelligence/evidence/<slug:kind>/<uuid:object_id>/",
        intelligence_views.evidence,
        name="intelligence-evidence",
    ),
    path("events/<uuid:object_id>/reevaluate/", ui.reevaluate, name="event-reevaluate"),
    path("intelligence/", intelligence_views.index, name="intelligence-home"),
    path(
        "intelligence/configuration/",
        intelligence_views.configuration,
        name="intelligence-configuration",
    ),
    path(
        "intelligence/new/<slug:kind>/", intelligence_views.configure, name="intelligence-configure"
    ),
    path(
        "intelligence/<slug:kind>/<uuid:object_id>/retire/",
        intelligence_views.retire,
        name="intelligence-retire",
    ),
    path(
        "intelligence/graph/<uuid:object_id>/export/",
        intelligence_views.graph_export,
        name="intelligence-graph-export",
    ),
    path("api/v1/collection-reports/", intelligence_views.report_api, name="collection-report-api"),
    path("governance/", governance_views.index, name="governance-home"),
    path("governance/new/<slug:kind>/", governance_views.edit, name="governance-create"),
    path(
        "governance/contracts/<uuid:object_id>/",
        governance_views.detail,
        name="governance-contract",
    ),
    path(
        "governance/contracts/<uuid:object_id>/revise/",
        governance_views.edit,
        {"kind": "contract"},
        name="governance-contract-revise",
    ),
    path(
        "governance/<slug:kind>/<uuid:object_id>/withdraw/",
        governance_views.withdraw,
        name="governance-withdraw",
    ),
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
    path("connectors/provisioning/", connector_views.index, name="provisioning-home"),
    path("connectors/provisioning/new/", connector_views.configure, name="connector-create"),
    path(
        "connectors/provisioning/<uuid:connector_id>/",
        connector_views.configure,
        name="connector-edit",
    ),
    path(
        "connectors/provisioning/<uuid:connector_id>/test/",
        connector_views.connector_action,
        {"action": "test"},
        name="connector-test",
    ),
    path(
        "connectors/provisioning/<uuid:connector_id>/enable/",
        connector_views.connector_action,
        {"action": "enable"},
        name="connector-enable",
    ),
    path(
        "connectors/provisioning/<uuid:connector_id>/disable/",
        connector_views.connector_action,
        {"action": "disable"},
        name="connector-disable",
    ),
    path(
        "connectors/bind-account/",
        connector_views.binding_create,
        {"kind": "account"},
        name="account-bind",
    ),
    path(
        "connectors/bind-group/",
        connector_views.binding_create,
        {"kind": "group"},
        name="group-bind",
    ),
    path(
        "connectors/changes/<uuid:change_id>/",
        connector_views.change_detail,
        name="external-change",
    ),
    path(
        "connectors/changes/<uuid:change_id>/retry/",
        connector_views.retry,
        name="external-change-retry",
    ),
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
