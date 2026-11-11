from django.contrib.auth import views as auth_views
from django.urls import path

from platform_core import access_contract_views, event_backfill_views
from platform_core.extensions.urls import extension_patterns
from platform_core.oidc import views as oidc_views
from platform_core.security import security_settings
from platform_modules.access import certificate_views, observe_views, ui
from platform_modules.connectors import business_views, creation_views, teamviewer_views
from platform_modules.connectors import views as connector_views
from platform_modules.governance import views as governance_views
from platform_modules.governance import workspace_views
from platform_modules.identity import binding_views as identity_views
from platform_modules.identity import directory_simulation_views, identity360_views, mover_views
from platform_modules.intelligence import views as intelligence_views
from platform_modules.pam import trust_views
from platform_modules.pam import views as pam_views
from platform_modules.recertification import views as recertification_views

urlpatterns = [
    path("identities/360/", identity360_views.inventory, name="identity360-inventory"),
    path("identities/360/<uuid:identity_id>/", identity360_views.detail, name="identity360-detail"),
    path("identities/360/<uuid:identity_id>/export/", identity360_views.export,
         name="identity360-export"),
    path("api/v1/identities/<uuid:identity_id>/360/", identity360_views.api,
         name="api-identity360"),
    path("identities/reconciliation/simulate/", directory_simulation_views.simulation,
         name="identity-directory-simulation"),
    path("governance/workspace/", workspace_views.workspace, name="governance-workspace"),
    path("api/v1/governance/workspace/", workspace_views.workspace,
         {"api": True}, name="api-governance-workspace"),
    path("governance/workspace/export/", workspace_views.workspace,
         {"export": True}, name="governance-workspace-export"),
    path("governance/exceptions/new/", workspace_views.exception_create,
         name="governance-exception-create"),
    path("governance/exceptions/<uuid:case_id>/decide/", workspace_views.exception_decide,
         name="governance-exception-decide"),
    path("observe/", observe_views.index, name="observe-home"),
    path("observe/events/<uuid:event_id>/", observe_views.detail, name="observe-detail"),
    path("observe/events/<uuid:event_id>/export/", observe_views.detail,
         {"export": True}, name="observe-export"),
    path("api/v1/observations/<uuid:event_id>/story/", observe_views.detail,
         {"api": True}, name="api-observation-story"),
    path(
        "access/intents/<uuid:intent_id>/contract/",
        access_contract_views.detail, name="access-contract-detail",
    ),
    path(
        "access/intents/<uuid:intent_id>/contract/export/",
        access_contract_views.detail, {"export": True}, name="access-contract-export",
    ),
    path(
        "api/v1/access-contracts/<uuid:intent_id>/",
        access_contract_views.detail, {"api": True}, name="api-access-contract",
    ),
    path("pam/trust/action/", trust_views.authenticate, name="pam-trust-action"),
    path("pam/trust/enrollment/", trust_views.enrollment, name="pam-trust-enrollment"),
    path("identities/mobility/", mover_views.home, name="mover-home"),
    path("identities/business-roles/", mover_views.catalog, name="mover-catalog"),
    path("identities/business-roles/new/", mover_views.role_config, name="mover-role-new"),
    path(
        "identities/business-roles/<slug:key>/edit/",
        mover_views.role_config,
        name="mover-role-edit",
    ),
    path("identities/<uuid:identity_id>/move/", mover_views.prepare, name="mover-prepare"),
    path("identities/mobility/<uuid:proposal_id>/", mover_views.detail, name="mover-detail"),
    path(
        "identities/mobility/<uuid:proposal_id>/business/",
        mover_views.business_proof,
        name="mover-business-proof",
    ),
    path(
        "identities/mobility/<uuid:proposal_id>/business/export/",
        mover_views.business_proof,
        {"export": True},
        name="mover-business-export",
    ),
    path(
        "identities/mobility/<uuid:proposal_id>/decision/",
        mover_views.decision,
        name="mover-decision",
    ),
    path("connectors/scim-accounts/new/", creation_views.configure, name="scim-creation-new"),
    path(
        "connectors/scim-accounts/<uuid:job_id>/",
        creation_views.detail,
        name="scim-creation-detail",
    ),
    path(
        "connectors/scim-accounts/<uuid:job_id>/proof/",
        creation_views.detail,
        {"export": True},
        name="scim-creation-export",
    ),
    path(
        "connectors/scim-accounts/<uuid:job_id>/reconcile/",
        creation_views.retry,
        name="scim-creation-retry",
    ),
    path(
        "access/business-associations/<uuid:association_id>/proof/",
        business_views.association_proof,
        name="business-association-proof",
    ),
    path(
        "access/intents/<uuid:intent_id>/business/",
        business_views.intent_context,
        name="intent-business-context",
    ),
    path(
        "access/intents/<uuid:intent_id>/business/export/",
        business_views.intent_context,
        {"export": True},
        name="intent-business-export",
    ),
    path(
        "access/intents/<uuid:intent_id>/business/new/",
        business_views.associate_intent,
        name="intent-business-associate",
    ),
    path(
        "access/business-associations/<uuid:association_id>/withdraw/",
        business_views.withdraw_association,
        name="business-association-withdraw",
    ),
    path("api/v1/business-records/", business_views.records_api, name="business-records-api"),
    path("api/v1/business-source/", business_views.source_api, name="business-source-api"),
    path("connectors/business/", business_views.sources, name="business-sources"),
    path(
        "connectors/business/<uuid:source_id>/command/",
        business_views.source_command,
        name="business-source-command",
    ),
    path(
        "connectors/business/receipts/<uuid:receipt_id>/",
        business_views.receipt_detail,
        name="business-receipt",
    ),
    path("system/members/<int:member_id>/", ui.system, name="membership-edit"),
    path("system/oidc/", oidc_views.providers, name="oidc-providers"),
    path("system/oidc/new/", oidc_views.configure, name="oidc-provider-new"),
    path("system/oidc/<uuid:provider_id>/", oidc_views.configure, name="oidc-provider-edit"),
    path(
        "system/oidc/<uuid:provider_id>/activation/",
        oidc_views.activation,
        name="oidc-provider-activation",
    ),
    path("system/oidc/drafts/<uuid:draft_id>/test/", oidc_views.test_start, name="oidc-test-start"),
    path("accounts/oidc/links/", oidc_views.my_links, name="oidc-my-links"),
    path("accounts/oidc/links/<uuid:link_id>/revoke/", oidc_views.revoke, name="oidc-link-revoke"),
    path("accounts/oidc/link/<uuid:provider_id>/", oidc_views.link_start, name="oidc-link-start"),
    path(
        "accounts/oidc/login/<uuid:provider_id>/", oidc_views.login_start, name="oidc-login-start"
    ),
    path("accounts/oidc/mfa/", oidc_views.mfa, name="oidc-mfa"),
    path(
        "accounts/oidc/<uuid:organization_id>/<slug:slug>/callback/",
        oidc_views.callback,
        name="oidc-callback",
    ),
    path(
        "identities/login-bindings/", identity_views.login_bindings, name="identity-login-bindings"
    ),
    path(
        "identities/login-bindings/<uuid:binding_id>/revoke/",
        identity_views.binding_revoke,
        name="identity-binding-revoke",
    ),
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
        oidc_views.PortalLogin.as_view(),
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
    path("connectors/teamviewer/", teamviewer_views.index, name="teamviewer-home"),
    path("connectors/teamviewer/new/", teamviewer_views.configure, name="teamviewer-new"),
    path("connectors/teamviewer/sessions/", teamviewer_views.sessions, name="teamviewer-sessions"),
    path(
        "connectors/teamviewer/sessions/<uuid:session_id>/",
        teamviewer_views.session_detail,
        name="teamviewer-session",
    ),
    path(
        "connectors/teamviewer/<uuid:collector_id>/mappings/",
        teamviewer_views.mappings,
        name="teamviewer-mappings",
    ),
    path(
        "connectors/teamviewer/<uuid:collector_id>/mappings/<slug:kind>/new/",
        teamviewer_views.mapping_create,
        name="teamviewer-mapping-new",
    ),
    path(
        "connectors/teamviewer/<uuid:collector_id>/",
        teamviewer_views.configure,
        name="teamviewer-edit",
    ),
    path(
        "connectors/teamviewer/<uuid:collector_id>/activation/",
        teamviewer_views.activation,
        name="teamviewer-activation",
    ),
    path(
        "connectors/teamviewer/reports/<uuid:report_id>/",
        teamviewer_views.report_detail,
        name="teamviewer-report",
    ),
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
    path("recertification/", recertification_views.index, name="recertification-home"),
    path(
        "recertification/schedules/new/",
        recertification_views.configure,
        name="recertification-schedule-new",
    ),
    path(
        "recertification/schedules/<uuid:schedule_id>/",
        recertification_views.schedule_detail,
        name="recertification-schedule",
    ),
    path(
        "recertification/schedules/<uuid:schedule_id>/edit/",
        recertification_views.configure,
        name="recertification-schedule-edit",
    ),
    path(
        "recertification/schedules/<uuid:schedule_id>/toggle/",
        recertification_views.toggle,
        name="recertification-schedule-toggle",
    ),
    path(
        "recertification/runs/<uuid:run_id>/",
        recertification_views.run_detail,
        name="recertification-run",
    ),
    path(
        "recertification/runs/<uuid:run_id>/proof/",
        recertification_views.run_detail,
        {"export": True},
        name="recertification-export",
    ),
    path("pam/", ui.pam_home, name="pam-home"),
    path("records/<slug:kind>/", ui.record_list, name="record-list"),
    path("records/<slug:kind>/new/", ui.record_create, name="record-create"),
    path("records/<slug:kind>/<uuid:object_id>/", ui.record_detail, name="record-detail"),
    path("identities/<uuid:object_id>/depart/", ui.depart, name="identity-depart"),
    path("approvals/<uuid:object_id>/decide/", ui.decision, name="intent-decide"),
    path(
        "recertification/<uuid:object_id>/review/",
        recertification_views.review,
        name="grant-review",
    ),
    path("pam/<uuid:object_id>/lease/", ui.lease, name="pam-lease"),
    path("audit/", ui.audit, name="audit-log"),
    path("system/", ui.system, name="system-status"),
    path(
        "system/notifications/backfill/",
        event_backfill_views.backfill,
        name="module-event-backfill",
    ),
    path("api/v1/events/", ui.api_events, name="api-events"),
    path(
        "api/v1/events/<uuid:object_id>/certificate-challenge/",
        certificate_views.certificate_proof,
        {"challenge_only": True},
        name="certificate-challenge",
    ),
    path(
        "api/v1/events/<uuid:object_id>/certificate-proof/",
        certificate_views.certificate_proof,
        name="certificate-proof",
    ),
    path("api/v1/events/<uuid:object_id>/export/", ui.export_event, name="event-export"),
    path(
        "events/<uuid:object_id>/mobility/",
        ui.event_mobility_context,
        name="event-mobility-context",
    ),
]

urlpatterns += extension_patterns()
