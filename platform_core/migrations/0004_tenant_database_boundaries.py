"""Database-enforced tenant relations, in addition to service and HTTP isolation."""

from django.db import migrations

SCOPED = [
    "identity_identity",
    "identity_resource",
    "identity_externalaccount",
    "identity_credential",
    "identity_grant",
    "access_accessintent",
    "access_accessevent",
    "access_accessevaluation",
    "approvals_approvaldecision",
    "connectors_eventsource",
    "recertification_campaign",
    "recertification_review",
    "pam_sessionlease",
]
RELATIONS = [
    ("identity_externalaccount", "identity", "identity_identity"),
    ("identity_credential", "identity", "identity_identity"),
    ("identity_credential", "resource", "identity_resource"),
    ("identity_grant", "identity", "identity_identity"),
    ("identity_grant", "account", "identity_externalaccount"),
    ("identity_grant", "resource", "identity_resource"),
    ("access_accessintent", "identity", "identity_identity"),
    ("access_accessintent", "account", "identity_externalaccount"),
    ("access_accessintent", "resource", "identity_resource"),
    ("access_accessevent", "identity", "identity_identity"),
    ("access_accessevent", "account", "identity_externalaccount"),
    ("access_accessevent", "resource", "identity_resource"),
    ("access_accessevent", "credential", "identity_credential"),
    ("access_accessevaluation", "event", "access_accessevent"),
    ("access_accessevaluation", "intent", "access_accessintent"),
    ("approvals_approvaldecision", "intent", "access_accessintent"),
    ("recertification_review", "campaign", "recertification_campaign"),
    ("recertification_review", "grant", "identity_grant"),
    ("pam_sessionlease", "intent", "access_accessintent"),
]


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(SCOPED):
        schema_editor.execute(
            f"CREATE UNIQUE INDEX pamolive_tenant_key_{index} ON {table} (organization_id, id)"
        )
    for index, (table, column, target) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT pamolive_tenant_relation_{index} "
            f"FOREIGN KEY (organization_id, {column}_id) "
            f"REFERENCES {target} (organization_id, id)"
        )
    for index, table in enumerate(
        ["access_accessevent", "access_accessevaluation", "approvals_approvaldecision"]
    ):
        schema_editor.execute(
            f"CREATE TRIGGER pamolive_proof_{index} BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION pamolive_audit_guard()"
        )


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(
        ["access_accessevent", "access_accessevaluation", "approvals_approvaldecision"]
    ):
        schema_editor.execute(f"DROP TRIGGER pamolive_proof_{index} ON {table}")
    for index, (table, _, _) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT pamolive_tenant_relation_{index}"
        )
    for index, _ in enumerate(SCOPED):
        schema_editor.execute(f"DROP INDEX pamolive_tenant_key_{index}")


class Migration(migrations.Migration):
    dependencies = [
        ("platform_core", "0003_postgres_audit_guard"),
        ("access", "0001_initial"),
        ("approvals", "0001_initial"),
        ("connectors", "0001_initial"),
        ("recertification", "0001_initial"),
        ("pam", "0001_initial"),
    ]
    operations = [migrations.RunPython(install, uninstall)]
