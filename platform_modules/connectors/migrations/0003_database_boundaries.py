from django.db import migrations

TABLES = [
    "connectors_provisioningconnector",
    "connectors_accountbinding",
    "connectors_groupbinding",
    "connectors_externalchange",
    "connectors_executionevidence",
]
RELATIONS = [
    ("connectors_accountbinding", "connector", "connectors_provisioningconnector"),
    ("connectors_accountbinding", "account", "identity_externalaccount"),
    ("connectors_groupbinding", "connector", "connectors_provisioningconnector"),
    ("connectors_groupbinding", "resource", "identity_resource"),
    ("connectors_externalchange", "account", "identity_externalaccount"),
    ("connectors_externalchange", "grant", "identity_grant"),
    ("connectors_externalchange", "binding", "connectors_accountbinding"),
    ("connectors_externalchange", "group", "connectors_groupbinding"),
    ("connectors_executionevidence", "change", "connectors_externalchange"),
    ("access_accessintent", "provisioned_grant", "identity_grant"),
]


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(TABLES):
        schema_editor.execute(
            f"CREATE UNIQUE INDEX pamolive_connector_key_{index} ON {table} (organization_id, id)"
        )
    for index, (table, column, target) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT pamolive_connector_relation_{index} "
            f"FOREIGN KEY (organization_id, {column}_id) REFERENCES {target} (organization_id, id)"
        )
    schema_editor.execute(
        "CREATE TRIGGER pamolive_execution_proof BEFORE UPDATE OR DELETE "
        "ON connectors_executionevidence FOR EACH ROW EXECUTE FUNCTION pamolive_audit_guard()"
    )


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute("DROP TRIGGER pamolive_execution_proof ON connectors_executionevidence")
    for index, (table, _, _) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT pamolive_connector_relation_{index}"
        )
    for index, _ in enumerate(TABLES):
        schema_editor.execute(f"DROP INDEX pamolive_connector_key_{index}")


class Migration(migrations.Migration):
    dependencies = [
        ("connectors", "0002_accountbinding_externalchange_executionevidence_and_more"),
        ("access", "0002_accessintent_fulfillment_and_more"),
        ("platform_core", "0004_tenant_database_boundaries"),
    ]
    operations = [migrations.RunPython(install, uninstall)]
