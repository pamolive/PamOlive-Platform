from django.db import migrations

TABLES = ("pam_sessionendpoint", "pam_relayconnection", "pam_recordingchunk")
RELATIONS = (
    ("pam_sessionendpoint", "account", "identity_externalaccount"),
    ("pam_sessionendpoint", "resource", "identity_resource"),
    ("pam_relayconnection", "lease", "pam_sessionlease"),
    ("pam_relayconnection", "endpoint", "pam_sessionendpoint"),
    ("pam_recordingchunk", "connection", "pam_relayconnection"),
)


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(TABLES):
        schema_editor.execute(
            f"CREATE UNIQUE INDEX pamolive_relay_key_{index} ON {table} (organization_id, id)"
        )
    for index, (table, column, target) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT pamolive_relay_relation_{index} "
            f"FOREIGN KEY (organization_id, {column}_id) REFERENCES {target} (organization_id, id)"
        )
    schema_editor.execute(
        "CREATE TRIGGER pamolive_recording_immutable BEFORE UPDATE OR DELETE "
        "ON pam_recordingchunk FOR EACH ROW EXECUTE FUNCTION pamolive_audit_guard()"
    )


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute("DROP TRIGGER pamolive_recording_immutable ON pam_recordingchunk")
    for index, (table, _, _) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT pamolive_relay_relation_{index}"
        )
    for index, _ in enumerate(TABLES):
        schema_editor.execute(f"DROP INDEX pamolive_relay_key_{index}")


class Migration(migrations.Migration):
    dependencies = [
        ("pam", "0002_sessionendpoint_relayconnection_recordingchunk_and_more"),
        ("platform_core", "0004_tenant_database_boundaries"),
    ]
    operations = [migrations.RunPython(install, uninstall)]
