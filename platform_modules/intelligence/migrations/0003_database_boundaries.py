from django.db import migrations

TABLES = [
    "intelligence_graphnode",
    "intelligence_contextlink",
    "intelligence_collectionscope",
    "intelligence_collectionreport",
    "intelligence_networkplacement",
]
RELATIONS = [
    ("intelligence_graphnode", "identity", "identity_identity"),
    ("intelligence_graphnode", "account", "identity_externalaccount"),
    ("intelligence_graphnode", "resource", "identity_resource"),
    ("intelligence_graphnode", "credential", "identity_credential"),
    ("intelligence_graphnode", "supplier", "governance_supplier"),
    ("intelligence_contextlink", "source", "intelligence_graphnode"),
    ("intelligence_contextlink", "target", "intelligence_graphnode"),
    ("intelligence_collectionscope", "source", "connectors_eventsource"),
    ("intelligence_collectionscope", "resource", "identity_resource"),
    ("intelligence_collectionreport", "scope", "intelligence_collectionscope"),
    ("intelligence_networkplacement", "identity", "identity_identity"),
    ("intelligence_networkplacement", "switch", "identity_resource"),
    ("access_accessintent", "network_switch", "identity_resource"),
    ("access_accessevent", "network_switch", "identity_resource"),
]
IMMUTABLE = ["intelligence_graphnode", "intelligence_collectionreport"]
RETIRABLE = [
    "intelligence_contextlink",
    "intelligence_collectionscope",
    "intelligence_networkplacement",
]


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(TABLES):
        schema_editor.execute(
            f"CREATE UNIQUE INDEX pamolive_graph_key_{index} ON {table} (organization_id, id)"
        )
    for index, (table, column, target) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT pamolive_graph_relation_{index} "
            f"FOREIGN KEY (organization_id, {column}_id) REFERENCES {target} (organization_id, id)"
        )
    for index, table in enumerate(IMMUTABLE):
        schema_editor.execute(
            f"CREATE TRIGGER pamolive_graph_proof_{index} BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION pamolive_audit_guard()"
        )
    schema_editor.execute("""
        CREATE FUNCTION pamolive_context_retire_only() RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Published evidence cannot be deleted'; END IF;
            IF (to_jsonb(NEW) - 'retired_at') IS DISTINCT FROM (to_jsonb(OLD) - 'retired_at')
                OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
                OR NEW.retired_at < statement_timestamp() - interval '1 minute'
                OR NEW.retired_at > statement_timestamp() + interval '1 minute' THEN
                RAISE EXCEPTION 'Only a current, first retirement may alter published context';
            END IF;
            RETURN NEW;
        END; $$ LANGUAGE plpgsql;
    """)
    for index, table in enumerate(RETIRABLE):
        schema_editor.execute(
            f"CREATE TRIGGER pamolive_context_retire_{index} BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION pamolive_context_retire_only()"
        )


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for index, table in enumerate(RETIRABLE):
        schema_editor.execute(f"DROP TRIGGER pamolive_context_retire_{index} ON {table}")
    schema_editor.execute("DROP FUNCTION pamolive_context_retire_only()")
    for index, table in enumerate(IMMUTABLE):
        schema_editor.execute(f"DROP TRIGGER pamolive_graph_proof_{index} ON {table}")
    for index, (table, _, _) in enumerate(RELATIONS):
        schema_editor.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT pamolive_graph_relation_{index}"
        )
    for index, _ in enumerate(TABLES):
        schema_editor.execute(f"DROP INDEX pamolive_graph_key_{index}")


class Migration(migrations.Migration):
    dependencies = [
        ("intelligence", "0002_graphnode_graph_exact_typed_subject"),
        ("access", "0005_alter_accessevaluation_rule_version"),
        ("governance", "0002_policy_database_boundaries"),
    ]
    operations = [migrations.RunPython(install, uninstall)]
