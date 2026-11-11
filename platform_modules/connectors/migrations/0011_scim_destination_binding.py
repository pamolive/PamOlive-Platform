from django.db import migrations, models

GUARDED_FIELDS = {
    "provisioningconnector": ("id", "organization_id", "base_url"),
    "accountbinding": ("id", "organization_id", "connector_id", "account_id", "remote_id"),
    "groupbinding": (
        "id",
        "organization_id",
        "connector_id",
        "resource_id",
        "entitlement",
        "remote_id",
    ),
    "externalchange": ("binding_id", "group_id", "account_id", "grant_id"),
}


def bind_existing(apps, schema_editor):
    from platform_modules.connectors.scim_credentials import destination_seal

    connector = apps.get_model("connectors", "ProvisioningConnector")
    rows = connector._base_manager.using(schema_editor.connection.alias)
    # Every prior application edit incremented the revision, but did not log the URL.
    # Only the initial revision establishes that the stored address was never edited.
    for row in rows.filter(revision=1).iterator(chunk_size=200):
        rows.filter(pk=row.pk).update(destination_seal=destination_seal(row))


def install_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute("""
        CREATE FUNCTION pamolive_scim_destination_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE field text;
        BEGIN
            FOREACH field IN ARRAY TG_ARGV LOOP
                IF TG_TABLE_NAME = 'connectors_externalchange'
                    AND (to_jsonb(OLD) -> field) = 'null'::jsonb THEN
                    CONTINUE;
                END IF;
                IF (to_jsonb(NEW) -> field) IS DISTINCT FROM (to_jsonb(OLD) -> field) THEN
                    RAISE EXCEPTION 'PAM-olive SCIM destination and mappings are immutable';
                END IF;
            END LOOP;
            RETURN NEW;
        END $$;
    """)
    for model, fields in GUARDED_FIELDS.items():
        args = ", ".join(f"'{field}'" for field in fields)
        schema_editor.execute(
            f"CREATE TRIGGER pamolive_scim_destination_guard BEFORE UPDATE ON connectors_{model} "
            f"FOR EACH ROW EXECUTE FUNCTION pamolive_scim_destination_guard({args})"
        )


def remove_guards(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        for model in GUARDED_FIELDS:
            schema_editor.execute(
                f"DROP TRIGGER pamolive_scim_destination_guard ON connectors_{model}"
            )
        schema_editor.execute("DROP FUNCTION pamolive_scim_destination_guard()")


class Migration(migrations.Migration):
    dependencies = [("connectors", "0010_scim_initial_accounts")]
    operations = [
        migrations.AddField(
            model_name="provisioningconnector",
            name="destination_seal",
            field=models.CharField(blank=True, editable=False, max_length=64),
        ),
        migrations.RunPython(bind_existing, migrations.RunPython.noop),
        migrations.RunPython(install_guards, remove_guards),
    ]
