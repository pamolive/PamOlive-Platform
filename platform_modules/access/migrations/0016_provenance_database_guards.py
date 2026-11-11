"""Protect server-assigned provenance and same-tenant references in PostgreSQL.

SQLite development databases receive insert/update guards. PostgreSQL is the
qualified deployment database and also protects receipt deletion and tenant FKs.
"""

from django.db import migrations


def install(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor == "postgresql":
        schema_editor.execute(
            "CREATE UNIQUE INDEX access_event_tenant_key "
            "ON access_accessevent (organization_id,id)"
        )
        schema_editor.execute(
            "CREATE UNIQUE INDEX access_source_tenant_key "
            "ON connectors_eventsource (organization_id,id)"
        )
        schema_editor.execute(
            "CREATE UNIQUE INDEX access_audit_tenant_key "
            "ON platform_core_auditevent (organization_id,id)"
        )
        relations = (
            ("access_accessevent", "collector_source", "connectors_eventsource"),
            ("access_accessprovenancereceipt", "event", "access_accessevent"),
            ("access_accessprovenancereceipt", "audit", "platform_core_auditevent"),
            ("access_accesseventconflict", "event", "access_accessevent"),
            ("access_accesseventconflict", "audit", "platform_core_auditevent"),
            ("access_accesseventquota", "first_denial_audit", "platform_core_auditevent"),
        )
        for index, (table, field, target) in enumerate(relations):
            schema_editor.execute(
                f"ALTER TABLE {table} ADD CONSTRAINT access_provenance_tenant_{index} "
                f"FOREIGN KEY (organization_id,{field}_id) "
                f"REFERENCES {target} (organization_id,id)"
            )
        schema_editor.execute("""
            CREATE FUNCTION access_provenance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF TG_TABLE_NAME = 'access_accessprovenancereceipt' THEN
                RAISE EXCEPTION 'Provenance receipt is immutable';
              END IF;
              IF TG_OP = 'INSERT' THEN
                IF NEW.provenance_channel = 'legacy_unknown' THEN
                  RAISE EXCEPTION 'New legacy provenance is forbidden';
                END IF;
                RETURN NEW;
              END IF;
              IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'Access event history is immutable';
              END IF;
              IF ROW(OLD.organization_id, OLD.source, OLD.external_id,
                     OLD.provenance_channel, OLD.collector_source_id,
                     OLD.manual_actor_id, OLD.internal_principal,
                     OLD.facts_schema, OLD.facts_digest, OLD.received_at)
                 IS DISTINCT FROM
                 ROW(NEW.organization_id, NEW.source, NEW.external_id,
                     NEW.provenance_channel, NEW.collector_source_id,
                     NEW.manual_actor_id, NEW.internal_principal,
                     NEW.facts_schema, NEW.facts_digest, NEW.received_at) THEN
                RAISE EXCEPTION 'Access event provenance is immutable';
              END IF;
              RETURN NEW;
            END $$;
        """)
        schema_editor.execute(
            "CREATE TRIGGER access_event_provenance_guard "
            "BEFORE INSERT OR UPDATE OR DELETE ON access_accessevent "
            "FOR EACH ROW EXECUTE FUNCTION access_provenance_guard()"
        )
        schema_editor.execute(
            "CREATE TRIGGER access_receipt_provenance_guard "
            "BEFORE UPDATE OR DELETE ON access_accessprovenancereceipt "
            "FOR EACH ROW EXECUTE FUNCTION access_provenance_guard()"
        )
    elif vendor == "sqlite":
        schema_editor.execute("""
            CREATE TRIGGER access_new_legacy_guard BEFORE INSERT ON access_accessevent
            WHEN NEW.provenance_channel = 'legacy_unknown'
            BEGIN SELECT RAISE(ABORT, 'New legacy provenance is forbidden'); END;
        """)
        schema_editor.execute("""
            CREATE TRIGGER access_event_provenance_guard BEFORE UPDATE ON access_accessevent
            WHEN OLD.organization_id IS NOT NEW.organization_id
              OR OLD.source IS NOT NEW.source OR OLD.external_id IS NOT NEW.external_id
              OR OLD.provenance_channel IS NOT NEW.provenance_channel
              OR OLD.collector_source_id IS NOT NEW.collector_source_id
              OR OLD.manual_actor_id IS NOT NEW.manual_actor_id
              OR OLD.internal_principal IS NOT NEW.internal_principal
              OR OLD.facts_schema IS NOT NEW.facts_schema
              OR OLD.facts_digest IS NOT NEW.facts_digest
              OR OLD.received_at IS NOT NEW.received_at
            BEGIN SELECT RAISE(ABORT, 'Access event provenance is immutable'); END;
        """)
        schema_editor.execute("""
            CREATE TRIGGER access_receipt_provenance_guard
            BEFORE UPDATE ON access_accessprovenancereceipt
            BEGIN SELECT RAISE(ABORT, 'Provenance receipt is immutable'); END;
        """)


def uninstall(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor in {"postgresql", "sqlite"}:
        # Reversing 0016 first and then failing to restore the old global unique
        # key in 0015 would leave newly written events without SQL guards. Quota
        # rows may also exist without accepted events and remain audit evidence.
        with schema_editor.connection.cursor() as cursor:
            for query in (
                "SELECT 1 FROM access_accessevent "
                "WHERE provenance_channel <> 'legacy_unknown' LIMIT 1",
                "SELECT 1 FROM access_accessprovenancereceipt LIMIT 1",
                "SELECT 1 FROM access_accesseventconflict LIMIT 1",
                "SELECT 1 FROM access_accesseventquota LIMIT 1",
            ):
                cursor.execute(query)
                if cursor.fetchone():
                    raise RuntimeError(
                        "P0-4 rollback requires explicit reconciliation of new event spaces."
                    )
    if vendor == "postgresql":
        schema_editor.execute(
            "DROP TRIGGER access_receipt_provenance_guard ON access_accessprovenancereceipt"
        )
        schema_editor.execute("DROP TRIGGER access_event_provenance_guard ON access_accessevent")
        schema_editor.execute("DROP FUNCTION access_provenance_guard()")
        for index, table in enumerate((
            "access_accessevent", "access_accessprovenancereceipt",
            "access_accessprovenancereceipt", "access_accesseventconflict",
            "access_accesseventconflict", "access_accesseventquota",
        )):
            schema_editor.execute(
                f"ALTER TABLE {table} DROP CONSTRAINT access_provenance_tenant_{index}"
            )
        schema_editor.execute("DROP INDEX access_audit_tenant_key")
        schema_editor.execute("DROP INDEX access_source_tenant_key")
        schema_editor.execute("DROP INDEX access_event_tenant_key")
    elif vendor == "sqlite":
        schema_editor.execute("DROP TRIGGER access_receipt_provenance_guard")
        schema_editor.execute("DROP TRIGGER access_event_provenance_guard")
        schema_editor.execute("DROP TRIGGER access_new_legacy_guard")


class Migration(migrations.Migration):
    dependencies = [("access", "0015_event_provenance")]
    operations = [migrations.RunPython(install, uninstall)]
