"""Release-scoped offline PostgreSQL upgrade with an in-transaction preservation gate."""

import argparse
import hashlib
import importlib
import io
import json
import os
import re
import sys
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from uuid import UUID

FORMAT = "pamolive-controlled-upgrade/1"
CATALOGS = {"auth_permission", "django_content_type", "django_migrations"}
REVIEWED = {
    ("access", "0010_observed_intervals"),
    ("access", "0011_signed_observation_context"),
    ("access", "0012_evaluation_proof_guard"),
    ("connectors", "0004_teamviewercollector_teamviewerrun_teamviewerreport"),
    ("connectors", "0005_teamviewer_mapping_evidence"),
    ("connectors", "0006_teamviewer_physical_sessions"),
    ("connectors", "0007_teamviewer_access_observations"),
}
NEW_DEFAULTS = {
    "access_accessevent": {"ended_at": None},
    "access_accessevaluation": {
        "audit_id": None,
        "context": {},
        "context_hash": "",
        "signature": "",
    },
}


class UpgradeRefused(RuntimeError):
    def __init__(self, code, *, rollback_verified=False):
        self.code = code
        self.rollback_verified = rollback_verified
        super().__init__(code)


class RollbackProbe(RuntimeError):
    pass


def canonical(value):
    def encode(item):
        if isinstance(item, datetime):
            return {"datetime": item.isoformat(timespec="microseconds")}
        if isinstance(item, time):
            return {"time": item.isoformat(timespec="microseconds")}
        if isinstance(item, date):
            return {"date": item.isoformat()}
        if isinstance(item, UUID):
            return {"uuid": str(item)}
        if isinstance(item, Decimal):
            return {"decimal": str(item)}
        if isinstance(item, (bytes, bytearray, memoryview)):
            data = bytes(item)
            return {"binary_sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}
        raise TypeError("Unsupported preservation value")

    return json.dumps(
        value,
        default=encode,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def guard_database(expected):
    from django.db import connection

    if not re.fullmatch(r"(?:test_)?pamolive(?:_[a-z0-9_]{1,100})?", expected):
        raise UpgradeRefused("unsupported_database_name")
    if connection.vendor != "postgresql" or connection.settings_dict["NAME"] != expected:
        raise UpgradeRefused("wrong_database")
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_schema(), current_user, session_user")
        database, schema, role, session_role = cursor.fetchone()
        if database != expected or schema != "public" or role != session_role:
            raise UpgradeRefused("wrong_database_or_schema")
        cursor.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
            "FROM pg_roles WHERE rolname=current_user"
        )
        if any(cursor.fetchone()):
            raise UpgradeRefused("privileged_database_role")
        cursor.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member "
            "WHERE r.rolname=current_user)"
        )
        if cursor.fetchone()[0]:
            raise UpgradeRefused("inherited_database_role")


def historical_specs(executor):
    from django.db.migrations.recorder import MigrationRecorder

    applied = set(executor.loader.applied_migrations)
    if applied - set(executor.loader.graph.nodes):
        raise UpgradeRefused("unknown_applied_migration")
    if not applied:
        raise UpgradeRefused("existing_installation_required")
    leaves = [
        key
        for key in applied
        if not any(child.key in applied for child in executor.loader.graph.node_map[key].children)
    ]
    registry = executor.loader.project_state(leaves).apps
    models = list(registry.get_models(include_auto_created=True)) + [MigrationRecorder.Migration]
    return specs(models)


def specs(models):
    result = {}
    for model in models:
        meta = model._meta
        if not meta.managed or meta.proxy:
            continue
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", meta.db_table) or not meta.pk.column:
            raise UpgradeRefused("unsupported_managed_table")
        result[meta.db_table] = dict(
            label=meta.label,
            pk=meta.pk.column,
            columns={field.column: field.get_internal_type() for field in meta.concrete_fields},
        )
    return dict(sorted(result.items()))


def current_specs():
    from django.apps import apps
    from django.db.migrations.recorder import MigrationRecorder

    return specs(list(apps.get_models(include_auto_created=True)) + [MigrationRecorder.Migration])


def snapshot(table_specs, *, after=False):
    from django.db import connection

    result, quote = {}, connection.ops.quote_name
    for table, spec in table_specs.items():
        columns = list(spec["columns"])
        extra = NEW_DEFAULTS.get(table, {}) if after else {}
        # Only columns newly added to this historical table are checked for defaults.
        extra = {key: value for key, value in extra.items() if key not in columns}
        selected = columns + list(extra)
        query = (
            f"SELECT {', '.join(map(quote, selected))} FROM {quote(table)} "
            f"ORDER BY {quote(spec['pk'])}"
        )
        rolling, count, rows = hashlib.sha256(), 0, {}
        with connection.chunked_cursor() as cursor:
            cursor.execute(query)
            while batch := cursor.fetchmany(200):
                for values in batch:
                    source = dict(zip(selected, values))
                    body = {}
                    for column in columns:
                        value = source[column]
                        if spec["columns"][column] == "JSONField" and value is not None:
                            value = {"json": json.loads(value) if isinstance(value, str) else value}
                        body[column] = value
                    for column, expected in extra.items():
                        actual = source[column]
                        if column == "context" and isinstance(actual, str):
                            actual = json.loads(actual)
                        if actual != expected:
                            raise UpgradeRefused("historical_default_changed")
                    payload = canonical(body)
                    rolling.update(b"\0" + payload)
                    count += 1
                    if table in CATALOGS:
                        rows[str(body[spec["pk"]])] = hashlib.sha256(payload).hexdigest()
        result[table] = dict(count=count, sha256=rolling.hexdigest(), rows=rows)
    return result


def assert_preserved(before, after):
    if set(before) != set(after):
        raise UpgradeRefused("historical_table_set_changed")
    for table, original in before.items():
        observed = after[table]
        if table in CATALOGS:
            if any(observed["rows"].get(key) != value for key, value in original["rows"].items()):
                raise UpgradeRefused("historical_catalog_changed")
        elif original != observed:
            raise UpgradeRefused("historical_data_changed")


def schema_hash():
    from django.db import connection

    queries = [
        "SELECT c.relname, a.attnum, a.attname, format_type(a.atttypid,a.atttypmod), "
        "a.attnotnull, pg_get_expr(d.adbin,d.adrelid) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid "
        "LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum "
        "WHERE n.nspname=current_schema() AND c.relkind IN ('r','p') "
        "AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
        "SELECT c.relname, x.conname, pg_get_constraintdef(x.oid) FROM pg_constraint x "
        "JOIN pg_class c ON c.oid=x.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=current_schema() ORDER BY c.relname,x.conname",
        "SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() "
        "ORDER BY tablename,indexname",
        "SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid) FROM pg_trigger t "
        "JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=current_schema() AND NOT t.tgisinternal ORDER BY c.relname,t.tgname",
        "SELECT p.oid::regprocedure::text,pg_get_functiondef(p.oid) FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() "
        "AND p.prokind='f' AND p.proname LIKE 'pamolive_%' ORDER BY 1",
        "SELECT sequencename,data_type,start_value,min_value,max_value,increment_by,"
        "cycle,cache_size "
        "FROM pg_sequences WHERE schemaname=current_schema() ORDER BY sequencename",
    ]
    observed = []
    with connection.cursor() as cursor:
        for query in queries:
            cursor.execute(query)
            observed.append(cursor.fetchall())
    return digest(observed)


def reviewed_plan(executor, expected):
    targets = executor.loader.graph.leaf_nodes()
    planned = executor.migration_plan(targets)
    entries = []
    for migration, backwards in planned:
        key = (migration.app_label, migration.name)
        if (
            backwards
            or key not in REVIEWED
            or not migration.atomic
            or any(operation.atomic is False for operation in migration.operations)
        ):
            raise UpgradeRefused("unreviewed_or_nontransactional_migration")
        module = importlib.import_module(migration.__module__)
        entries.append(
            dict(
                app=key[0],
                migration=key[1],
                sha256=hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest(),
            )
        )
    return dict(format=FORMAT, database=expected, migrations=entries)


def make_plan(expected):
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    guard_database(expected)
    executor = MigrationExecutor(connection)
    historical_specs(executor)
    return reviewed_plan(executor, expected)


def upgrade(expected, approved, *, offline=False, rollback_probe=False):
    from django.core.management import call_command
    from django.db import connection, transaction
    from django.db.migrations.executor import MigrationExecutor

    if not offline or connection.in_atomic_block or not connection.features.can_rollback_ddl:
        raise UpgradeRefused("offline_transactional_upgrade_required")
    guard_database(expected)
    before_specs, before, before_schema, report = None, None, None, None
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(5263693, 5591111)")
        if not cursor.fetchone()[0]:
            raise UpgradeRefused("another_upgrade_is_running")
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout='5s'")
                cursor.execute("SET LOCAL statement_timeout='60s'")
            executor = MigrationExecutor(connection)
            actual = reviewed_plan(executor, expected)
            if actual != approved:
                raise UpgradeRefused("reviewed_plan_changed")
            before_specs = historical_specs(executor)
            with connection.cursor() as cursor:
                tables = ", ".join(connection.ops.quote_name(table) for table in before_specs)
                cursor.execute(f"LOCK TABLE {tables} IN SHARE ROW EXCLUSIVE MODE")
            before, before_schema = snapshot(before_specs), schema_hash()
            call_command("migrate", interactive=False, verbosity=0, stdout=io.StringIO())
            if MigrationExecutor(connection).migration_plan(executor.loader.graph.leaf_nodes()):
                raise UpgradeRefused("pending_migrations_after_upgrade")
            assert_preserved(before, snapshot(before_specs, after=True))
            after_specs = current_specs()
            if set(before_specs) - set(after_specs):
                raise UpgradeRefused("historical_model_removed")
            for table, old in before_specs.items():
                added = set(after_specs[table]["columns"]) - set(old["columns"])
                if added - set(NEW_DEFAULTS.get(table, {})):
                    raise UpgradeRefused("unreviewed_historical_column")
            for table in set(after_specs) - set(before_specs):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT EXISTS (SELECT 1 FROM {connection.ops.quote_name(table)})"
                    )
                    if cursor.fetchone()[0]:
                        raise UpgradeRefused("unexpected_seed_data")
            report = dict(
                format=FORMAT,
                database=expected,
                migrations=len(actual["migrations"]),
                historical_models=len(before_specs),
                historical_rows=sum(row["count"] for row in before.values()),
                new_models=len(after_specs) - len(before_specs),
                preservation="exact_old_columns",
                microseconds_preserved=True,
                new_historical_defaults_checked=True,
                permanent_containers_added=0,
            )
            if rollback_probe:
                raise RollbackProbe
    except Exception as error:
        from django.contrib.contenttypes.models import ContentType

        ContentType.objects.clear_cache()
        if before is not None:
            try:
                assert_preserved(before, snapshot(before_specs))
                if schema_hash() != before_schema:
                    raise UpgradeRefused("rollback_schema_changed")
            except Exception:
                raise UpgradeRefused("rollback_not_verified") from None
            if isinstance(error, RollbackProbe):
                return dict(report, committed=False, rollback_schema_and_rows_verified=True)
            code = error.code if isinstance(error, UpgradeRefused) else "migration_or_gate_failed"
            raise UpgradeRefused(code, rollback_verified=True) from None
        raise
    finally:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(5263693, 5591111)")
        except Exception:
            connection.close()
    return dict(report, committed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "probe-rollback"))
    parser.add_argument("--database", required=True)
    parser.add_argument("--reviewed-plan", type=Path)
    parser.add_argument("--offline-ack", action="store_true")
    args = parser.parse_args()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    try:
        if args.action == "plan":
            report = make_plan(args.database)
        else:
            if args.reviewed_plan is None:
                raise UpgradeRefused("reviewed_plan_required")
            if str(args.reviewed_plan) == "-":
                raw = sys.stdin.buffer.read(65537)
                if len(raw) > 65536:
                    raise UpgradeRefused("reviewed_plan_too_large")
                approved = json.loads(raw)
            else:
                if args.reviewed_plan.stat().st_size > 65536:
                    raise UpgradeRefused("reviewed_plan_too_large")
                approved = json.loads(args.reviewed_plan.read_text())
            report = upgrade(
                args.database,
                approved,
                offline=args.offline_ack,
                rollback_probe=args.action == "probe-rollback",
            )
        print(json.dumps(report, sort_keys=True))
    except UpgradeRefused as error:
        print(
            json.dumps(
                dict(error=error.code, committed=False, rollback_verified=error.rollback_verified)
            ),
            flush=True,
        )
        raise SystemExit(1) from None
    except Exception as error:
        state = getattr(error.__cause__, "sqlstate", None) or getattr(error, "sqlstate", None)
        code = (
            state if isinstance(state, str) and re.fullmatch(r"[A-Z0-9]{5}", state) else "unknown"
        )
        raise SystemExit("upgrade_failed_rollback_required_check; sqlstate=" + code) from None


if __name__ == "__main__":
    main()
