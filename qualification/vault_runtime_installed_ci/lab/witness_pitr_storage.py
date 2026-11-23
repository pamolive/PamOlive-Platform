"""Qualify a physical, named-point PostgreSQL recovery in the owned W01 lab."""

import re
import time
from dataclasses import dataclass

from lab.restore_sql import check_result, need
from lab.witness_postgres import restore_database
from lab.witness_restore_storage import (
    LOCAL,
    MAX_ARCHIVE,
    NONLOGIN_ROLES,
    OBSERVER,
    PSQL,
    TABLES,
    _WitnessPostgres,
    context,
    observer_grants,
    source_guard,
)

RESTORE_POINT = "pamolive_w01_closed"
COPY_READY = b"W01_PITR_COPY_READY\n"
PG_BIN = "/usr/lib/postgresql/17/bin/"
COPY_COMMAND = r"""
umask 077
base=/backup/base
data=/var/lib/postgresql/data
test -d "$base"
test ! -L "$base"
test -d "$data"
test ! -L "$data"
test "$(stat -c '%u:%g:%a' -- "$data")" = 999:999:700
test -z "$(find "$data" -mindepth 1 -maxdepth 1 -print -quit)"
test -z "$(find "$base" -xdev ! -type d ! -type f -print -quit)"
test "$(du -skx -- "$base" | cut -f1)" -le 262144
test "$(cat "$base/PG_VERSION")" = 17
test -f "$base/backup_label"
test -f "$base/backup_manifest"
test ! -e "$base/recovery.signal"
test ! -e "$base/standby.signal"
/usr/lib/postgresql/17/bin/pg_verifybackup --exit-on-error --quiet "$base"
cp -a --no-preserve=ownership -- "$base/." "$data/"
(set -C; : > "$data/recovery.signal")
sync -f "$data"
printf '%s\n' W01_PITR_COPY_READY
""".strip()
BASE_CHECK = r"""
test -d /backup
test ! -L /backup
test "$(stat -c '%u:%g:%a' -- /backup)" = 999:999:700
test -d /backup/wal
test ! -L /backup/wal
test "$(stat -c '%u:%g:%a' -- /backup/wal)" = 999:999:700
test ! -e /backup/base
test ! -L /backup/base
test "$(du -skx -- /backup/wal | cut -f1)" -le 131072
"""
ARCHIVE_WAIT = b"W01_PITR_ARCHIVE_WAIT\n"
ARCHIVE_READY = b"W01_PITR_ARCHIVE_READY\n"
ARCHIVE_CHECK = r"""
test "$(du -skx -- /backup/wal | cut -f1)" -le 131072
for name do
    archived=/backup/wal/$name
    original=/var/lib/postgresql/data/pg_wal/$name
    test ! -L "$archived"
    if test ! -e "$archived"; then
        printf '%s\n' W01_PITR_ARCHIVE_WAIT
        exit 0
    fi
    test -f "$archived"
    test -f "$original"
    test ! -L "$original"
    test "$(stat -c %s -- "$archived")" = 16777216
    cmp -s -- "$original" "$archived"
done
printf '%s\n' W01_PITR_ARCHIVE_READY
"""
LSN = rb"[0-9A-F]{1,8}/[0-9A-F]{1,8}"
WAL = rb"[0-9A-F]{24}"
POINT_RECEIPT = re.compile(rb"(" + LSN + rb")\|(" + LSN + rb")\|(" + WAL + rb")\|(" + WAL + rb")\n")


class PitrRefused(ValueError):
    """Report only the fixed failed phase to the public controller."""

    def __init__(self, phase):
        super().__init__("witness_pitr_refused")
        self.phase = phase


@dataclass(frozen=True, slots=True, repr=False)
class _PitrBase:
    reservation: str
    source_cid: str
    system_identifier: bytes
    timeline: int


class _PitrPostgres(_WitnessPostgres):
    def execute(self, argv, *, data=None, cap=8192, timeout=9):
        result = self.lab.exec(
            self.item, self.spec, *LOCAL, *argv, data=data, timeout=timeout, stdout_cap=cap,
            stdin_cap=MAX_ARCHIVE,
        )
        check_result(result, cap)
        need(result.stderr == b"")
        return result.stdout


def _run_names(lab, run_id):
    restored = restore_database(run_id)
    original = f"w01_{run_id}_wpg"
    need(restored == original + "_restored")
    need(re.fullmatch(r"pv-[0-9a-f]{32}", lab.reservation))
    need(run_id == lab.reservation[3:19])
    return original, restored


def _timeline(cluster):
    value = cluster.sql("postgres", "SELECT timeline_id FROM pg_control_checkpoint();\n")
    need(re.fullmatch(rb"[1-9][0-9]{0,9}\n", value))
    return int(value)


def _setup_control(original):
    empty = "\n AND ".join(f"NOT EXISTS(SELECT FROM pam_usage_anchor.{table})" for table in TABLES)
    return rf"""
BEGIN;
SET LOCAL search_path=pg_catalog;
SELECT (({context(original)}) AND
  current_setting('archive_mode')='on'
  AND current_setting('synchronous_commit')='on'
  AND pg_size_bytes(current_setting('wal_segment_size'))=16777216
  AND NOT EXISTS(SELECT FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global'))
  AND to_regnamespace('w01_pitr_control') IS NULL
  AND {empty}
) IS TRUE AS w01_setup \gset
\if :w01_setup
CREATE SCHEMA w01_pitr_control AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA w01_pitr_control FROM PUBLIC;
CREATE TABLE w01_pitr_control.markers (
 name text PRIMARY KEY CHECK(name IN ('included','excluded'))
);
\echo W01_PITR_CONTROL_READY
\endif
COMMIT;
"""


def take_pitr_base(lab, source_item, source_spec, run_id):
    """Back up the schema before the witness driver writes any evidence."""
    phase = "inputs"
    try:
        original, restored = _run_names(lab, run_id)
        source = _PitrPostgres(lab, source_item, source_spec, "w-postgres")
        phase = "base_control"
        need(source.sql("postgres", source_guard(original, restored)) == b"W01_TARGET_ABSENT\n")
        identity = source.cluster_id()
        timeline = _timeline(source)
        need(timeline == 1)
        need(source.sql(original, _setup_control(original), read_only=False)
             == b"W01_PITR_CONTROL_READY\n")

        phase = "base_backup"
        need(source.execute(("/bin/sh", "-ec", BASE_CHECK)) == b"")
        need(source.execute((
            PG_BIN + "pg_basebackup", "--host=/var/run/postgresql", "--port=5432",
            "--username=postgres",
            "--no-password", "--pgdata=/backup/base", "--format=plain", "--wal-method=stream",
            "--checkpoint=fast", "--manifest-checksums=SHA256",
        ), timeout=55) == b"")

        phase = "base_verify"
        verify = (PG_BIN + "pg_verifybackup", "--exit-on-error", "--quiet", "/backup/base")
        need(source.execute(verify, timeout=35) == b"")
        return _PitrBase(lab.reservation, source_item["identity"], identity, timeline)
    except Exception:
        raise PitrRefused(phase) from None


def _take_restore_point(original):
    return rf"""
SELECT (({context(original)}) AND
  current_setting('archive_mode')='on'
  AND current_setting('synchronous_commit')='on'
  AND NOT EXISTS(SELECT FROM w01_pitr_control.markers)
  AND EXISTS(SELECT FROM pam_usage_anchor.contexts WHERE serving_state='closed')
  AND EXISTS(SELECT FROM pam_usage_anchor.leases WHERE serving_state='closed' AND epoch>1)
) IS TRUE AS w01_point_allowed \gset
\if :w01_point_allowed
INSERT INTO w01_pitr_control.markers(name) VALUES('included');
SELECT pg_create_restore_point('{RESTORE_POINT}') AS w01_point \gset
INSERT INTO w01_pitr_control.markers(name) VALUES('excluded');
SELECT pg_current_wal_insert_lsn() AS w01_late \gset
SELECT concat_ws('|', :'w01_point', :'w01_late',
                 pg_walfile_name(:'w01_point'), pg_walfile_name(:'w01_late'))
WHERE :'w01_late'::pg_lsn > :'w01_point'::pg_lsn
 AND (SELECT array_agg(name ORDER BY name COLLATE "C") FROM w01_pitr_control.markers)
     = ARRAY['excluded','included'];
SELECT pg_switch_wal() AS w01_switch \gset
\endif
"""


def _lsn_number(value):
    high, low = value.split(b"/")
    return (int(high, 16) << 32) + int(low, 16)


def _wait_archive(source, segments):
    deadline = time.monotonic() + 35
    args = ("/bin/sh", "-ec", ARCHIVE_CHECK, "witness-archive", *dict.fromkeys(segments))
    while time.monotonic() < deadline:
        result = source.execute(args, timeout=7)
        if result == ARCHIVE_READY:
            return
        need(result == ARCHIVE_WAIT)
        time.sleep(0.2)
    need(False)


def _replay_check(point, later):
    return rf"""
SELECT (({context('postgres')}) AND current_setting('recovery_target_name')='{RESTORE_POINT}'
 AND pg_last_wal_replay_lsn()='{point}'::pg_lsn
 AND pg_last_wal_replay_lsn()<'{later}'::pg_lsn) IS TRUE AS w01_exact_replay \gset
\if :w01_exact_replay
CHECKPOINT;
\echo W01_PITR_REPLAYED
\endif
"""


def _restricted_catalog(restored):
    names = ", ".join(f"'{role}'" for role in NONLOGIN_ROLES)
    return f"""
SELECT 'W01_PITR_LOGIN_RESTRICTED' WHERE
 ARRAY(SELECT rolname::text FROM pg_roles WHERE rolcanlogin
       ORDER BY rolname::text COLLATE "C")=ARRAY['postgres','{OBSERVER}']
 AND ARRAY(SELECT rolname::text FROM pg_roles
           WHERE rolname IN ({names}) AND NOT rolcanlogin
           ORDER BY rolname::text COLLATE "C")=ARRAY[{names}]
 AND NOT EXISTS(
   SELECT FROM pg_roles WHERE rolname IN ({names},'{OBSERVER}')
     AND (rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
       OR EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid OR roleid=pg_roles.oid))
 )
 AND NOT EXISTS(SELECT FROM pg_authid WHERE rolname IN ({names},'postgres')
                AND rolpassword IS NOT NULL)
 AND EXISTS(SELECT FROM pg_authid WHERE rolname='{OBSERVER}'
            AND rolpassword LIKE 'SCRAM-SHA-256$%')
 AND NOT EXISTS(
   SELECT FROM pg_roles WHERE rolname IN ({names},'{OBSERVER}')
     AND rolname<>'{OBSERVER}' AND rolname<>'usage_anchor_owner'
     AND has_database_privilege(oid, '{restored}', 'CONNECT')
 );
"""


def finish_witness_pitr(
    lab, source_item, source_spec, target_item, target_spec, run_id, *,
    base, switch_clusters, role_sql,
):
    """Recover closed witness evidence and prove an archived later commit was excluded."""
    phase = "inputs"
    try:
        original, restored = _run_names(lab, run_id)
        source = _PitrPostgres(lab, source_item, source_spec, "w-postgres")
        target = _PitrPostgres(lab, target_item, target_spec, "w-postgres-restore")
        need(source_item["identity"] != target_item["identity"])
        need(type(base) is _PitrBase and callable(switch_clusters))
        need(base.reservation == lab.reservation and base.source_cid == source_item["identity"])
        need(type(role_sql) is bytes and 0 < len(role_sql) <= 128 * 1024 and role_sql.isascii())
        target.inactive("created")

        phase = "source"
        need(source.cluster_id() == base.system_identifier and _timeline(source) == base.timeline)
        before = source.snapshot(original)

        phase = "restore_point"
        row = source.sql(original, _take_restore_point(original), read_only=False)
        point = POINT_RECEIPT.fullmatch(row)
        need(point is not None)
        before_lsn, after_lsn, before_wal, after_wal = point.groups()
        need(_lsn_number(before_lsn) < _lsn_number(after_lsn))
        files = before_wal, after_wal
        need(all(int(name[:8], 16) == base.timeline for name in files))

        phase = "wal_archive"
        _wait_archive(source, tuple(name.decode("ascii") for name in files))
        need(source.snapshot(original) == before)

        phase = "cutoff"
        target.inactive("created")
        switch_clusters()
        source.inactive("exited")

        phase = "replay"
        check = _replay_check(before_lsn.decode("ascii"), after_lsn.decode("ascii"))
        need(target.sql("postgres", check, read_only=False) == b"W01_PITR_REPLAYED\n")
        need(target.cluster_id() == base.system_identifier)
        need(_timeline(target) == base.timeline + 1)

        phase = "restrict"
        provisioned = target.execute((*PSQL, "-d", "postgres", "-f", "-"), data=role_sql)
        need(provisioned == f"W01_{run_id}_wpr_PITR_RESTRICTED\n".encode("ascii"))

        phase = "verify"
        marker = """
SELECT 'W01_PITR_MARKERS_EXACT' WHERE
 (SELECT array_agg(name) FROM w01_pitr_control.markers)=ARRAY['included'];
"""
        need(target.sql(restored, marker) == b"W01_PITR_MARKERS_EXACT\n")
        need(target.snapshot(restored) == before)
        need(target.sql("postgres", source_guard(restored, original)) == b"W01_TARGET_ABSENT\n")
        need(target.sql(restored, observer_grants(restored)) == b"W01_TARGET_READ_ONLY\n")
        need(target.sql(restored, _restricted_catalog(restored)) == b"W01_PITR_LOGIN_RESTRICTED\n")
        source.inactive("exited")
        return {
            "base_backup_verified": True,
            "wal_archived": True,
            "named_point_recovered": True,
            "post_target_write_excluded": True,
            "physical_identity_preserved": True,
            "timeline_advanced": True,
            "source_cluster_unavailable": True,
            "history_and_state_preserved": True,
            "read_only_grants_verified": True,
        }
    except Exception:
        raise PitrRefused(phase) from None
