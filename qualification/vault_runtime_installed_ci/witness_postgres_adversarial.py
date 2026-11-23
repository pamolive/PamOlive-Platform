"""Inert W01 PostgreSQL pair contracts: no driver, socket, PKI or SQL execution."""

import ast
import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ATTEMPTS = []


def fence(event, args):
    if event.startswith(("socket.", "subprocess.", "ctypes.", "sqlite3.")):
        ATTEMPTS.append(event)
        raise AssertionError("external execution forbidden")
    if event == "open" and len(args) > 2 and type(args[2]) is int:
        # O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND; this suite is read-only.
        if args[2] & (1 | 2 | 64 | 512 | 1024):
            ATTEMPTS.append("file_write")
            raise AssertionError("file mutation forbidden")


sys.addaudithook(fence)
SPEC = importlib.util.spec_from_file_location("_w01_pg_data", HERE / "lab/witness_postgres.py")
pg = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pg
SPEC.loader.exec_module(pg)

RUN = "0123456789abcdef"
SOURCES = {
    "witness": "components/usage-anchor/sql/schema.sql",
    "vault": "components/vault/runtime/sql/schema.sql",
    "mirror": "components/usage-anchor/sql/mirror.sql",
}
SCHEMAS = {name: (ROOT / path).read_bytes() for name, path in SOURCES.items()}


def inputs():
    credentials = {}
    tls = {}
    serial = 0
    for role in ("wpg", "vpg"):
        credentials[role] = {}
        for login in ("postgres", *pg.ROLES[role]):
            serial += 1
            credentials[role][login] = f"SYNTHETIC_ONLY_{serial:02d}".ljust(40, "x")
        tls[role] = {kind: f"-----BEGIN SYNTHETIC {role} {kind}-----\n"
                     f"inert-data-not-a-certificate\n-----END SYNTHETIC-----\n".encode("ascii")
                     for kind in ("ca", "certificate", "key")}
    return {"run_id": RUN,
            "databases": {role: f"w01_{RUN}_{role}" for role in pg.ROLES},
            "credentials": credentials, "tls": tls, "schemas": dict(SCHEMAS),
            "schema_pins": dict(pg.SCHEMA_PINS)}


def ready():
    pair = pg.prepare_pair(**inputs())
    for role in ("wpg", "vpg"):
        pair.accept_preflight(role, 0, f"W01_{RUN}_{role}_EMPTY\n".encode())
    return pair


def accept(pair, role):
    pair.accept_provision(role, 0, f"W01_{RUN}_{role}_PROVISIONED\n".encode())


class WitnessPostgresTests(unittest.TestCase):
    def test_01_exact_cluster_profiles_and_files(self):
        pair = pg.prepare_pair(**inputs())
        self.assertEqual(set(pair.clusters), {"wpg", "vpg"})
        for role, cluster in pair.clusters.items():
            self.assertEqual((cluster.hostname, cluster.address), pg.HOSTS[role])
            self.assertEqual((cluster.uid, cluster.gid, cluster.port), (999, 999, 5432))
            self.assertEqual(cluster.server_version, 170012)
            self.assertEqual(cluster.pgdata_mode, 0o700)
            self.assertEqual(cluster.pgdata_tmpfs_bytes, 256 * 1024 * 1024)
            self.assertEqual(set(cluster.files), {"ca.crt", "server.crt", "server.key",
                                                  "initial-password", "postgresql.conf",
                                                  "pg_hba.conf"})
            for name, value in cluster.files.items():
                self.assertEqual((value.uid, value.gid), (999, 999))
                self.assertEqual(value.mode, 0o400 if name in
                                 {"server.key", "initial-password"} else 0o444)
        with self.assertRaises(TypeError):
            pair.clusters["unknown"] = pair.clusters["wpg"]

    def test_02_separate_preflights_have_no_writes(self):
        pair = pg.prepare_pair(**inputs())
        for role in pair.clusters:
            script = pair.preflight_sql(role)
            self.assertIn(b"REPEATABLE READ READ ONLY", script)
            self.assertIn(b"current_user='postgres'", script)
            self.assertIn(b"oid=10 AND rolname='postgres'", script)
            for mutation in (b"CREATE ROLE", b"CREATE DATABASE", b"GRANT ", b"INSERT "):
                self.assertNotIn(mutation, script)
            self.assertIn(f"W01_{RUN}_{role}_EMPTY".encode(), script)

    def test_03_both_receipts_required_before_first_write(self):
        for received in ((), ("wpg",), ("vpg",)):
            with self.subTest(received=received):
                pair = pg.prepare_pair(**inputs())
                for role in received:
                    pair.accept_preflight(role, 0, f"W01_{RUN}_{role}_EMPTY\n".encode())
                with self.assertRaises(pg.Refused):
                    pair.take_provision("wpg")
                self.assertTrue(pair.failed)

    def test_04_order_and_success(self):
        pair = ready()
        for role in ("wpg", "vpg"):
            script = pair.take_provision(role)
            self.assertIn(b"REPEATABLE READ READ ONLY", script)
            self.assertIn(b"\\if :w01_blank\nCREATE ROLE", script)
            self.assertNotIn(b"IF NOT EXISTS", script)
            self.assertNotIn(b"DROP DATABASE", script)
            accept(pair, role)
        self.assertTrue(pair.complete)
        self.assertFalse(pair.failed)

    def test_05_wrong_order_and_double_take_are_terminal(self):
        pair = ready()
        with self.assertRaises(pg.Refused):
            pair.take_provision("vpg")
        self.assertTrue(pair.failed)
        pair = ready()
        pair.take_provision("wpg")
        with self.assertRaises(pg.Refused):
            pair.take_provision("wpg")
        self.assertTrue(pair.failed)

    def test_06_invalid_preflight_or_unknown_ack_fail_closed(self):
        for code, output in ((True, b""), (None, b""), (1, b""), (0, pg.REFUSED),
                             (0, f"W01_{RUN}_vpg_EMPTY\n".encode()),
                             (0, f"W01_{RUN}_wpg_EMPTY\nextra".encode())):
            with self.subTest(code=code):
                pair = pg.prepare_pair(**inputs())
                with self.assertRaises(pg.Refused):
                    pair.accept_preflight("wpg", code, output)
                self.assertTrue(pair.failed)
                with self.assertRaises(pg.Refused):
                    pair.accept_preflight("wpg", 0, f"W01_{RUN}_wpg_EMPTY\n".encode())

    def test_07_partial_provision_never_repairs_or_rearms(self):
        pair = ready()
        pair.take_provision("wpg")
        accept(pair, "wpg")
        pair.take_provision("vpg")
        with self.assertRaises(pg.Refused):
            pair.accept_provision("vpg", None, b"")
        self.assertTrue(pair.failed)
        self.assertFalse(pair.complete)
        for role in ("wpg", "vpg"):
            with self.assertRaises(pg.Refused):
                pair.take_provision(role)

    def test_08_explicit_abort_is_irreversible(self):
        pair = ready()
        pair.abort()
        with self.assertRaises(pg.Refused):
            pair.take_provision("wpg")
        self.assertFalse(pair.complete)

    def test_09_replayed_preflight_receipt_is_refused(self):
        pair = ready()
        with self.assertRaises(pg.Refused):
            pair.accept_preflight("wpg", 0, f"W01_{RUN}_wpg_EMPTY\n".encode())
        self.assertTrue(pair.failed)

    def test_10_schema_bytes_and_external_pins_both_required(self):
        for name in SCHEMAS:
            for change_pin in (False, True):
                value = inputs()
                value["schemas"][name] += b"\n-- changed\n"
                if change_pin:
                    value["schema_pins"][name] = pg.hashlib.sha256(
                        value["schemas"][name]).hexdigest()
                with self.assertRaises(pg.Refused):
                    pg.prepare_pair(**value)

    def test_11_roles_and_ddl_are_exact(self):
        pair = ready()
        wsql = pair.take_provision("wpg")
        accept(pair, "wpg")
        vsql = pair.take_provision("vpg")
        self.assertIn(SCHEMAS["witness"], wsql)
        self.assertNotIn(SCHEMAS["vault"], wsql)
        self.assertIn(SCHEMAS["vault"], vsql)
        self.assertIn(SCHEMAS["mirror"], vsql)
        for role, script in (("wpg", wsql), ("vpg", vsql)):
            self.assertIn(
                f'CREATE ROLE "{pg.OWNERS[role]}" NOLOGIN {pg.ROLE_FLAGS};'.encode(), script)
            for login in pg.ROLES[role]:
                self.assertIn(
                    f'CREATE ROLE "{login}" LOGIN {pg.ROLE_FLAGS} PASSWORD '.encode(), script)
            grants = [line for line in script.splitlines() if line.startswith(b'GRANT "')]
            self.assertEqual(
                grants, [f'GRANT "{pg.OWNERS[role]}" TO "{pg.ROLES[role][1]}";'.encode()])
        self.assertIn(
            b"GRANT SELECT ON ALL TABLES IN SCHEMA pam_usage_anchor TO usage_anchor_observer", wsql)

    def test_12_hba_scopes_and_postgres_never_remote(self):
        pair = pg.prepare_pair(**inputs())
        for role, cluster in pair.clusters.items():
            hba = cluster.files["pg_hba.conf"].raw.decode()
            self.assertIn("local postgres postgres peer\n", hba)
            self.assertIn("local all all reject\n", hba)
            remote = [line for line in hba.splitlines() if line.startswith("hostssl ")]
            self.assertFalse(any(" postgres " in line for line in remote))
            self.assertEqual(len(remote), len(pg.ROLES[role]) + 1)
            for login in pg.ROLES[role]:
                self.assertIn(
                    f"hostssl {cluster.database} {login} 10.253.249.4/32 scram-sha-256", remote)
            ip = "10.253.249.3" if role == "wpg" else "10.253.249.6"
            self.assertIn(
                f"hostssl {cluster.database} {pg.ROLES[role][0]} {ip}/32 scram-sha-256", remote)
            self.assertTrue(
                hba.endswith("host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"))

    def test_13_destination_and_run_aliases_refused(self):
        for bad in ("", "ABCDEF0123456789", "0" * 15, "../synthetic", 123):
            value = inputs()
            value["run_id"] = bad
            with self.assertRaises(pg.Refused):
                pg.prepare_pair(**value)
        for bad in ("postgres", f"w01_{RUN}_vpg", "other;DROP DATABASE existing"):
            value = inputs()
            value["databases"]["wpg"] = bad
            with self.assertRaises(pg.Refused):
                pg.prepare_pair(**value)

    def test_14_passwords_are_explicit_distinct_and_sql_safe(self):
        for bad in ("", "short", "x'" * 32, "A" * 31 + "\n", b"A" * 40):
            value = inputs()
            value["credentials"]["wpg"]["usage_anchor_runtime"] = bad
            with self.assertRaises(pg.Refused):
                pg.prepare_pair(**value)
        value = inputs()
        value["credentials"]["wpg"]["usage_anchor_runtime"] = (
            value["credentials"]["vpg"]["vault_n0_runtime"])
        with self.assertRaises(pg.Refused):
            pg.prepare_pair(**value)

    def test_15_missing_extra_or_shared_inputs_refused(self):
        for field in ("databases", "credentials", "tls", "schemas", "schema_pins"):
            value = inputs()
            value[field]["unexpected"] = b"inert"
            with self.assertRaises(pg.Refused):
                pg.prepare_pair(**value)
        value = inputs()
        value["tls"]["vpg"] = copy.deepcopy(value["tls"]["wpg"])
        with self.assertRaises(pg.Refused):
            pg.prepare_pair(**value)

    def test_16_input_mutation_cannot_rewrite_generated_scripts(self):
        value = inputs()
        pair = pg.prepare_pair(**value)
        value["credentials"]["wpg"]["usage_anchor_runtime"] = "later".ljust(40, "x")
        value["schemas"]["witness"] = b"changed"
        for role in ("wpg", "vpg"):
            pair.accept_preflight(role, 0, f"W01_{RUN}_{role}_EMPTY\n".encode())
        script = pair.take_provision("wpg")
        self.assertIn(SCHEMAS["witness"], script)
        self.assertNotIn(b"'later", script)

    def test_17_exec_is_local_exact_and_not_executed(self):
        args = pg.exec_args("a" * 64)
        self.assertEqual(args[:5], ("exec", "--interactive", "--user", "999:999", "a" * 64))
        self.assertIn("-U postgres -d postgres -f -", args[-1])
        self.assertIn("-h /var/run/postgresql", args[-1])
        self.assertNotIn("PGPASSWORD", args[-1])
        for bad in ("", "a" * 63, "a" * 64 + ";", "CID", None):
            with self.assertRaises(pg.Refused):
                pg.exec_args(bad)

    def test_18_guard_preserves_installed_bootstrap_checks(self):
        tree = ast.parse((HERE / "lab/pg_bootstrap.py").read_text(encoding="utf-8"))
        original = next(ast.literal_eval(node.value) for node in tree.body
                        if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "CHECK_BLANK"
                                for target in node.targets))
        expected = original.split(b"\\if :pamolive_empty", 1)[0]
        expected = expected.replace(b"vault_n0_admin", b"postgres").replace(
            b"pamolive_empty", b"w01_blank")
        actual = pg._blank_guard()
        for extra in (b" AND current_setting('port')='5432'\n",
                      b" AND current_setting('synchronous_commit')='on'\n"):
            actual = actual.replace(extra, b"")
        actual = actual.replace(b" AND current_setting('fsync')='on'", b"")
        self.assertEqual(b"".join(actual.split()), b"".join(expected.split()))

    def test_19_private_repr_has_no_material(self):
        value = inputs()
        pair = pg.prepare_pair(**value)
        representations = (repr(pair) + repr(pair.clusters["wpg"])
                           + repr(pair.clusters["wpg"].files["server.key"]))
        self.assertNotIn(value["credentials"]["wpg"]["postgres"], representations)
        self.assertNotIn("inert-data-not-a-certificate", representations)

    def test_20_pinned_observer_hba_is_opt_in_and_witness_only(self):
        plain = pg.prepare_pair(**inputs())
        recovery = pg.prepare_pair(**inputs(), recovery=True)
        for role in pg.ROLES:
            baseline = plain.clusters[role].files["pg_hba.conf"].raw
            selected = recovery.clusters[role].files["pg_hba.conf"].raw
            if role == "wpg":
                rule = (f"hostssl w01_{RUN}_wpg usage_anchor_observer"
                        " 10.253.249.3/32 scram-sha-256\n").encode("ascii")
                self.assertNotIn(rule, baseline)
                self.assertIn(rule, selected)
                self.assertEqual(selected.replace(rule, b"", 1), baseline)
            else:
                self.assertEqual(selected, baseline)
        with self.assertRaises(pg.Refused):
            pg.prepare_pair(**inputs(), recovery=1)

    def test_21_restore_rules_scope_an_explicit_clone_to_the_observer(self):
        recovery = pg.prepare_pair(**inputs(), recovery=True)
        restored = pg.prepare_pair(**inputs(), recovery=True, restore_witness=True)
        clone = f"w01_{RUN}_wpg_restored"
        self.assertEqual(pg.restore_database(RUN), clone)
        source_rules = recovery.clusters["wpg"].files["pg_hba.conf"].raw.splitlines()
        restore_rules = restored.clusters["wpg"].files["pg_hba.conf"].raw.splitlines()
        added = [line for line in restore_rules if line not in source_rules]
        self.assertEqual(
            [line.decode("ascii") for line in added],
            [
                f"local {clone} postgres peer",
                f"hostssl {clone} usage_anchor_observer 10.253.249.3/32 scram-sha-256",
                f"hostssl {clone} usage_anchor_observer 10.253.249.4/32 scram-sha-256",
            ],
        )
        self.assertEqual([line for line in restore_rules if line not in added], source_rules)
        self.assertLess(restore_rules.index(added[0]), restore_rules.index(b"local all all reject"))
        self.assertLess(restore_rules.index(added[2]),
                        restore_rules.index(b"host all all 0.0.0.0/0 reject"))
        self.assertEqual(restored.clusters["vpg"].files, recovery.clusters["vpg"].files)
        self.assertEqual(restored.preflight_sql("wpg"), recovery.preflight_sql("wpg"))

    def test_22_restore_rejects_an_implicit_profile_or_invalid_destination(self):
        for args in ({"restore_witness": True}, {"recovery": True, "restore_witness": 1}):
            with self.subTest(args=args), self.assertRaises(pg.Refused):
                pg.prepare_pair(**inputs(), **args)
        for run in (None, "other", RUN.upper(), RUN + " "):
            with self.subTest(run=run), self.assertRaises(pg.Refused):
                pg.restore_database(run)

    def test_23_restore_client_rules_do_not_replace_either_cluster_endpoint(self):
        restored = pg.prepare_pair(**inputs(), recovery=True, restore_witness=True)
        for role, cluster in restored.clusters.items():
            with self.subTest(role=role):
                self.assertEqual((cluster.hostname, cluster.address), pg.HOSTS[role])
                self.assertEqual(cluster.database, f"w01_{RUN}_{role}")

    def test_24_separate_restore_hba_exposes_only_the_exact_observer_route(self):
        target_passwords = {"postgres": "p" * 40, "usage_anchor_observer": "o" * 40}
        cluster = pg.prepare_restore_cluster(
            RUN, credentials=target_passwords, tls=inputs()["tls"]["wpg"]
        )
        database = pg.restore_database(RUN)
        self.assertEqual((cluster.hostname, cluster.address), pg.RESTORE_HOST)
        self.assertEqual(cluster.database, database)
        self.assertEqual(cluster.role, "wpr")
        self.assertEqual(
            cluster.files["pg_hba.conf"].raw.decode().splitlines(),
            [
                "local postgres postgres peer",
                f"local {database} postgres peer",
                "local all all reject",
                f"hostssl {database} usage_anchor_observer 10.253.249.3/32 scram-sha-256",
                f"hostssl {database} usage_anchor_observer 10.253.249.4/32 scram-sha-256",
                "host all all 0.0.0.0/0 reject",
                "host all all ::/0 reject",
            ],
        )
        self.assertIn(b"listen_addresses='10.253.249.7'\n", cluster.files["postgresql.conf"].raw)
        self.assertNotIn(target_passwords["usage_anchor_observer"].encode(),
                         b"".join(file.raw for file in cluster.files.values()))

    def test_25_separate_restore_role_script_is_blank_guarded_and_schema_free(self):
        target_passwords = {"postgres": "p" * 40, "usage_anchor_observer": "o" * 40}
        tls = inputs()["tls"]["wpg"]
        cluster = pg.prepare_restore_cluster(RUN, credentials=target_passwords, tls=tls)
        preflight, provision = pg.restore_cluster_scripts(
            RUN, cluster, target_passwords["usage_anchor_observer"]
        )
        self.assertTrue(provision.startswith(pg._blank_guard() + b"\\if :w01_blank\n"))
        self.assertIn(f"W01_{RUN}_wpr_EMPTY".encode(), preflight)
        self.assertIn(f"W01_{RUN}_wpr_PROVISIONED".encode(), provision)
        self.assertNotIn(b"CREATE ROLE", preflight)
        self.assertNotIn(b"GRANT ", provision)
        self.assertNotIn(b"CREATE DATABASE", provision)
        self.assertNotIn(b"CREATE SCHEMA", provision)
        self.assertNotIn(target_passwords["postgres"].encode(), provision)
        self.assertIn(b'CREATE ROLE "usage_anchor_observer" LOGIN ', provision)
        for role in {pg.OWNERS["wpg"], *pg.ROLES["wpg"]} - {"usage_anchor_observer"}:
            self.assertIn(f'CREATE ROLE "{role}" NOLOGIN '.encode(), provision)
        reused = dict.fromkeys(target_passwords, target_passwords["postgres"])
        with self.assertRaises(pg.Refused):
            pg.prepare_restore_cluster(RUN, credentials=reused, tls=tls)

    def test_26_pitr_archive_only_changes_the_witness_source(self):
        baseline = pg.prepare_pair(**inputs(), recovery=True)
        pitr = pg.prepare_pair(**inputs(), recovery=True, pitr=True)
        source = pitr.clusters["wpg"].files
        original = baseline.clusters["wpg"].files
        self.assertEqual(
            source["postgresql.conf"].raw,
            original["postgresql.conf"].raw + pg.PITR_SOURCE.encode("ascii"),
        )
        self.assertIn(b'"/backup/wal/%f"', source["postgresql.conf"].raw)
        self.assertIn(b'cmp -s "%p" "$dst" && sync -f /backup/wal', source["postgresql.conf"].raw)
        self.assertIn(b"wal_keep_size='64MB'\n", source["postgresql.conf"].raw)
        peer = b"local replication postgres peer\n"
        hba = source["pg_hba.conf"].raw
        self.assertEqual(hba.replace(peer, b""), original["pg_hba.conf"].raw)
        self.assertLess(hba.index(peer), hba.index(b"local all all reject"))
        self.assertEqual(pitr.clusters["vpg"].files, baseline.clusters["vpg"].files)
        with self.assertRaises(pg.Refused):
            pg.prepare_pair(**inputs(), pitr=True)
        with self.assertRaises(pg.Refused):
            pg.prepare_pair(**inputs(), recovery=True, restore_witness=True, pitr=True)

    def test_27_pitr_target_keeps_observer_only_hba_and_promotes_at_named_point(self):
        parameters = {
            "credentials": {"postgres": "p" * 40, "usage_anchor_observer": "o" * 40},
            "tls": inputs()["tls"]["wpg"],
        }
        logical = pg.prepare_restore_cluster(RUN, **parameters)
        physical = pg.prepare_restore_cluster(RUN, **parameters, pitr=True)
        self.assertEqual(physical.files["pg_hba.conf"].raw, logical.files["pg_hba.conf"].raw)
        config = physical.files["postgresql.conf"].raw
        self.assertIn(b'restore_command=\'cp "/backup/wal/%f" "%p"\'\n', config)
        self.assertIn(b"recovery_target_name='pamolive_w01_closed'\n", config)
        self.assertIn(b"recovery_target_action='promote'\n", config)
        self.assertNotIn(b"local replication ", physical.files["pg_hba.conf"].raw)
        with self.assertRaises(pg.Refused):
            pg.restore_cluster_scripts(RUN, physical, "a" * 40)
        with self.assertRaises(pg.Refused):
            pg.restrict_physical_restore(RUN, logical, "a" * 40)

    def test_28_pitr_restriction_requires_promoted_peer_and_retires_old_logins(self):
        passwords = {"postgres": "p" * 40, "usage_anchor_observer": "o" * 40}
        cluster = pg.prepare_restore_cluster(
            RUN, credentials=passwords, tls=inputs()["tls"]["wpg"], pitr=True
        )
        script = pg.restrict_physical_restore(RUN, cluster, passwords["usage_anchor_observer"])
        self.assertIn(b"inet_server_addr() IS NULL AND NOT pg_is_in_recovery()", script)
        self.assertIn(b"current_setting('listen_addresses')='10.253.249.7'", script)
        self.assertIn(b"\\if :w01_pitr_restrict\nREVOKE ALL PRIVILEGES ON DATABASE", script)
        self.assertIn(b'REVOKE "usage_anchor_owner" FROM "usage_anchor_admin";', script)
        for role in set(pg.ROLES["wpg"]) - {"usage_anchor_observer"}:
            self.assertIn(f'ALTER ROLE "{role}" NOLOGIN PASSWORD NULL;'.encode(), script)
        self.assertIn(b"ALTER ROLE postgres PASSWORD NULL;", script)
        self.assertNotIn(b'ALTER ROLE "usage_anchor_observer" NOLOGIN', script)
        self.assertIn(passwords["usage_anchor_observer"].encode(), script)
        self.assertNotIn(passwords["postgres"].encode(), script)
        self.assertIn(
            f'ALTER DATABASE "w01_{RUN}_wpg" RENAME TO "w01_{RUN}_wpg_restored";'.encode(),
            script,
        )
        self.assertIn(f"COMMIT;\n\\echo W01_{RUN}_wpr_PITR_RESTRICTED\n".encode(), script)
        self.assertIn(b"\\else\nROLLBACK;\n\\echo W01_CLUSTER_REFUSED", script)
        self.assertNotIn(b"CREATE SCHEMA", script)
        self.assertNotIn(b"GRANT ", script)


def main():
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(WitnessPostgresTests).run(result)
    report = {"schema": "pamolive.w01-postgres-inert-tests/1", "tests": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "skips": len(result.skipped), "external_attempts": ATTEMPTS,
              "native_lab_executed": False}
    print(json.dumps(report, separators=(",", ":")))
    if not result.wasSuccessful():
        # All material in this suite is explicit inert DATA, never real secrets.
        for test, detail in result.errors + result.failures:
            print(test.id(), detail)
    return 0 if result.wasSuccessful() and not result.skipped and not ATTEMPTS else 1


if __name__ == "__main__":
    raise SystemExit(main())
