"""Prepare role mounts for one offline, disposable W01 laboratory."""

import argparse
import base64
import json
import os
import re
import secrets
import stat
import sys
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path

from support import read_regular, sha

from . import role_files, witness_postgres

WORK = Path("/work")
SOURCE_LEDGER = Path("/witness/witness-source.sha256")
INSTALLED = Path("/opt/vault/share/pamolive")
SCHEMAS = {
    "witness": INSTALLED / "usage-anchor/schema.sql",
    "vault": INSTALLED / "vault-reservation/schema.sql",
    "mirror": Path("/witness/fixtures/sql/mirror.sql"),
}
POSTGRES = {"wpg": "w-postgres", "vpg": "v-postgres"}
RESTORE_POSTGRES = "w-postgres-restore"
PITR_VOLUMES = ("w-pitr-archive", "w-pitr-data")
OBSERVER = "usage_anchor_observer"
WITNESS_FILES = {
    "slot.json": role_files.PUBLIC,
    "materials.bin": role_files.PUBLIC,
    "server.crt": role_files.PUBLIC,
    "server.key": role_files.KEY,
    "ca.crt": role_files.PUBLIC,
}
RUNTIME_FILES = {"runtime.json": role_files.KEY, "sql-ca.crt": role_files.PUBLIC}
RECOVERY_ROLE = "witness-recovery"
RESTORE_ROLE = "witness-restored"
HISTORY_MOUNTS = {RECOVERY_ROLE: "recovery_mount", RESTORE_ROLE: "restore_mount"}
RECOVERY_TLS_SLOT = {
    name: attributes for name, attributes in WITNESS_FILES.items() if name != "materials.bin"
}
MOUNTS = {
    **dict.fromkeys(
        (*POSTGRES.values(), RESTORE_POSTGRES),
        {
            **dict.fromkeys(
                ("ca.crt", "server.crt", "postgresql.conf", "pg_hba.conf"), (0o444, 999, 999)
            ),
            **dict.fromkeys(("server.key", "initial-password"), (0o400, 999, 999)),
        },
    ),
    "driver": {
        "driver.json": role_files.KEY,
        "wpg-ca.crt": role_files.PUBLIC,
        "vpg-ca.crt": role_files.PUBLIC,
    },
    "vault": RUNTIME_FILES,
    "witness": {**RUNTIME_FILES, **WITNESS_FILES, "bindings.json": role_files.PUBLIC},
    **dict.fromkeys(
        HISTORY_MOUNTS, {**RUNTIME_FILES, **RECOVERY_TLS_SLOT, "bindings.json": role_files.PUBLIC}
    ),
}
CAP = 256 * 1024


class Refused(ValueError):
    def __init__(self):
        super().__init__("witness_preparation_refused")


def need(condition):
    if not condition:
        raise Refused()


def kernel_check():
    need(os.getuid() == os.getgid() == 0 and sys.flags.isolated and sys.dont_write_bytecode)
    with Path("/proc/self/status").open("rb") as stream:
        raw = stream.read(65537)
    need(len(raw) <= 65536)
    values = dict(line.split(":", 1) for line in raw.decode("ascii").splitlines() if ":" in line)
    need(values["Uid"].split() == values["Gid"].split() == ["0"] * 4)
    need(values["NoNewPrivs"].strip() == "1" and values["Seccomp"].strip() == "2")
    need(set(values["Groups"].split()) <= {"0"})
    for capability in ("CapEff", "CapPrm", "CapBnd"):
        need(int(values[capability], 16) == 1)  # CAP_CHOWN
    need(int(values["CapInh"], 16) == int(values["CapAmb"], 16) == 0)


def encode(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        + b"\n"
    )


def canonical(raw, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum and raw.isascii())
    value = json.loads(raw)
    # Re-encoding also rejects duplicate fields, since the parser collapses them.
    need(raw == encode(value))
    return value


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def unb64(value, maximum):
    need(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3))
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise Refused() from None
    need(0 < len(decoded) <= maximum and b64(decoded) == value)
    return decoded


def certificate_pair(hostname, now):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    # PostgreSQL 17.12's SCRAM channel binding needs a digest from the
    # certificate signature algorithm. ECDSA signs with explicit SHA-256.
    ca_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic " + hostname + " CA")])

    def builder(name, key, ca):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=2 if ca else 1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
            .add_extension(
                x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False), True
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
            )
        )

    ca = builder(ca_name, ca_key, True).sign(ca_key, hashes.SHA256())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    leaf = (
        builder(name, server_key, False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(ca_key, hashes.SHA256())
    )
    return {
        "ca": ca.public_bytes(serialization.Encoding.PEM),
        "certificate": leaf.public_bytes(serialization.Encoding.PEM),
        "key": server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }


def in_directory(parent, name):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent)
    try:
        info = os.fstat(fd)
        role_files.directory(info)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(role_files.identity(info) == role_files.identity(named))
        return fd
    except BaseException:
        os.close(fd)
        raise


def mount_layout(role, *, restore_cluster=False):
    need(not restore_cluster or role == "driver")
    layout = MOUNTS[role]
    return {**layout, "wpr-ca.crt": role_files.PUBLIC} if restore_cluster else layout


def stage_directory(root, role, *, expected=None, files=None, restore_cluster=False):
    allowed = mount_layout(role, restore_cluster=restore_cluster)
    if files is not None:
        need(type(files) is dict and files.keys() == allowed.keys())
        for name, (raw, mode, uid, gid) in files.items():
            need(type(raw) is bytes and 0 < len(raw) <= role_files.MAX_FILE)
            need((mode, uid, gid) == allowed[name])
    with ExitStack() as stack:
        stage = in_directory(root, "stage")
        stack.callback(os.close, stage)
        mount = in_directory(stage, role)
        stack.callback(os.close, mount)
        initial = os.fstat(mount)
        selected = initial.st_dev, initial.st_ino
        need(stat.S_IMODE(initial.st_mode) in {0o700, 0o755})
        need(expected is None or expected == list(selected))
        need(not role_files.names(os, mount, 0))
        if files is None:
            return selected

        def check(mode):
            need(
                role_files.identity(os.fstat(stage))
                == role_files.identity(os.stat("stage", dir_fd=root, follow_symlinks=False))
            )
            opened = os.fstat(mount)
            role_files.directory(opened, mode=mode)
            need((opened.st_dev, opened.st_ino) == selected)
            need(
                role_files.identity(opened)
                == role_files.identity(os.stat(role, dir_fd=stage, follow_symlinks=False))
            )

        os.fchmod(mount, 0o700)
        observed = {}
        for name, row in files.items():
            check(0o700)
            observed[name] = role_files.write_file(os, mount, name, row)
        os.fsync(mount)
        os.fchmod(mount, 0o555)
        os.fsync(mount)
        check(0o555)
        need(role_files.names(os, mount, len(files)) == files.keys())
        for name, (raw, *attributes) in files.items():
            final = os.stat(name, dir_fd=mount, follow_symlinks=False)
            need(role_files.file_identity(final, tuple(attributes), len(raw)) == observed[name])
        return selected


def stage_pitr_volume(root, role, *, expected=None):
    """Bind empty writable storage by inode before transferring ownership."""
    need(role in PITR_VOLUMES)
    with ExitStack() as stack:
        stage = in_directory(root, "stage")
        stack.callback(os.close, stage)
        mount = in_directory(stage, role)
        stack.callback(os.close, mount)
        initial = os.fstat(mount)
        selected = initial.st_dev, initial.st_ino
        need(stat.S_IMODE(initial.st_mode) in {0o700, 0o755})
        need(not role_files.names(os, mount, 0))
        if expected is None:
            return selected
        need(expected == list(selected))

        def transfer(fd):
            os.fchmod(fd, 0o700)
            os.fchown(fd, 999, 999)
            os.fsync(fd)
            owned = os.fstat(fd)
            need(stat.S_ISDIR(owned.st_mode) and stat.S_IMODE(owned.st_mode) == 0o700)
            need(owned.st_uid == owned.st_gid == 999)
            return owned

        if role == "w-pitr-archive":
            os.mkdir("wal", 0o700, dir_fd=mount)
            wal = in_directory(mount, "wal")
            stack.callback(os.close, wal)
            need(not role_files.names(os, wal, 0))
            owned = transfer(wal)
            need(
                role_files.identity(owned)
                == role_files.identity(os.stat("wal", dir_fd=mount, follow_symlinks=False))
            )
            need(role_files.names(os, mount, 1) == {"wal"})
        owned = transfer(mount)
        need((owned.st_dev, owned.st_ino) == selected)
        need(
            role_files.identity(owned)
            == role_files.identity(os.stat(role, dir_fd=stage, follow_symlinks=False))
        )
        need(
            role_files.identity(os.fstat(stage))
            == role_files.identity(os.stat("stage", dir_fd=root, follow_symlinks=False))
        )
        return selected


def write_private(work, name, raw):
    need(0 < len(raw) <= CAP)
    role_files.write_file(os, work, name, (raw, 0o600, 0, 0))
    os.fsync(work)


def role_bytes(role, materials, *, restore_cluster=False):
    allowed = mount_layout(role, restore_cluster=restore_cluster)
    need(type(materials) is dict and materials.keys() == allowed.keys())
    return {name: (raw, *allowed[name]) for name, raw in materials.items()}


def pair_for(run, credentials, tls, *, recovery=False, restore_witness=False, pitr=False):
    return witness_postgres.prepare_pair(
        run,
        databases={role: f"w01_{run}_{role}" for role in POSTGRES},
        credentials=credentials,
        tls=tls,
        schemas={name: read_regular(path, 65536) for name, path in SCHEMAS.items()},
        schema_pins=dict(witness_postgres.SCHEMA_PINS),
        recovery=recovery,
        restore_witness=restore_witness,
        pitr=pitr,
    )


def endpoint(cluster):
    return {
        "host": cluster.hostname,
        "hostaddr": cluster.address,
        "port": cluster.port,
        "dbname": cluster.database,
    }


def runtime(cluster, passwords):
    user = witness_postgres.ROLES[cluster.role][0]
    return {**endpoint(cluster), "user": user, "password": passwords[user]}


def history_roles(recovery, restore_witness, restore_cluster=False, pitr=False):
    need(all(type(value) is bool for value in (recovery, restore_witness, restore_cluster, pitr)))
    need(recovery or not (restore_witness or restore_cluster))
    need(not (restore_witness and restore_cluster))
    need(not pitr or restore_cluster)
    if restore_witness or restore_cluster:
        return RECOVERY_ROLE, RESTORE_ROLE
    return (RECOVERY_ROLE,) if recovery else ()


def stage_restore_cluster(root, work, run, location, credentials, tls, now, *, pitr=False):
    target_secrets = {user: secrets.token_urlsafe(32) for user in ("postgres", OBSERVER)}
    passwords = {password for users in credentials.values() for password in users.values()}
    need(passwords.isdisjoint(target_secrets.values()))
    target_tls = certificate_pair(witness_postgres.RESTORE_HOST[0], now)
    need(all(target_tls[name] != files[name] for name in target_tls for files in tls.values()))
    cluster = witness_postgres.prepare_restore_cluster(
        run, credentials=target_secrets, tls=target_tls, pitr=pitr
    )
    files = {
        name: (row.raw, row.mode, row.uid, row.gid) for name, row in cluster.files.items()
    }
    stage_directory(root, RESTORE_POSTGRES, expected=location, files=files)
    observer = target_secrets[OBSERVER]
    if pitr:
        restriction = witness_postgres.restrict_physical_restore(run, cluster, observer)
        write_private(work, "wpr-pitr.sql", restriction)
    else:
        preflight, provision = witness_postgres.restore_cluster_scripts(run, cluster, observer)
        write_private(work, "wpr-preflight.sql", preflight)
        write_private(work, "wpr-provision.sql", provision)
    row = {**endpoint(cluster), "credentials": {OBSERVER: observer}}
    return row, target_tls["ca"]


def base(
    root, work, run, *, recovery=False, restore_witness=False, restore_cluster=False, pitr=False
):
    history = history_roles(recovery, restore_witness, restore_cluster, pitr)
    need(not role_files.names(os, work, 0))
    locations = {
        role: list(stage_directory(root, role))
        for role in MOUNTS
        if role not in HISTORY_MOUNTS or role in history
        if role != RESTORE_POSTGRES or restore_cluster
    }
    if pitr:
        locations.update({role: list(stage_pitr_volume(root, role)) for role in PITR_VOLUMES})
    need(len({tuple(value) for value in locations.values()}) == len(locations))
    if pitr:
        for role in PITR_VOLUMES:
            stage_pitr_volume(root, role, expected=locations[role])
    now = datetime.now(UTC)
    credentials, tls = {}, {}
    for role, users in witness_postgres.ROLES.items():
        credentials[role] = {user: secrets.token_urlsafe(32) for user in ("postgres", *users)}
        tls[role] = certificate_pair(witness_postgres.HOSTS[role][0], now)
    pair = pair_for(
        run, credentials, tls, recovery=recovery, restore_witness=restore_witness, pitr=pitr
    )
    for role, mount in POSTGRES.items():
        materials = {
            name: (row.raw, row.mode, row.uid, row.gid)
            for name, row in pair.clusters[role].files.items()
        }
        stage_directory(root, mount, expected=locations[mount], files=materials)
        write_private(work, role + "-preflight.sql", pair.preflight_sql(role))
    driver = {
        role: {
            **endpoint(pair.clusters[role]),
            "credentials": {user: credentials[role][user] for user in witness_postgres.ROLES[role]},
        }
        for role in POSTGRES
    }
    driver_config = {"run": run, "databases": driver}
    driver_files = {role + "-ca.crt": tls[role]["ca"] for role in POSTGRES}
    restore_state = {}
    if restore_cluster:
        restored, ca = stage_restore_cluster(
            root, work, run, locations[RESTORE_POSTGRES], credentials, tls, now, pitr=pitr
        )
        driver_config["database_restored"] = restored
        driver_files["wpr-ca.crt"] = ca
        restore_state["cluster_restore"] = {
            "observer": restored["credentials"][OBSERVER],
            "ca": b64(ca),
        }
        if pitr:
            restore_state["cluster_restore"]["pitr"] = True
    driver_files["driver.json"] = encode(driver_config)
    stage_directory(
        root,
        "driver",
        expected=locations["driver"],
        files=role_bytes("driver", driver_files, restore_cluster=restore_cluster),
        restore_cluster=restore_cluster,
    )
    vault_files = {
        "runtime.json": encode(runtime(pair.clusters["vpg"], credentials["vpg"])),
        "sql-ca.crt": tls["vpg"]["ca"],
    }
    stage_directory(
        root, "vault", expected=locations["vault"], files=role_bytes("vault", vault_files)
    )
    write_private(
        work,
        "base.json",
        encode(
            {
                "run": run,
                "witness_mount": locations["witness"],
                **{HISTORY_MOUNTS[role]: locations[role] for role in history},
                **restore_state,
                "credentials": credentials,
                "tls": {
                    role: {name: b64(raw) for name, raw in keys.items()}
                    for role, keys in tls.items()
                },
            }
        ),
    )
    return "W01_BASE_READY"


def restore_base(run):
    state = canonical(read_regular(WORK / "base.json", CAP), CAP)
    need(type(state) is dict)
    restore_cluster = "cluster_restore" in state
    if restore_cluster:
        need(type(state["cluster_restore"]) is dict)
    pitr = restore_cluster and "pitr" in state["cluster_restore"]
    history = history_roles(
        "recovery_mount" in state,
        "restore_mount" in state and not restore_cluster,
        restore_cluster,
        pitr,
    )
    mounts = {"witness_mount", *(HISTORY_MOUNTS[role] for role in history)}
    fields = {"run", "credentials", "tls", *mounts}
    if restore_cluster:
        fields.add("cluster_restore")
        cluster_fields = {"observer", "ca"}
        if pitr:
            cluster_fields.add("pitr")
            need(state["cluster_restore"]["pitr"] is True)
        witness_postgres.closed(state["cluster_restore"], cluster_fields)
    witness_postgres.closed(state, fields)
    need(state["run"] == run)
    for name in mounts:
        location = state[name]
        need(type(location) is list and len(location) == 2)
        need(all(type(item) is int and item >= 0 for item in location))
    need(len({tuple(state[name]) for name in mounts}) == len(mounts))
    witness_postgres.closed(state["tls"], POSTGRES)
    tls = {}
    for role, files in state["tls"].items():
        witness_postgres.closed(files, {"ca", "certificate", "key"})
        tls[role] = {name: unb64(value, 16384) for name, value in files.items()}
    return state, tls


def preflighted_pair(run, receipts):
    need(receipts == b"".join(f"W01_{run}_{role}_EMPTY\n".encode("ascii") for role in POSTGRES))
    state, tls = restore_base(run)
    pair = pair_for(
        run, state["credentials"], tls,
        recovery="recovery_mount" in state,
        restore_witness="restore_mount" in state and "cluster_restore" not in state,
        pitr=state.get("cluster_restore", {}).get("pitr", False),
    )
    for role, line in zip(POSTGRES, receipts.splitlines(keepends=True), strict=True):
        pair.accept_preflight(role, 0, line)
    return pair


def provision(work, run, receipts):
    pair = preflighted_pair(run, receipts)
    write_private(work, "preflight.receipts", receipts)
    write_private(work, "wpg-provision.sql", pair.take_provision("wpg"))
    write_private(work, "wpg.ready", run.encode("ascii"))
    return "W01_PROVISION_READY"


def provision_vault(work, run, witness_receipt):
    # A prior prepare emits W only. V requires the verified response from W's
    # owned PostgreSQL container, supplied by the trusted parent.
    need(read_regular(WORK / "wpg.ready", 16) == run.encode("ascii"))
    pair = preflighted_pair(run, read_regular(WORK / "preflight.receipts", 256))
    witness_sql = pair.take_provision("wpg")
    need(read_regular(WORK / "wpg-provision.sql", 128 * 1024) == witness_sql)
    pair.accept_provision("wpg", 0, witness_receipt)
    write_private(work, "vpg-provision.sql", pair.take_provision("vpg"))
    write_private(work, "provision.ready", run.encode("ascii"))
    return "W01_VAULT_PROVISION_READY"


def material_frame(raw, expected_source):
    value = canonical(raw, CAP)
    witness_postgres.closed(value, {"files", "bindings"})
    witness_postgres.closed(value["files"], WITNESS_FILES)
    bindings = value["bindings"]
    witness_postgres.closed(bindings, {"source_sha256", "slot_sha256", "materials_sha256"})
    need(
        all(
            type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in bindings.values()
        )
    )
    need(bindings["source_sha256"] == expected_source)
    files = {name: unb64(encoded, role_files.MAX_FILE) for name, encoded in value["files"].items()}
    for name, field in (("materials.bin", "materials_sha256"), ("slot.json", "slot_sha256")):
        need(sha(files[name]) == bindings[field])
    return {**files, "bindings.json": encode(bindings)}


def stage_witness(
    root, run, raw, *, recovery=False, restore_witness=False, restore_cluster=False, pitr=False
):
    history = history_roles(recovery, restore_witness, restore_cluster, pitr)
    need(read_regular(WORK / "provision.ready", 16) == run.encode("ascii"))
    state, tls = restore_base(run)
    need({HISTORY_MOUNTS[role] for role in history} == HISTORY_MOUNTS.values() & state.keys())
    need(restore_cluster == ("cluster_restore" in state))
    need(pitr == state.get("cluster_restore", {}).get("pitr", False))
    pair = pair_for(
        run, state["credentials"], tls,
        recovery=recovery, restore_witness=restore_witness, pitr=pitr,
    )
    files = material_frame(raw, sha(read_regular(SOURCE_LEDGER, 16384)))
    cluster = pair.clusters["wpg"]
    credentials = state["credentials"]["wpg"]
    files["runtime.json"] = encode(runtime(cluster, credentials))
    files["sql-ca.crt"] = tls["wpg"]["ca"]
    stage_directory(
        root, "witness", expected=state["witness_mount"], files=role_bytes("witness", files)
    )
    for role in history:
        bindings = canonical(files["bindings.json"], CAP)
        connection = {
            **endpoint(cluster), "user": OBSERVER, "password": credentials[OBSERVER],
        }
        ca = tls["wpg"]["ca"]
        if role == RESTORE_ROLE:
            connection["dbname"] = witness_postgres.restore_database(run)
            if restore_cluster:
                host, address = witness_postgres.RESTORE_HOST
                target = state["cluster_restore"]
                witness_postgres.password(target["observer"])
                ca = unb64(target["ca"], 16384)
                need(all(ca != record["ca"] for record in tls.values()))
                need(all(target["observer"] not in users.values()
                         for users in state["credentials"].values()))
                connection.update(host=host, hostaddr=address, password=target["observer"])
        history_files = {
            **{name: files[name] for name in RECOVERY_TLS_SLOT},
            "bindings.json": encode(
                {name: bindings[name] for name in ("source_sha256", "slot_sha256")}
            ),
            "runtime.json": encode(connection),
            "sql-ca.crt": ca,
        }
        stage_directory(
            root,
            role,
            expected=state[HISTORY_MOUNTS[role]],
            files=role_bytes(role, history_files),
        )
    return "W01_WITNESS_READY"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("base", "provision", "provision-vault", "stage-witness"))
    parser.add_argument("--run", required=True)
    parser.add_argument("--recovery", action="store_true")
    parser.add_argument("--restore-witness", action="store_true")
    parser.add_argument("--restore-cluster", action="store_true")
    parser.add_argument("--pitr", action="store_true")
    args = parser.parse_args()
    try:
        need(re.fullmatch(r"[0-9a-f]{16}", args.run) is not None)
        need(not args.recovery or args.phase in {"base", "stage-witness"})
        history_roles(args.recovery, args.restore_witness, args.restore_cluster, args.pitr)
        kernel_check()
        os.environ.clear()
        os.environ.update(LANG="C.UTF-8", LC_ALL="C.UTF-8")
        with ExitStack() as stack:
            root = in_directory(None, "/")
            stack.callback(os.close, root)
            work = in_directory(root, WORK.name)
            stack.callback(os.close, work)
            role_files.directory(os.fstat(work), mode=0o700)
            if args.phase == "base":
                marker = base(
                    root, work, args.run, recovery=args.recovery,
                    restore_witness=args.restore_witness,
                    restore_cluster=args.restore_cluster,
                    pitr=args.pitr,
                )
            elif args.phase == "provision":
                marker = provision(work, args.run, sys.stdin.buffer.read(257))
            elif args.phase == "provision-vault":
                marker = provision_vault(work, args.run, sys.stdin.buffer.read(257))
            else:
                marker = stage_witness(
                    root, args.run, sys.stdin.buffer.read(CAP + 1), recovery=args.recovery,
                    restore_witness=args.restore_witness,
                    restore_cluster=args.restore_cluster,
                    pitr=args.pitr,
                )
    except Exception:
        print("W01 synthetic preparation refused.", file=sys.stderr)
        return 42
    print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
