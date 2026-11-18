"""Stage the synthetic role mounts from one offline test process."""

import argparse
import os
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

LAB = Path("/inputs/lab")
WORK = Path("/work")
PKI = LAB / "fixtures.source"
PREFIX = Path("/opt/vault")
sys.path[:0] = [str(LAB), "/inputs/controller"]
import adapter_v2  # noqa: E402
import fixture_stage  # noqa: E402
import installed_runner  # noqa: E402
import installed_ten  # noqa: E402
import pg_bootstrap  # noqa: E402
import postgres_stage  # noqa: E402
import role_files  # noqa: E402
import schema  # noqa: E402
import support  # noqa: E402


def stage(role, files):
    fd = os.open(Path("/stage") / role, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        state = os.fstat(fd)
        role_files.directory(state)
        support.need(stat.S_IMODE(state.st_mode) in (0o700, 0o755) and not os.listdir(fd))
        os.fchmod(fd, 0o700)
        role_files.stage_role(role, files, (role, state.st_dev, state.st_ino))
    finally:
        os.close(fd)


def private_file(name, raw):
    path = WORK / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    with (WORK / (name + ".ready")).open("xb"):
        pass


def wait_for_bootstrap():
    receipt = WORK / "bootstrap.receipt"
    deadline = time.monotonic() + 90
    while not receipt.exists():
        support.need(time.monotonic() < deadline)
        time.sleep(0.1)
    raw = support.read_regular(receipt, 4096)
    pg_bootstrap.require_success(0, raw)
    return raw


def prepare(args):
    raw = support.read_regular(Path("/inputs/descriptor.json"), 65536)
    support.need(support.sha(raw) == args.input_sha256)
    descriptor = adapter_v2.descriptor(schema.parse(raw))
    controller = SimpleNamespace(
        support=support, adapter_v2=adapter_v2, installed_runner=installed_runner, schema=schema
    )

    def verify_installed():
        return installed_ten.installed_check(descriptor, controller)

    verify_installed()
    pki = fixture_stage.load_public_pki(PKI, read_regular=support.read_regular)
    primitives = postgres_stage.load_public_pg(
        PKI, fixture_support=fixture_stage, read_regular=support.read_regular
    )
    leaves, public = pki.tls_materials()
    passwords = pki.passwords()
    postgres = postgres_stage.prepare_postgres(
        primitives=primitives,
        fixture_support=fixture_stage,
        bootstrap=pg_bootstrap,
        leaves=leaves,
        public=public,
        passwords=passwords,
        database=args.database,
        schema=support.read_regular(PREFIX / "share/pamolive/vault-reservation/schema.sql", 65536),
        descriptor=descriptor,
    )
    stage("pg", postgres.files)
    private_file("pg.sql", postgres.guarded_sql)
    receipt = wait_for_bootstrap()
    signing = fixture_stage.load_public_fixture(
        LAB / "signing-fixture.py",
        read_regular=support.read_regular,
        verify_installed=verify_installed,
        new_signing_key=pki.new_signing_key,
    )
    tables = fixture_stage.build_stage(
        fixture=signing,
        leaves=leaves,
        public=public,
        passwords=passwords,
        database=args.database,
        now=int(time.time()),
    )
    sql = postgres_stage.commissioning_sql(
        postgres=postgres,
        stage=tables,
        primitives=primitives,
        fixture_support=fixture_stage,
        bootstrap=pg_bootstrap,
        schema_returncode=0,
        schema_stdout=receipt,
    )
    stage("server", tables.server_files)
    stage("client", tables.client_files)
    private_file("seed.sql", sql)
    deadline = time.monotonic() + 45
    while not (WORK / "finished").exists():
        support.need(time.monotonic() < deadline)
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--input-sha256", required=True)
    try:
        prepare(parser.parse_args())
    except Exception:
        print("Vault synthetic preparation refused.", file=sys.stderr)
        raise SystemExit(42) from None


if __name__ == "__main__":
    main()
