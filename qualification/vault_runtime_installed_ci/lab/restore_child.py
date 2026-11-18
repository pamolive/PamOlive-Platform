"""Run a bounded restoration observation using the pinned installed Vault."""

import argparse
import contextlib
import io
import json
import os
import stat
import sys
import time
from pathlib import Path

INPUTS = Path("/inputs")
PRIVATE = Path("/work/restore-private")
MAX_PRIVATE = 65536
PHASES = ("before-dump", "after-restore", "after-commission")
sys.path.insert(0, str(INPUTS / "lab"))
import installed_ten as installed  # noqa: E402
import restore_probe  # noqa: E402

need = installed.need


class Private:
    PRIVATE = PRIVATE

    def __init__(self, support):
        self.support = support

    def private_file(self, name, value=None):
        need(name in {"restore.json", "restore-runtime-denials.json"})
        folder = PRIVATE.lstat()
        need(stat.S_ISDIR(folder.st_mode) and stat.S_IMODE(folder.st_mode) == 0o700)
        need(folder.st_uid == folder.st_gid == 1000)
        path = PRIVATE / name
        if value is not None:
            raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            need(0 < len(raw) <= MAX_PRIVATE)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                need(stream.write(raw) == len(raw))
            return None
        row = path.lstat()
        need(stat.S_ISREG(row.st_mode) and stat.S_IMODE(row.st_mode) == 0o600)
        need(row.st_uid == row.st_gid == 1000)
        return json.loads(self.support.read_regular(path, MAX_PRIVATE))

    @staticmethod
    def tls(reception, request):
        with contextlib.closing(reception.client()) as connection:
            status, value = reception.post(connection, request)
            need(status == 200)
            return value

    @staticmethod
    def same_pending(answer, row):
        keys = ("reservation_id", "issued_at", "expires_at")
        need(type(answer) is dict and set(answer) == {*keys, "state", "authorized"})
        need(answer["state"] == "pending_proofs" and answer["authorized"] is False)
        need(all(answer[key] == row[key] for key in keys))
        issued, expires = row["issued_at"], row["expires_at"]
        need(type(issued) is type(expires) is int and issued < expires <= issued + 30)
        need(int(time.time()) < expires)


def execute(args, output):
    controller = installed.controller_modules(INPUTS / "controller")
    support = controller.support
    path = INPUTS / "descriptor.json"
    raw = support.read_regular(path, 65536)
    need(support.sha(raw) == args.input_sha256)
    description = controller.adapter_v2.descriptor(controller.schema.parse(raw, 65536))
    directory = INPUTS / "runtime/integration"
    fixtures = installed.fixture_bytes(directory, description, args.test_sha256, controller)
    base = installed.installed_check(description, controller)
    reception = installed.load_fixture(directory, fixtures)
    with contextlib.redirect_stdout(output):
        result = restore_probe.execute(args.phase, reception, Private(support))
    need(installed.fixture_bytes(directory, description, args.test_sha256, controller) == fixtures)
    need(installed.installed_check(description, controller) == base)
    need(support.read_regular(path, 65536) == raw)
    return result


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--execute-new-synthetic-lab", action="store_true", required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--test-sha256", required=True)
    try:
        public = io.StringIO()
        with (
            contextlib.redirect_stdout(installed.Discard()),
            contextlib.redirect_stderr(installed.Discard()),
        ):
            result = execute(parser.parse_args(), public)
        raw = public.getvalue()
        need(0 < len(raw) <= 8192 and raw.count("\n") == 1)
        print(raw, end="")
        return result
    except (Exception, SystemExit):
        print(json.dumps({"error": "restore_child_refused", "authority": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
