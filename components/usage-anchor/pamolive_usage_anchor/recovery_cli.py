"""Operate one locally held witness recovery scope without access to signing keys."""

import argparse
import json
import os
import stat
import sys
from dataclasses import asdict
from pathlib import Path

from . import codec, recovery_manifest, recovery_store, signed_anchor

SCHEMA = "pamolive.witness-custody-result/1"


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "invalid_request\n")


def _parser():
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--directory", required=True, type=Path, help="Dedicated custody directory")
    parser.add_argument("--governance-key", required=True, help="Pinned Ed25519 public key in hex")
    parser.add_argument("--organization", required=True)
    parser.add_argument("--installation", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--slot-sha256", required=True)
    commands = parser.add_subparsers(dest="operation", required=True)
    for operation in ("commission", "advance"):
        command = commands.add_parser(operation, allow_abbrev=False)
        command.add_argument("--manifest", required=True, type=Path)
        command.add_argument("--proposal-sha256", required=True)
        command.add_argument("--checkpoint", action="append", required=True, type=Path)
        if operation == "advance":
            command.add_argument("--current-sha256", required=True)
    restore = commands.add_parser("restore", allow_abbrev=False)
    restore.add_argument("--current-sha256", required=True)
    restore.add_argument("--checkpoint-sha256", required=True)
    return parser


def _read(path, maximum):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        codec.need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum)
        data = stream.read(maximum + 1)
    codec.need(len(data) == info.st_size)
    return data


def _proposal(options):
    expected = codec.digest(options.proposal_sha256)
    codec.need(len(options.checkpoint) <= recovery_manifest.MAX_ADMISSIONS)
    manifest = _read(options.manifest, recovery_manifest.MAX_BYTES)
    codec.need(codec.sha(manifest) == expected, "anchor_refused", 403)
    checkpoints = {}
    for path in options.checkpoint:
        raw = _read(path, signed_anchor.MAX_ANCHOR_BYTES)
        digest = codec.sha(raw)
        codec.need(digest not in checkpoints)
        checkpoints[digest] = raw
    return manifest, checkpoints


def _execute(options):
    scope = recovery_manifest.RecoveryScope(
        options.organization, options.installation, options.context, options.slot_sha256
    )
    store = recovery_store.RecoveryStore(
        options.directory,
        owner_uid=os.geteuid(),
        governance_key=bytes.fromhex(codec.digest(options.governance_key)),
        scope=scope,
    )
    result = {"schema": SCHEMA, "operation": options.operation}
    if options.operation == "restore":
        expected = codec.digest(options.current_sha256)
        digest = codec.digest(options.checkpoint_sha256)
        point = store.restore(expected=expected, checkpoint_sha256=digest)
        return dict(
            result, manifest_sha256=expected, checkpoint_sha256=digest, checkpoint=asdict(point)
        )
    manifest, checkpoints = _proposal(options)
    if options.operation == "commission":
        current = store.commission(manifest, checkpoints=checkpoints)
    else:
        current = store.advance(
            manifest, expected=codec.digest(options.current_sha256), checkpoints=checkpoints
        )
    return dict(result, manifest_sha256=current)


def main(argv=None):
    options = _parser().parse_args(argv)
    try:
        codec.need(sys.platform == "linux", "unavailable", 503)
        result = _execute(options)
        receipt = (json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
        if os.write(1, receipt) != len(receipt):
            raise OSError
    except codec.Error as error:
        print(error.code, file=sys.stderr)
        return 1
    except OSError:
        print("unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
