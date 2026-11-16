"""TEST-only closed fixture contracts; no process, socket or filesystem IO."""

import hashlib
import re

PURPOSE = "pamolive.gpg-selected-signer-revoked-fixture/2"
UID = "PamOlive TEST selected-subkey-revoked <test-only@example.invalid>"
MESSAGE = b"PamOlive synthetic selected signing subkey revocation fixture v1\n"
COMMANDS = b"key 1\nrevkey\ny\n1\n\ny\nsave\n"
GETS = (
    ("GET_LINE", "keyedit.prompt"),
    ("GET_LINE", "keyedit.prompt"),
    ("GET_BOOL", "keyedit.revoke.subkey.okay"),
    ("GET_LINE", "ask_revocation_reason.code"),
    ("GET_LINE", "ask_revocation_reason.text"),
    ("GET_BOOL", "ask_revocation_reason.okay"),
    ("GET_LINE", "keyedit.prompt"),
)
TOOLS = ("gpg", "gpg-agent", "gpg-connect-agent", "gpgconf")
PUBLIC_NAMES = (
    "certificate-before.pgp",
    "certificate-revoked.pgp",
    "message.bin",
    "signature.sig",
    "signature-future.sig",
    "signature-expired.sig",
)
PYTHON = "/usr/bin/python3.12"
MAX_PUBLIC = 65536
REPOSITORY = "pamolive/PamOlive-Platform"


def need(ok, code):
    if not ok:
        raise ValueError(code)


def digest(raw):
    need(type(raw) is bytes, "immutable_bytes")
    return hashlib.sha256(raw).hexdigest()


def ci_context(env):
    need(
        all(
            env.get(key) == value
            for key, value in {
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu24",
                "GITHUB_REPOSITORY": REPOSITORY,
            }.items()
        ),
        "disposable_CI_profile",
    )
    event, ref = env.get("GITHUB_EVENT_NAME"), env.get("GITHUB_REF", "")
    need(event in {"push", "pull_request", "workflow_dispatch"}, "CI_event")
    if event == "pull_request":
        need(
            env.get("P1G_HEAD_REPOSITORY") == REPOSITORY
            and re.fullmatch(r"refs/pull/[1-9][0-9]{0,9}/merge", ref),
            "CI_fork_or_ref",
        )
    else:
        need(re.fullmatch(r"refs/heads/agent/[A-Za-z0-9_.-]{1,96}", ref), "CI_branch")
    fields = {
        key: env.get(key, "")
        for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
    }
    need(re.fullmatch("[0-9a-f]{40}", fields["GITHUB_SHA"]), "CI_head")
    need(
        all(
            re.fullmatch("[1-9][0-9]{0,19}", fields[key])
            for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        ),
        "CI_run",
    )
    need(re.fullmatch("[A-Za-z0-9_-]{1,64}", fields["GITHUB_JOB"]), "CI_job")
    return {
        "head": fields["GITHUB_SHA"],
        "run": fields["GITHUB_RUN_ID"],
        "attempt": fields["GITHUB_RUN_ATTEMPT"],
        "job": fields["GITHUB_JOB"],
        "event": event,
        "runner_image": "ubuntu24",
        "repository": REPOSITORY,
    }


def fingerprint(value):
    need(type(value) is str and re.fullmatch("[0-9A-F]{40}", value), "fingerprint")
    return value


def base(home):
    need(type(home) is str and home.startswith("/tmp/pamolive-fixture-"), "private_home")
    need(re.fullmatch(r"/tmp/pamolive-fixture-[0-9a-f]{32}/home", home), "private_home")
    return [
        "/usr/bin/gpg",
        "--no-options",
        "--homedir",
        home,
        "--batch",
        "--no-tty",
        "--no-autostart",
        "--no-auto-key-retrieve",
        "--no-auto-key-import",
        "--auto-key-locate",
        "clear",
        "--no-auto-check-trustdb",
        "--require-cross-certification",
    ]


def argv(role, home, primary=None, signer=None, paths=None):
    result = base(home)
    paths = {} if paths is None else paths
    if primary is not None:
        fingerprint(primary)
    if signer is not None:
        fingerprint(signer)
    if role == "generate":
        return result + [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            UID,
            "rsa2048",
            "cert",
            "1d",
        ]
    if role == "add_signer" and primary:
        return result + [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-add-key",
            primary,
            "rsa2048",
            "sign",
            "1d",
        ]
    if role == "list":
        return result + [
            "--with-colons",
            "--with-fingerprint",
            "--with-subkey-fingerprint",
            "--list-keys",
        ]
    if role == "export" and primary:
        return result + ["--export", primary]
    if role == "sign" and signer:
        return result + [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--local-user",
            signer + "!",
            "--digest-algo",
            "SHA256",
            "--output",
            "-",
            "--detach-sign",
            paths["message"],
        ]
    if role == "import":
        return result + ["--import", paths["certificate"]]
    if role == "verify":
        return result + ["--status-fd", "1", "--verify", paths["signature"], paths["message"]]
    if role == "revoke" and primary:
        return result + [
            "--command-file",
            paths["commands"],
            "--status-fd",
            "1",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--edit-key",
            primary,
        ]
    raise ValueError("unknown_role")


def creation_times(anchor):
    # The key's unchanged one-day expiry is anchor-3600+86400; it must also fit uint32.
    need(type(anchor) is int and 3600 < anchor < 2**32 - 82800, "creation_anchor")
    return {
        "anchor": anchor,
        "key": anchor - 3600,
        "future": anchor + 3600,
        "expired": anchor - 600,
        "signature_duration": 60,
    }


def creation_argv(role, home, *, epoch, primary=None, signer=None, paths=None):
    need(type(epoch) is int and 0 < epoch < 2**32, "creation_epoch")
    need(
        role in {"generate", "add_signer", "future_signature", "expired_signature"}, "creation_role"
    )
    actual = "sign" if role in {"future_signature", "expired_signature"} else role
    args = argv(actual, home, primary, signer, paths)
    prefix = base(home)
    need(args[: len(prefix)] == prefix, "creation_prefix")
    extra = ["--faked-system-time", f"{epoch}!"]
    if role == "expired_signature":
        # GnuPG2.4.7 keygen.c parse_expire_string; bare60 is days, not seconds.
        extra += ["--default-sig-expire", "seconds=60"]
    return prefix + extra + args[len(prefix) :]


def real_clock(anchor, since, wall, monotonic):
    need(
        type(anchor) is int
        and type(wall) is int
        and type(since) in {int, float}
        and type(monotonic) in {int, float},
        "clock_shape",
    )
    elapsed = monotonic - since
    need(0 <= elapsed <= 150 and abs(wall - (anchor + elapsed)) <= 5, "real_clock_changed")
    return wall


def key_creation(raw, guard, primary, signer, epoch):
    keys = guard.one_primary(raw, primary)
    expected = {primary} if signer is None else {primary, signer}
    need(
        set(keys) == expected
        and all(
            keys[key]["created"] == str(epoch) and keys[key]["expires"] == str(epoch + 86400)
            for key in expected
        ),
        "native_key_creation_time",
    )


def packet_key_times(raw, packets, primary, signer, epoch):
    found, primary_block, subs = packets.blocks(raw)
    need(found == primary and set(subs) == {signer}, "creation_packet_keys")
    need(
        all(
            int.from_bytes(body[1:5], "big") == epoch
            for body in (primary_block[0][1], subs[signer][0][1])
        ),
        "creation_packet_time",
    )


def normal(result):
    row = result.facts()
    need(
        row.get("spawn_attempted") is True
        and type(row.get("pid")) is int
        and row["pid"] > 0
        and type(row.get("returncode")) is int
        and row["returncode"] == 0
        and row.get("reason") is None
        and row.get("exception_type") is None
        and row.get("cleanup_exception_type") is None
        and row.get("killed_owned_child") is False
        and row.get("owned_child_reaped") is True
        and row.get("drains_complete") is True,
        "client_unknown",
    )
    need(type(result.stdout) is bytes and type(result.stderr) is bytes, "client_bytes")
    need(
        row["stdout_bytes"] == len(result.stdout) and row["stderr_bytes"] == len(result.stderr),
        "client_byte_counts",
    )
    return row


def version(raw, name):
    need(name in TOOLS and type(raw) is bytes and len(raw) <= 16384, "version_budget")
    first = raw.split(b"\n", 1)[0]
    match = re.fullmatch(re.escape(name.encode()) + rb" \(GnuPG\) (2\.4\.[0-9]{1,3})", first)
    need(match is not None, "tool_version")
    return match[1].decode("ascii")


def version_argv(name, home):
    need(name in TOOLS, "version_role")
    if name == "gpg":
        return base(home) + ["--version"]
    if name == "gpg-agent":
        return ["/usr/bin/gpg-agent", "--no-options", "--homedir", home, "--version"]
    if name == "gpg-connect-agent":
        return [
            "/usr/bin/gpg-connect-agent",
            "--no-autostart",
            "--no-history",
            "--homedir",
            home,
            "--version",
        ]
    return ["/usr/bin/gpgconf", "--homedir", home, "--version"]


def discover(raw, guard, *, primary=None, signer=None, now):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PUBLIC, "listing_budget")
    rows = [line.split(":") for line in raw.decode("utf-8", "strict").splitlines()]
    pubs = [i for i, row in enumerate(rows) if row[0] == "pub"]
    need(len(pubs) == 1 and pubs[0] + 1 < len(rows), "one_test_primary")
    next_row = rows[pubs[0] + 1]
    need(len(next_row) > 9 and next_row[0] == "fpr", "test_primary_fpr")
    p = fingerprint(next_row[9])
    need(primary is None or p == primary, "test_primary_changed")
    keys = guard.one_primary(raw, p)
    need(
        "c" in keys[p]["caps"] and not any(k in keys[p]["caps"] for k in "sea"),
        "test_primary_cert_only",
    )
    subs = [key for key in keys if key != p]
    need(len(subs) <= 1, "one_test_signer")
    if signer is not None:
        need(subs == [signer] and p != signer, "test_signer_changed")
    if subs:
        need(
            "s" in keys[subs[0]]["caps"] and not any(k in keys[subs[0]]["caps"] for k in "cea"),
            "test_subkey_sign_only",
        )
        guard.signing_capability(keys, p, subs[0], now)
    return p, (subs[0] if subs else None)


def transcript(raw, bad):
    need(type(raw) is bytes and 0 < len(raw) <= 16384, "transcript_budget")
    rows = raw.decode("ascii", "strict").splitlines()
    need(
        len(rows) <= 256 and all(row.startswith("[GNUPG:] ") for row in rows), "transcript_framing"
    )
    fields = [row[9:].split() for row in rows]
    need(all(row and row[0] not in bad for row in fields), "transcript_bad")
    asks = []
    for row in fields:
        if row[0].startswith("GET_"):
            need(len(row) == 2, "transcript_get_shape")
            asks.append(tuple(row))
    need(tuple(asks) == GETS, "revocation_dialogue")


def lineage(before, after, packets, p, s):
    fingerprint(p)
    fingerprint(s)
    a, primary_a, subs_a = packets.blocks(before)
    b, primary_b, subs_b = packets.blocks(after)
    need(a == b == p and p != s and set(subs_a) == set(subs_b) == {s}, "lineage_keys")
    need(primary_a == primary_b, "lineage_primary_changed")
    old, new = subs_a[s], subs_b[s]
    need(not any(tag == 2 and body[1] == 0x28 for tag, body, _ in old), "already_revoked")
    added = [i for i, (tag, body, _) in enumerate(new) if tag == 2 and body[1] == 0x28]
    need(len(added) == 1 and len(new) == len(old) + 1, "one_revocation_packet")
    need(new[: added[0]] + new[added[0] + 1 :] == old, "lineage_other_change")
    return True


def revoked(raw, p, s, guard, now):
    keys = guard.one_primary(raw, p)
    need(set(keys) == {p, s} and p != s and keys[s]["validity"] == "r", "native_subkey_r")
    try:
        guard.signing_capability(keys, p, s, now)
    except ValueError as error:
        need(error.args == ("key_unusable",), "unexpected_negative_reason")
    else:
        raise ValueError("revocation_guard_not_refused")


def socket_route(home, uid, runtime_exists):
    need(
        type(home) is str
        and re.fullmatch(r"/tmp/pamolive-fixture-[0-9a-f]{32}/(?:home|positive|negative)", home),
        "socket_home",
    )
    need(type(uid) is int and uid > 0 and type(runtime_exists) is bool, "socket_uid")
    if not runtime_exists:
        return home + "/S.gpg-agent"
    # GnuPG homedir.c: identifier for a nondefault homedir, not an authentication hash.
    raw = hashlib.sha1(home.encode(), usedforsecurity=False).digest()[:15]
    bits = "".join(f"{byte:08b}" for byte in raw)
    alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
    encoded = "".join(alphabet[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5))
    return f"/run/user/{uid}/gnupg/d.{encoded}/S.gpg-agent"


def peer_ok(peer, pid, uid, gid, alive):
    need(type(pid) is int and pid > 0 and alive is True, "agent_not_owned_alive")
    need(peer == (pid, uid, gid) and all(type(x) is int for x in peer), "socket_peer")


def export_facts(buffers, p, s, *, cleanup, unknown):
    need(unknown is False and cleanup is True, "fixture_not_admitted")
    need(type(buffers) is dict and set(buffers) == set(PUBLIC_NAMES), "public_allowlist")
    fingerprint(p)
    fingerprint(s)
    need(p != s and buffers["message.bin"] == MESSAGE, "public_fixture_identity")
    need(
        all(type(raw) is bytes and 0 < len(raw) <= MAX_PUBLIC for raw in buffers.values()),
        "public_byte_budget",
    )
    need(sum(len(raw) for raw in buffers.values()) <= 4 * MAX_PUBLIC, "public_total_budget")
    return {
        "schema": PURPOSE,
        "purpose": "TEST_ONLY",
        "production_authority": False,
        "operational_GO": False,
        "primary": p,
        "signer": s,
        "selected_subkey_revocation": "NATIVE_GUARD_REFUSED",
        "cleanup_complete": True,
        "unknown": False,
        "adr034_matrix_complete": False,
        "temporal_signatures": "CREATED_PENDING_INDEPENDENT_NATIVE_CONSUMER",
        "missing_cases": [
            "primary_revoked_RSA",
            "signature_future",
            "signature_expired",
            "wrong_S2",
        ],
        "files": {
            name: {"bytes": len(raw), "sha256": digest(raw)} for name, raw in buffers.items()
        },
    }
