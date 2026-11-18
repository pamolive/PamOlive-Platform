"""Root-private stage/cleanup only. No payload execution or v3 authority.

This is a finite lifecycle inside the existing Root bootstrap, not a process
supervisor. Only FD identities acquired after exclusive creation enter its
ledger. Pure tests inject OS actors; native admission remains source-pinned.
"""

import json
import stat
import time
from contextlib import contextmanager
from pathlib import PurePosixPath

PROFILE_NAME = "chrome-stage-only-profile.json"
PROFILE_SHA = "14f1f02f2f987c7a07f62079f534fa0c48282b4efba0f04d595d8976625a0841"
PROFILE_SCHEMA = "pamolive.chrome-private-stage-profile/1"
STAGED_SCHEMA = "pamolive.chrome-private-stage-receipt/1"
RESULT_SCHEMA = "pamolive.chrome-private-stage-cleanup/1"
PURPOSE = "STAGE_CLEANUP_ONLY"
CLEANUP_SECONDS = 20
RESERVED = {".bundle-manifest.json", ".bundle-receipt.json"}


def root_only(ops):
    values = [ops.getuid(), ops.geteuid(), ops.getgid(), ops.getegid()]
    if not all(type(value) is int and value == 0 for value in values):
        raise ValueError("phase_a_root_only")


def admit(bundle, tree, raw, pin):
    bundle.need(bundle.sha_field(pin) and bundle.digest(raw) == pin, "phase_a_profile_pin")
    profile = bundle.json_bytes(raw)
    bundle.need(
        type(profile) is dict
        and set(profile)
        == {"schema", "purpose", "admitted", "package_sha256", "tree_sha256", "privileged_roles"}
        and profile["schema"] == PROFILE_SCHEMA
        and profile["purpose"] == PURPOSE
        and profile["admitted"] is True,
        "phase_a_profile_unadmitted",
    )
    names = bundle._admitted_tree(tree, profile)
    bundle.need(not RESERVED.intersection(names), "phase_a_reserved_path")
    return names


def object_key(row):
    return (row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode), row.st_uid, row.st_gid)


class PrivateCycle:
    """Only this invocation's new prefix; no received/persisted ledger is adopted."""

    STAGED_SCHEMA = STAGED_SCHEMA

    def __init__(self, bundle, tree, raw, pin, env, bindings, until, ops, clock):
        root_only(ops)
        bundle.budget(until, clock)
        self.bundle, self.ops, self.clock = bundle, ops, clock
        self.until, self.work_until = until, until - CLEANUP_SECONDS
        bundle.budget(self.work_until, clock)
        self.path = bundle.root_path(env)
        self.env = {key: env[key] for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
        self.bindings_raw = bundle.canonical(bindings)
        self.tree_raw = bundle.canonical(tree)
        self.tree = bundle.json_bytes(self.tree_raw)
        self.profile_raw, self.profile_sha = raw, pin
        self.names = admit(bundle, self.tree, raw, pin)
        self.created = self.bound = self.verified = self.cleaned = False
        self.directories, self.files = {}, {}
        self.deleted_files = self.deleted_directories = 0
        self.root_identity = self.receipt_sha = None

    def validate(self, env, bindings):
        root_only(self.ops)
        self.bundle.need(
            self.bundle.root_path(env) == self.path
            and {key: env[key] for key in self.env} == self.env
            and self.bundle.canonical(bindings) == self.bindings_raw,
            "phase_a_cycle_binding",
        )

    def admit(self, tree, raw, pin):
        self.bundle.need(
            self.bundle.canonical(tree) == self.tree_raw
            and raw == self.profile_raw
            and pin == self.profile_sha,
            "phase_a_cycle_binding",
        )
        return admit(self.bundle, tree, raw, pin)

    def claimed(self, parent, name):
        self.bundle.need(not self.created and name == self.path.name, "phase_a_ownership")
        self.created = True
        row = self.ops.stat(name, dir_fd=parent, follow_symlinks=False)
        self.bundle.need(
            stat.S_ISDIR(row.st_mode)
            and row.st_uid == row.st_gid == 0
            and stat.S_IMODE(row.st_mode) == 0o700,
            "phase_a_ownership",
        )
        self.root_identity = self.bundle.directory_key(row)

    def bind(self, parent, fd, name):
        self.bundle.need(
            self.created
            and not self.bound
            and name == self.path.name
            and self.bundle.directory_key(self.ops.fstat(fd)) == self.root_identity
            == self.bundle.directory_key(self.ops.stat(name, dir_fd=parent, follow_symlinks=False)),
            "phase_a_ownership",
        )
        self.bound = True
        self.directories["."] = {"identity": object_key(self.ops.fstat(fd)), "mode": 0o700}

    def directory(self, name, row):
        self.bundle.need(
            name in self.names and self.names[name]["type"] == "directory", "phase_a_ledger"
        )
        self.bundle.need(
            stat.S_ISDIR(row.st_mode)
            and row.st_uid == row.st_gid == 0
            and stat.S_IMODE(row.st_mode) in {0o700, 0o755},
            "phase_a_ledger",
        )
        previous = self.directories.get(name)
        self.bundle.need(
            previous is None or previous["identity"] == object_key(row), "phase_a_identity_drift"
        )
        self.directories[name] = {"identity": object_key(row), "mode": stat.S_IMODE(row.st_mode)}

    def file(self, name, row, expected):
        self.bundle.need(
            name not in self.files and (name in self.names or name in RESERVED), "phase_a_ledger"
        )
        self.bundle.need(
            stat.S_ISREG(row.st_mode)
            and row.st_uid == row.st_gid == 0
            and row.st_nlink == 1
            and row.st_size == 0
            and stat.S_IMODE(row.st_mode) == 0o600,
            "phase_a_ledger",
        )
        self.files[name] = {
            "identity": object_key(row),
            "expected": dict(expected),
            "complete": False,
            "final_key": None,
        }

    def complete_file(self, name, row):
        item = self.files[name]
        self.bundle.need(object_key(row) == item["identity"], "phase_a_identity_drift")
        item["complete"], item["final_key"] = True, self.bundle.file_key(row)

    def stage_verified(self, receipt):
        self.verified = True
        self.receipt_sha = self.bundle.digest(self.bundle.canonical(receipt))

    def _directory(self, fd, name):
        self.bundle.budget(self.until, self.clock)
        row = self.ops.fstat(fd)
        self.bundle.budget(self.until, self.clock)
        expected = self.directories[name]
        self.bundle.need(
            object_key(row) == expected["identity"]
            and stat.S_IMODE(row.st_mode) == expected["mode"],
            "phase_a_identity_drift",
        )

    def _anchor(self, parent, root, name):
        self.bundle.budget(self.until, self.clock)
        self.bundle.need(
            self.bound and name == self.path.name
            and self.bundle.directory_key(self.ops.fstat(root)) == self.root_identity
            == self.bundle.directory_key(self.ops.stat(name, dir_fd=parent, follow_symlinks=False)),
            "phase_a_identity_drift",
        )
        self.bundle.budget(self.until, self.clock)

    def _parent(self, root, name):
        current, held, prefix = root, [], []
        try:
            self._directory(root, ".")
            for part in PurePosixPath(name).parts[:-1]:
                self.bundle.budget(self.until, self.clock)
                current = self.bundle.open_child(current, part, self.ops)
                held.append(current)
                self.bundle.budget(self.until, self.clock)
                prefix.append(part)
                self._directory(current, "/".join(prefix))
            yield current
        finally:
            self.bundle._close_owned(self.ops, held)

    def _scan(self, fd, prefix, observed):
        self.bundle.budget(self.until, self.clock)
        self._directory(fd, prefix or ".")
        ledger = set(self.directories) | set(self.files)
        expected = {
            name[len(prefix) + 1 :].split("/", 1)[0] if prefix else name.split("/", 1)[0]
            for name in ledger - {"."}
            if not prefix or name.startswith(prefix + "/")
        }
        actual = self.ops.listdir(fd)
        self.bundle.budget(self.until, self.clock)
        self.bundle.need(
            len(actual) == len(set(actual)) and set(actual) == expected, "phase_a_unexpected_entry"
        )
        for child in sorted(expected):
            name = prefix + "/" + child if prefix else child
            if name in self.directories:
                child_fd = self.bundle.open_child(fd, child, self.ops)
                try:
                    self._scan(child_fd, name, observed)
                finally:
                    self.ops.close(child_fd)
            else:
                item = self.files[name]
                row = item["expected"]
                hashed, _, info = self.bundle.hash_leaf(
                    fd, child, row["bytes"], ops=self.ops, until=self.until, clock=self.clock
                )
                self.bundle.need(object_key(info) == item["identity"], "phase_a_identity_drift")
                mode = stat.S_IMODE(info.st_mode)
                exact = (
                    info.st_size == row["bytes"] and hashed == row["sha256"] and mode == row["mode"]
                )
                if item["complete"]:
                    self.bundle.need(
                        exact and self.bundle.file_key(info) == item["final_key"],
                        "phase_a_resource_drift",
                    )
                else:
                    self.bundle.need(
                        (mode == 0o600 and info.st_size <= row["bytes"]) or exact,
                        "phase_a_partial_drift",
                    )
                observed[name] = self.bundle.file_key(info)

    def cleanup(self, parent, root, name):
        """Revalidate all owned objects before any unlink; never follow/adopt unknowns."""
        try:
            root_only(self.ops)
            self.bundle.budget(self.until, self.clock)
            self.admit(self.tree, self.profile_raw, self.profile_sha)
            self._anchor(parent, root, name)
            observed = {}
            self._scan(root, "", observed)
            self._anchor(parent, root, name)
            # Revoke only the exact newly-created helper before deletion.
            helper = "chrome-sandbox"
            if helper in self.files:
                self.bundle.budget(self.until, self.clock)
                fd = self.ops.open(
                    helper,
                    self.ops.O_RDONLY | self.ops.O_NOFOLLOW
                    | self.ops.O_CLOEXEC | self.ops.O_NONBLOCK,
                    dir_fd=root,
                )
                try:
                    self.bundle.budget(self.until, self.clock)
                    self.bundle.need(
                        self.bundle.file_key(self.ops.fstat(fd)) == observed[helper],
                        "phase_a_identity_drift",
                    )
                    self._anchor(parent, root, name)
                    self.ops.fchmod(fd, 0o600)
                    self.bundle.budget(self.until, self.clock)
                    self.ops.fsync(fd)
                    self.bundle.budget(self.until, self.clock)
                    row = self.ops.fstat(fd)
                    self.bundle.need(
                        object_key(row) == self.files[helper]["identity"]
                        and stat.S_IMODE(row.st_mode) == 0o600
                        and self.bundle.file_key(row) == self.bundle.file_key(
                            self.ops.stat(helper, dir_fd=root, follow_symlinks=False)
                        ),
                        "phase_a_identity_drift",
                    )
                    self.bundle.budget(self.until, self.clock)
                    observed[helper] = self.bundle.file_key(row)
                finally:
                    self.ops.close(fd)
            leaves = sorted(
                self.files, key=lambda value: (-len(PurePosixPath(value).parts), value)
            )
            for leaf in leaves:
                self.bundle.budget(self.until, self.clock)
                with contextmanager(self._parent)(root, leaf) as location:
                    self.bundle.need(
                        self.bundle.file_key(self.ops.stat(
                            PurePosixPath(leaf).name, dir_fd=location, follow_symlinks=False
                        )) == observed[leaf],
                        "phase_a_identity_drift",
                    )
                    self._anchor(parent, root, name)
                    self.ops.unlink(PurePosixPath(leaf).name, dir_fd=location)
                    self.deleted_files += 1
                    self.bundle.budget(self.until, self.clock)
            directories = sorted(
                set(self.directories) - {"."},
                key=lambda value: (-len(PurePosixPath(value).parts), value),
            )
            for directory in directories:
                self.bundle.budget(self.until, self.clock)
                with contextmanager(self._parent)(root, directory) as location:
                    row = self.ops.stat(
                        PurePosixPath(directory).name, dir_fd=location, follow_symlinks=False
                    )
                    self.bundle.need(
                        object_key(row) == self.directories[directory]["identity"]
                        and stat.S_IMODE(row.st_mode) == self.directories[directory]["mode"],
                        "phase_a_identity_drift",
                    )
                    self._anchor(parent, root, name)
                    self.ops.rmdir(PurePosixPath(directory).name, dir_fd=location)
                    self.deleted_directories += 1
                    self.bundle.budget(self.until, self.clock)
            self._directory(root, ".")
            self.bundle.need(
                self.bundle.directory_key(self.ops.stat(
                    name, dir_fd=parent, follow_symlinks=False
                )) == self.root_identity,
                "phase_a_identity_drift",
            )
            self.bundle.budget(self.until, self.clock)
            self.ops.rmdir(name, dir_fd=parent)
            self.deleted_directories += 1
            self.bundle.budget(self.until, self.clock)
            self.ops.fsync(parent)
            self.bundle.budget(self.until, self.clock)
            try:
                self.ops.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("phase_a_prefix_still_present")
            self.bundle.budget(self.until, self.clock)
            self.cleaned = True
        except BaseException:
            raise ValueError("phase_a_cleanup_unknown") from None


def run(bundle, stream, tree, raw, pin, env, bindings, *, until, ops=None, clock=time.monotonic):
    if ops is None:
        import os
        ops = os
    cycle = PrivateCycle(bundle, tree, raw, pin, env, bindings, until, ops, clock)
    try:
        bundle.stage(
            stream, tree, raw, pin, env, bindings, until=cycle.work_until,
            ops=ops, clock=clock, _phase_a=cycle,
        )
        bundle.budget(until, clock)
        bundle.need(cycle.verified and cycle.cleaned, "phase_a_cycle_unknown")
    except BaseException:
        raise ValueError("phase_a_cycle_unknown") from None
    result = {
        "schema": RESULT_SCHEMA,
        "state": "COMPLETE_PRIVATE_STAGE_AND_CLEANUP",
        "purpose": PURPOSE,
        **json.loads(cycle.bindings_raw),
        "run": env["GITHUB_RUN_ID"],
        "attempt": env["GITHUB_RUN_ATTEMPT"],
        "package_sha256": tree["package_sha256"],
        "tree_sha256": tree["tree_sha256"],
        "profile_sha256": pin,
        "manifest_sha256": bundle.digest(cycle.tree_raw),
        "prefix": str(cycle.path),
        "root_identity": list(cycle.root_identity),
        "staged_receipt_sha256": cycle.receipt_sha,
        "deleted_files": cycle.deleted_files,
        "deleted_directories": cycle.deleted_directories,
        "prefix_absent_verified": True,
        "UI_eligible": False,
        "v3_receipt_emitted": False,
        "browser_executed": False,
        "all_OS_descendants_released": False,
        "operational_GO": False,
    }
    bundle.need(len(bundle.canonical(result)) <= 32768, "phase_a_result_budget")
    bundle.budget(until, clock)
    return result


def result_contract(bundle, raw, tree, pin, env, bindings):
    """Finite Phase A DATA only, independently checked after normal Root H1."""
    bundle.need(type(raw) is bytes and len(raw) <= 32768, "phase_a_result_budget")
    result = bundle.json_bytes(raw)
    required = {"schema", "state", "purpose", "revision", "pins_manifest_sha256",
                "context_receipt_sha256", "package_version", "signature", "key_scope",
                "root_interpreter", "run", "attempt", "package_sha256", "tree_sha256",
                "profile_sha256", "manifest_sha256", "prefix", "root_identity",
                "staged_receipt_sha256", "deleted_files", "deleted_directories",
                "prefix_absent_verified", "UI_eligible", "v3_receipt_emitted",
                "browser_executed", "all_OS_descendants_released", "operational_GO"}
    expected = {key: value for key, value in bindings.items() if key != "root_interpreter"}
    bundle.need(
        type(result) is dict and set(result) == required
        and result["schema"] == RESULT_SCHEMA
        and result["state"] == "COMPLETE_PRIVATE_STAGE_AND_CLEANUP"
        and result["purpose"] == PURPOSE
        and all(result[key] == value for key, value in expected.items())
        and result["run"] == env["GITHUB_RUN_ID"]
        and result["attempt"] == env["GITHUB_RUN_ATTEMPT"]
        and result["package_sha256"] == tree["package_sha256"]
        and result["tree_sha256"] == tree["tree_sha256"]
        and result["manifest_sha256"] == bundle.digest(bundle.canonical(tree))
        and result["profile_sha256"] == pin
        and result["prefix"] == str(bundle.root_path(env))
        and bundle.sha_field(result["staged_receipt_sha256"])
        and result["prefix_absent_verified"] is True
        and all(result[key] is False for key in ("UI_eligible", "v3_receipt_emitted",
                "browser_executed", "all_OS_descendants_released", "operational_GO")),
        "phase_a_result_binding",
    )
    identity = result["root_identity"]
    bundle.need(type(identity) is list and len(identity) == 5
                and all(type(value) is int and value >= 0 for value in identity)
                and stat.S_ISDIR(identity[2]) and stat.S_IMODE(identity[2]) == 0o700
                and identity[3] == identity[4] == 0, "phase_a_result_identity")
    counts = (
        ("deleted_files", 2 + sum(row["type"] == "regular" for row in tree["entries"])),
        ("deleted_directories", sum(row["type"] == "directory" for row in tree["entries"])),
    )
    for key, expected_count in counts:
        bundle.need(
            type(result[key]) is int and result[key] == expected_count, "phase_a_result_counts"
        )
    return result


def assert_absent(bundle, env, *, until, ops=None, clock=time.monotonic):
    """The received prefix string is never used to choose a filesystem target."""
    if ops is None:
        import os
        ops = os
    path = bundle.root_path(env)
    bundle.budget(until, clock)
    with contextmanager(bundle.root_parents)(path.parent, ops) as parent:
        bundle.budget(until, clock)
        try:
            ops.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("phase_a_prefix_still_present")
        bundle.budget(until, clock)
