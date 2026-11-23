"""Read-only eligibility check for the stock Chrome executable on a hosted runner."""

import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from qualification.p1g_headless import chrome_bundle, chrome_sandbox_probe  # noqa: E402
from qualification.p1g_headless import lab_support as support  # noqa: E402

BRANCH = "refs/heads/agent/p1g-chrome-canonical-preflight"
BINARY = Path("/opt/google/chrome/chrome")


def inspect_executable():
    inspected = []

    def refused(code):
        return {"state": "REFUSED", "code": code, "path_metadata": inspected}

    # Establish trust from / downwards before opening any executable for hashing.
    for path in (*reversed(BINARY.parents), BINARY):
        try:
            row = path.lstat()
        except FileNotFoundError:
            return refused("canonical_path_missing")
        except OSError:
            return refused("canonical_path_unreadable")
        executable = path == BINARY
        required_type = stat.S_ISREG if executable else stat.S_ISDIR
        inspected.append(
            {
                "path": path.as_posix(),
                "uid": row.st_uid,
                "gid": row.st_gid,
                "mode": stat.S_IMODE(row.st_mode),
                "required_type_present": required_type(row.st_mode),
            }
        )
        if (
            not required_type(row.st_mode)
            or row.st_uid != 0
            or row.st_gid != 0
            or row.st_mode & 0o7022
        ):
            return refused(
                "canonical_executable_untrusted" if executable else "canonical_ancestor_untrusted"
            )
        if executable and (stat.S_IMODE(row.st_mode) != 0o755 or row.st_nlink != 1):
            return refused("canonical_executable_untrusted")

    if row.st_size != chrome_sandbox_probe.CHROME_BYTES:
        return refused("canonical_elf_size_mismatch")
    try:
        pin = support.tool_pin(BINARY, cap=chrome_sandbox_probe.CHROME_BYTES)
    except (OSError, ValueError):
        return refused("canonical_elf_read_refused")
    if (pin["uid"], pin["mode"], pin["bytes"]) != (0, 0o755, row.st_size):
        return refused("canonical_elf_read_refused")
    if pin["sha256"] != chrome_sandbox_probe.CHROME_SHA:
        return refused("canonical_elf_hash_mismatch")
    return {"state": "ELF_PIN_MATCH", "executable": pin, "path_metadata": inspected}


def main():
    support.need(
        sys.platform == "linux" and os.getuid() == os.geteuid() > 0, "canonical_preflight_nonroot"
    )
    identity = chrome_sandbox_probe.run_identity(os.environ, branch=BRANCH)
    scratch = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    report = {
        "schema": "pamolive.chrome-canonical-preflight/1",
        **identity,
        "browser_version_pin": chrome_sandbox_probe.BROWSER_VERSION,
        "installation_tree_verified": False,
        "browser_executed": False,
        "operational_GO": False,
        **inspect_executable(),
    }
    path = scratch / f"pamolive-canonical-{identity['run']}-{identity['attempt']}.json"
    support.fresh_write(path, chrome_bundle.canonical(report))
    return 0 if report["state"] == "ELF_PIN_MATCH" else 42


if __name__ == "__main__":
    raise SystemExit(main())
