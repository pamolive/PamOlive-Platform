"""Real APT dry-run plan, private authenticated lists, no installer invocation."""

import io
import re


def need(value, code):
    if not value:
        raise ValueError(code)


def parse_plan(raw, indices, before, codecs):
    need(type(raw) is bytes and len(raw) <= 1024**2 and b"\x00" not in raw, "solver_output_cap")
    text = raw.decode("utf8")
    wanted, configured = {}, {}
    # Do not implement dependency or Debian version ordering. The real APT chose these tuples.
    for line in text.splitlines():
        if line.startswith("Remv "):
            raise ValueError("solver_removal")
        if line.startswith(("Inst ", "Conf ")):
            match = re.fullmatch(
                r"(Inst|Conf) ([a-z0-9][a-z0-9+.-]*)(?::(amd64))?"
                r"(?: \[([^\]\r\n]+)\])? \(([0-9A-Za-z.+:~_-]+) ([^\r\n]+)\)",
                line,
            )
            need(match is not None and len(line) <= 4096, "solver_action_framing")
            action, name, _arch, old, version, _origin = match.groups()
            rows = wanted if action == "Inst" else configured
            need(name not in rows, "solver_duplicate_action")
            if old is not None:
                need(name in before and before[name]["version"] == old, "solver_old_version")
            rows[name] = version
    need(0 <= len(wanted) <= 512 and wanted == configured, "solver_Inst_Conf_set")
    candidates = {name: [] for name in wanted}
    for suite, raw_index in indices.items():
        for row in codecs.controls(
            io.BytesIO(raw_index), maximum=codecs.MAX_INDEX, max_line=128 * 1024
        ):
            name, version, arch = codecs.package_identity(row)
            if wanted.get(name) == version:
                candidates[name].append((suite, row, arch))
    selection = []
    for name, version in sorted(wanted.items()):
        rows = candidates[name]
        need(rows, "solver_record_missing")
        # Same tuple can legitimately be repeated in suites only with identical material bytes.
        identities = {
            (row.get("SHA256"), row.get("Size"), row.get("Filename"), arch) for _, row, arch in rows
        }
        need(len(identities) == 1, "solver_ambiguous_origin_record")
        suite, row, arch = sorted(rows, key=lambda value: value[0])[0]
        need(
            re.fullmatch(r"[a-f0-9]{64}", row.get("SHA256", ""))
            and re.fullmatch(r"[1-9][0-9]{0,9}", row.get("Size", "")),
            "solver_record_hash_size",
        )
        need(int(row["Size"]) <= codecs.MAX_DEB, "solver_DEB_cap")
        codecs.relative(row.get("Filename", ""))
        need(row["Filename"].startswith("pool/"), "solver_origin_path")
        selection.append(
            {
                "suite": suite,
                "package": name,
                "version": version,
                "architecture": arch,
                "deb": "debs/" + row["SHA256"] + ".deb",
                "record": row,
            }
        )
    return selection


def configure(runner, gate, indices, signed, transaction):
    root = transaction.WORK
    for name in ("solver-lists", "solver-lists/partial", "solver-empty", "solver-cache"):
        (root / name).mkdir(mode=0o700)
    source = []
    for suite, uri in gate.REPOSITORIES.items():
        # APT's canonical cache filename for this fixed URI; no arbitrary escaping algorithm.
        prefix = "deb.debian.org_" + ("debian-security" if suite.endswith("security") else "debian")
        prefix += "_dists_" + suite + "_"
        transaction.write_new(root / "solver-lists" / (prefix + "InRelease"), signed[suite], 0o644)
        transaction.write_new(
            root / "solver-lists" / (prefix + "main_binary-amd64_Packages"), indices[suite], 0o644
        )
        source.append(
            "deb [arch=amd64 signed-by=/expat-apt-work/debian-archive-keyring.pgp] "
            + uri
            + " "
            + suite
            + " main\n"
        )
    transaction.write_new(root / "solver.sources.list", "".join(source).encode(), 0o644)
    # Cache files are derived ONLY from already authenticated raw indices. No apt-get update.
    config = (
        transaction.apt_configuration()
        .replace(
            b'Dir::Etc::sourcelist "/dev/null";',
            b'Dir::Etc::sourcelist "/expat-apt-work/solver.sources.list";',
        )
        .replace(
            b'Dir::State::lists "/expat-apt-work/empty-lists";',
            b'Dir::State::lists "/expat-apt-work/solver-lists";',
        )
    )
    config += b'APT::Color "false";\nAPT::Get::Show-Versions "true";\n'
    transaction.write_new(root / "solver.conf", config, 0o644)
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": str(root),
        "APT_CONFIG": str(root / "solver.conf"),
        "DEBIAN_FRONTEND": "noninteractive",
    }
    stdout, _ = runner.call(
        [
            "/usr/bin/apt-get",
            "--simulate",
            "--no-download",
            "--no-remove",
            "--no-install-recommends",
            "install",
            *gate.REQUESTS,
        ],
        seconds=90,
        cap=1024**2,
        env=env,
    )
    return stdout
