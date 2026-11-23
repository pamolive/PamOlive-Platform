"""Compare the installed Trixie ncurses commands with the exact package archives."""

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

BASELINE = "6.5+20250216-2"
CANDIDATE = BASELINE + "+pamolive1"
PACKAGES = {
    "ncurses-bin": "amd64",
    "libtinfo6": "amd64",
    "libncursesw6": "amd64",
    "ncurses-base": "all",
}
LIBRARIES = ("libtinfo.so.6", "libncursesw.so.6")
REQUIRED_COMMANDS = {"infocmp", "tic", "tput"}
BINDIR = Path("/usr/bin")
LIBDIR = Path("/usr/lib/x86_64-linux-gnu")
EVIDENCE = Path("/evidence")
PACKAGE_ARCHIVES = Path("/packages")
MATERIALS = {"ncurses-bin.deb", "stock-ncurses-bin.deb", "buildinfo", "test-summary.txt"}
MAX_FILE = 8 * 1024**2
MAX_PAYLOAD = 16 * 1024**2
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
TERM = "pamolive-ncurses-ci"
TERMINFO = """pamolive-ncurses-ci|PamOlive synthetic terminal,
	am, cols#91, lines#42,
	clear=\\E[9J, cup=\\E[%i%p1%d;%p2%dH, is2=\\E[?1h,
"""


def require(condition, code):
    if not condition:
        raise ValueError(code)


def run(argv, *, env=ENVIRONMENT, limit=MAX_FILE):
    output = subprocess.run(
        argv,
        check=True,
        timeout=15,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout
    require(len(output) <= limit, "ncurses_command_output")
    return output


def hash_file(path, limit=MAX_FILE):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "ncurses_regular_file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_checksums():
    manifest = PACKAGE_ARCHIVES / "checksums.sha256"
    require(
        {path.name for path in PACKAGE_ARCHIVES.iterdir()} == MATERIALS | {manifest.name},
        "ncurses_archive_set",
    )
    manifest_hash = hash_file(manifest, 4096)
    sums = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([A-Za-z0-9.-]+)", line)
        require(match is not None, "ncurses_archive_manifest")
        digest, name = match.groups()
        require(name in MATERIALS and name not in sums, "ncurses_archive_manifest")
        sums[name] = digest
    require(
        sums.keys() == MATERIALS
        and all(hash_file(PACKAGE_ARCHIVES / name) == digest for name, digest in sums.items()),
        "ncurses_archive_digest",
    )
    return {**sums, manifest.name: manifest_hash}


def installed(version):
    format_string = (
        "${source:Package}\t${Version}\t${Architecture}\t${Status}\t${Pre-Depends}\t${Depends}\n"
    )
    result = {}
    for name, arch in PACKAGES.items():
        expected = version if name == "ncurses-bin" else BASELINE
        observed = run(["/usr/bin/dpkg-query", "-W", "-f=" + format_string, name], limit=4096)
        fields = observed.decode("utf-8").removesuffix("\n").split("\t")
        require(
            len(fields) == 6 and fields[:4] == ["ncurses", expected, arch, "install ok installed"],
            "ncurses_package_identity",
        )
        result[name] = {
            "version": expected,
            "architecture": arch,
            "pre_depends": " ".join(fields[4].split()),
            "depends": " ".join(fields[5].split()),
        }
    return result


def command_name(value):
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", value) is not None


def archive_commands(archive_path):
    payload = run(["/usr/bin/dpkg-deb", "--fsys-tarfile", str(archive_path)], limit=MAX_PAYLOAD)
    result = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name.removeprefix("./"))
            if path.parent != PurePosixPath("usr/bin"):
                continue
            name = path.name
            require(
                command_name(name)
                and name not in result
                and member.uid == member.gid == 0
                and (member.issym() or not member.mode & 0o7022),
                "ncurses_archive_command_metadata",
            )
            row = {"uid": member.uid, "gid": member.gid, "mode": member.mode}
            if member.isfile():
                require(64 <= member.size <= MAX_FILE, "ncurses_archive_command_size")
                with archive.extractfile(member) as stream:
                    row.update(
                        type="file", sha256=hashlib.file_digest(stream, "sha256").hexdigest()
                    )
            elif member.islnk() or member.issym():
                link = member.linkname
                if member.islnk():
                    target = PurePosixPath(link.removeprefix("./"))
                    require(
                        target.parent == PurePosixPath("usr/bin"), "ncurses_archive_command_link"
                    )
                    row.update(type="hardlink", target=target.name)
                else:
                    target = PurePosixPath(link)
                    require(
                        target.parent in (PurePosixPath("."), PurePosixPath("/usr/bin")),
                        "ncurses_archive_command_link",
                    )
                    row.update(type="symlink", target=target.name, link=link)
            else:
                raise ValueError("ncurses_archive_command_type")
            result[name] = row
    require(
        REQUIRED_COMMANDS <= result.keys() and result["infocmp"]["type"] == "file",
        "ncurses_core_command_set",
    )
    for row in result.values():
        if row["type"] != "file":
            require(
                result.get(row["target"], {}).get("type") == "file", "ncurses_archive_command_link"
            )
    return result


def elf_contract(path):
    with path.open("rb") as stream:
        header = stream.read(64)
    require(
        len(header) == 64
        and header[:6] == b"\x7fELF\x02\x01"
        and header[18:20] == b"\x3e\x00"
        and header[16:18] in (b"\x02\x00", b"\x03\x00"),
        "ncurses_elf_identity",
    )
    rows = run(["/usr/bin/readelf", "--dynamic", "--dyn-syms", "--wide", str(path)])
    tags = {name: [] for name in ("NEEDED", "SONAME", "RPATH", "RUNPATH")}
    exports, imports = [], set()
    for line in rows.decode("utf-8").splitlines():
        match = re.search(r"\((NEEDED|SONAME|RPATH|RUNPATH)\).*\[([^\]]+)\]\s*$", line)
        if match:
            tag, value = match.groups()
            tags[tag].append(value)
        fields = line.split(maxsplit=7)
        if len(fields) != 8 or not re.fullmatch(r"[0-9]+:", fields[0]):
            continue
        _, _, size, kind, binding, visibility, section, name = fields
        if section == "UND" and "@" in name:
            imports.add(name.rsplit("@", 1)[1].split()[0])
        if section != "UND" and binding in {"GLOBAL", "WEAK", "UNIQUE"}:
            exports.append(
                [name, kind, binding, visibility, size if kind in {"OBJECT", "TLS"} else ""]
            )
    require(tags["NEEDED"] and imports, "ncurses_elf_dependencies")
    return {
        "type": header[16],
        "dynamic": tags,
        "exports": sorted(exports),
        "required_versions": sorted(imports),
    }


def inspect_commands(archive_path):
    archived = archive_commands(archive_path)
    listed = run(["/usr/bin/dpkg-query", "-L", "ncurses-bin"]).decode("utf-8").splitlines()
    names = {PurePosixPath(path).name for path in listed if PurePosixPath(path).parent == BINDIR}
    require(names == archived.keys(), "ncurses_installed_command_set")
    commands = {}
    for name, row in archived.items():
        path = BINDIR / name
        info = path.lstat()
        require(
            (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            == (row["uid"], row["gid"], row["mode"]),
            "ncurses_installed_command_mode",
        )
        kind = row["type"]
        if kind == "symlink":
            require(
                stat.S_ISLNK(info.st_mode)
                and os.readlink(path) == row["link"]
                and path.resolve(strict=True) == BINDIR / row["target"],
                "ncurses_installed_link",
            )
            commands[name] = row
        elif kind == "hardlink":
            target = (BINDIR / row["target"]).lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and stat.S_ISREG(target.st_mode)
                and (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino),
                "ncurses_installed_link",
            )
            commands[name] = row
        else:
            require(hash_file(path) == row["sha256"], "ncurses_installed_elf_digest")
            commands[name] = {**row, "elf": elf_contract(path)}
    return commands


def inspect_libraries():
    result = {}
    for name in LIBRARIES:
        alias = LIBDIR / name
        require(alias.is_symlink(), "ncurses_library_alias")
        path = alias.resolve(strict=True)
        require(path.parent == LIBDIR and path.name.startswith(name + "."), "ncurses_library_alias")
        info = path.lstat()
        digest = hash_file(path)
        require(elf_contract(path)["dynamic"]["SONAME"] == [name], "ncurses_library_soname")
        result[name] = {
            "path": str(path),
            "link": os.readlink(alias),
            "sha256": digest,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode),
        }
    return result


def smoke():
    with tempfile.TemporaryDirectory(prefix="ncurses-qualification-") as directory:
        root = Path(directory)
        source, compiled = root / "source", root / "terminfo"
        source.write_text(TERMINFO, encoding="ascii")
        compiled.mkdir()
        env = {
            **ENVIRONMENT,
            "HOME": directory,
            "TERM": TERM,
            "TERMINFO": str(compiled),
            "TERMINFO_DIRS": str(compiled),
        }
        run([str(BINDIR / "tic"), "-o", str(compiled), str(source)], env=env, limit=8192)
        info = run([str(BINDIR / "infocmp"), "-I", "-A", str(compiled), TERM], env=env, limit=8192)
        require(
            all(token in info for token in (TERM.encode(), b"cols#91", b"lines#42", b"is2=")),
            "ncurses_infocmp_source",
        )
        analysis = run(
            [str(BINDIR / "infocmp"), "-i", "-A", str(compiled), TERM], env=env, limit=8192
        )
        require(analysis.strip(), "ncurses_infocmp_initialization")
        tput = [str(BINDIR / "tput"), "-T", TERM]
        require(
            run([*tput, "cols"], env=env, limit=8192) == b"91\n"
            and run([*tput, "clear"], env=env, limit=8192) == b"\x1b[9J"
            and run([*tput, "cup", "1", "2"], env=env, limit=8192) == b"\x1b[2;3H",
            "ncurses_tput_terminfo",
        )
    return {"tic": True, "infocmp_I": True, "infocmp_i": True, "tput": True}


def capture(version, archive, checksums):
    return {
        "packages": installed(version),
        "archives": checksums,
        "commands": inspect_commands(PACKAGE_ARCHIVES / archive),
        "libraries": inspect_libraries(),
        "synthetic_terminfo": smoke(),
    }


def compare(stock, candidate):
    require(stock["archives"] == candidate["archives"], "ncurses_archive_changed")
    require(stock["libraries"] == candidate["libraries"], "ncurses_stock_libraries_changed")
    before, after = stock["packages"], candidate["packages"]
    for name in PACKAGES:
        if name == "ncurses-bin":
            require(
                before[name] == {**after[name], "version": BASELINE},
                "ncurses_package_dependencies_changed",
            )
        else:
            require(before[name] == after[name], "ncurses_stock_package_changed")
    original, rebuilt = stock["commands"], candidate["commands"]
    require(original.keys() == rebuilt.keys(), "ncurses_command_set_changed")
    for name, command in original.items():
        require(
            {k: v for k, v in command.items() if k != "sha256"}
            == {k: v for k, v in rebuilt[name].items() if k != "sha256"},
            "ncurses_command_abi_or_metadata_changed",
        )
    require(
        original["infocmp"]["sha256"] != rebuilt["infocmp"]["sha256"], "ncurses_infocmp_unchanged"
    )


def record(name, data):
    with (EVIDENCE / name).open("x", encoding="ascii") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(args):
    require(args in (["stock"], ["candidate"]), "ncurses_mode")
    require(
        sys.platform == "linux" and os.getuid() == os.geteuid() == 65534, "ncurses_execution_uid"
    )
    checksums = archive_checksums()
    if args == ["stock"]:
        record("stock.json", capture(BASELINE, "stock-ncurses-bin.deb", checksums))
        return
    stock_path = EVIDENCE / "stock.json"
    stock_sha = hash_file(stock_path)
    before = json.loads(stock_path.read_bytes())
    after = capture(CANDIDATE, "ncurses-bin.deb", checksums)
    compare(before, after)
    record("candidate.json", after)
    record(
        "qualification.json",
        {
            "schema": "pamolive.ncurses-trixie-runtime/1",
            "packages": after["packages"],
            "archives": checksums,
            "buildinfo_sha256": checksums["buildinfo"],
            "test_summary_sha256": checksums["test-summary.txt"],
            "stock_sha256": stock_sha,
            "candidate_sha256": hash_file(EVIDENCE / "candidate.json"),
            "infocmp_sha256": after["commands"]["infocmp"]["sha256"],
            "native_abi_preserved": True,
            "synthetic_terminfo_verified": True,
            "product_image_verified": False,
            "release_admitted": False,
        },
    )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        code = str(error)
        print(
            code if re.fullmatch(r"ncurses_[a-z_]+", code) else "ncurses_qualification_refused",
            file=sys.stderr,
        )
        raise SystemExit(42)
