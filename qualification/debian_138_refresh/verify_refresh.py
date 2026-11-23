"""Qualify the selected Debian archives and their installed ABI in an isolated build."""

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

WORK = Path("/opt/pamolive-refresh")
CACHE = Path("/opt/pamolive-apt-cache")
APT_LISTS = Path("/opt/pamolive-apt-lists")
LIB = "/usr/lib/x86_64-linux-gnu/"
MIB = 1024 * 1024
FAMILIES = {
    "glibc": (
        "2.41-12+deb13u5", "trixie", "pool/main/g/glibc/",
        ("libc6", "libc-bin", "libc6-dev", "libc-dev-bin"),
    ),
    "krb5": (
        "1.21.3-5+deb13u2", "trixie-security", "pool/updates/main/k/krb5/",
        (
            "libkrb5-3", "libk5crypto3", "libkrb5support0", "libgssapi-krb5-2", "libkrb5-dev",
            "krb5-multidev", "libgssrpc4t64", "libkadm5clnt-mit12", "libkadm5srv-mit12",
            "libkdb5-10t64",
        ),
    ),
}
PACKAGES = {
    name: (source, version, suite, pool)
    for source, (version, suite, pool, names) in FAMILIES.items()
    for name in names
}
NATIVE_FILES = {
    "libc6": (LIB + "libc.so.6", LIB + "ld-linux-x86-64.so.2"),
    "libkrb5-3": (LIB + "libkrb5.so.3.3",),
    "libk5crypto3": (LIB + "libk5crypto.so.3.1",),
    "libkrb5support0": (LIB + "libkrb5support.so.0.1",),
    "libgssapi-krb5-2": (LIB + "libgssapi_krb5.so.2.2",),
}
RELEASES = {
    "trixie": "deb.debian.org_debian_dists_trixie_InRelease",
    "trixie-security": "deb.debian.org_debian-security_dists_trixie-security_InRelease",
}
CHECKS = (
    "apt_authenticated_update", "archives_bound", "offline_install", "installed_versions_exact",
    "native_files_bound", "sdk_link", "native_smoke",
)
EXECUTION_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "HOME": "/nonexistent",
    "LC_ALL": "C",
    "LANG": "C",
    "APT_CONFIG": str(WORK / "apt.conf"),
    "DEBIAN_FRONTEND": "noninteractive",
    "KRB5_CONFIG": "/dev/null",
    "KRB5_KDC_PROFILE": "/dev/null",
    "KRB5_CCNAME": "MEMORY:pamolive-release",
}
PACKAGE_FIELDS = ("package", "source", "version", "suite", "archive_sha256", "archive_bytes")
# Projected from the independent signed-APT lab, run 45087805069, artifact 14780245532.
REVIEWED_MATERIALS_SHA256 = "60fddfe334dea69f2982980360ad5899418b5dedf16b8586c1e67311296e8b66"


class Refused(ValueError):
    """A fixed diagnostic for qualification without publishing tool output."""


def need(condition, code):
    if not condition:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def materials_sha256(selection, files):
    """Bind the verified archive identities and ELF bytes across signed index rotations."""
    materials = {"packages": selection["packages"], "installed_elf_sha256": files}
    encoded = json.dumps(materials, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha((encoded + "\n").encode("ascii"))


def is_sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def command(argv, *, phase, cap=4 * MIB, timeout=30):
    try:
        result = subprocess.run(
            argv, cwd=WORK, env=EXECUTION_ENV, capture_output=True,
            stdin=subprocess.DEVNULL, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise Refused(phase + "_timeout") from None
    need(result.returncode == 0 and len(result.stdout) <= cap, phase)
    return result.stdout


def read_regular(path, cap, *, installed=False):
    mode = path.lstat()
    need(stat.S_ISREG(mode.st_mode) and 0 < mode.st_size <= cap, "file_type_or_size")
    if installed:
        need(mode.st_uid == mode.st_gid == 0 and mode.st_mode & 0o022 == 0, "installed_permissions")
        need(path.resolve(strict=True) == path, "installed_path_alias")
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    need(len(raw) == mode.st_size, "file_length")
    return raw


def closed_json(path, value):
    with path.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        stream.write("\n")


def unique_dict(items):
    out = {}
    for key, value in items:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def load_json(path):
    return json.loads(read_regular(path, 128 * 1024), object_pairs_hook=unique_dict)


def controls(raw):
    rows = []
    for paragraph in raw.decode("utf-8").strip().split("\n\n"):
        values = {}
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                continue
            key, mark, value = line.partition(":")
            need(mark == ":" and key not in values, "apt_record_framing")
            values[key] = value.strip()
        if values:
            rows.append(values)
    return rows


def archive_name(name):
    return f"{name}_{PACKAGES[name][1]}_amd64.deb"


def apt_record(name, raw):
    source, version, suite, pool = PACKAGES[name]
    filename = pool + archive_name(name)
    candidates = [row for row in controls(raw) if "Filename" in row]
    need(len(candidates) == 1, "apt_record_ambiguous")
    row = candidates[0]
    need(
        row.get("Package") == name and row.get("Version") == version
        and row.get("Architecture") == "amd64" and row.get("Filename") == filename
        and row.get("Source") in (source, f"{source} ({version})"),
        "apt_record_identity",
    )
    size = row.get("Size", "")
    need(is_sha(row.get("SHA256")) and re.fullmatch(r"[1-9][0-9]{0,7}", size), "apt_record_digest")
    need(int(size) <= 16 * MIB, "apt_archive_cap")
    return dict(
        package=name, source=source, version=version, suite=suite,
        archive_sha256=row["SHA256"], archive_bytes=int(size),
    )


def verify_archive(item):
    name = item["package"]
    path = CACHE / archive_name(name)
    raw = read_regular(path, item["archive_bytes"])
    need(len(raw) == item["archive_bytes"] and sha(raw) == item["archive_sha256"], "archive_digest")
    data = command(
        ["/usr/bin/dpkg-deb", "-f", str(path), "Package", "Version", "Architecture", "Source"],
        phase="archive_control", cap=8192,
    )
    rows = controls(data)
    need(len(rows) == 1, "archive_control")
    row = rows[0]
    need(
        row.get("Package") == name and row.get("Version") == item["version"]
        and row.get("Architecture") == "amd64"
        and row.get("Source") in (item["source"], f"{item['source']} ({item['version']})"),
        "archive_control",
    )
    return path


def archive_bytes_by_file(path, names):
    raw = command(["/usr/bin/dpkg-deb", "--fsys-tarfile", str(path)],
                  phase="archive_payload", cap=32 * MIB)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for info in archive:
            target = "/" + info.name.removeprefix("./")
            if target not in names:
                continue
            need(target not in files and info.isreg() and info.uid == info.gid == 0
                 and info.mode & 0o022 == 0 and 0 < info.size <= 8 * MIB, "archive_payload_file")
            with archive.extractfile(info) as stream:
                raw = stream.read(8 * MIB + 1)
            need(
                len(raw) == info.size and raw[:6] == b"\x7fELF\x02\x01"
                and raw[18:20] == b"\x3e\x00", "archive_elf"
            )
            files[target] = sha(raw)
    need(set(files) == set(names), "archive_payload_file_set")
    return files


def package_refs():
    return [f"{name}={PACKAGES[name][1]}" for name in sorted(PACKAGES)]


def apt_install(*flags):
    return [
        "/usr/bin/apt-get", "-y", "--no-install-recommends", "--no-remove", "--reinstall",
        *flags, "install", *package_refs(), "gcc",
    ]


def acquire():
    need(command(["/usr/bin/dpkg", "--print-architecture"], phase="arch") == b"amd64\n", "arch")
    command(["/usr/bin/apt-get", "update"], phase="apt_update", timeout=120)
    repos = {}
    for suite, filename in RELEASES.items():
        raw = read_regular(APT_LISTS / filename, MIB)
        need(raw.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n")
             and f"\nCodename: {suite}\n".encode("ascii") in raw, "apt_release")
        repos[suite] = sha(raw)

    packages = [
        apt_record(name, command(["/usr/bin/apt-cache", "show", name + "=" + PACKAGES[name][1]],
                                 phase="apt_cache", cap=128 * 1024))
        for name in sorted(PACKAGES)
    ]
    command(apt_install("--download-only"), phase="apt_download", timeout=240)
    for item in packages:
        verify_archive(item)
    closed_json(WORK / "apt-selection.json", {"releases": repos, "packages": packages})


def validate_selection(value):
    need(type(value) is dict and set(value) == {"releases", "packages"}, "selection_shape")
    releases, packages = value["releases"], value["packages"]
    need(type(releases) is dict and set(releases) == set(RELEASES)
         and all(is_sha(row) for row in releases.values()), "selection_releases")
    need(type(packages) is list and len(packages) == len(PACKAGES), "selection_count")
    for name, item in zip(sorted(PACKAGES), packages, strict=True):
        source, version, suite, _ = PACKAGES[name]
        need(type(item) is dict and set(item) == set(PACKAGE_FIELDS), "selection_record")
        need((item["package"], item["source"], item["version"], item["suite"])
             == (name, source, version, suite), "selection_identity")
        need(is_sha(item["archive_sha256"]) and type(item["archive_bytes"]) is int
             and 0 < item["archive_bytes"] <= 16 * MIB, "selection_archive")
    return value


def validate_receipt(value):
    need(type(value) is dict and set(value) == {
        "schema", "architecture", "selection", "installed_elf_sha256", "checks",
    }, "receipt_shape")
    need(value["schema"] == "pamolive.debian-138-refresh/1"
         and value["architecture"] == "amd64", "receipt_identity")
    validate_selection(value["selection"])
    checks, files = value["checks"], value["installed_elf_sha256"]
    need(type(checks) is dict and set(checks) == set(CHECKS)
         and all(row is True for row in checks.values()), "receipt_checks")
    need(type(files) is dict and set(files) == {
        path for names in NATIVE_FILES.values() for path in names
    } and all(is_sha(row) for row in files.values()), "receipt_installed_files")
    return value


def qualify():
    selection = validate_selection(load_json(WORK / "apt-selection.json"))
    file_hashes = {}
    for item in selection["packages"]:
        path = verify_archive(item)
        names = NATIVE_FILES.get(item["package"])
        if names:
            file_hashes.update(archive_bytes_by_file(path, names))
    need(materials_sha256(selection, file_hashes) == REVIEWED_MATERIALS_SHA256,
         "unreviewed_debian_materials")
    command(apt_install("--no-download"), phase="apt_install", timeout=240)
    fmt = (
        "${binary:Package}|\t${Version}|\t${Architecture}|\t"
        "${source:Package}|\t${db:Status-Status}\n"
    )
    for item in selection["packages"]:
        name = item["package"]
        status = command(["/usr/bin/dpkg-query", "-W", f"-f={fmt}", name],
                         phase="installed_query", cap=8192)
        expected = [name, item["version"], "amd64", item["source"], "installed"]
        fields = status.decode("ascii").rstrip("\n").split("|\t")
        fields[0] = fields[0].removesuffix(":amd64")
        need(fields == expected, "installed_identity")
    for path, digest in file_hashes.items():
        installed_file = read_regular(Path(path), 8 * MIB, installed=True)
        need(sha(installed_file) == digest, "installed_bytes_differ")

    command(["/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "smoke.c",
             "-o", "smoke", "-lkrb5", "-lgssapi_krb5"], phase="sdk_build")
    need(command([str(WORK / "smoke"), *sorted(file_hashes)], phase="native_smoke", cap=1024)
         == b"debian-138-native-ok\n", "native_receipt")
    result = validate_receipt(dict(
        schema="pamolive.debian-138-refresh/1", architecture="amd64", selection=selection,
        installed_elf_sha256=file_hashes, checks=dict.fromkeys(CHECKS, True),
    ))
    receipt = WORK / "debian-138-refresh.json"
    closed_json(receipt, result)
    receipt.chmod(0o644)


def main(arguments):
    os.umask(0o077)
    if arguments == ["acquire"]:
        acquire()
    elif arguments == ["qualify"]:
        qualify()
    elif len(arguments) == 2 and arguments[0] == "validate":
        validate_receipt(load_json(Path(arguments[1])))
        print("Debian 13.8 qualification receipt validated.")
    else:
        raise Refused("command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Refused as error:
        sys.exit(str(error))
    except (OSError, ValueError, KeyError, tarfile.TarError):
        sys.exit("qualification_refused")
