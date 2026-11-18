#!/usr/bin/env bash
# Download and authenticate the single public Linux binary in a fresh CI directory.
set -euo pipefail
umask 077

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux && "${RUNNER_ARCH:-}" == X64 ]]
[[ $# == 1 && "${1%/*}" == "$RUNNER_TEMP" && ! -e "$1" && ! -L "$1" ]]
[[ "${1##*/}" =~ ^pamolive-openbao-[1-9][0-9]*-[1-9][0-9]*$ ]]
mkdir -- "$1"
cd -- "$1"
mkdir -- gpg

version=2.7.2
base="https://github.com/openbao/openbao/releases/download/v$version"
archive="openbao_${version}_linux_amd64.tar.gz"
key=openbao-gpg-pub-20240618.asc
primary=66D15FDD87287219C8E15478D200CD702853E6D0

fetch() {
  curl --disable --fail --silent --show-error --location --max-redirs 3 \
    --proto '=https' --proto-redir '=https' --max-time 90 --max-filesize "$3" \
    --output "$2" "$1"
}
fetch "$base/$archive" "$archive" 100663296
fetch "$base/$archive.gpgsig" "$archive.gpgsig" 4096
fetch "$base/$key" "$key" 16384
printf '%s  %s\n' \
  582b1f3c2fdc5afd443b2d57a225ef654de75adea609fdb66731fd582a9cbc96 "$archive" \
  a24c60b00d0e9c75582330bf241a55dad365e97c83a9135cab90b17edc87605d "$archive.gpgsig" \
  1862a196422947124282e026ea4e09d6f7c5d383b628d90c17906936e6e5a8e0 "$key" \
  | sha256sum --check --strict

gpg --no-options --homedir "$PWD/gpg" --batch --import "$key"
gpg --no-options --homedir "$PWD/gpg" --batch --no-auto-key-retrieve \
  --status-fd 1 --verify "$archive.gpgsig" "$archive" \
  | awk -v primary="$primary" '
    $1 == "[GNUPG:]" && $2 == "VALIDSIG" && $NF == primary { count++ }
    END { exit(count != 1) }
  '

# Copy only the signed executable; no archive-provided names or modes reach disk.
python -I -B - "$archive" <<'PY'
import os
import shutil
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    entries = archive.getmembers()
    binaries = [entry for entry in entries if entry.name.removeprefix("./") == "bao"]
    if len(entries) > 32 or len(binaries) != 1:
        raise SystemExit("Unexpected OpenBao archive inventory")
    binary = binaries[0]
    if not binary.isfile() or not 0 < binary.size <= 512 * 1024**2:
        raise SystemExit("Unexpected OpenBao executable")
    descriptor = os.open("bao", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(descriptor, "wb") as output, archive.extractfile(binary) as source:
        shutil.copyfileobj(source, output, 256 * 1024)
        if output.tell() != binary.size:
            raise SystemExit("Truncated OpenBao executable")
PY

[[ "$(./bao version)" == "OpenBao v$version "* ]]
