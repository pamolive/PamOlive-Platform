#!/bin/sh
set -eu

inputs=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

case "${1-}" in
  acquire)
    cd /opt/cairo-source
    install -d -m 0755 /var/lib/apt/cairo-source-lists
    chown _apt:root /opt/cairo-source
    apt-get -c "$inputs/source-apt.conf" update
    apt-get -c "$inputs/source-apt.conf" --download-only source cairo=1.18.4-1
    sha256sum --check --strict "$inputs/source.sha256"
    test "$(find . -maxdepth 1 -type f | wc -l)" -eq 3
    ;;
  toolchain)
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources
    apt-get update
    apt-get install -y --no-install-recommends --no-remove build-essential dpkg-dev fakeroot
    apt-get build-dep -y --no-install-recommends cairo
    rm -rf /var/lib/apt/lists/*
    ;;
  prepare)
    cd /opt/cairo-build
    sha256sum --check --strict "$inputs/source.sha256"
    dpkg-source -x cairo_1.18.4-1.dsc tree
    python -I -B -S "$inputs/prepare.py" tree "$inputs/disabled-exports.txt"
    chmod 0755 "$inputs"
    chmod 0444 "$inputs/materials.sh"
    chown -R 65534:65534 /opt/cairo-build
    ;;
  build)
    dpkg-checkbuilddeps
    log=/opt/cairo-build/build.log
    if dpkg-buildpackage -b -us -uc -j2 > "$log" 2>&1; then
      tail -n 32 "$log"
    else
      code=$?
      tail -n 140 "$log" >&2
      exit "$code"
    fi
    ;;
  verify-packages)
    cd "$2"
    sha256sum --check --strict "$inputs/package.sha256"
    ;;
  *)
    exit 42
    ;;
esac
