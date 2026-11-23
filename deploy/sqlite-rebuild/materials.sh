#!/bin/sh
set -eu

case "${1-}" in
  acquire)
    cd /opt/sqlite-source
    mkdir -m 0755 /var/lib/apt/sqlite-source-lists
    chown _apt:root /opt/sqlite-source
    apt-get -c /opt/sqlite-inputs/source-apt.conf update
    apt-get -c /opt/sqlite-inputs/source-apt.conf --download-only source sqlite3=3.54.1-2
    ;;
  toolchain)
    apt-get update
    apt-get install -y --no-install-recommends --no-remove \
      build-essential debhelper autoconf libtool automake pkgconf chrpath lynx fakeroot libreadline-dev \
      tcl8.6-dev tcl9.0-dev libtommath-dev libicu-dev
    rm -rf /var/lib/apt/lists/*
    ;;
  prepare)
    cd /opt/sqlite-build
    sha256sum --check --strict /opt/sqlite-inputs/source.sha256
    test "$(find . -maxdepth 1 -type f | wc -l)" = 4
    dpkg-source -x sqlite3_3.54.1-2.dsc tree
    python -I -B -S /opt/sqlite-inputs/prepare.py tree
    chmod -R u+rwX,go-w /opt/sqlite-build
    chown -R 65534:65534 /opt/sqlite-build
    ;;
  *)
    exit 42
    ;;
esac
