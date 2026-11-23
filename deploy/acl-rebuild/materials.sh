#!/bin/sh
set -eu

case "${1-}" in
  acquire)
    cd /opt/acl-source
    mkdir -m 0755 /var/lib/apt/acl-source-lists
    chown _apt:root /opt/acl-source
    apt-get -c /opt/acl-inputs/source-apt.conf update
    apt-get -c /opt/acl-inputs/source-apt.conf --download-only source acl=2.4.0-1
    ;;
  toolchain)
    apt-get update
    apt-get install -y --no-install-recommends --no-remove \
      build-essential debhelper gettext libattr1-dev fakeroot
    rm -rf /var/lib/apt/lists/*
    ;;
  prepare)
    cd /opt/acl-build
    sha256sum --check --strict /opt/acl-inputs/source.sha256
    test "$(find . -maxdepth 1 -type f | wc -l)" = 4
    dpkg-source -x acl_2.4.0-1.dsc tree
    python -I -B -S /opt/acl-inputs/prepare.py tree
    chmod -R u+rwX,go-w /opt/acl-build
    chown -R 65534:65534 /opt/acl-build
    ;;
  *)
    exit 42
    ;;
esac
