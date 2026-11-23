#!/bin/sh
set -eu

source_version='2.1.28+dfsg1-12'
version="$source_version~pamolive13u1"
inputs=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

case "${1-}" in
  acquire)
    cd /opt/sasl-source
    install -d -m 0755 /var/lib/apt/sasl-source-lists
    chown _apt:root /opt/sasl-source
    apt-get -c "$inputs/source-apt.conf" update
    apt-get -c "$inputs/source-apt.conf" --download-only source "cyrus-sasl2=$source_version"
    sha256sum --check --strict "$inputs/source.sha256"
    test "$(find . -maxdepth 1 -type f | wc -l)" -eq 3
    ;;
  toolchain)
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources
    apt-get update
    apt-get install -y --no-install-recommends --no-remove build-essential dpkg-dev fakeroot
    apt-get -P nodoc build-dep -y --arch-only --no-install-recommends cyrus-sasl2
    rm -rf /var/lib/apt/lists/*
    ;;
  prepare)
    cd /opt/sasl-build
    sha256sum --check --strict "$inputs/source.sha256"
    dpkg-source -x "cyrus-sasl2_$source_version.dsc" tree
    cd tree
    test "$(dpkg-parsechangelog -SVersion)" = "$source_version"
    test -s debian/patches/0043-CVE-2026-107161.patch
    grep -Fxq '0043-CVE-2026-107161.patch' .pc/applied-patches
    printf '%s\n' \
      "cyrus-sasl2 ($version) trixie; urgency=medium" '' \
      '  * Rebuild the Debian source on Trixie.' '' \
      ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
      > debian/pamolive-changelog
    cat debian/changelog >> debian/pamolive-changelog
    mv debian/pamolive-changelog debian/changelog
    # The subsequent build runs as nobody, including from a private build context.
    chmod 0755 "$inputs"
    chmod 0444 "$inputs/materials.sh"
    chown -R 65534:65534 /opt/sasl-build
    ;;
  build)
    dpkg-checkbuilddeps -B -P nodoc
    dpkg-buildpackage -B --build-profiles=nodoc -us -uc -j2
    ;;
  install-runtime|install-sdk)
    mode=$1
    cd "$2"
    sha256sum --check --strict "$inputs/package.sha256"
    set -- "libsasl2-modules-db_${version}_amd64.deb" "libsasl2-2_${version}_amd64.deb"
    if test "$mode" = install-sdk; then
      set -- "$@" "libsasl2-dev_${version}_amd64.deb"
    fi
    dpkg --install "$@"
    test -z "$(dpkg --audit)"
    ;;
  *)
    exit 42
    ;;
esac
