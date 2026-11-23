#!/bin/sh
set -eu
umask 022
export LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive

inputs=/opt/openssl-inputs
baseline='3.5.9-1~deb13u1'
candidate="$baseline+pamolive1"
packages='libssl3t64 libssl-dev openssl openssl-provider-legacy'

case "${1-}" in
  acquire)
    apt-get -o APT::Get::AllowUnauthenticated=false --download-only source "openssl=$baseline"
    sha256sum --check --strict "$inputs/source.sha256"
    test "$(find . -maxdepth 1 -type f | wc -l)" -eq 4
    python -I -B -S "$inputs/patches.py" acquire
    ;;
  build)
    cd /work
    sha256sum --check --strict "$inputs/source.sha256"
    dpkg-source -x "openssl_$baseline.dsc" tree
    cd tree
    test "$(dpkg-parsechangelog -SVersion)" = "$baseline"
    dpkg-checkbuilddeps -B
    sha256sum --check --strict "$inputs/preimage.sha256"
    python -I -B -S "$inputs/patches.py" prepare
    QUILT_PATCHES=debian/patches QUILT_PATCH_OPTS='--fuzz=0' quilt push -a
    sha256sum --check --strict "$inputs/postimage.sha256"

    printf '%s\n' \
      "openssl ($candidate) trixie; urgency=medium" '' \
      '  * Apply the reviewed OpenSSL 3.5 security deltas.' '' \
      ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
      > debian/pamolive-changelog
    cat debian/changelog >> debian/pamolive-changelog
    mv debian/pamolive-changelog debian/changelog

    export DEB_BUILD_OPTIONS=parallel=2
    if ! dpkg-buildpackage -B -us -uc -j2 >/work/debian-build.log 2>&1; then
      tail -n 80 /work/debian-build.log >&2
      exit 1
    fi
    sha256sum --check --strict "$inputs/postimage.sha256"
    grep -Fxq 'Result: PASS' /work/debian-build.log
    if grep -Fiq 'Skipping tests' /work/debian-build.log; then exit 1; fi
    grep -E '(/SKIP| skipped: |Result:)' /work/debian-build.log > /work/test-summary.txt
    ;;
  baseline)
    apt-get -o APT::Update::Error-Mode=any update
    set --
    for package in $packages; do set -- "$@" "$package=$baseline"; done
    apt-get install -y --no-install-recommends --no-remove "$@"
    rm -rf /var/lib/apt/lists/*
    ;;
  install)
    set --
    for package in $packages; do
      path="/packages/${package}_${candidate}_amd64.deb"
      test "$(dpkg-deb -f "$path" Package)" = "$package"
      test "$(dpkg-deb -f "$path" Version)" = "$candidate"
      test "$(dpkg-deb -f "$path" Architecture)" = amd64
      set -- "$@" "$path"
      install -m 0444 "$path" "/evidence/$package.deb"
    done
    dpkg --install "$@"
    test -z "$(dpkg --audit)"
    install -m 0444 "/packages/openssl_${candidate}_amd64.buildinfo" /evidence/buildinfo
    install -m 0444 /packages/test-summary.txt /evidence/test-summary.txt
    ;;
  *) exit 42 ;;
esac
