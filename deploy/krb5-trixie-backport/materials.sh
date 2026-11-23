#!/bin/sh
set -eu
umask 022
export LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive

inputs=/opt/krb5-inputs
baseline='1.21.3-5+deb13u2'
candidate="$baseline+pamolive1"
packages='libkrb5-3 libk5crypto3 libkrb5support0 libgssapi-krb5-2 libkrb5-dev krb5-multidev libgssrpc4t64 libkadm5clnt-mit12 libkadm5srv-mit12 libkdb5-10t64'
patch_commit=62196e2b269159a5465f5b8d0ed7cf6f29c3282a
preimage=55d1f0a500aae5805e23c6f18c999488c0c42ce789aebbbb156b6b4bf03e07ad
postimage=b4ac5c48469b035789b2807507a4420ae6f2d1ece847dc82f240cdb0bba4fcf3

case "${1-}" in
  acquire)
    apt-get -o APT::Get::AllowUnauthenticated=false --download-only source "krb5=$baseline"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 90 \
      --max-filesize 8192 --output mit-62196e2.patch \
      "https://github.com/krb5/krb5/commit/$patch_commit.patch"
    sha256sum --check --strict "$inputs/source.sha256"
    test "$(find . -maxdepth 1 -type f | wc -l)" -eq 5
    ;;
  build)
    cd /work
    sha256sum --check --strict "$inputs/source.sha256"
    sha256sum --check --strict "$inputs/test-patch.sha256"
    dpkg-source -x "krb5_$baseline.dsc" tree
    cd tree
    test "$(dpkg-parsechangelog -SVersion)" = "$baseline"
    dpkg-checkbuilddeps -B

    affected=src/lib/krb5/krb/rd_cred.c
    printf '%s  %s\n' "$preimage" "$affected" | sha256sum --check --strict
    install -m 0444 /work/mit-62196e2.patch debian/patches/pamolive-mit-62196e2.patch
    printf '%s\n' pamolive-mit-62196e2.patch >> debian/patches/series
    QUILT_PATCHES=debian/patches QUILT_PATCH_OPTS='--fuzz=0' quilt push
    grep -Fxq pamolive-mit-62196e2.patch .pc/applied-patches
    printf '%s  %s\n' "$postimage" "$affected" | sha256sum --check --strict

    # Reuse the established test-only compatibility patch after the real
    # builder capability probe. The runtime source stays intact.
    grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status
    if keyctl add user pamolive-krb5-backport synthetic @p >/work/probe.out 2>/work/probe.err; then
      exit 42
    else
      test "$?" -eq 1
    fi
    test ! -s /work/probe.out
    test "$(cat /work/probe.err)" = 'add_key: Operation not permitted'
    install -m 0444 "$inputs/krb5-test-keyring-seccomp.patch" \
      debian/patches/pamolive-test-keyring-seccomp.patch
    printf '%s\n' pamolive-test-keyring-seccomp.patch >> debian/patches/series
    QUILT_PATCHES=debian/patches QUILT_PATCH_OPTS='--fuzz=0' quilt push
    grep -Fxq pamolive-test-keyring-seccomp.patch .pc/applied-patches

    printf '%s\n' \
      "krb5 ($candidate) trixie; urgency=medium" '' \
      '  * Backport the MIT fix 62196e2 for CVE-2026-107778 onto Trixie.' '' \
      ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
      > debian/pamolive-changelog
    cat debian/changelog >> debian/pamolive-changelog
    mv debian/pamolive-changelog debian/changelog

    export PYTHON=/usr/bin/python3 DEB_BUILD_OPTIONS=parallel=1
    if ! dpkg-buildpackage -B -us -uc -j1 >/work/debian-build.log 2>&1; then
      tail -n 80 /work/debian-build.log >&2
      exit 1
    fi
    printf '%s  %s\n' "$postimage" "$affected" | sha256sum --check --strict
    grep -F '*** Skipping:' /work/debian-build.log > /work/skipped-tests.txt || test "$?" -eq 1
    cat /work/skipped-tests.txt
    ;;
  baseline)
    apt-get -o APT::Update::Error-Mode=any update
    set --
    for package in $packages; do set -- "$@" "$package=$baseline"; done
    apt-get install -y --no-install-recommends --no-remove build-essential "$@"
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
    install -m 0444 "/packages/krb5_${candidate}_amd64.buildinfo" /evidence/buildinfo
    install -m 0444 /packages/skipped-tests.txt /evidence/skipped-tests.txt
    ;;
  *) exit 42 ;;
esac
