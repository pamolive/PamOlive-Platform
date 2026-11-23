#!/bin/sh
set -eu
umask 022
export LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive

inputs=/opt/util-linux-inputs
baseline='2.41.5-0+deb13u1'
candidate="$baseline+pamolive1"
packages='bsdutils libblkid1 liblastlog2-2 libmount1 libsmartcols1 libuuid1 login mount util-linux'

case "${1-}" in
  acquire)
    apt-get -o APT::Get::AllowUnauthenticated=false --download-only source "util-linux=$baseline"
    sha256sum --check --strict "$inputs/source.sha256"
    while read -r _ name; do
      curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 60 \
        --max-filesize 16384 --output "$name" \
        "https://github.com/util-linux/util-linux/commit/${name%.patch}.patch"
    done < "$inputs/patches.sha256"
    sha256sum --check --strict "$inputs/patches.sha256"
    ;;
  build)
    cd /work
    sha256sum --check --strict "$inputs/source.sha256"
    sha256sum --check --strict "$inputs/patches.sha256"
    dpkg-source -x "util-linux_$baseline.dsc" tree
    cd tree
    test "$(dpkg-parsechangelog -SVersion)" = "$baseline"
    dpkg-checkbuilddeps -B
    sha256sum --check --strict "$inputs/preimage.sha256"

    while read -r _ name; do
      patch="debian/patches/pamolive-$name"
      if [ "$name" = '286dd3ff41526b582ef48830de239dffbaa61f90.patch' ]; then
        # The 2.41 stable change already supplies its close-on-exec hunk.
        grep -Fq 'open(fdpath, O_WRONLY | O_APPEND | O_CLOEXEC)' sys-utils/nsenter.c
        awk '
          /^@@ / { skipping = ($0 ~ /^@@ -483,7 [+]485,7 @@ /); if (skipping) omitted++ }
          !skipping { print }
          END { if (omitted != 1) exit 1 }
        ' "/work/$name" > "$patch"
        printf '%s  %s\n' 4c7cef5c1b15d8dd5a3144b1fe51eee5aa8c62b8b0b8fa31df00e4b13f290ea2 "$patch" \
          | sha256sum --check --strict
      else
        install -m 0444 "/work/$name" "$patch"
      fi
      printf '%s\n' "pamolive-$name" >> debian/patches/series
      QUILT_PATCHES=debian/patches QUILT_PATCH_OPTS='--fuzz=0' quilt push
    done < "$inputs/patches.sha256"
    sha256sum --check --strict "$inputs/postimage.sha256"

    printf '%s\n' \
      "util-linux ($candidate) trixie; urgency=medium" '' \
      '  * Backport the reviewed stable libmount and nsenter security changes.' '' \
      ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
      > debian/pamolive-changelog
    cat debian/changelog >> debian/pamolive-changelog
    mv debian/pamolive-changelog debian/changelog

    export DEB_BUILD_OPTIONS=parallel=2
    if ! dpkg-buildpackage -B -us -uc -j2 >/work/debian-build.log 2>&1; then
      grep -niE 'error:|undefined reference|No rule to make|No such file|Permission denied|FAILED' \
        /work/debian-build.log | sed -n '1,50p' >&2
      tail -n 50 /work/debian-build.log >&2
      exit 1
    fi
    sha256sum --check --strict "$inputs/postimage.sha256"
    if ! grep -Eq '^[[:space:]]*All [1-9][0-9]* tests PASSED[[:space:]]*$' /work/debian-build.log; then
      printf '%s\n' 'Debian util-linux test completion missing.' >&2
      tail -n 45 /work/debian-build.log >&2
      exit 1
    fi
    grep -Ei '(All [0-9]+ tests PASSED|skipped|[[:space:]]SKIP|KNOWN FAILED)' \
      /work/debian-build.log > /work/test-summary.txt
    ;;
  baseline)
    apt-get -o APT::Update::Error-Mode=any update
    apt-get install -y --no-install-recommends --no-remove \
      "bsdutils=1:$baseline" "login=1:4.16.0-2+really$baseline" \
      "libblkid1=$baseline" "liblastlog2-2=$baseline" "libmount1=$baseline" \
      "libsmartcols1=$baseline" "libuuid1=$baseline" "mount=$baseline" "util-linux=$baseline"
    rm -rf /var/lib/apt/lists/*
    ;;
  export)
    for package in $packages; do
      set -- /packages/"$package"_*_amd64.deb
      test "$#" -eq 1
      test -f "$1"
      test ! -L "$1"
      test "$(dpkg-deb -f "$1" Package)" = "$package"
      test "$(dpkg-deb -f "$1" Architecture)" = 'amd64'
      actual="$(dpkg-deb -f "$1" Version)"
      case "$package" in
        bsdutils) test "$actual" = "1:$candidate" ;;
        login) test "$actual" = "1:4.16.0-2+really$candidate" ;;
        *) test "$actual" = "$candidate" ;;
      esac
      install -m 0444 "$1" "/evidence/$package.deb"
    done
    install -m 0444 "/packages/util-linux_${candidate}_amd64.buildinfo" /evidence/buildinfo
    install -m 0444 /packages/test-summary.txt /evidence/test-summary.txt
    cd /evidence
    sha256sum ./buildinfo ./test-summary.txt ./*.deb > checksums.sha256
    ;;
  install)
    cd /packages
    sha256sum --check --strict checksums.sha256
    apt-get install -y --no-download --no-install-recommends --no-remove /packages/*.deb
    test -z "$(dpkg --audit)"
    ;;
  *) exit 42 ;;
esac
