#!/bin/sh
set -eu
umask 022
export LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive

inputs=/opt/glibc-inputs
baseline='2.41-12+deb13u5'
candidate="$baseline+pamolive1"
packages='libc6 libc-bin libc-dev-bin libc6-dev'
buildinfo="glibc_${candidate}_amd64.buildinfo"
backport='pamolive-CVE-2026-84243.patch'
upstream='https://raw.githubusercontent.com/bminor/glibc'
commit='03067f3c5e39aec5ec250a44bc1b395a1afd45e8'
parent='b941c17c0356f03946afb9c080242f89557bc0b2'

regular() {
  test -f "$1"
  test ! -L "$1"
}

verify_package() {
  regular "$1"
  test "$(dpkg-deb -f "$1" Package)" = "$2"
  test "$(dpkg-deb -f "$1" Source)" = glibc
  test "$(dpkg-deb -f "$1" Architecture)" = amd64
  test "$(dpkg-deb -f "$1" Version)" = "$3"
  if test "$2" = libc-bin; then
    test "$(dpkg-deb -f "$1" Essential)" = yes
  fi
  if test "$2" = libc6-dev; then
    depends=$(dpkg-deb -f "$1" Depends)
    case "$depends" in
      "libc6 (= $3), libc-dev-bin (= $3), "*) ;;
      *) return 1 ;;
    esac
  fi
}

verify_installed() {
  info=$(dpkg-query -W -f='${source:Package}|${Version}|${Architecture}|${Status}' "$1:amd64")
  test "$info" = "glibc|$2|amd64|install ok installed"
}

verify_buildinfo() (
  regular "$1"
  grep -Fxq 'Source: glibc' "$1"
  grep -Fxq "Version: $candidate" "$1"
  for package in $packages; do
    name="${package}_${candidate}_amd64.deb"
    if test "$2" = exported; then
      archive="./$package.deb"
    else
      archive="./$name"
    fi
    regular "$archive"
    checksum=$(sha256sum < "$archive")
    length=$(wc -c < "$archive")
    awk -v name="$name" -v sha="${checksum%% *}" -v size="$length" '
      $0 == "Checksums-Sha256:" { checksums = 1; next }
      /^[^[:space:]]/ { checksums = 0 }
      checksums && NF == 3 && $3 == name {
        seen++; if ($1 == sha && $2 == size) matched++
      }
      END { exit !(seen == 1 && matched == 1) }
    ' "$1"
  done
)

export_checksums() {
  sha256sum ./buildinfo ./test-summary.txt \
    ./libc6.deb ./libc-bin.deb ./libc-dev-bin.deb ./libc6-dev.deb \
    ./stock-libc6.deb ./stock-libc-bin.deb ./stock-libc-dev-bin.deb ./stock-libc6-dev.deb
}

summarize_tests() {
  # Debian deliberately retains suite failures in some stable-update builds.
  # The package build status alone is therefore insufficient for the receipt.
  printf '%s\n' 'debian_build=passed'
  regular build-tree/amd64-libc/tests.sum
  for flavour in libc i386 x32; do
    log="build-tree/amd64-$flavour/tests.sum"
    if test -f "$log"; then
      regular "$log"
      awk -v flavour="$flavour" -f "$inputs/test-summary.awk" "$log"
    else
      printf 'suite.%s.result=no_tests_sum\n' "$flavour"
    fi
  done
  sed -n \
    -e '/^CHECK SUMMARY$/p' \
    -e '/^check for .* \(passed\|failed\)$/p' \
    -e '/tests have been skipped\|skipping tests\|Tests have been disabled/p' \
    /work/debian-build.log
}

case "${1-}" in
  acquire)
    cd /work
    install -d -m 0755 /var/lib/apt/glibc-source-lists
    apt_conf="$inputs/source-apt.conf"
    apt-get -c "$apt_conf" update
    apt-get -c "$apt_conf" --download-only source "glibc=$baseline"
    sha256sum --check --strict "$inputs/source.sha256"
    for package in $packages; do
      apt-get -c "$apt_conf" download "$package:amd64=$baseline"
      archive="${package}_${baseline}_amd64.deb"
      stock="stock-$package.deb"
      regular "$archive"
      test ! -e "$stock"
      test ! -L "$stock"
      mv -- "$archive" "$stock"
    done
    sha256sum --check --strict "$inputs/stock.sha256"
    for package in $packages; do
      verify_package "./stock-$package.deb" "$package" "$baseline"
    done
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 60 \
      --max-filesize 65536 --output dcigettext-before.c "$upstream/$parent/intl/dcigettext.c"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 60 \
      --max-filesize 65536 --output dcigettext-after.c "$upstream/$commit/intl/dcigettext.c"
    sha256sum --check --strict "$inputs/upstream.sha256"
    ;;
  build)
    test "$(id -u)" -ne 0
    cd /work
    sha256sum --check --strict "$inputs/source.sha256"
    sha256sum --check --strict "$inputs/upstream.sha256"
    sha256sum --check --strict "$inputs/stock.sha256"
    dpkg-source -x "glibc_$baseline.dsc" tree
    cd tree
    test "$(dpkg-parsechangelog -SVersion)" = "$baseline"
    unset DEB_BUILD_PROFILES
    export DEB_BUILD_OPTIONS=parallel=2
    dpkg-checkbuilddeps -B
    sha256sum --check --strict "$inputs/preimage.sha256"

    # Both input blobs are the production file. The diff excludes every other commit path.
    diff_status=0
    diff -u --label a/intl/dcigettext.c --label b/intl/dcigettext.c \
      /work/dcigettext-before.c /work/dcigettext-after.c \
      > "debian/patches/$backport" || diff_status=$?
    test "$diff_status" -eq 1
    sha256sum --check --strict "$inputs/patch.sha256"
    printf '%s\n' "$backport" >> debian/patches/series
    QUILT_PATCHES=debian/patches QUILT_PATCH_OPTS='--fuzz=0' quilt push
    sha256sum --check --strict "$inputs/postimage.sha256"

    printf '%s\n' \
      "glibc ($candidate) trixie; urgency=medium" '' \
      '  * Backport the gettext locale validation fix for CVE-2026-84243.' '' \
      ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
      > debian/pamolive-changelog
    cat debian/changelog >> debian/pamolive-changelog
    mv debian/pamolive-changelog debian/changelog

    if ! dpkg-buildpackage -B -us -uc -j2 >/work/debian-build.log 2>&1; then
      grep -E '^CHECK SUMMARY$|^check for .* (passed|failed)$' /work/debian-build.log >&2 || :
      tail -n 80 /work/debian-build.log >&2
      exit 1
    fi
    sha256sum --check --strict "$inputs/postimage.sha256"
    summarize_tests > /work/test-summary.txt
    cd /work
    for package in $packages; do
      verify_package "./${package}_${candidate}_amd64.deb" "$package" "$candidate"
    done
    verify_buildinfo "./$buildinfo" versioned
    ;;
  export)
    cd /packages
    sha256sum --check --strict "$inputs/stock.sha256"
    verify_buildinfo "./$buildinfo" versioned
    regular ./test-summary.txt
    grep -Fxq 'debian_build=passed' ./test-summary.txt
    grep -Eq '^suite\.libc\.result=(no_unexpected_failures|reported_failures)$' ./test-summary.txt
    for package in $packages; do
      verify_package "./${package}_${candidate}_amd64.deb" "$package" "$candidate"
      verify_package "./stock-$package.deb" "$package" "$baseline"
    done
    for name in buildinfo test-summary.txt checksums.sha256 $packages; do
      case "$name" in
        buildinfo|test-summary.txt|checksums.sha256) outputs="$name" ;;
        *) outputs="$name.deb stock-$name.deb" ;;
      esac
      for output in $outputs; do
        test ! -e "/evidence/$output"
        test ! -L "/evidence/$output"
      done
    done
    for package in $packages; do
      install -m 0444 "./${package}_${candidate}_amd64.deb" "/evidence/$package.deb"
      install -m 0444 "./stock-$package.deb" "/evidence/stock-$package.deb"
    done
    install -m 0444 "./$buildinfo" /evidence/buildinfo
    install -m 0444 ./test-summary.txt /evidence/test-summary.txt
    cd /evidence
    export_checksums > checksums.sha256
    chmod 0444 checksums.sha256
    ;;
  baseline|install)
    cd /packages
    for package in $packages; do
      regular "./$package.deb"
      regular "./stock-$package.deb"
    done
    for name in buildinfo test-summary.txt checksums.sha256; do
      regular "./$name"
    done
    checksums=$(export_checksums)
    printf '%s\n' "$checksums" | cmp - ./checksums.sha256
    sha256sum --check --strict "$inputs/stock.sha256"
    if test "$1" = baseline; then
      prefix=stock-
      version=$baseline
    else
      prefix=
      version=$candidate
      verify_buildinfo ./buildinfo exported
    fi
    set --
    for package in $packages; do
      archive="./$prefix$package.deb"
      verify_package "$archive" "$package" "$version"
      set -- "$@" "$archive"
    done
    # Dpkg unpacks matching runtime and SDK packages in a single transaction.
    dpkg --install "$@"
    for package in $packages; do
      verify_installed "$package" "$version"
    done
    audit=$(dpkg --audit)
    test -z "$audit"
    ;;
  *) exit 42 ;;
esac
