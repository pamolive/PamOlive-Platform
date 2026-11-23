#!/bin/sh
set -eu
umask 022
export LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive

inputs=/opt/ncurses-inputs
baseline='6.5+20250216-2'
candidate="$baseline+pamolive1"
stock_deb="ncurses-bin_${baseline}_amd64.deb"
candidate_deb="ncurses-bin_${candidate}_amd64.deb"
candidate_buildinfo="ncurses_${candidate}_amd64.buildinfo"
upstream='ncurses-6.5-20251213.patch.gz'
backport='pamolive-CVE-2025-69720.patch'

regular() {
  test -f "$1"
  test ! -L "$1"
}

verify_package() {
  regular "$1"
  test "$(dpkg-deb -f "$1" Package)" = ncurses-bin
  test "$(dpkg-deb -f "$1" Source)" = ncurses
  test "$(dpkg-deb -f "$1" Architecture)" = amd64
  test "$(dpkg-deb -f "$1" Version)" = "$2"
  test "$(dpkg-deb -f "$1" Essential)" = yes
}

verify_installed() {
  info=$(dpkg-query -W -f='${source:Package}|${Version}|${Architecture}|${Status}' "$1")
  test "$info" = "ncurses|$2|$3|install ok installed"
}

verify_stock_runtime() {
  verify_installed libtinfo6:amd64 "$baseline" amd64
  verify_installed libncursesw6:amd64 "$baseline" amd64
  verify_installed ncurses-base "$baseline" all
}

verify_buildinfo() {
  regular "$1"
  grep -Fxq 'Source: ncurses' "$1"
  grep -Fxq "Version: $candidate" "$1"
  checksum=$(sha256sum < "$2")
  length=$(wc -c < "$2")
  awk -v name="$candidate_deb" -v sha="${checksum%% *}" -v size="$length" '
    $0 == "Checksums-Sha256:" { checksums = 1; next }
    /^[^[:space:]]/ { checksums = 0 }
    checksums && NF == 3 && $3 == name {
      seen++; if ($1 == sha && $2 == size) matched++
    }
    END { exit !(seen == 1 && matched == 1) }
  ' "$1"
}

export_checksums() {
  sha256sum ./buildinfo ./ncurses-bin.deb ./stock-ncurses-bin.deb ./test-summary.txt
}

case "${1-}" in
  acquire)
    cd /work
    install -d -m 0755 /var/lib/apt/ncurses-source-lists
    apt_conf="$inputs/source-apt.conf"
    apt-get -c "$apt_conf" update
    apt-get -c "$apt_conf" --download-only source "ncurses=$baseline"
    sha256sum --check --strict "$inputs/source.sha256"
    apt-get -c "$apt_conf" download "ncurses-bin:amd64=$baseline"
    regular "./$stock_deb"
    test ! -e stock-ncurses-bin.deb
    test ! -L stock-ncurses-bin.deb
    mv -- "$stock_deb" stock-ncurses-bin.deb
    sha256sum --check --strict "$inputs/stock.sha256"
    verify_package ./stock-ncurses-bin.deb "$baseline"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 60 \
      --max-filesize 16384 --output "$upstream" \
      "https://invisible-island.net/archives/ncurses/6.5/$upstream"
    sha256sum --check --strict "$inputs/patches.sha256"
    ;;
  build)
    test "$(id -u)" -ne 0
    cd /work
    sha256sum --check --strict "$inputs/source.sha256"
    sha256sum --check --strict "$inputs/patches.sha256"
    sha256sum --check --strict "$inputs/stock.sha256"
    dpkg-source -x "ncurses_$baseline.dsc" tree
    cd tree
    test "$(dpkg-parsechangelog -SVersion)" = "$baseline"
    dpkg-checkbuilddeps -B
    sha256sum --check --strict "$inputs/preimage.sha256"

    # Keep only the two functional infocmp hunks from Dickey's 20251213 patch.
    gzip -dc "/work/$upstream" > /work/upstream.patch
    awk '
      BEGIN { print "--- a/progs/infocmp.c"; print "+++ b/progs/infocmp.c" }
      $0 == "Index: progs/infocmp.c" { selected = 1; sections++; next }
      /^Index: / { selected = 0 }
      selected && /^@@ / {
        keep = ($0 == "@@ -847,7 +847,7 @@" || $0 == "@@ -877,7 +877,8 @@")
        if (keep) hunks++
      }
      selected && keep { print }
      END { exit !(sections == 1 && hunks == 2) }
    ' /work/upstream.patch > "debian/patches/$backport"
    sha256sum --check --strict "$inputs/reduced.sha256"
    printf '%s\n' "$backport" >> debian/patches/series
    QUILT_PATCHES=debian/patches QUILT_PATCH_OPTS='--fuzz=0' quilt push
    sha256sum --check --strict "$inputs/postimage.sha256"

    printf '%s\n' \
      "ncurses ($candidate) trixie; urgency=medium" '' \
      '  * Backport the upstream infocmp check for CVE-2025-69720.' '' \
      ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
      > debian/pamolive-changelog
    cat debian/changelog >> debian/pamolive-changelog
    mv debian/pamolive-changelog debian/changelog

    export DEB_BUILD_OPTIONS=parallel=2
    if ! dpkg-buildpackage -B -us -uc -j2 >/work/debian-build.log 2>&1; then
      tail -n 60 /work/debian-build.log >&2
      exit 1
    fi
    sha256sum --check --strict "$inputs/postimage.sha256"
    verify_package "/work/$candidate_deb" "$candidate"
    verify_buildinfo "/work/$candidate_buildinfo" "/work/$candidate_deb"

    # These Debian autopkgtests exercise ordinary bundled terminfo data.
    verify_stock_runtime
    mkdir -m 0700 /work/test-install
    dpkg-deb -x "/work/$candidate_deb" /work/test-install
    test_path=/work/test-install/usr/bin:/usr/bin:/bin
    regular /work/test-install/usr/bin/infocmp
    test -x /work/test-install/usr/bin/infocmp
    timeout --signal=TERM --kill-after=2s 30s env -i PATH="$test_path" LC_ALL=C HOME=/work \
      /bin/sh debian/tests/backspace-delete-keys
    timeout --signal=TERM --kill-after=2s 30s env -i PATH="$test_path" LC_ALL=C HOME=/work \
      /bin/bash debian/tests/infocmp-dumb
    printf '%s\n' \
      'debian_build=passed' \
      'debian_autopkgtest_backspace_delete_keys=passed' \
      'debian_autopkgtest_infocmp_dumb=passed' \
      'debian_autopkgtest_manpage_references=not_run_requires_documentation_and_sdk' \
      'upstream_interactive_examples=not_run' \
      > /work/test-summary.txt
    ;;
  export)
    cd /packages
    regular ./stock-ncurses-bin.deb
    sha256sum --check --strict "$inputs/stock.sha256"
    verify_package ./stock-ncurses-bin.deb "$baseline"
    verify_package "./$candidate_deb" "$candidate"
    verify_buildinfo "./$candidate_buildinfo" "./$candidate_deb"
    regular ./test-summary.txt
    grep -Fxq 'debian_build=passed' ./test-summary.txt
    grep -Fxq 'debian_autopkgtest_backspace_delete_keys=passed' ./test-summary.txt
    grep -Fxq 'debian_autopkgtest_infocmp_dumb=passed' ./test-summary.txt
    for output in ncurses-bin.deb stock-ncurses-bin.deb buildinfo test-summary.txt checksums.sha256; do
      test ! -e "/evidence/$output"
      test ! -L "/evidence/$output"
    done
    install -m 0444 "./$candidate_deb" /evidence/ncurses-bin.deb
    install -m 0444 ./stock-ncurses-bin.deb /evidence/stock-ncurses-bin.deb
    install -m 0444 "./$candidate_buildinfo" /evidence/buildinfo
    install -m 0444 ./test-summary.txt /evidence/test-summary.txt
    cd /evidence
    export_checksums > checksums.sha256
    chmod 0444 checksums.sha256
    ;;
  baseline|install)
    cd /packages
    for artifact in ncurses-bin.deb stock-ncurses-bin.deb buildinfo test-summary.txt checksums.sha256; do
      regular "./$artifact"
    done
    checksums=$(export_checksums)
    printf '%s\n' "$checksums" | cmp - ./checksums.sha256
    sha256sum --check --strict "$inputs/stock.sha256"
    verify_stock_runtime
    if test "$1" = baseline; then
      deb=./stock-ncurses-bin.deb
      version=$baseline
    else
      deb=./ncurses-bin.deb
      version=$candidate
      verify_buildinfo ./buildinfo "$deb"
    fi
    verify_package "$deb" "$version"
    dpkg --install "$deb"
    verify_installed ncurses-bin "$version" amd64
    verify_stock_runtime
    audit=$(dpkg --audit)
    test -z "$audit"
    ;;
  *) exit 42 ;;
esac
