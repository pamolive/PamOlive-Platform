#!/bin/sh
set -eu

inputs=/opt/x11-inputs
x11_version='2:1.8.14-1'
xrender_version='1:0.9.13-1'
suffix='~pamolive13u1'

prepare() (
  package=$1
  version=$2
  dpkg-source -x "${package}_${version#*:}.dsc" "$package-tree"
  cd "$package-tree"
  test "$(dpkg-parsechangelog -SSource)" = "$package"
  test "$(dpkg-parsechangelog -SVersion)" = "$version"
  printf '%s\n' \
    "$package ($version$suffix) trixie; urgency=medium" '' \
    '  * Rebuild the Debian source on Trixie.' '' \
    ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
    > debian/pamolive-changelog
  cat debian/changelog >> debian/pamolive-changelog
  mv debian/pamolive-changelog debian/changelog
)

build() (
  cd "/opt/x11-build/$1-tree"
  dpkg-checkbuilddeps
  dpkg-buildpackage -b -us -uc -j2
)

retain() {
  package=$1
  source=$2
  revision=$3$suffix
  arch=$4
  file="/packages/${package}_${revision#*:}_$arch.deb"
  test "$(dpkg-deb -f "$file" Package)" = "$package"
  test "$(dpkg-deb -f "$file" Source)" = "$source"
  test "$(dpkg-deb -f "$file" Version)" = "$revision"
  test "$(dpkg-deb -f "$file" Architecture)" = "$arch"
  install -m 0444 "$file" "/evidence/$package.deb"
}

case "${1-}" in
  acquire)
    cd /opt/x11-source
    install -d -m 0755 /var/lib/apt/x11-source-lists
    chown _apt:root /opt/x11-source
    apt-get -c "$inputs/source-apt.conf" update
    apt-get -c "$inputs/source-apt.conf" --download-only source \
      "libx11=$x11_version" "libxrender=$xrender_version"
    sha256sum --check --strict "$inputs/source.sha256"
    test "$(find . -maxdepth 1 -type f | wc -l)" -eq 6
    ;;
  toolchain)
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources
    apt-get update
    apt-get install -y --no-install-recommends --no-remove build-essential dpkg-dev fakeroot
    apt-get build-dep -y --no-install-recommends libx11 libxrender
    rm -rf /var/lib/apt/lists/*
    ;;
  prepare)
    cd /opt/x11-build
    sha256sum --check --strict "$inputs/source.sha256"
    prepare libx11 "$x11_version"
    prepare libxrender "$xrender_version"
    chown -R 65534:65534 /opt/x11-build
    ;;
  build)
    build libx11
    build libxrender
    ;;
  install)
    retain libx11-6 libx11 "$x11_version" amd64
    retain libx11-data libx11 "$x11_version" all
    retain libxrender1 libxrender "$xrender_version" amd64
    dpkg --install /evidence/libx11-data.deb /evidence/libx11-6.deb /evidence/libxrender1.deb
    test -z "$(dpkg --audit)"
    install -m 0444 "/packages/libx11_${x11_version#*:}${suffix}_amd64.buildinfo" /evidence/libx11.buildinfo
    install -m 0444 "/packages/libxrender_${xrender_version#*:}${suffix}_amd64.buildinfo" /evidence/libxrender.buildinfo
    ;;
  *)
    exit 42
    ;;
esac
