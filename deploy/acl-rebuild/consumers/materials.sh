#!/bin/sh
set -eu

inputs=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

source_version() {
    case "$1" in
        coreutils) printf '%s\n' '9.7-3' ;;
        sed) printf '%s\n' '4.9-2+deb13u1' ;;
        tar) printf '%s\n' '1.35+dfsg-3.1' ;;
        *) return 42 ;;
    esac
}

audit_packages() {
    audit=$(dpkg --audit)
    test -z "$audit"
}

test "$#" -eq 2
case "$1" in
    acquire|toolchain|prepare|build)
        package=$2
        version=$(source_version "$package")
        ;;
esac

case "$1" in
    acquire|toolchain)
        sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources
        grep -Fxq 'Types: deb deb-src' /etc/apt/sources.list.d/debian.sources
        apt-get -o APT::Update::Error-Mode=any update
        ;;
esac

case "$1" in
    acquire)
        install -d -m 0755 -o _apt "/opt/$package-source"
        cd "/opt/$package-source"
        apt-get -o APT::Get::AllowUnauthenticated=false --download-only source "$package=$version"
        sha256sum --check --strict "$inputs/$package-source.sha256"
        test "$(find . -maxdepth 1 -type f | wc -l)" -eq "$(wc -l < "$inputs/$package-source.sha256")"
        ;;
    toolchain)
        case "$package" in
            sed|tar) set -- acl ;;
            coreutils) set -- ;;
        esac
        apt-get install -y --no-install-recommends --no-remove "$@" build-essential fakeroot quilt
        apt-get build-dep -y --no-install-recommends --arch-only "$package=$version"
        rm -rf /var/lib/apt/lists/*
        ;;
    prepare)
        (cd /acl-packages && sha256sum --check --strict "$inputs/libacl.sha256")
        dpkg --install /acl-packages/libacl1_2.4.0-1~pamolive13u1_amd64.deb \
            /acl-packages/libacl1-dev_2.4.0-1~pamolive13u1_amd64.deb
        audit_packages
        cd "/opt/$package-build"
        sha256sum --check --strict "$inputs/$package-source.sha256"
        dpkg-source -x "${package}_$version.dsc" tree
        python -I -B -S "$inputs/prepare_consumer.py" "$package" tree "$inputs"
        chown -R 65534:65534 "/opt/$package-build"
        ;;
    build)
        cd "/opt/$package-build/tree"
        dpkg-checkbuilddeps
        dpkg-buildpackage -B -us -uc -j2
        sha256sum --check --strict "$inputs/$package-postimage.sha256"
        ;;
    install)
        cd "$2"
        sha256sum --check --strict "$inputs/package.sha256"
        set --
        for package in coreutils sed tar; do
            version="$(source_version "$package")+pamolive1"
            archive="${package}_${version}_amd64.deb"
            test "$(dpkg-deb -f "$archive" Package)" = "$package"
            test "$(dpkg-deb -f "$archive" Version)" = "$version"
            test "$(dpkg-deb -f "$archive" Architecture)" = amd64
            installed=$(dpkg-query -W -f='${Version}' "$package")
            dpkg --compare-versions "$installed" le "$version"
            set -- "$@" "$archive"
        done
        dpkg --install "$@"
        audit_packages
        apt-get check
        for package in coreutils sed tar; do
            version="$(source_version "$package")+pamolive1"
            test "$(dpkg-query -W -f='${Version}|${Architecture}|${Status}' "$package")" = \
                "$version|amd64|install ok installed"
        done
        ;;
    *)
        exit 42
        ;;
esac
