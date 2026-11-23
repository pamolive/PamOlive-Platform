FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY deploy/acl-rebuild/forky.sources qualification/sasl_trixie_build/source-apt.conf qualification/sasl_trixie_build/source.sha256 /opt/sasl-inputs/
WORKDIR /opt/sasl-source
RUN set -eu; \
    install -d -m 0755 /var/lib/apt/sasl-source-lists; \
    chown _apt:root /opt/sasl-source; \
    apt-get -c /opt/sasl-inputs/source-apt.conf update; \
    apt-get -c /opt/sasl-inputs/source-apt.conf --download-only source cyrus-sasl2=2.1.28+dfsg1-12; \
    sha256sum --check --strict /opt/sasl-inputs/source.sha256; \
    test "$(find . -maxdepth 1 -type f | wc -l)" -eq 3

FROM trixie AS builder
RUN set -eu; \
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-remove build-essential dpkg-dev fakeroot; \
    apt-get -P nodoc build-dep -y --arch-only --no-install-recommends cyrus-sasl2; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/sasl-build
COPY --from=source /opt/sasl-source/ ./
RUN --network=none set -eu; \
    dpkg-source -x cyrus-sasl2_2.1.28+dfsg1-12.dsc tree; \
    cd tree; \
    test "$(dpkg-parsechangelog -SVersion)" = '2.1.28+dfsg1-12'; \
    test -s debian/patches/0043-CVE-2026-107161.patch; \
    grep -Fxq '0043-CVE-2026-107161.patch' .pc/applied-patches; \
    printf '%s\n' \
      'cyrus-sasl2 (2.1.28+dfsg1-12~pamolive13u1) trixie; urgency=medium' '' \
      '  * Rebuild the Debian source on Trixie.' '' \
      ' -- PamOlive Build <pamolive-automation@users.noreply.github.com>  Mon, 23 Nov 2026 00:00:00 +0000' '' \
      > debian/pamolive-changelog; \
    cat debian/changelog >> debian/pamolive-changelog; \
    mv debian/pamolive-changelog debian/changelog; \
    chown -R 65534:65534 /opt/sasl-build
USER 65534:65534
WORKDIR /opt/sasl-build/tree
ENV HOME=/opt/sasl-build LC_ALL=C.UTF-8 DEB_BUILD_OPTIONS=parallel=2
RUN --network=none dpkg-checkbuilddeps -B -P nodoc \
 && dpkg-buildpackage -B --build-profiles=nodoc -us -uc -j2

FROM trixie AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove \
    binutils libldap2 libpq5=17.12-0+deb13u1 \
    libsasl2-2=2.1.28+dfsg1-9 libsasl2-modules-db=2.1.28+dfsg1-9 \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -m 0755 -o 65534 -g 65534 /evidence
COPY --chmod=0444 qualification/sasl_trixie_build/check.py /opt/sasl-checks/
ENV LC_ALL=C.UTF-8

FROM runtime AS baseline
USER 65534:65534
RUN --network=none python -I -B -S /opt/sasl-checks/check.py runtime 2.1.28+dfsg1-9 > /evidence/baseline.json

FROM runtime AS candidate
COPY --from=baseline /evidence/baseline.json /evidence/baseline.json
RUN --network=none --mount=from=builder,source=/opt/sasl-build,target=/packages,ro \
    set -eu; \
    version='2.1.28+dfsg1-12~pamolive13u1'; \
    for package in libsasl2-2 libsasl2-modules-db; do \
      path="/packages/${package}_${version}_amd64.deb"; \
      test "$(dpkg-deb -f "$path" Package)" = "$package"; \
      test "$(dpkg-deb -f "$path" Source)" = 'cyrus-sasl2'; \
      test "$(dpkg-deb -f "$path" Version)" = "$version"; \
      test "$(dpkg-deb -f "$path" Architecture)" = amd64; \
      install -m 0444 "$path" "/evidence/$package.deb"; \
    done; \
    dpkg --install /evidence/libsasl2-modules-db.deb /evidence/libsasl2-2.deb; \
    test -z "$(dpkg --audit)"; \
    install -m 0444 "/packages/cyrus-sasl2_${version}_amd64.buildinfo" /evidence/buildinfo
USER 65534:65534
RUN --network=none python -I -B -S /opt/sasl-checks/check.py runtime 2.1.28+dfsg1-12~pamolive13u1 > /evidence/candidate.json \
 && python -I -B -S /opt/sasl-checks/check.py compare /evidence > /evidence/qualification.json

FROM scratch AS sasl-qualification
COPY --from=candidate /evidence/ /
