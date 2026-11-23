FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY deploy/sasl-rebuild/forky.sources deploy/sasl-rebuild/source-apt.conf deploy/sasl-rebuild/source.sha256 deploy/sasl-rebuild/materials.sh /opt/sasl-inputs/
WORKDIR /opt/sasl-source
RUN sh /opt/sasl-inputs/materials.sh acquire

FROM trixie AS builder
COPY --chmod=0444 deploy/sasl-rebuild/materials.sh deploy/sasl-rebuild/source.sha256 /opt/sasl-inputs/
RUN sh /opt/sasl-inputs/materials.sh toolchain
WORKDIR /opt/sasl-build
COPY --from=source /opt/sasl-source/ ./
RUN --network=none sh /opt/sasl-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/sasl-build/tree
ENV HOME=/opt/sasl-build LC_ALL=C.UTF-8 DEB_BUILD_OPTIONS=parallel=2
RUN --network=none sh /opt/sasl-inputs/materials.sh build

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
COPY --chmod=0444 deploy/sasl-rebuild/materials.sh deploy/sasl-rebuild/package.sha256 /opt/sasl-inputs/
RUN --network=none --mount=from=builder,source=/opt/sasl-build,target=/packages,ro \
    set -eu; \
    version='2.1.28+dfsg1-12~pamolive13u1'; \
    sh /opt/sasl-inputs/materials.sh install-runtime /packages; \
    for package in libsasl2-2 libsasl2-modules-db; do \
      path="/packages/${package}_${version}_amd64.deb"; \
      test "$(dpkg-deb -f "$path" Package)" = "$package"; \
      test "$(dpkg-deb -f "$path" Source)" = 'cyrus-sasl2'; \
      test "$(dpkg-deb -f "$path" Version)" = "$version"; \
      test "$(dpkg-deb -f "$path" Architecture)" = amd64; \
      install -m 0444 "$path" "/evidence/$package.deb"; \
    done; \
    install -m 0444 "/packages/cyrus-sasl2_${version}_amd64.buildinfo" /evidence/buildinfo
USER 65534:65534
RUN --network=none python -I -B -S /opt/sasl-checks/check.py runtime 2.1.28+dfsg1-12~pamolive13u1 > /evidence/candidate.json \
 && python -I -B -S /opt/sasl-checks/check.py compare /evidence > /evidence/qualification.json

FROM scratch AS sasl-qualification
COPY --from=candidate /evidence/ /
