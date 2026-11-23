FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY deploy/acl-rebuild/source-apt.conf deploy/acl-rebuild/forky.sources deploy/acl-rebuild/materials.sh /opt/acl-inputs/
WORKDIR /opt/acl-source
RUN sh /opt/acl-inputs/materials.sh acquire

FROM trixie AS builder
COPY deploy/acl-rebuild/materials.sh deploy/acl-rebuild/source.sha256 deploy/acl-rebuild/prepare.py /opt/acl-inputs/
RUN sh /opt/acl-inputs/materials.sh toolchain
COPY --from=source /opt/acl-source/ /opt/acl-build/
RUN --network=none sh /opt/acl-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/acl-build/tree
ENV HOME=/opt/acl-build LC_ALL=C.UTF-8
RUN --network=none dpkg-checkbuilddeps && dpkg-buildpackage -b -us -uc -j2

FROM trixie AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove \
    libc6=2.41-12+deb13u5 libc-bin=2.41-12+deb13u5 libacl1=2.3.2-2+b1 binutils \
 && rm -rf /var/lib/apt/lists/*
COPY --chmod=0444 qualification/acl_trixie_build/smoke.py /opt/acl-checks/
ENV LC_ALL=C.UTF-8

FROM runtime AS baseline
RUN --network=none install -d -m 0755 -o 65534 -g 65534 /evidence
USER 65534:65534
RUN --network=none python -I -B /opt/acl-checks/smoke.py baseline > /evidence/baseline.json

FROM runtime AS candidate
COPY --from=baseline /evidence/baseline.json /evidence/baseline.json
COPY --chmod=0444 qualification/acl_trixie_build/compare.py deploy/acl-rebuild/package.sha256 /opt/acl-checks/
RUN --network=none --mount=from=builder,source=/opt/acl-build,target=/packages,ro \
    set -eu; \
    package=/packages/libacl1_2.4.0-1~pamolive13u1_amd64.deb; \
    (cd /packages && sha256sum --check --strict /opt/acl-checks/package.sha256); \
    test "$(dpkg-deb -f "$package" Package)" = libacl1; \
    test "$(dpkg-deb -f "$package" Source)" = acl; \
    test "$(dpkg-deb -f "$package" Version)" = '2.4.0-1~pamolive13u1'; \
    test "$(dpkg-deb -f "$package" Architecture)" = amd64; \
    dpkg --install "$package"; \
    test -z "$(dpkg --audit)"; \
    install -m 0444 "$package" /evidence/libacl1.deb; \
    install -m 0444 /packages/acl_2.4.0-1~pamolive13u1_amd64.buildinfo /evidence/buildinfo; \
    chown 65534:65534 /evidence
USER 65534:65534
RUN --network=none python -I -B /opt/acl-checks/smoke.py candidate > /evidence/candidate.json \
 && python -I -B -S /opt/acl-checks/compare.py /evidence > /evidence/qualification.json

FROM scratch AS acl-qualification
COPY --from=candidate /evidence/ /
