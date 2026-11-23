FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY deploy/sasl-rebuild/forky.sources qualification/x11_trixie_build/source-apt.conf qualification/x11_trixie_build/source.sha256 qualification/x11_trixie_build/materials.sh /opt/x11-inputs/
WORKDIR /opt/x11-source
RUN sh /opt/x11-inputs/materials.sh acquire

FROM trixie AS builder
COPY --chmod=0444 qualification/x11_trixie_build/materials.sh qualification/x11_trixie_build/source.sha256 /opt/x11-inputs/
RUN sh /opt/x11-inputs/materials.sh toolchain
WORKDIR /opt/x11-build
COPY --from=source /opt/x11-source/ ./
RUN --network=none sh /opt/x11-inputs/materials.sh prepare
USER 65534:65534
ENV HOME=/opt/x11-build LC_ALL=C.UTF-8 DEB_BUILD_OPTIONS=parallel=2
RUN --network=none sh /opt/x11-inputs/materials.sh build

FROM trixie AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove \
    binutils libcairo2 libpangocairo-1.0-0 fonts-dejavu-core \
    libx11-6=2:1.8.12-1 libx11-data=2:1.8.12-1 libxrender1=1:0.9.12-1 \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -m 0755 -o 65534 -g 65534 /evidence
COPY --chmod=0444 qualification/x11_trixie_build/check.py /opt/x11-checks/
ENV LC_ALL=C.UTF-8

FROM runtime AS baseline
USER 65534:65534
RUN --network=none python -I -B -S /opt/x11-checks/check.py runtime baseline > /evidence/baseline.json

FROM runtime AS candidate
COPY --from=baseline /evidence/baseline.json /evidence/baseline.json
COPY --chmod=0444 qualification/x11_trixie_build/materials.sh /opt/x11-inputs/
RUN --network=none --mount=from=builder,source=/opt/x11-build,target=/packages,ro \
    sh /opt/x11-inputs/materials.sh install
USER 65534:65534
RUN --network=none python -I -B -S /opt/x11-checks/check.py runtime candidate > /evidence/candidate.json \
 && python -I -B -S /opt/x11-checks/check.py compare /evidence > /evidence/qualification.json

FROM scratch AS x11-qualification
COPY --from=candidate /evidence/ /
