FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
COPY --chmod=0444 deploy/glibc-trixie-backport/ /opt/glibc-inputs/
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.pgp \
 && sed -i 's|http://deb.debian.org/|https://deb.debian.org/|g' /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' 'Acquire::Check-Valid-Until "true";' \
    'Acquire::AllowInsecureRepositories "false";' \
    'APT::Get::AllowUnauthenticated "false";' \
    'APT::Update::Error-Mode "any";' > /etc/apt/apt.conf.d/99pamolive-glibc \
 && chmod 0755 /opt/glibc-inputs

FROM trixie AS builder
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
 && grep -Fxq 'Types: deb deb-src' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends --no-remove build-essential fakeroot quilt curl ca-certificates \
 && apt-get build-dep -y --arch-only --no-install-recommends 'glibc=2.41-12+deb13u5' \
 && install -d -m 0755 -o _apt /work
WORKDIR /work
RUN sh /opt/glibc-inputs/materials.sh acquire \
 && chown -R 65534:65534 /work \
 && rm -rf /var/lib/apt/lists/*
ENV HOME=/work
USER 65534:65534
RUN --network=none sh /opt/glibc-inputs/materials.sh build

FROM trixie AS export
RUN install -d -m 0755 -o 65534 -g 65534 /evidence
USER 65534:65534
RUN --network=none --mount=from=builder,source=/work,target=/packages,ro \
    sh /opt/glibc-inputs/materials.sh export

FROM trixie AS stock
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove gcc binutils linux-libc-dev \
    'libc6=2.41-12+deb13u5' 'libc-bin=2.41-12+deb13u5' \
    'libc6-dev=2.41-12+deb13u5' 'libc-dev-bin=2.41-12+deb13u5' \
 && install -d -m 0755 -o 65534 -g 65534 /evidence
COPY --chmod=0444 qualification/glibc_trixie_backport/check.py /opt/glibc-checks/
RUN chmod 0755 /opt/glibc-checks
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    sh /opt/glibc-inputs/materials.sh baseline \
 && apt-get check
USER 65534:65534
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    python -I -B -S /opt/glibc-checks/check.py stock

FROM stock AS corrected
USER root
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    sh /opt/glibc-inputs/materials.sh install \
 && apt-get check
USER 65534:65534
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    python -I -B -S /opt/glibc-checks/check.py candidate

FROM scratch AS glibc-trixie-backport-evidence
COPY --from=export /evidence/ /
COPY --from=corrected /evidence/ /
