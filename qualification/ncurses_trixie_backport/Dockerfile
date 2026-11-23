FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
COPY --chmod=0444 deploy/ncurses-trixie-backport/ /opt/ncurses-inputs/
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.pgp \
 && sed -i 's|http://deb.debian.org/|https://deb.debian.org/|g' /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' 'Acquire::Check-Valid-Until "true";' \
    'Acquire::AllowInsecureRepositories "false";' \
    'APT::Get::AllowUnauthenticated "false";' \
    'APT::Update::Error-Mode "any";' > /etc/apt/apt.conf.d/99pamolive-ncurses \
 && chmod 0755 /opt/ncurses-inputs

FROM trixie AS builder
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
 && grep -Fxq 'Types: deb deb-src' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends --no-remove build-essential fakeroot quilt curl ca-certificates \
    'libtinfo6=6.5+20250216-2' 'libncursesw6=6.5+20250216-2' 'ncurses-base=6.5+20250216-2' \
 && apt-get build-dep -y --arch-only --no-install-recommends 'ncurses=6.5+20250216-2' \
 && install -d -m 0755 -o _apt /work
WORKDIR /work
RUN sh /opt/ncurses-inputs/materials.sh acquire \
 && chown -R 65534:65534 /work \
 && rm -rf /var/lib/apt/lists/*
ENV HOME=/work
USER 65534:65534
RUN --network=none sh /opt/ncurses-inputs/materials.sh build

FROM trixie AS export
RUN install -d -m 0755 -o 65534 -g 65534 /evidence
USER 65534:65534
RUN --network=none --mount=from=builder,source=/work,target=/packages,ro \
    sh /opt/ncurses-inputs/materials.sh export

FROM trixie AS stock
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove binutils \
    'libtinfo6=6.5+20250216-2' 'libncursesw6=6.5+20250216-2' 'ncurses-base=6.5+20250216-2' \
 && install -d -m 0755 -o 65534 -g 65534 /evidence
COPY --chmod=0444 qualification/ncurses_trixie_backport/check.py /opt/ncurses-checks/
RUN chmod 0755 /opt/ncurses-checks
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    sh /opt/ncurses-inputs/materials.sh baseline \
 && apt-get check
USER 65534:65534
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    python -I -B -S /opt/ncurses-checks/check.py stock

FROM stock AS corrected
USER root
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    sh /opt/ncurses-inputs/materials.sh install \
 && apt-get check
USER 65534:65534
RUN --network=none --mount=from=export,source=/evidence,target=/packages,ro \
    python -I -B -S /opt/ncurses-checks/check.py candidate

FROM scratch AS ncurses-trixie-backport-evidence
COPY --from=export /evidence/ /
COPY --from=corrected /evidence/ /
