FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
COPY --chmod=0444 materials.sh source.sha256 patches.sha256 preimage.sha256 postimage.sha256 /opt/util-linux-inputs/
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.pgp \
 && chmod 0755 /opt/util-linux-inputs

FROM trixie AS builder
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
 && grep -Fxq 'Types: deb deb-src' /etc/apt/sources.list.d/debian.sources \
 && apt-get -o APT::Update::Error-Mode=any update \
 && apt-get install -y --no-install-recommends --no-remove build-essential fakeroot quilt curl ca-certificates \
 && apt-get build-dep -y --arch-only --no-install-recommends 'util-linux=2.41.5-0+deb13u1' \
 && install -d -m 0755 -o _apt /work
WORKDIR /work
RUN sh /opt/util-linux-inputs/materials.sh acquire \
 && chown -R 65534:65534 /work \
 && rm -rf /var/lib/apt/lists/*
ENV HOME=/work
USER 65534:65534
RUN --network=none sh /opt/util-linux-inputs/materials.sh build

FROM trixie AS export
RUN install -d -m 0755 -o 65534 -g 65534 /evidence
USER 65534:65534
RUN --network=none --mount=from=builder,source=/work,target=/packages,ro \
    sh /opt/util-linux-inputs/materials.sh export

FROM scratch AS util-linux-trixie-backport-evidence
COPY --from=export /evidence/ /
