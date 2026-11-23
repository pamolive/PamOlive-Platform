FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
COPY --chmod=0444 deploy/openssl-trixie-backport/materials.sh deploy/openssl-trixie-backport/patches.py deploy/openssl-trixie-backport/patches.txt deploy/openssl-trixie-backport/source.sha256 deploy/openssl-trixie-backport/preimage.sha256 deploy/openssl-trixie-backport/postimage.sha256 deploy/openssl-trixie-backport/dane.patch deploy/openssl-trixie-backport/dane-patch.sha256 deploy/openssl-trixie-backport/dane-preimage.sha256 deploy/openssl-trixie-backport/dane-provenance.json /opt/openssl-inputs/
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.pgp \
 && chmod 0755 /opt/openssl-inputs

FROM trixie AS builder
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
 && grep -Fxq 'Types: deb deb-src' /etc/apt/sources.list.d/debian.sources \
 && apt-get -o APT::Update::Error-Mode=any update \
 && apt-get install -y --no-install-recommends --no-remove build-essential fakeroot quilt curl ca-certificates \
 && apt-get build-dep -y --arch-only --no-install-recommends 'openssl=3.5.9-1~deb13u1' \
 && install -d -m 0755 -o _apt /work
WORKDIR /work
RUN sh /opt/openssl-inputs/materials.sh acquire \
 && chown -R 65534:65534 /work \
 && rm -rf /var/lib/apt/lists/*
ENV HOME=/work
USER 65534:65534
RUN --network=none sh /opt/openssl-inputs/materials.sh build

FROM trixie AS stock
RUN apt-get -o APT::Update::Error-Mode=any update \
 && apt-get install -y --no-install-recommends --no-remove build-essential \
 && sh /opt/openssl-inputs/materials.sh baseline \
 && install -d -m 0755 -o 65534 -g 65534 /evidence
COPY --chmod=0444 qualification/openssl_trixie_backport/check.py /opt/openssl-checks/
COPY --chmod=0444 deploy/krb5-remediation/abi_data.py deploy/krb5-remediation/bounded_io.py deploy/krb5-remediation/common.py deploy/krb5-remediation/legacy_inventory.py deploy/krb5-remediation/source_model.py /opt/openssl-checks/
RUN chmod 0755 /opt/openssl-checks
USER 65534:65534
RUN --network=none python -I -B -S /opt/openssl-checks/check.py stock

FROM stock AS corrected
USER root
RUN --network=none --mount=from=builder,source=/work,target=/packages,ro \
    sh /opt/openssl-inputs/materials.sh install
USER 65534:65534
RUN --network=none python -I -B -S /opt/openssl-checks/check.py candidate

FROM scratch AS openssl-trixie-backport-evidence
COPY --from=corrected /evidence/ /
