FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
COPY --chmod=0444 qualification/krb5_trixie_backport/materials.sh qualification/krb5_trixie_backport/source.sha256 qualification/krb5_trixie_backport/test-patch.sha256 deploy/krb5-test-keyring-seccomp.patch /opt/krb5-inputs/
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg \
 && chmod 0755 /opt/krb5-inputs

FROM trixie AS builder
RUN printf '%s\n' 'deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://security.debian.org/debian-security trixie-security main' > /etc/apt/sources.list.d/pamolive-krb5-source.list \
 && apt-get -o APT::Update::Error-Mode=any update \
 && apt-get install -y --no-install-recommends --no-remove build-essential fakeroot quilt keyutils curl ca-certificates \
 && apt-get build-dep -y --arch-only --no-install-recommends 'krb5=1.21.3-5+deb13u2' \
 && install -d -m 0755 -o _apt /work
WORKDIR /work
RUN sh /opt/krb5-inputs/materials.sh acquire \
 && chown -R 65534:65534 /work \
 && rm -rf /var/lib/apt/lists/*
ENV HOME=/work
USER 65534:65534
RUN --network=none sh /opt/krb5-inputs/materials.sh build

FROM trixie AS stock
RUN sh /opt/krb5-inputs/materials.sh baseline \
 && install -d -m 0755 -o 65534 -g 65534 /evidence
COPY --chmod=0444 qualification/krb5_trixie_backport/check.py qualification/debian_138_refresh/smoke.c qualification/debian_138_refresh/verify_refresh.py /opt/krb5-checks/
COPY --chmod=0444 deploy/krb5-remediation/abi_data.py deploy/krb5-remediation/bounded_io.py deploy/krb5-remediation/common.py deploy/krb5-remediation/legacy_inventory.py deploy/krb5-remediation/source_model.py /opt/krb5-checks/
RUN chmod 0755 /opt/krb5-checks
ENV KRB5_CONFIG=/dev/null KRB5_KDC_PROFILE=/dev/null KRB5CCNAME=MEMORY:pamolive30
USER 65534:65534
RUN --network=none python -I -B -S /opt/krb5-checks/check.py stock

FROM stock AS corrected
USER root
RUN --network=none --mount=from=builder,source=/work,target=/packages,ro \
    sh /opt/krb5-inputs/materials.sh install
USER 65534:65534
RUN --network=none python -I -B -S /opt/krb5-checks/check.py candidate

FROM scratch AS krb5-trixie-backport-evidence
COPY --from=corrected /evidence/ /
