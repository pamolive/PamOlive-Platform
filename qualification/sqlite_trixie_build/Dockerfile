FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY deploy/sqlite-rebuild/source-apt.conf deploy/sqlite-rebuild/forky.sources deploy/sqlite-rebuild/materials.sh /opt/sqlite-inputs/
WORKDIR /opt/sqlite-source
RUN sh /opt/sqlite-inputs/materials.sh acquire

FROM trixie AS toolchain
COPY deploy/sqlite-rebuild/materials.sh deploy/sqlite-rebuild/source.sha256 deploy/sqlite-rebuild/prepare.py /opt/sqlite-inputs/
RUN sh /opt/sqlite-inputs/materials.sh toolchain
COPY --from=source /opt/sqlite-source/ /opt/sqlite-build/
RUN --network=none sh /opt/sqlite-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/sqlite-build/tree
ENV HOME=/opt/sqlite-build LC_ALL=C.UTF-8
RUN --network=none dpkg-checkbuilddeps && dpkg-buildpackage -b -us -uc -j2

FROM trixie AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove \
    libc6=2.41-12+deb13u5 libc-bin=2.41-12+deb13u5 \
    libsqlite3-0=3.46.1-7+deb13u2 liblastlog2-2 binutils \
 && rm -rf /var/lib/apt/lists/*
COPY qualification/sqlite_trixie_build/smoke.py qualification/sqlite_trixie_build/abi.py deploy/sqlite-rebuild/check_runtime.py /opt/sqlite-checks/
ENV LC_ALL=C.UTF-8

FROM runtime AS baseline
RUN --network=none mkdir -m 0755 /baseline \
 && python -I -B /opt/sqlite-checks/smoke.py baseline /baseline/history.sqlite \
    > /baseline/smoke.json \
 && python -I -B /opt/sqlite-checks/abi.py baseline > /baseline/abi.json

FROM runtime AS candidate
COPY --from=toolchain /opt/sqlite-build/libsqlite3-0_3.54.1-2~pamolive13u1_amd64.deb /tmp/
COPY --from=baseline /baseline/ /baseline/
RUN --network=none set -eu; \
    package=/tmp/libsqlite3-0_3.54.1-2~pamolive13u1_amd64.deb; \
    python -I -B -S /opt/sqlite-checks/check_runtime.py --package "$package"; \
    test "$(dpkg-deb -f "$package" Package)" = libsqlite3-0; \
    test "$(dpkg-deb -f "$package" Source)" = sqlite3; \
    test "$(dpkg-deb -f "$package" Version)" = '3.54.1-2~pamolive13u1'; \
    test "$(dpkg-deb -f "$package" Architecture)" = amd64; \
    dpkg --install "$package"; \
    test -z "$(dpkg --audit)"; \
    test "$(dpkg-query -W -f='${Version}' libsqlite3-0)" = '3.54.1-2~pamolive13u1'; \
    mkdir -m 0755 /evidence; \
    python -I -B -S /opt/sqlite-checks/check_runtime.py > /evidence/candidate-runtime.json; \
    sha256sum "$package" | cut -d' ' -f1 > /evidence/candidate-package.sha256; \
    python -I -B /opt/sqlite-checks/smoke.py candidate /baseline/history.sqlite \
      > /evidence/candidate-smoke.json; \
    python -I -B /opt/sqlite-checks/abi.py candidate /baseline/abi.json > /evidence/candidate-abi.json; \
    cp /baseline/smoke.json /evidence/baseline-smoke.json; \
    cp /baseline/abi.json /evidence/baseline-abi.json

FROM scratch AS sqlite-qualification
COPY --from=candidate /evidence/ /
