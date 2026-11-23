FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY source-apt.conf forky.sources source.sha256 /opt/sqlite-inputs/
WORKDIR /opt/sqlite-source
RUN mkdir -m 0755 /var/lib/apt/sqlite-source-lists \
 && chown _apt:root /opt/sqlite-source \
 && apt-get -c /opt/sqlite-inputs/source-apt.conf update \
 && apt-get -c /opt/sqlite-inputs/source-apt.conf --download-only source sqlite3=3.54.1-2
RUN --network=none sha256sum --check --strict /opt/sqlite-inputs/source.sha256 \
 && test "$(find . -maxdepth 1 -type f | wc -l)" = 4

FROM trixie AS toolchain
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove \
    build-essential debhelper autoconf libtool automake pkgconf chrpath lynx fakeroot libreadline-dev \
    tcl8.6-dev tcl9.0-dev libtommath-dev libicu-dev \
 && rm -rf /var/lib/apt/lists/*
COPY --from=source /opt/sqlite-source/ /opt/sqlite-build/
COPY prepare.py /opt/sqlite-build/prepare.py
WORKDIR /opt/sqlite-build
RUN --network=none dpkg-source -x sqlite3_3.54.1-2.dsc tree \
 && python -I -B -S prepare.py tree \
 && chmod -R u+rwX,go-w /opt/sqlite-build \
 && chown -R 65534:65534 /opt/sqlite-build
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
COPY smoke.py abi.py /opt/sqlite-checks/
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
    test "$(dpkg-deb -f "$package" Package)" = libsqlite3-0; \
    test "$(dpkg-deb -f "$package" Source)" = sqlite3; \
    test "$(dpkg-deb -f "$package" Version)" = '3.54.1-2~pamolive13u1'; \
    test "$(dpkg-deb -f "$package" Architecture)" = amd64; \
    dpkg --install "$package"; \
    test -z "$(dpkg --audit)"; \
    test "$(dpkg-query -W -f='${Version}' libsqlite3-0)" = '3.54.1-2~pamolive13u1'; \
    mkdir -m 0755 /evidence; \
    sha256sum "$package" | cut -d' ' -f1 > /evidence/candidate-package.sha256; \
    python -I -B /opt/sqlite-checks/smoke.py candidate /baseline/history.sqlite \
      > /evidence/candidate-smoke.json; \
    python -I -B /opt/sqlite-checks/abi.py candidate /baseline/abi.json > /evidence/candidate-abi.json; \
    cp /baseline/smoke.json /evidence/baseline-smoke.json; \
    cp /baseline/abi.json /evidence/baseline-abi.json

FROM scratch AS sqlite-qualification
COPY --from=candidate /evidence/ /
