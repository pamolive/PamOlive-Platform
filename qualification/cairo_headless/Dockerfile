FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY deploy/cairo-headless/trixie.sources deploy/cairo-headless/source-apt.conf deploy/cairo-headless/source.sha256 deploy/cairo-headless/materials.sh /opt/cairo-inputs/
WORKDIR /opt/cairo-source
RUN sh /opt/cairo-inputs/materials.sh acquire

FROM trixie AS builder
COPY --chmod=0444 deploy/cairo-headless/source.sha256 deploy/cairo-headless/prepare.py deploy/cairo-headless/disabled-exports.txt deploy/cairo-headless/materials.sh /opt/cairo-inputs/
RUN sh /opt/cairo-inputs/materials.sh toolchain
WORKDIR /opt/cairo-build
COPY --from=source /opt/cairo-source/ ./
RUN --network=none sh /opt/cairo-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/cairo-build/tree
ENV HOME=/opt/cairo-build LC_ALL=C.UTF-8 DEB_BUILD_OPTIONS=parallel=2
RUN --network=none sh /opt/cairo-inputs/materials.sh build

FROM trixie AS sdk
COPY --chmod=0444 deploy/cairo-headless/materials.sh deploy/cairo-headless/package.sha256 /opt/cairo-inputs/
RUN --mount=from=builder,source=/opt/cairo-build,target=/packages,ro \
    set -eu; \
    version='1.18.4-1+pamolive13u1'; \
    sh /opt/cairo-inputs/materials.sh verify-packages /packages; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-remove build-essential pkgconf fonts-dejavu-core \
      "/packages/libcairo2_${version}_amd64.deb" "/packages/libcairo-gobject2_${version}_amd64.deb" \
      "/packages/libcairo-script-interpreter2_${version}_amd64.deb" "/packages/libcairo2-dev_${version}_amd64.deb"; \
    test -z "$(dpkg --audit)"; \
    for package in libcairo2 libcairo2-dev libcairo-gobject2 libcairo-script-interpreter2; do \
      test "$(dpkg-query -W -f='${Version}' "$package")" = "$version"; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    install -d -m 0755 -o 65534 -g 65534 /evidence
COPY --chmod=0444 --from=builder /opt/cairo-build/tree/debian/tests/build /opt/cairo-debian-sdk-test
USER 65534:65534
RUN --network=none set -eu; \
    pkg-config --exists cairo-png cairo-ft cairo-fc; \
    for backend in cairo-xlib cairo-xlib-xrender cairo-xcb cairo-xcb-shm; do \
      if pkg-config --exists "$backend"; then exit 42; fi; \
    done; \
    sh /opt/cairo-debian-sdk-test > /evidence/sdk-result.txt

FROM trixie AS probe
COPY --chmod=0444 qualification/x11_trixie_build/check.py /opt/cairo-checks/x11_check.py
COPY --chmod=0444 qualification/cairo_headless/check.py deploy/cairo-headless/disabled-exports.txt /opt/cairo-checks/
ENV LC_ALL=C.UTF-8
RUN chmod 0755 /opt/cairo-checks \
 && install -d -m 0755 -o 65534 -g 65534 /evidence

FROM probe AS baseline
RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-remove binutils libcairo2=1.18.4-1+b1 libpangocairo-1.0-0=1.56.3-1 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*
USER 65534:65534
RUN --network=none python -I -B -S /opt/cairo-checks/check.py runtime baseline > /evidence/baseline.json

FROM probe AS candidate
COPY --from=baseline /evidence/baseline.json /evidence/baseline.json
COPY --from=sdk /evidence/sdk-result.txt /evidence/sdk-result.txt
COPY --chmod=0444 deploy/cairo-headless/materials.sh deploy/cairo-headless/package.sha256 /opt/cairo-inputs/
RUN --mount=from=builder,source=/opt/cairo-build,target=/packages,ro \
    set -eu; \
    version='1.18.4-1+pamolive13u1'; \
    sh /opt/cairo-inputs/materials.sh verify-packages /packages; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-remove binutils libpangocairo-1.0-0=1.56.3-1 fonts-dejavu-core \
      "/packages/libcairo2_${version}_amd64.deb"; \
    test -z "$(dpkg --audit)"; \
    rm -rf /var/lib/apt/lists/*; \
    for package in libcairo2 libcairo2-dev libcairo-gobject2 libcairo-script-interpreter2; do \
      file="/packages/${package}_${version}_amd64.deb"; \
      test "$(dpkg-deb -f "$file" Package)" = "$package"; \
      test "$(dpkg-deb -f "$file" Source)" = cairo; \
      test "$(dpkg-deb -f "$file" Version)" = "$version"; \
      test "$(dpkg-deb -f "$file" Architecture)" = amd64; \
      install -m 0444 "$file" "/evidence/$package.deb"; \
    done; \
    install -m 0444 "/packages/cairo_${version}_amd64.buildinfo" /evidence/buildinfo
USER 65534:65534
RUN --network=none python -I -B -S /opt/cairo-checks/check.py runtime candidate > /evidence/candidate.json \
 && python -I -B -S /opt/cairo-checks/check.py compare /evidence > /evidence/qualification.json

FROM scratch AS cairo-qualification
COPY --from=candidate /evidence/ /
