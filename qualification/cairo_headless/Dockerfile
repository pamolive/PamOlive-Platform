FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS trixie
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM trixie AS source
COPY qualification/cairo_headless/trixie.sources qualification/cairo_headless/source-apt.conf qualification/cairo_headless/source.sha256 /opt/cairo-inputs/
WORKDIR /opt/cairo-source
RUN set -eu; \
    install -d -m 0755 /var/lib/apt/cairo-source-lists; \
    chown _apt:root /opt/cairo-source; \
    apt-get -c /opt/cairo-inputs/source-apt.conf update; \
    apt-get -c /opt/cairo-inputs/source-apt.conf --download-only source cairo=1.18.4-1; \
    sha256sum --check --strict /opt/cairo-inputs/source.sha256; \
    test "$(find . -maxdepth 1 -type f | wc -l)" -eq 3

FROM trixie AS builder
RUN set -eu; \
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-remove build-essential dpkg-dev fakeroot; \
    apt-get build-dep -y --no-install-recommends cairo; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/cairo-build
COPY --from=source /opt/cairo-source/ ./
COPY --chmod=0444 qualification/cairo_headless/source.sha256 qualification/cairo_headless/prepare.py qualification/cairo_headless/disabled-exports.txt /opt/cairo-inputs/
RUN --network=none set -eu; \
    sha256sum --check --strict /opt/cairo-inputs/source.sha256; \
    dpkg-source -x cairo_1.18.4-1.dsc tree; \
    python -I -B -S /opt/cairo-inputs/prepare.py tree /opt/cairo-inputs/disabled-exports.txt; \
    chown -R 65534:65534 /opt/cairo-build
USER 65534:65534
WORKDIR /opt/cairo-build/tree
ENV HOME=/opt/cairo-build LC_ALL=C.UTF-8 DEB_BUILD_OPTIONS=parallel=2
RUN --network=none set -eu; \
    dpkg-checkbuilddeps; \
    log=/opt/cairo-build/build.log; \
    if dpkg-buildpackage -b -us -uc -j2 > "$log" 2>&1; then \
        tail -n 32 "$log"; \
    else \
        code=$?; tail -n 140 "$log" >&2; exit "$code"; \
    fi

FROM trixie AS sdk
RUN --mount=from=builder,source=/opt/cairo-build,target=/packages,ro \
    set -eu; \
    version='1.18.4-1+pamolive13u1'; \
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
COPY --chmod=0444 qualification/cairo_headless/check.py qualification/cairo_headless/disabled-exports.txt /opt/cairo-checks/
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
RUN --mount=from=builder,source=/opt/cairo-build,target=/packages,ro \
    set -eu; \
    version='1.18.4-1+pamolive13u1'; \
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
