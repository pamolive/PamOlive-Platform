ARG LIBPQ_DEBIAN_VERSION=17.12-0+deb13u1
ARG JANSSON_DEBIAN_VERSION=2.14-2+b3
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS debian-refresh-inputs
WORKDIR /opt/pamolive-refresh
COPY qualification/debian_138_refresh/Dockerfile qualification/debian_138_refresh/apt.conf qualification/debian_138_refresh/debian.list qualification/debian_138_refresh/smoke.c qualification/debian_138_refresh/test_refresh.py qualification/debian_138_refresh/verify_refresh.py qualification/debian_138_refresh/source-checksums.sha256 ./
RUN test "$(dpkg --print-architecture)" = amd64 && test -s /usr/share/keyrings/debian-archive-keyring.gpg \
  && sha256sum --check --strict source-checksums.sha256 \
  && mkdir -m 0755 /opt/pamolive-apt-cache /opt/pamolive-apt-lists \
  && python -I -B -S verify_refresh.py acquire

FROM debian-refresh-inputs AS debian-refresh-verified
RUN --network=none python -I -B -S verify_refresh.py qualify

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS debian-runtime
COPY --from=debian-refresh-verified /opt/pamolive-refresh/debian.list /etc/apt/pamolive-debian.list
COPY --from=debian-refresh-verified /opt/pamolive-refresh/debian-138-refresh.json /usr/share/pamolive/debian-refresh/debian-138-refresh.json
COPY --from=debian-refresh-verified /opt/pamolive-refresh/verify_refresh.py /app/qualification/debian_138_refresh/verify_refresh.py
COPY deploy/debian_refresh_inventory.py /app/deploy/debian_refresh_inventory.py
# Keep Debian release, updates and security authenticated across product builds.
# The version preference does not authorize a downgrade.
RUN printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie-updates main' >> /etc/apt/pamolive-debian.list \
  && printf '%s\n' 'Dir::Etc::sourcelist "/etc/apt/pamolive-debian.list";' 'Dir::Etc::sourceparts "-";' \
    'Acquire::AllowInsecureRepositories "false";' 'Acquire::AllowDowngradeToInsecureRepositories "false";' \
    'Acquire::Check-Valid-Until "true";' 'Acquire::By-Hash "true";' \
    'Acquire::https::Verify-Peer "true";' 'Acquire::https::Verify-Host "true";' \
    'Acquire::https::AllowRedirect "false";' 'Acquire::https::Timeout "30";' 'Acquire::Retries "1";' \
    'APT::Get::AllowUnauthenticated "false";' 'APT::Update::Error-Mode "any";' > /etc/apt/apt.conf.d/99pamolive-debian \
  && printf '%s\n' \
    'Package: libc6 libc-bin libc6-dev libc-dev-bin' 'Pin: version 2.41-12+deb13u5' 'Pin-Priority: 999' '' \
    'Package: libkrb5-3 libk5crypto3 libkrb5support0 libgssapi-krb5-2 libkrb5-dev krb5-multidev libgssrpc4t64 libkadm5clnt-mit12 libkadm5srv-mit12 libkdb5-10t64' \
    'Pin: version 1.21.3-5+deb13u2' 'Pin-Priority: 999' > /etc/apt/preferences.d/pamolive-debian
RUN --mount=from=debian-refresh-inputs,source=/opt/pamolive-apt-cache,target=/tmp/debian-refresh-archives,ro \
  archives=/tmp/debian-refresh-archives && apt-get update \
  && apt-get install -y --no-install-recommends --no-remove --reinstall \
    "$archives/libc6_2.41-12+deb13u5_amd64.deb" "$archives/libc-bin_2.41-12+deb13u5_amd64.deb" \
    "$archives/libkrb5-3_1.21.3-5+deb13u2_amd64.deb" "$archives/libk5crypto3_1.21.3-5+deb13u2_amd64.deb" \
    "$archives/libkrb5support0_1.21.3-5+deb13u2_amd64.deb" "$archives/libgssapi-krb5-2_1.21.3-5+deb13u2_amd64.deb" \
  && rm -rf /var/lib/apt/lists/*
RUN --network=none cd /app && python -B -m deploy.debian_refresh_inventory --root / --output /tmp/debian-refresh-base.json && rm /tmp/debian-refresh-base.json

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS debian-rebuild-base
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -s /usr/share/keyrings/debian-archive-keyring.gpg

FROM debian-rebuild-base AS sqlite-trixie-source
COPY deploy/sqlite-rebuild/source-apt.conf deploy/sqlite-rebuild/forky.sources deploy/sqlite-rebuild/materials.sh /opt/sqlite-inputs/
WORKDIR /opt/sqlite-source
RUN sh /opt/sqlite-inputs/materials.sh acquire

FROM debian-rebuild-base AS sqlite-trixie-package
COPY deploy/sqlite-rebuild/materials.sh deploy/sqlite-rebuild/source.sha256 deploy/sqlite-rebuild/prepare.py /opt/sqlite-inputs/
RUN sh /opt/sqlite-inputs/materials.sh toolchain
COPY --from=sqlite-trixie-source /opt/sqlite-source/ /opt/sqlite-build/
RUN --network=none sh /opt/sqlite-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/sqlite-build/tree
ENV HOME=/opt/sqlite-build LC_ALL=C.UTF-8
RUN --network=none dpkg-checkbuilddeps && dpkg-buildpackage -b -us -uc -j2

FROM debian-rebuild-base AS acl-trixie-source
COPY deploy/acl-rebuild/source-apt.conf deploy/acl-rebuild/forky.sources deploy/acl-rebuild/materials.sh /opt/acl-inputs/
WORKDIR /opt/acl-source
RUN sh /opt/acl-inputs/materials.sh acquire

FROM debian-rebuild-base AS acl-trixie-package
COPY deploy/acl-rebuild/materials.sh deploy/acl-rebuild/source.sha256 deploy/acl-rebuild/prepare.py /opt/acl-inputs/
RUN sh /opt/acl-inputs/materials.sh toolchain
COPY --from=acl-trixie-source /opt/acl-source/ /opt/acl-build/
RUN --network=none sh /opt/acl-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/acl-build/tree
ENV HOME=/opt/acl-build LC_ALL=C.UTF-8
RUN --network=none dpkg-checkbuilddeps && dpkg-buildpackage -b -us -uc -j2

FROM debian-rebuild-base AS sasl-trixie-source
COPY deploy/sasl-rebuild/forky.sources deploy/sasl-rebuild/source-apt.conf deploy/sasl-rebuild/source.sha256 deploy/sasl-rebuild/materials.sh /opt/sasl-inputs/
WORKDIR /opt/sasl-source
RUN sh /opt/sasl-inputs/materials.sh acquire

FROM debian-rebuild-base AS sasl-trixie-package
COPY --chmod=0444 deploy/sasl-rebuild/materials.sh deploy/sasl-rebuild/source.sha256 /opt/sasl-inputs/
RUN sh /opt/sasl-inputs/materials.sh toolchain
WORKDIR /opt/sasl-build
COPY --from=sasl-trixie-source /opt/sasl-source/ ./
RUN --network=none sh /opt/sasl-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/sasl-build/tree
ENV HOME=/opt/sasl-build LC_ALL=C.UTF-8 DEB_BUILD_OPTIONS=parallel=2
RUN --network=none sh /opt/sasl-inputs/materials.sh build

FROM debian-rebuild-base AS cairo-trixie-source
COPY deploy/cairo-headless/trixie.sources deploy/cairo-headless/source-apt.conf deploy/cairo-headless/source.sha256 deploy/cairo-headless/materials.sh /opt/cairo-inputs/
WORKDIR /opt/cairo-source
RUN sh /opt/cairo-inputs/materials.sh acquire

FROM debian-rebuild-base AS cairo-trixie-package
COPY --chmod=0444 deploy/cairo-headless/source.sha256 deploy/cairo-headless/prepare.py deploy/cairo-headless/disabled-exports.txt deploy/cairo-headless/materials.sh /opt/cairo-inputs/
RUN sh /opt/cairo-inputs/materials.sh toolchain
WORKDIR /opt/cairo-build
COPY --from=cairo-trixie-source /opt/cairo-source/ ./
RUN --network=none sh /opt/cairo-inputs/materials.sh prepare
USER 65534:65534
WORKDIR /opt/cairo-build/tree
ENV HOME=/opt/cairo-build LC_ALL=C.UTF-8 DEB_BUILD_OPTIONS=parallel=2
RUN --network=none sh /opt/cairo-inputs/materials.sh build

FROM debian-runtime AS expat-prepared
RUN --mount=from=debian-refresh-inputs,source=/opt/pamolive-apt-cache,target=/tmp/debian-refresh-archives,ro \
  archives=/tmp/debian-refresh-archives && apt-get update \
  && apt-get install -y --no-install-recommends build-essential binutils patch gpg=2.4.7-21+deb13u1+b5 dpkg-dev debhelper autoconf automake libtool pkg-config docbook-to-man docbook2x libexpat1-dev=2.9.0-1~deb13u1 ca-certificates \
    "$archives/libc6-dev_2.41-12+deb13u5_amd64.deb" "$archives/libc-dev-bin_2.41-12+deb13u5_amd64.deb" \
  && rm -rf /var/lib/apt/lists/*
COPY deploy/expat-remediation/ /opt/expat4/
RUN python -I -B -S /opt/expat4/download.py /expat-materials
# Only these pinned public inputs become traversable by the non-root GPG preflight.
# Files remain root-owned0444; its supervisor journal remains private0700.
RUN --network=none chmod 0755 /expat-materials
FROM expat-prepared AS expat-source-builder
RUN --network=none python -I -B -S /opt/expat4/abi_gate.py capture /expat-before
RUN --network=none python -I -B -S /opt/expat4/build_debian.py /expat-materials /expat-packages
RUN --network=none python -I -B -S /opt/expat4/source_audit.py /expat-materials /expat-source-audit.json
RUN --network=none python -I -B -S /opt/expat4/check_sanitizer.py /expat-materials /expat-sanitizer

FROM expat-prepared AS expat-python-builder
COPY --from=expat-source-builder /expat-packages/runtime/ /tmp/expat-runtime/
COPY --from=expat-source-builder /expat-packages/sdk/ /tmp/expat-sdk/
COPY --from=expat-source-builder /expat-before/ABI.json /expat-before.json
RUN --network=none dpkg --install /tmp/expat-runtime/*.deb /tmp/expat-sdk/*.deb && rm -r /tmp/expat-runtime /tmp/expat-sdk
RUN --network=none python -I -B -S /opt/expat4/build_python_xml.py --optimization-policy xml-local-no-pgo-v1 /expat-materials /python-xml-build
RUN --network=none install -m 0755 /python-xml-build/pyexpat.cpython-312-x86_64-linux-gnu.so /usr/local/lib/python3.12/lib-dynload/pyexpat.cpython-312-x86_64-linux-gnu.so && install -m 0755 /python-xml-build/_elementtree.cpython-312-x86_64-linux-gnu.so /usr/local/lib/python3.12/lib-dynload/_elementtree.cpython-312-x86_64-linux-gnu.so
RUN --network=none python -I -B -S /opt/expat4/abi_gate.py capture /usr/share/pamolive/expat4/after && python -I -B -S /opt/expat4/abi_gate.py compare /expat-before.json /usr/share/pamolive/expat4/after/ABI.json
RUN --network=none python -I -B -S /opt/expat4/qualify_linux.py /expat-materials /expat-tests

FROM debian-runtime AS expat-runtime
COPY --from=expat-source-builder /expat-packages/runtime/ /tmp/expat-runtime/
RUN --network=none dpkg --install /tmp/expat-runtime/*.deb && rm -r /tmp/expat-runtime
COPY --from=expat-python-builder /usr/local/lib/python3.12/lib-dynload/pyexpat.cpython-312-x86_64-linux-gnu.so /usr/local/lib/python3.12/lib-dynload/
COPY --from=expat-python-builder /usr/local/lib/python3.12/lib-dynload/_elementtree.cpython-312-x86_64-linux-gnu.so /usr/local/lib/python3.12/lib-dynload/
COPY --from=expat-python-builder /usr/share/pamolive/expat4/after/ABI.json /usr/share/pamolive/expat4/after/ABI.json
COPY --from=expat-python-builder /expat-before.json /usr/share/pamolive/expat4/before.json
COPY --from=expat-python-builder /python-xml-build/BUILD.json /usr/share/pamolive/expat4/python-xml-build.json
COPY --from=expat-python-builder /expat-tests/QUALIFICATION.json /usr/share/pamolive/expat4/qualification.json
COPY --from=expat-source-builder /expat-packages/SOURCE-REBUILD.json /usr/share/pamolive/expat4/source-rebuild.json
COPY --from=expat-source-builder /expat-source-audit.json /usr/share/pamolive/expat4/source-audit.json
COPY --from=expat-source-builder /expat-sanitizer/SANITIZER.json /usr/share/pamolive/expat4/sanitizer.json
COPY deploy/expat-remediation/common.py deploy/expat-remediation/bounded_io.py deploy/expat-remediation/verify_runtime.py deploy/expat-remediation/run_python_case.py deploy/expat-remediation/python_cases.py /usr/local/libexec/pamolive-expat4/
RUN --network=none python -I -B -S /usr/local/libexec/pamolive-expat4/verify_runtime.py /usr/share/pamolive/expat4/runtime-base
RUN --network=none find /usr/share/pamolive/expat4 -type d -exec chmod 0755 {} + && find /usr/share/pamolive/expat4 -type f -exec chmod 0444 {} +

FROM expat-runtime AS expat-sdk
RUN --mount=from=debian-refresh-inputs,source=/opt/pamolive-apt-cache,target=/tmp/debian-refresh-archives,ro \
  archives=/tmp/debian-refresh-archives && apt-get update \
  && apt-get install -y --no-install-recommends --no-remove \
    "$archives/libc6-dev_2.41-12+deb13u5_amd64.deb" "$archives/libc-dev-bin_2.41-12+deb13u5_amd64.deb" \
    "$archives/libkrb5-dev_1.21.3-5+deb13u2_amd64.deb" "$archives/krb5-multidev_1.21.3-5+deb13u2_amd64.deb" \
    "$archives/libgssrpc4t64_1.21.3-5+deb13u2_amd64.deb" "$archives/libkadm5clnt-mit12_1.21.3-5+deb13u2_amd64.deb" \
    "$archives/libkadm5srv-mit12_1.21.3-5+deb13u2_amd64.deb" "$archives/libkdb5-10t64_1.21.3-5+deb13u2_amd64.deb" \
  && rm -rf /var/lib/apt/lists/*
COPY --from=expat-source-builder /expat-packages/sdk/ /tmp/expat-sdk/
RUN --network=none dpkg --install /tmp/expat-sdk/*.deb && rm -r /tmp/expat-sdk

FROM expat-sdk AS freerdp-builder
ARG JANSSON_DEBIAN_VERSION
COPY --chmod=0444 deploy/cairo-headless/materials.sh deploy/cairo-headless/package.sha256 /opt/cairo-inputs/
RUN --mount=from=cairo-trixie-package,source=/opt/cairo-build,target=/packages,ro \
  cairo='1.18.4-1+pamolive13u1' \
  && sh /opt/cairo-inputs/materials.sh verify-packages /packages \
  && apt-get update && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends --no-remove build-essential cmake pkg-config curl ca-certificates gnupg patchelf libssl-dev zlib1g-dev libjpeg62-turbo-dev libjansson-dev=${JANSSON_DEBIAN_VERSION} patch libicu-dev liburiparser-dev \
    "/packages/libcairo2_${cairo}_amd64.deb" "/packages/libcairo2-dev_${cairo}_amd64.deb" \
    "/packages/libcairo-gobject2_${cairo}_amd64.deb" "/packages/libcairo-script-interpreter2_${cairo}_amd64.deb" \
  && test "$(dpkg-query -W -f='${Version}' libcairo2-dev)" = "$cairo" \
  && rm -rf /var/lib/apt/lists/*
RUN --network=none cd /app && python -B -m deploy.debian_refresh_inventory --root / --sdk --output /tmp/debian-refresh-sdk.json && rm /tmp/debian-refresh-sdk.json
COPY deploy/build-freerdp.sh /build-freerdp.sh
RUN --network=none test "$(dpkg-query --show --showformat='${Version}' libexpat1)" = '2.10.0-1+pamolive2' && test "$(dpkg-query --show --showformat='${Version}' libexpat1-dev)" = '2.10.0-1+pamolive2'
COPY deploy/freerdp-jansson-compat.patch /freerdp-jansson-compat.patch
RUN sh /build-freerdp.sh

FROM freerdp-builder AS guacd-builder
ENV PKG_CONFIG_PATH=/opt/pamolive-freerdp/lib/pkgconfig LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib
RUN apt-get update && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends --no-remove libtool-bin libcairo2-dev=1.18.4-1+pamolive13u1 libpng-dev libpango1.0-dev libssh2-1-dev uuid-dev \
  && test "$(dpkg-query -W -f='${Version}' libcairo2)" = '1.18.4-1+pamolive13u1' \
  && rm -rf /var/lib/apt/lists/*
RUN --network=none cd /app && python -B -m deploy.debian_refresh_inventory --root / --sdk --output /tmp/debian-refresh-sdk.json && rm /tmp/debian-refresh-sdk.json
COPY deploy/build-guacd.sh /build-guacd.sh
COPY deploy/guacd-deny-rdp-redirection.patch /guacd-deny-rdp-redirection.patch
COPY deploy/guacd-freerdp3-gdi-lifecycle.patch /guacd-freerdp3-gdi-lifecycle.patch
RUN --network=none test "$(dpkg-query --show --showformat='${Version}' libexpat1)" = '2.10.0-1+pamolive2' && test "$(dpkg-query --show --showformat='${Version}' libexpat1-dev)" = '2.10.0-1+pamolive2'
RUN sh /build-guacd.sh

FROM expat-sdk AS directory-builder
ARG LIBPQ_DEBIAN_VERSION
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential libldap2-dev libsasl2-dev libpq-dev=${LIBPQ_DEBIAN_VERSION} libpq5=${LIBPQ_DEBIAN_VERSION} && rm -rf /var/lib/apt/lists/*
COPY --chmod=0444 deploy/sasl-rebuild/materials.sh deploy/sasl-rebuild/package.sha256 /opt/sasl-inputs/
RUN --network=none --mount=from=sasl-trixie-package,source=/opt/sasl-build,target=/tmp/pamolive-sasl-build,ro \
  sh /opt/sasl-inputs/materials.sh install-sdk /tmp/pamolive-sasl-build
RUN --network=none cd /app && python -B -m deploy.debian_refresh_inventory --root / --sdk --output /tmp/debian-refresh-sdk.json && rm /tmp/debian-refresh-sdk.json
RUN --network=none test "$(dpkg-query --show --showformat='${Version}' libexpat1)" = '2.10.0-1+pamolive2' && test "$(dpkg-query --show --showformat='${Version}' libexpat1-dev)" = '2.10.0-1+pamolive2'
COPY requirements-bootstrap.lock requirements-python-runtime-linux.lock requirements-python-build-tools-linux.lock requirements-python-native-sources-linux.lock requirements-python-native-test-linux.lock /tmp/
COPY deploy/python_materials.py deploy/python-materials.linux-amd64.json /tmp/
RUN python /tmp/python_materials.py acquire --manifest /tmp/python-materials.linux-amd64.json --locks /tmp --output /opt/python-inputs
RUN --network=none export PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-inputs/bootstrap --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-bootstrap.lock && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-inputs/build-tools --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-python-build-tools-linux.lock && python -m pip wheel --no-cache-dir --no-index --find-links=/opt/python-inputs/sources --no-binary=:all: --no-build-isolation --check-build-dependencies --no-deps --require-hashes --wheel-dir /opt/directory-wheels -r /tmp/requirements-python-native-sources-linux.lock && python /tmp/python_materials.py capture-derived --manifest /tmp/python-materials.linux-amd64.json --locks /tmp --inputs /opt/python-inputs --wheels /opt/directory-wheels --output /opt/python-evidence && cp /tmp/python-materials.linux-amd64.json /tmp/requirements-bootstrap.lock /tmp/requirements-python-*.lock /opt/python-evidence/

FROM expat-runtime AS runtime-build
ARG JANSSON_DEBIAN_VERSION
ARG LIBPQ_DEBIAN_VERSION
COPY --chmod=0444 deploy/cairo-headless/materials.sh deploy/cairo-headless/package.sha256 /opt/cairo-inputs/
RUN --mount=from=cairo-trixie-package,source=/opt/cairo-build,target=/packages,ro \
  cairo='1.18.4-1+pamolive13u1' \
  && sh /opt/cairo-inputs/materials.sh verify-packages /packages \
  && apt-get update && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends --no-remove "/packages/libcairo2_${cairo}_amd64.deb" libpng16-16t64 libjpeg62-turbo libpango-1.0-0 libpangocairo-1.0-0 libssh2-1t64 libssl3t64 libjansson4=${JANSSON_DEBIAN_VERSION} libkrb5-3 libgssapi-krb5-2 libicu76 liburiparser1 zlib1g fonts-dejavu-core libldap2 libsasl2-2 libpq5=${LIBPQ_DEBIAN_VERSION} \
  && test "$(dpkg-query -W -f='${Version}' libcairo2)" = "$cairo" \
  && rm -rf /opt/cairo-inputs /var/lib/apt/lists/*
COPY --from=freerdp-builder /opt/pamolive-freerdp/lib /opt/pamolive-freerdp/lib
COPY --from=freerdp-builder /opt/pamolive-freerdp/share/pamolive-freerdp /opt/pamolive-freerdp/share/pamolive-freerdp
COPY --from=guacd-builder /opt/pamolive-guac /opt/pamolive-guac
ENV LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PSYCOPG_IMPL=c
WORKDIR /app
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin pamolive && useradd --uid 1001 --no-create-home --shell /usr/sbin/nologin pamolive-guacd
COPY requirements.lock requirements-bootstrap.lock requirements-python-runtime-linux.lock ./
COPY --from=directory-builder /opt/python-inputs/runtime-inputs /opt/python-wheels
COPY --from=directory-builder /opt/directory-wheels /opt/directory-wheels
COPY --from=directory-builder /opt/python-evidence /usr/share/pamolive/python-materials
COPY deploy/ensurepip_bundle.py /tmp/ensurepip_bundle.py
RUN --network=none python -B /tmp/ensurepip_bundle.py --wheel /opt/python-wheels/pip-26.3-py3-none-any.whl && rm /tmp/ensurepip_bundle.py
RUN --network=none export PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-wheels --only-binary=:all: --no-deps --require-hashes -r requirements-bootstrap.lock && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-wheels --only-binary=:all: --no-deps --require-hashes -r requirements-python-runtime-linux.lock && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/directory-wheels --only-binary=:all: --no-deps --require-hashes -r /usr/share/pamolive/python-materials/requirements-python-derived-linux.lock && python -m pip check && rm -r /opt/python-wheels /opt/directory-wheels
COPY manage.py pyproject.toml README.md LICENSE .env.example ./
COPY config/ ./config/
COPY deploy/ ./deploy/
COPY docs/ ./docs/
COPY examples/ ./examples/
COPY integrations/ ./integrations/
COPY platform_core/ ./platform_core/
COPY platform_modules/ ./platform_modules/
COPY templates/ ./templates/
COPY tests/ ./tests/
COPY third_party/ ./third_party/
RUN --network=none --mount=from=sqlite-trixie-package,source=/opt/sqlite-build,target=/tmp/pamolive-sqlite-build,ro \
  set -eu; \
  package=/tmp/pamolive-sqlite-build/libsqlite3-0_3.54.1-2~pamolive13u1_amd64.deb; \
  python -I -B -S deploy/sqlite-rebuild/check_runtime.py --package "$package"; \
  dpkg --install "$package"; \
  test -z "$(dpkg --audit)"; \
  python -I -B -S deploy/sqlite-rebuild/check_runtime.py
RUN --network=none --mount=from=acl-trixie-package,source=/opt/acl-build,target=/tmp/pamolive-acl-build,ro \
  cd /tmp/pamolive-acl-build \
  && sha256sum --check --strict /app/deploy/acl-rebuild/package.sha256 \
  && dpkg --install libacl1_2.4.0-1~pamolive13u1_amd64.deb \
  && test -z "$(dpkg --audit)"
RUN --network=none --mount=from=sasl-trixie-package,source=/opt/sasl-build,target=/tmp/pamolive-sasl-build,ro \
  sh deploy/sasl-rebuild/materials.sh install-runtime /tmp/pamolive-sasl-build
RUN python deploy/native_inventory.py --capture --output /opt/pamolive-native-manifest.json
RUN --network=none python -B -m deploy.debian_refresh_inventory --root / --output /tmp/debian-refresh-runtime.json && rm /tmp/debian-refresh-runtime.json
RUN python manage.py collectstatic --noinput
USER root
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/', timeout=4)"
CMD ["python", "deploy/runtime.py"]

# Recheck active files after all product APT/Python installs, before the clean snapshot.
RUN --network=none python -I -B -S /usr/local/libexec/pamolive-expat4/verify_runtime.py /usr/share/pamolive/expat4/runtime-product && find /usr/share/pamolive/expat4 -type d -exec chmod 0755 {} + && find /usr/share/pamolive/expat4 -type f -exec chmod 0444 {} +

FROM scratch AS runtime-copy
# No --chown/--chmod: retain stage numeric ownership, modes and symlink nodes.
COPY --from=runtime-build / /
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305 PYTHON_VERSION=3.12.16 PYTHON_SHA256=b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c
ENV LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PSYCOPG_IMPL=c
WORKDIR /app
USER root
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/', timeout=4)"
CMD ["python", "deploy/runtime.py"]
# Compare image roots without the verification worker's proc/sys mounts.
FROM runtime-build AS snapshot-check
RUN --network=none --mount=from=runtime-build,source=/,target=/__pamolive_previous,ro --mount=from=runtime-copy,source=/,target=/__pamolive_candidate,ro python -I -B -S /app/deploy/expat_snapshot.py /__pamolive_previous /__pamolive_candidate /usr/share/pamolive/expat4/snapshot.json

# Inherit the clean COPY configuration; carry only the successful comparison receipt.
FROM runtime-copy AS runtime
COPY --from=snapshot-check /usr/share/pamolive/expat4/snapshot.json /usr/share/pamolive/expat4/snapshot.json

FROM guacd-builder AS native-test-builder
COPY tests/fixtures/rdp_fixture.c /tmp/rdp_fixture.c
COPY tests/fixtures/winpr_jansson_regression.c /tmp/winpr_jansson_regression.c
COPY deploy/jansson_oracle_identity.py /tmp/jansson_oracle_identity.py
RUN mkdir -p /opt/pamolive-test && cc -O2 -Wall -Wextra -Werror -Wno-error=deprecated-declarations -pthread /tmp/rdp_fixture.c -o /opt/pamolive-test/rdp-fixture -Wl,-rpath,/opt/pamolive-freerdp/lib $(pkg-config --cflags --libs freerdp3 winpr3)

RUN cc -O2 -Wall -Wextra -Werror /tmp/winpr_jansson_regression.c -o /opt/pamolive-test/winpr-jansson-regression -Wl,-rpath,/opt/pamolive-freerdp/lib $(pkg-config --cflags --libs freerdp3 winpr3) -lm
RUN --network=none /opt/pamolive-test/winpr-jansson-regression > /opt/pamolive-test/winpr-jansson-regression.json && python /tmp/jansson_oracle_identity.py build /opt/pamolive-test/build-identity.json

# Isolated differential reference only. The old vulnerable library and executable
# are never copied into production or native-test. Only DATA leaves this target.
FROM native-test-builder AS json-reference-test
ARG CJSON_REFERENCE_VERSION=1.7.18-3.1+deb13u1
RUN apt-get update && apt-get install -y --no-install-recommends libcjson-dev=${CJSON_REFERENCE_VERSION} && rm -rf /var/lib/apt/lists/*
RUN --network=none cd /app && python -B -m deploy.debian_refresh_inventory --root / --sdk --output /tmp/debian-refresh-sdk.json && rm /tmp/debian-refresh-sdk.json
COPY tests/fixtures/json_backend_reference.c /tmp/json_backend_reference.c
RUN cc -O2 -Wall -Wextra -Werror /tmp/json_backend_reference.c -o /tmp/json-backend-reference -Wl,-rpath,/opt/pamolive-freerdp/lib $(pkg-config --cflags --libs freerdp3 winpr3 jansson libcjson)
RUN --network=none /tmp/json-backend-reference > /json-reference.jsonl && python /tmp/jansson_oracle_identity.py reference /reference-identity.json

FROM runtime AS native-test
COPY --from=native-test-builder /opt/pamolive-test /opt/pamolive-test
RUN --network=none /opt/pamolive-test/winpr-jansson-regression > /opt/pamolive-test/winpr-jansson-runtime.json && python deploy/jansson_oracle_identity.py runtime /opt/pamolive-test/runtime-identity.json
COPY requirements-python-native-test-linux.lock /tmp/requirements-python-native-test-linux.lock
COPY --from=directory-builder /opt/python-inputs/native-test /opt/python-native-test-wheels
RUN --network=none python -m pip --isolated --disable-pip-version-check install --no-compile --no-cache-dir --no-index --find-links=/opt/python-native-test-wheels --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-python-native-test-linux.lock && python -m pip check && rm -r /opt/python-native-test-wheels

FROM scratch AS json-reference-data
COPY --from=json-reference-test /json-reference.jsonl /json-reference.jsonl
COPY --from=json-reference-test /reference-identity.json /reference-identity.json
COPY --from=native-test-builder /opt/pamolive-test/winpr-jansson-regression.json /winpr-jansson-build.json
COPY --from=native-test-builder /opt/pamolive-test/build-identity.json /build-identity.json
COPY --from=native-test /opt/pamolive-test/winpr-jansson-runtime.json /winpr-jansson-runtime.json
COPY --from=native-test /opt/pamolive-test/runtime-identity.json /runtime-identity.json

FROM runtime AS production
