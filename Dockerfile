ARG LIBPQ_DEBIAN_VERSION=17.12-0+deb13u1
ARG JANSSON_DEBIAN_VERSION=2.14-2+b3
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS expat-prepared
RUN apt-get update && apt-get install -y --no-install-recommends build-essential binutils patch gpg=2.4.7-21+deb13u1+b5 dpkg-dev debhelper autoconf automake libtool pkg-config docbook-to-man docbook2x libexpat1-dev=2.9.0-1~deb13u1 ca-certificates && rm -rf /var/lib/apt/lists/*
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

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS krb5-builder
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential curl ca-certificates gpgv debian-archive-keyring dpkg-dev devscripts quilt && rm -rf /var/lib/apt/lists/*
COPY deploy/build-krb5.sh deploy/krb5-asn1-sequence.patch deploy/krb5-test-keyring-seccomp.patch deploy/check_krb5_asn1.sh deploy/krb5_inventory.py tests/fixtures/krb5_asn1_regression.c /build-fixtures/
RUN sh /build-fixtures/build-krb5.sh fetch
RUN python /build-fixtures/krb5_inventory.py --capture-baseline --output /usr/share/pamolive/krb5-backport/baseline.json
RUN --network=none sh /build-fixtures/build-krb5.sh build

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS krb5-runtime
COPY --from=krb5-builder /packages/runtime /tmp/pamolive-krb5-runtime
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends /tmp/pamolive-krb5-runtime/*.deb && rm -r /tmp/pamolive-krb5-runtime && rm -rf /var/lib/apt/lists/*
COPY --from=krb5-builder /usr/share/pamolive/krb5-backport /usr/share/pamolive/krb5-backport
COPY deploy/krb5_inventory.py /tmp/krb5_inventory.py
RUN python /tmp/krb5_inventory.py --capture --output /usr/share/pamolive/krb5-backport/inventory.json && chmod 0444 /usr/share/pamolive/krb5-backport/inventory.json && rm /tmp/krb5_inventory.py

FROM krb5-runtime AS expat-runtime
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
RUN apt-get update && apt-get install -y --no-install-recommends libc6-dev && rm -rf /var/lib/apt/lists/*
COPY --from=expat-source-builder /expat-packages/sdk/ /tmp/expat-sdk/
RUN --network=none dpkg --install /tmp/expat-sdk/*.deb && rm -r /tmp/expat-sdk

FROM expat-sdk AS freerdp-builder
ARG JANSSON_DEBIAN_VERSION
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential cmake pkg-config curl ca-certificates gnupg patchelf libssl-dev zlib1g-dev libjpeg62-turbo-dev libjansson-dev=${JANSSON_DEBIAN_VERSION} patch libicu-dev liburiparser-dev libcairo2-dev
COPY --from=krb5-builder /packages/runtime /tmp/pamolive-krb5-runtime
COPY --from=krb5-builder /packages/sdk /tmp/pamolive-krb5-sdk
RUN apt-get install -y --no-install-recommends /tmp/pamolive-krb5-runtime/*.deb /tmp/pamolive-krb5-sdk/*.deb && rm -r /tmp/pamolive-krb5-runtime /tmp/pamolive-krb5-sdk && rm -rf /var/lib/apt/lists/*
COPY deploy/build-freerdp.sh /build-freerdp.sh
RUN --network=none test "$(dpkg-query --show --showformat='${Version}' libexpat1)" = '2.10.0-1+pamolive1' && test "$(dpkg-query --show --showformat='${Version}' libexpat1-dev)" = '2.10.0-1+pamolive1'
COPY deploy/freerdp-jansson-compat.patch /freerdp-jansson-compat.patch
RUN sh /build-freerdp.sh

FROM freerdp-builder AS guacd-builder
ENV PKG_CONFIG_PATH=/opt/pamolive-freerdp/lib/pkgconfig LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends libtool-bin libcairo2-dev libpng-dev libpango1.0-dev libssh2-1-dev uuid-dev && rm -rf /var/lib/apt/lists/*
COPY deploy/build-guacd.sh /build-guacd.sh
COPY deploy/guacd-deny-rdp-redirection.patch /guacd-deny-rdp-redirection.patch
COPY deploy/guacd-freerdp3-gdi-lifecycle.patch /guacd-freerdp3-gdi-lifecycle.patch
RUN --network=none test "$(dpkg-query --show --showformat='${Version}' libexpat1)" = '2.10.0-1+pamolive1' && test "$(dpkg-query --show --showformat='${Version}' libexpat1-dev)" = '2.10.0-1+pamolive1'
RUN sh /build-guacd.sh

FROM expat-sdk AS directory-builder
ARG LIBPQ_DEBIAN_VERSION
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential libldap2-dev libsasl2-dev libpq-dev=${LIBPQ_DEBIAN_VERSION} libpq5=${LIBPQ_DEBIAN_VERSION} && rm -rf /var/lib/apt/lists/*
RUN --network=none test "$(dpkg-query --show --showformat='${Version}' libexpat1)" = '2.10.0-1+pamolive1' && test "$(dpkg-query --show --showformat='${Version}' libexpat1-dev)" = '2.10.0-1+pamolive1'
COPY requirements-bootstrap.lock requirements-python-runtime-linux.lock requirements-python-build-tools-linux.lock requirements-python-native-sources-linux.lock requirements-python-native-test-linux.lock /tmp/
COPY deploy/python_materials.py deploy/python-materials.linux-amd64.json /tmp/
RUN python /tmp/python_materials.py acquire --manifest /tmp/python-materials.linux-amd64.json --locks /tmp --output /opt/python-inputs
RUN --network=none export PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-inputs/bootstrap --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-bootstrap.lock && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-inputs/build-tools --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-python-build-tools-linux.lock && python -m pip wheel --no-cache-dir --no-index --find-links=/opt/python-inputs/sources --no-binary=:all: --no-build-isolation --check-build-dependencies --no-deps --require-hashes --wheel-dir /opt/directory-wheels -r /tmp/requirements-python-native-sources-linux.lock && python /tmp/python_materials.py capture-derived --manifest /tmp/python-materials.linux-amd64.json --locks /tmp --inputs /opt/python-inputs --wheels /opt/directory-wheels --output /opt/python-evidence && cp /tmp/python-materials.linux-amd64.json /tmp/requirements-bootstrap.lock /tmp/requirements-python-*.lock /opt/python-evidence/

FROM expat-runtime AS runtime-build
ARG JANSSON_DEBIAN_VERSION
ARG LIBPQ_DEBIAN_VERSION
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends libcairo2 libpng16-16t64 libjpeg62-turbo libpango-1.0-0 libpangocairo-1.0-0 libssh2-1t64 libssl3t64 libjansson4=${JANSSON_DEBIAN_VERSION} libkrb5-3 libgssapi-krb5-2 libicu76 liburiparser1 zlib1g fonts-dejavu-core libldap2 libsasl2-2 libpq5=${LIBPQ_DEBIAN_VERSION} && rm -rf /var/lib/apt/lists/*
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
RUN python deploy/native_inventory.py --capture --output /opt/pamolive-native-manifest.json
RUN python deploy/krb5_inventory.py --verify --output /tmp/krb5-verification.json && rm /tmp/krb5-verification.json
RUN python manage.py collectstatic --noinput
USER root
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/', timeout=4)"
CMD ["python", "deploy/runtime.py"]

# Recheck active files after all product APT/Python installs, before the clean snapshot.
RUN --network=none python -I -B -S /usr/local/libexec/pamolive-expat4/verify_runtime.py /usr/share/pamolive/expat4/runtime-product && find /usr/share/pamolive/expat4 -type d -exec chmod 0755 {} + && find /usr/share/pamolive/expat4 -type f -exec chmod 0444 {} +

FROM scratch AS runtime
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
RUN --network=none --mount=from=runtime-build,source=/,target=/__pamolive_previous,ro python -I -B -S /app/deploy/expat_snapshot.py /__pamolive_previous / /usr/share/pamolive/expat4/snapshot.json

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
