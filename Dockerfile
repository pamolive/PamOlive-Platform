ARG LIBPQ_DEBIAN_VERSION=17.12-0+deb13u1
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

FROM krb5-runtime AS freerdp-builder
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential cmake pkg-config curl ca-certificates gnupg patchelf libssl-dev zlib1g-dev libjpeg62-turbo-dev libcjson-dev libicu-dev liburiparser-dev libcairo2-dev
COPY --from=krb5-builder /packages/runtime /tmp/pamolive-krb5-runtime
COPY --from=krb5-builder /packages/sdk /tmp/pamolive-krb5-sdk
RUN apt-get install -y --no-install-recommends /tmp/pamolive-krb5-runtime/*.deb /tmp/pamolive-krb5-sdk/*.deb && rm -r /tmp/pamolive-krb5-runtime /tmp/pamolive-krb5-sdk && rm -rf /var/lib/apt/lists/*
COPY deploy/build-freerdp.sh /build-freerdp.sh
RUN sh /build-freerdp.sh

FROM freerdp-builder AS guacd-builder
ENV PKG_CONFIG_PATH=/opt/pamolive-freerdp/lib/pkgconfig LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends libtool-bin libcairo2-dev libpng-dev libpango1.0-dev libssh2-1-dev uuid-dev && rm -rf /var/lib/apt/lists/*
COPY deploy/build-guacd.sh /build-guacd.sh
COPY deploy/guacd-deny-rdp-redirection.patch /guacd-deny-rdp-redirection.patch
COPY deploy/guacd-freerdp3-gdi-lifecycle.patch /guacd-freerdp3-gdi-lifecycle.patch
RUN sh /build-guacd.sh

FROM krb5-runtime AS directory-builder
ARG LIBPQ_DEBIAN_VERSION
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential libldap2-dev libsasl2-dev libpq-dev=${LIBPQ_DEBIAN_VERSION} libpq5=${LIBPQ_DEBIAN_VERSION} && rm -rf /var/lib/apt/lists/*
COPY requirements-bootstrap.lock requirements-python-runtime-linux.lock requirements-python-build-tools-linux.lock requirements-python-native-sources-linux.lock requirements-python-native-test-linux.lock /tmp/
COPY deploy/python_materials.py deploy/python-materials.linux-amd64.json /tmp/
RUN python /tmp/python_materials.py acquire --manifest /tmp/python-materials.linux-amd64.json --locks /tmp --output /opt/python-inputs
RUN --network=none export PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-inputs/bootstrap --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-bootstrap.lock && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/python-inputs/build-tools --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-python-build-tools-linux.lock && python -m pip wheel --no-cache-dir --no-index --find-links=/opt/python-inputs/sources --no-binary=:all: --no-build-isolation --check-build-dependencies --no-deps --require-hashes --wheel-dir /opt/directory-wheels -r /tmp/requirements-python-native-sources-linux.lock && python /tmp/python_materials.py capture-derived --manifest /tmp/python-materials.linux-amd64.json --locks /tmp --inputs /opt/python-inputs --wheels /opt/directory-wheels --output /opt/python-evidence && cp /tmp/python-materials.linux-amd64.json /tmp/requirements-bootstrap.lock /tmp/requirements-python-*.lock /opt/python-evidence/

FROM krb5-runtime AS runtime
ARG LIBPQ_DEBIAN_VERSION
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends libcairo2 libpng16-16t64 libjpeg62-turbo libpango-1.0-0 libpangocairo-1.0-0 libssh2-1t64 libssl3t64 libcjson1 libkrb5-3 libgssapi-krb5-2 libicu76 liburiparser1 zlib1g fonts-dejavu-core libldap2 libsasl2-2 libpq5=${LIBPQ_DEBIAN_VERSION} && rm -rf /var/lib/apt/lists/*
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

FROM guacd-builder AS native-test-builder
COPY tests/fixtures/rdp_fixture.c /tmp/rdp_fixture.c
RUN mkdir -p /opt/pamolive-test && cc -O2 -Wall -Wextra -Werror -Wno-error=deprecated-declarations -pthread /tmp/rdp_fixture.c -o /opt/pamolive-test/rdp-fixture -Wl,-rpath,/opt/pamolive-freerdp/lib $(pkg-config --cflags --libs freerdp3 winpr3)

FROM runtime AS native-test
COPY --from=native-test-builder /opt/pamolive-test /opt/pamolive-test
COPY requirements-python-native-test-linux.lock /tmp/requirements-python-native-test-linux.lock
COPY --from=directory-builder /opt/python-inputs/native-test /opt/python-native-test-wheels
RUN --network=none python -m pip --isolated --disable-pip-version-check install --no-compile --no-cache-dir --no-index --find-links=/opt/python-native-test-wheels --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-python-native-test-linux.lock && python -m pip check && rm -r /opt/python-native-test-wheels

FROM runtime AS production
