FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS freerdp-builder
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential cmake pkg-config curl ca-certificates gnupg patchelf libssl-dev zlib1g-dev libjpeg62-turbo-dev libcjson-dev libkrb5-dev libicu-dev liburiparser-dev libcairo2-dev && rm -rf /var/lib/apt/lists/*
COPY deploy/build-freerdp.sh /build-freerdp.sh
RUN sh /build-freerdp.sh

FROM freerdp-builder AS guacd-builder
ENV PKG_CONFIG_PATH=/opt/pamolive-freerdp/lib/pkgconfig LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends libtool-bin libcairo2-dev libpng-dev libpango1.0-dev libssh2-1-dev uuid-dev && rm -rf /var/lib/apt/lists/*
COPY deploy/build-guacd.sh /build-guacd.sh
COPY deploy/guacd-deny-rdp-redirection.patch /guacd-deny-rdp-redirection.patch
COPY deploy/guacd-freerdp3-gdi-lifecycle.patch /guacd-freerdp3-gdi-lifecycle.patch
RUN sh /build-guacd.sh

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS directory-builder
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends build-essential libldap2-dev libsasl2-dev libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements-directory.lock requirements-bootstrap.lock requirements-native-build.lock requirements-database-build.lock /tmp/
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-bootstrap.lock && python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes -r /tmp/requirements-native-build.lock && python -m pip wheel --no-cache-dir --no-build-isolation --no-deps --require-hashes --wheel-dir /opt/directory-wheels -r /tmp/requirements-database-build.lock && python -m pip wheel --no-cache-dir --no-build-isolation --no-deps --wheel-dir /opt/directory-wheels -r /tmp/requirements-directory.lock

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends libcairo2 libpng16-16t64 libjpeg62-turbo libpango-1.0-0 libpangocairo-1.0-0 libssh2-1t64 libssl3t64 libcjson1 libkrb5-3 libgssapi-krb5-2 libicu76 liburiparser1 zlib1g fonts-dejavu-core libldap2 libsasl2-2 libpq5 && rm -rf /var/lib/apt/lists/*
COPY --from=freerdp-builder /opt/pamolive-freerdp/lib /opt/pamolive-freerdp/lib
COPY --from=freerdp-builder /opt/pamolive-freerdp/share/pamolive-freerdp /opt/pamolive-freerdp/share/pamolive-freerdp
COPY --from=guacd-builder /opt/pamolive-guac /opt/pamolive-guac
ENV LD_LIBRARY_PATH=/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PSYCOPG_IMPL=c
WORKDIR /app
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin pamolive && useradd --uid 1001 --no-create-home --shell /usr/sbin/nologin pamolive-guacd
COPY requirements.lock requirements-bootstrap.lock ./
COPY --from=directory-builder /opt/directory-wheels /opt/directory-wheels
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes -r requirements-bootstrap.lock && python -m pip install --no-cache-dir --no-index --no-deps /opt/directory-wheels/psycopg_c-3.2.10-*.whl && python -m pip install --no-cache-dir --find-links=/opt/directory-wheels -r requirements.lock && python -m pip check && rm -r /opt/directory-wheels
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
COPY requirements-native-test.lock /tmp/requirements-native-test.lock
RUN pip install --no-cache-dir -r /tmp/requirements-native-test.lock

FROM runtime AS production
