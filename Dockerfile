FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS guacd-builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config curl ca-certificates gnupg libtool-bin libcairo2-dev libpng-dev libjpeg62-turbo-dev libpango1.0-dev libssh2-1-dev libssl-dev freerdp3-dev uuid-dev
COPY deploy/build-guacd.sh /build-guacd.sh
COPY deploy/guacd-deny-rdp-redirection.patch /guacd-deny-rdp-redirection.patch
RUN sh /build-guacd.sh

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libcairo2 libpng16-16t64 libjpeg62-turbo libpango-1.0-0 libpangocairo-1.0-0 libssh2-1t64 libssl3t64 libfreerdp3-3 libfreerdp-client3-3 libwinpr3-3 fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
COPY --from=guacd-builder /opt/pamolive-guac /opt/pamolive-guac
ENV LD_LIBRARY_PATH=/opt/pamolive-guac/lib

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin pamolive && useradd --uid 1001 --no-create-home --shell /usr/sbin/nologin pamolive-guacd
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY . .
RUN python manage.py collectstatic --noinput
USER root
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/', timeout=4)"
CMD ["python", "deploy/runtime.py"]

FROM guacd-builder AS native-test-builder
COPY tests/fixtures/rdp_fixture.c /tmp/rdp_fixture.c
RUN mkdir -p /opt/pamolive-test && cc -O2 -Wall -Wextra -Werror -Wno-error=deprecated-declarations -pthread /tmp/rdp_fixture.c -o /opt/pamolive-test/rdp-fixture $(pkg-config --cflags --libs freerdp3 winpr3)

FROM runtime AS native-test
COPY --from=native-test-builder /opt/pamolive-test /opt/pamolive-test

FROM runtime AS production
