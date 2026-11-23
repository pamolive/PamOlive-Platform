FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
WORKDIR /opt/qualification
ENV LC_ALL=C.UTF-8 PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1
RUN test "$(dpkg --print-architecture)" = amd64 \
 && apt-get -o APT::Update::Error-Mode=any update \
 && apt-get install -y --no-install-recommends --no-remove build-essential libldap2-dev \
    libsasl2-dev libpq-dev=17.12-0+deb13u1 libpq5=17.12-0+deb13u1 \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=0444 deploy/python_materials.py deploy/native_inventory.py deploy/python-materials.linux-amd64.json ./
COPY --chmod=0444 requirements-bootstrap.lock requirements-python-runtime-linux.lock requirements-python-build-tools-linux.lock requirements-python-native-sources-linux.lock requirements-python-native-test-linux.lock ./
RUN umask 022 && python -B python_materials.py acquire --manifest python-materials.linux-amd64.json \
    --locks . --output /opt/python-inputs
RUN --network=none python -m pip install --no-compile --no-cache-dir --no-index \
    --find-links=/opt/python-inputs/bootstrap --only-binary=:all: --no-deps --require-hashes \
    -r requirements-bootstrap.lock \
 && python -m pip install --no-compile --no-cache-dir --no-index \
    --find-links=/opt/python-inputs/build-tools --only-binary=:all: --no-deps --require-hashes \
    -r requirements-python-build-tools-linux.lock \
 && install -d -m 0700 -o 65534 -g 65534 \
    /opt/wheels /opt/trace /opt/installed /opt/qualification-work /evidence
COPY --chmod=0555 qualification/python_native_provenance/compiler_probe.py /opt/compiler-probe
COPY --chmod=0444 qualification/python_native_provenance/validate_observations.py ./
USER 65534:65534
ENV HOME=/tmp PATH=/usr/local/bin:/usr/bin:/bin PAMOLIVE_PROVENANCE_DIR=/opt/trace
RUN --network=none CC=/opt/compiler-probe LDSHARED='/opt/compiler-probe -shared' CXX=/bin/false \
    python -m pip wheel --no-cache-dir --no-index --find-links=/opt/python-inputs/sources \
    --no-binary=:all: --no-build-isolation --check-build-dependencies --no-deps --require-hashes \
    --wheel-dir /opt/wheels -r requirements-python-native-sources-linux.lock \
 && python -B python_materials.py capture-derived --manifest python-materials.linux-amd64.json \
    --locks . --inputs /opt/python-inputs --wheels /opt/wheels \
    --output /opt/qualification-work/derived \
 && python -m pip install --no-compile --no-cache-dir --no-index --find-links=/opt/wheels \
    --only-binary=:all: --no-deps --require-hashes --target /opt/installed \
    -r /opt/qualification-work/derived/requirements-python-derived-linux.lock \
 && python -B validate_observations.py

FROM scratch AS evidence
COPY --from=build --chown=0:0 --chmod=0444 /evidence/compiler-observations.json /evidence/derived-manifest.json /evidence/qualification.json /
