# New SOURCE-only qualification recipe; product Dockerfile is not changed.
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS capture
COPY deploy/expat_apt/ /opt/expat-apt/
ARG CODE_PINS_SHA
ARG POLICY_SHA
# Real kernel negatives run in a disposable network-none stage before capture.
# Transport-only summary: the driver itself requires COMPLETE_DATA_ONLY.
RUN --network=none /usr/bin/timeout --signal=TERM --kill-after=5s 45s \
    /usr/local/bin/python3.12 -I -B -S /opt/expat-apt/supervisor.py native-fence "${CODE_PINS_SHA}"
RUN --mount=type=bind,from=c-authority,target=/c-authority,ro \
    /usr/bin/timeout --signal=TERM --kill-after=15s 1850s \
    /usr/local/bin/python3.12 -I -B -S /opt/expat-apt/supervisor.py \
    capture "${CODE_PINS_SHA}" "${POLICY_SHA}" expat-prepared-only-v1
FROM scratch AS capture-data
COPY --from=capture /c-status.json /supervisor.json
COPY --from=capture /c-supervisor/ /supervisor/
COPY --from=capture /c-capture/ /inputs/
COPY --from=capture /c-base/ /base/
COPY --from=capture /expat-apt-proof/ /commands/
COPY --from=capture /c-fence-native/ /fence-native/

FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS apply
COPY deploy/expat_apt/ /opt/expat-apt/
ARG CODE_PINS_SHA
ARG POLICY_SHA
ARG MATERIAL_SET_SHA
RUN --network=none \
    --mount=type=bind,from=c-base,target=/c-base,ro \
    --mount=type=bind,from=c-input,target=/c-input,ro \
    --mount=type=bind,from=c-bootstrap,target=/c-bootstrap,ro \
    --mount=type=bind,from=c-authority,target=/c-authority,ro \
    /usr/bin/timeout --signal=TERM --kill-after=15s 950s \
    /usr/local/bin/python3.12 -I -B -S /opt/expat-apt/supervisor.py \
    apply "${CODE_PINS_SHA}" "${POLICY_SHA}" expat-prepared-only-v1 "${MATERIAL_SET_SHA}"
FROM scratch AS apply-data
COPY --from=apply /c-status.json /supervisor.json
COPY --from=apply /c-supervisor/ /supervisor/
COPY --from=apply /expat-apt-proof/ /proof/
