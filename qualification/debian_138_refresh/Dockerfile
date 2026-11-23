FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS debian-138-refresh-verification
WORKDIR /opt/pamolive-refresh
COPY debian.list apt.conf verify_refresh.py smoke.c ./
RUN test "$(dpkg --print-architecture)" = amd64 && test -s /usr/share/keyrings/debian-archive-keyring.gpg && mkdir -m 0755 /opt/pamolive-apt-cache /opt/pamolive-apt-lists && python -I -B -S verify_refresh.py acquire
RUN --network=none python -I -B -S verify_refresh.py qualify

FROM scratch AS debian-138-refresh-evidence
COPY --from=debian-138-refresh-verification /opt/pamolive-refresh/debian-138-refresh.json /
