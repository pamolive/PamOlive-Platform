#!/bin/sh
set -eu
cd /tmp
curl -fsSLo guacamole-server.tar.gz https://dlcdn.apache.org/guacamole/1.6.0/source/guacamole-server-1.6.0.tar.gz
printf '%s  %s\n' 8bc45675da96d7b6f39728160181e3d4ff3c08f460f6d26de5805b642bf13f2b guacamole-server.tar.gz | sha256sum -c -
curl -fsSLo guacamole-server.asc https://dlcdn.apache.org/guacamole/1.6.0/source/guacamole-server-1.6.0.tar.gz.asc
curl -fsSLo guacamole-KEYS https://downloads.apache.org/guacamole/KEYS
gpg --batch --import guacamole-KEYS
gpg --batch --verify guacamole-server.asc guacamole-server.tar.gz
tar -xzf guacamole-server.tar.gz
cd guacamole-server-1.6.0
patch --batch --forward -p1 < /guacd-deny-rdp-redirection.patch
pkg-config --exists freerdp3
./configure --prefix=/opt/pamolive-guac --with-ssh --with-rdp --without-vnc --without-telnet --without-websockets --without-pulse --without-vorbis --without-libavcodec --without-libavformat --without-libavutil --without-libswscale
make -j2
make install
test -e /opt/pamolive-guac/lib/libguac-client-ssh.so
test -e /opt/pamolive-guac/lib/libguac-client-rdp.so
mkdir -p /opt/pamolive-guac/share/pamolive
cp LICENSE NOTICE /opt/pamolive-guac/share/pamolive/
cp /guacd-deny-rdp-redirection.patch /opt/pamolive-guac/share/pamolive/
pkg-config --modversion freerdp3 > /opt/pamolive-guac/share/pamolive/freerdp-version.txt
