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
printf '%s  %s\n' 22abebc3df34da38a96bd476b7387754c97eefc51477112a7ad812dd08a3cb05 /guacd-freerdp3-gdi-lifecycle.patch | sha256sum -c -
patch --batch --forward --fuzz=0 -p1 < /guacd-freerdp3-gdi-lifecycle.patch
pkg-config --exists freerdp3
# FreeRDP 3 headers contain deprecated compatibility helpers. Preserve
# warnings and all other -Werror checks; only these deprecations remain warnings.
CFLAGS="-O2 -Wno-error=deprecated-declarations" LDFLAGS="-Wl,-rpath,/opt/pamolive-freerdp/lib" ./configure --prefix=/opt/pamolive-guac --with-ssh --with-rdp --without-vnc --without-telnet --without-websockets --without-pulse --without-vorbis --without-libavcodec --without-libavformat --without-libavutil --without-libswscale
make -j1
make install
test -e /opt/pamolive-guac/lib/libguac-client-ssh.so
test -e /opt/pamolive-guac/lib/libguac-client-rdp.so
mkdir -p /opt/pamolive-guac/share/pamolive
cp LICENSE NOTICE /opt/pamolive-guac/share/pamolive/
cp /guacd-deny-rdp-redirection.patch /opt/pamolive-guac/share/pamolive/
cp /guacd-freerdp3-gdi-lifecycle.patch /opt/pamolive-guac/share/pamolive/
printf '%s\n' ab36756b596520ae2a94cd4d25e406e0b5aa820b > /opt/pamolive-guac/share/pamolive/gdi-upstream-commit.txt
pkg-config --modversion freerdp3 > /opt/pamolive-guac/share/pamolive/freerdp-version.txt
printf '%s\n' 1.6.0 > /opt/pamolive-guac/share/pamolive/version.txt
printf '%s\n' 8bc45675da96d7b6f39728160181e3d4ff3c08f460f6d26de5805b642bf13f2b > /opt/pamolive-guac/share/pamolive/source-sha256.txt
printf '%s\n' '--with-ssh --with-rdp --without-vnc --without-telnet --without-websockets --without-pulse --without-vorbis --without-libavcodec --without-libavformat --without-libavutil --without-libswscale' > /opt/pamolive-guac/share/pamolive/build-options.txt
