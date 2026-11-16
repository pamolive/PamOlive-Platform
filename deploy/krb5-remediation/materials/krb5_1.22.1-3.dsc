-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: krb5
Binary: krb5-user, krb5-kdc, krb5-kdc-ldap, krb5-admin-server, krb5-kpropd, krb5-multidev, libkrb5-dev, libkrb5-dbg, krb5-pkinit, krb5-otp, krb5-k5tls, krb5-doc, libkrb5-3, libgssapi-krb5-2, libgssrpc4t64, libkadm5srv-mit12, libkadm5clnt-mit12, libk5crypto3, libkdb5-10t64, libkrb5support0, libkrad0, krb5-gss-samples, krb5-locales, libkrad-dev
Architecture: any all
Version: 1.22.1-3
Maintainer: Sam Hartman <hartmans@debian.org>
Uploaders: Russ Allbery <rra@debian.org>, Benjamin Kaduk <kaduk@mit.edu>
Homepage: https://web.mit.edu/kerberos/
Standards-Version: 4.7.0
Vcs-Browser: https://salsa.debian.org/debian/krb5
Vcs-Git: https://salsa.debian.org/debian/krb5
Testsuite: autopkgtest
Testsuite-Triggers: ldap-utils, libsasl2-modules-gssapi-mit, slapd
Build-Depends: byacc | bison, comerr-dev, debhelper-compat (= 13), docbook-to-man, dpkg-dev (>= 1.22.5), libkeyutils-dev [linux-any], libldap2-dev <!stage1>, liblmdb-dev, libnss-myhostname, libsasl2-dev <!stage1>, libssl-dev, libverto-dev, pkgconf, ss-dev
Build-Depends-Arch: dpkg-dev (>= 1.22.5), keyutils [linux-any] <!nocheck>, libcmocka-dev <!nocheck>, python3-kdcproxy <!nocheck>, python3-pyrad <!nocheck>
Build-Depends-Indep: doxygen, doxygen-latex, python3, python3-cheetah, python3-lxml, python3-sphinx, tex-gyre
Package-List:
 krb5-admin-server deb net optional arch=any
 krb5-doc deb doc optional arch=all
 krb5-gss-samples deb net optional arch=any
 krb5-k5tls deb net optional arch=any
 krb5-kdc deb net optional arch=any
 krb5-kdc-ldap deb net optional arch=any profile=!stage1 profile:v1=!stage1
 krb5-kpropd deb net optional arch=any
 krb5-locales deb localization optional arch=all
 krb5-multidev deb libdevel optional arch=any
 krb5-otp deb net optional arch=any
 krb5-pkinit deb net optional arch=any
 krb5-user deb net optional arch=any
 libgssapi-krb5-2 deb libs optional arch=any
 libgssrpc4t64 deb libs optional arch=any
 libk5crypto3 deb libs optional arch=any
 libkadm5clnt-mit12 deb libs optional arch=any
 libkadm5srv-mit12 deb libs optional arch=any
 libkdb5-10t64 deb libs optional arch=any
 libkrad-dev deb libdevel optional arch=any
 libkrad0 deb libs optional arch=any
 libkrb5-3 deb libs optional arch=any
 libkrb5-dbg deb debug optional arch=any
 libkrb5-dev deb libdevel optional arch=any
 libkrb5support0 deb libs optional arch=any
Checksums-Sha1:
 24ae28fd36e6ecb56238733eb1123e7168989770 8747101 krb5_1.22.1.orig.tar.gz
 8b8cde628d3c84abd3ec95c465a7325460043ad3 833 krb5_1.22.1.orig.tar.gz.asc
 1d8d7d0ebabe58a4c8fd73e994b9185fddeb70d6 111476 krb5_1.22.1-3.debian.tar.xz
Checksums-Sha256:
 1a8832b8cad923ebbf1394f67e2efcf41e3a49f460285a66e35adec8fa0053af 8747101 krb5_1.22.1.orig.tar.gz
 598334b7b54f63a2280f72cc566bee6f9cbc5ef4dcd9ccabd3a0460641908a64 833 krb5_1.22.1.orig.tar.gz.asc
 519ad7537260ebc450a678b38f00c8deaf0e05d848d0e5cfeef1ddb154663ba8 111476 krb5_1.22.1-3.debian.tar.xz
Files:
 8f841cea186ef6856ea6c2a063091861 8747101 krb5_1.22.1.orig.tar.gz
 afd720bb67a95e728eb9715a5a28e93c 833 krb5_1.22.1.orig.tar.gz.asc
 43ba1f462c405922f93d52df62f9d3dd 111476 krb5_1.22.1-3.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQSj2jRwbAdKzGY/4uAsbEw8qDeGdAUCajVTzQAKCRAsbEw8qDeG
dFzwAP9S4Hx/Aw+IvDANg3vyYxbr0XB32Aq0KpHUEvLWats8RQD/cKG9v4zUWUT8
909bNqfOmL7KM5u6ASF9UEiXiuqXaA4=
=F+oY
-----END PGP SIGNATURE-----
