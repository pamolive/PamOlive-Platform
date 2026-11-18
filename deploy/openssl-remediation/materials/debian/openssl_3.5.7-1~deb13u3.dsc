-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: openssl
Binary: openssl, openssl-provider-legacy, openssl-provider-fips, libssl3t64, libcrypto3-udeb, libssl3-udeb, libssl-dev, libssl-doc
Architecture: any all
Version: 3.5.7-1~deb13u3
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Uploaders: Christoph Martin <christoph.martin@uni-mainz.de>, Kurt Roeckx <kurt@roeckx.be>, Sebastian Andrzej Siewior <sebastian@breakpoint.cc>
Homepage: https://openssl-library.org
Standards-Version: 4.7.2
Vcs-Browser: https://salsa.debian.org/debian/openssl
Vcs-Git: https://salsa.debian.org/debian/openssl.git
Testsuite: autopkgtest
Testsuite-Triggers: perl
Build-Depends: debhelper-compat (= 13), dpkg-dev (>= 1.22.5), libzstd-dev, zlib1g-dev
Package-List:
 libcrypto3-udeb udeb debian-installer optional arch=any profile=!noudeb profile:v1=!noudeb
 libssl-dev deb libdevel optional arch=any
 libssl-doc deb doc optional arch=all
 libssl3-udeb udeb debian-installer optional arch=any profile=!noudeb profile:v1=!noudeb
 libssl3t64 deb libs optional arch=any
 openssl deb utils optional arch=any
 openssl-provider-fips deb utils optional arch=any
 openssl-provider-legacy deb utils optional arch=any
Checksums-Sha1:
 53d331880fbde8e6fe25870d5325a61201f6264d 53153930 openssl_3.5.7.orig.tar.gz
 9408998095f984b36591732286ef1df1ba7ce492 833 openssl_3.5.7.orig.tar.gz.asc
 11a6b388b1ce45f8c60021ed66f8772f7c963c62 147344 openssl_3.5.7-1~deb13u3.debian.tar.xz
Checksums-Sha256:
 a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 53153930 openssl_3.5.7.orig.tar.gz
 d3d082bee3f658c31db53af625eceecf29d777c7010394bed5787ebcc98abdf2 833 openssl_3.5.7.orig.tar.gz.asc
 0a427fdc3e773f4119a7dd5b36d1f0903a163cf4ea15d812bb823b251ff1cbc5 147344 openssl_3.5.7-1~deb13u3.debian.tar.xz
Files:
 36608cd5445f708d0c2200aea9682c35 53153930 openssl_3.5.7.orig.tar.gz
 1550a37dc3382ec617b5fd7d4140b92c 833 openssl_3.5.7.orig.tar.gz.asc
 6f660602c694d6fc1439abf05cb3d29e 147344 openssl_3.5.7-1~deb13u3.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEV4kucFIzBRM39v3RBWQfF1cS+lsFAmq8HwcACgkQBWQfF1cS
+lui3Qv+N5VpnmxefKqZZQ8xFDLGIQ4bcxsaKgu2JNz23VoMa+peOSfX5TQ6B1yU
JUtdnS4jupLlt7Qiib4OPk7Ec/RmuGemuQ/uhafVgZuEmHQ8i1PA9vWgIxgdZj4f
2kmZ/9HqYNQdRVNUJXsRRtG5M/pgCxR/Imcwv4knSiEarDqfzE3K1YNju3Wu2QS1
pH6X+EFzf0JPfc13QPSya+icLDzTXBcqGPFJtrymRwJ2ngXJugWgSEChhNyWB1kn
G/stozsFA0hHkkO/oQmTRGJeD2h23okM/uZlnCUS494RnxInKKZnMTaEzXxvzntk
ygwfKNCdEC4wiRvv+lOlYpZc7+KRmlIYNdBqrSQWto1RgakDWqUBPkG1djPYflTh
WLcsqA1bzNmXL13jP4mcyynsQA7KbMR2px4KXvqKGxYUJ9JP5GWZZkTlg2fFCgbh
zD7/BlgcqFjFWxKdC3LjBFFePsXs0a80OD8NAUUKCNcrQ/wa04xD81sOGN4Ljyoy
+QVw5Csv
=m8ma
-----END PGP SIGNATURE-----
