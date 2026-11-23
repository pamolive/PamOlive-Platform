# ADR-042 — Correctifs OpenSSL sur le socle Trixie de livraison

Les deux scans du candidat intégré refusent 31 groupes, dont huit pour les
paquets OpenSSL Trixie `3.5.9-1~deb13u1`. La branche préparatoire OpenSSL
sur `3.5.7` qualifie des contrôles de source. Elle n'a encore ni résultat
de compilation native, ni mesure d'ABI pour `3.5.9`.
[Scan intégré](https://github.com/pamolive/PamOlive-Platform/actions/runs/45126161877)

OpenSSL annonce la publication de `3.5.10` le 1er décembre 2026. Au
23 novembre, l'archive de version signée n'est pas publiée. Six corrections
annoncées au public figurent sur la branche OpenSSL 3.5. Le correctif CMS
de CVE-2026-121482 y figure également. Les sept changements production
s'appliquent dans l'ordre amont à la source Debian `3.5.9`. Les contextes
et les empreintes des neuf fichiers modifiés ont été vérifiés en mémoire.
[Avis du 10 novembre](https://openssl-library.org/news/secadv/20261110.txt) ·
[Avis du 17 novembre](https://openssl-library.org/news/secadv/20261117.txt) ·
[Correctif CMS OpenSSL](https://github.com/openssl/openssl/commit/468c287cf451a834b370b69ab321b8ffdfac23aa)

Le laboratoire retient le socle source exact de Trixie authentifié par APT
et les deltas de production des sept commits. Les empreintes des correctifs
bruts et de leurs projections sont fixées séparément. Ces commits publics
ne remplacent pas la signature d'une archive de version. La compilation et
l'installation s'exécutent hors réseau. Les tests Debian existants, les
SONAME, les exports versionnés, le SDK, les providers et une session TLS 1.3
avec vérification du certificat sur un transport en mémoire sont contrôlés.

CVE-2026-84786 reste ouverte sur Trixie et sans correction intégrée à
OpenSSL 3.5 dans le périmètre inspecté. La qualification native et le scan
de l'image produit restent indispensables. La politique de livraison ne
change pas. Le binaire de laboratoire conserve son identité locale Debian.
[Suivi Debian](https://security-tracker.debian.org/tracker/CVE-2026-84786) ·
[Correction amont en revue](https://github.com/openssl/openssl/pull/33634)

## Qualification et intégration

Le laboratoire sur `7fc4465` a vérifié 5 868 exports de `libcrypto.so.3`
et 609 de `libssl.so.3` face aux paquets officiels. La suite principale
reporte `PASS` pour 4 932 tests comptabilisés. Le résumé conserve les
cas ignorés. Le SDK, le chargement des providers et la session TLS 1.3
sont également vérifiés.
[Artefact natif](https://github.com/pamolive/PamOlive-Platform/actions/runs/45134682372/artifacts/14799723947)

La recette produit reconstruit les quatre paquets avec les mêmes entrées
et vérifie leurs empreintes avant installation. Les trois paquets runtime
et le SDK sont installés explicitement à la version locale. L'inventaire
compare les deux bibliothèques, le programme `openssl` et le module
`legacy.so` aux ELF extraits de l'artefact qualifié. Le rapport de l'image
et son SBOM lient les paquets et le reçu au digest de l'archive et à
l'identifiant de configuration. L'intégration et le scan restent à
exécuter sur le candidat produit complet.
