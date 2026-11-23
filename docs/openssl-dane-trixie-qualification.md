# Qualification du correctif DANE sur OpenSSL Trixie

Debian classe OpenSSL Trixie `3.5.9-1~deb13u1` vulnérable à
CVE-2026-84786. La proposition OpenSSL #33634 est encore en revue sur
la branche principale du fournisseur. Le candidat de laboratoire
`3.5.9-1~deb13u1+pamolive2` applique cette correction après les sept
deltas déjà qualifiés dans sa propre recette de construction.
[Suivi Debian](https://security-tracker.debian.org/tracker/CVE-2026-84786) ·
[Proposition OpenSSL](https://github.com/openssl/openssl/pull/33634)

La projection directe du premier commit ne s'applique pas au fichier
Trixie. Une fusion à trois voies du seul fichier de production
`crypto/x509/x509_vfy.c` produit un delta unique sans conflit. Le
manifeste fixe les révisions et les empreintes de l'ancêtre amont, de
la proposition amont complète et des deux fichiers Trixie.
[Manifeste](../qualification/openssl_trixie_backport/dane-provenance.json)

Le build vérifie les sources Debian et les correctifs existants, puis
l'empreinte du fichier cible après les sept corrections, le delta DANE
et les empreintes des neuf fichiers résultants. La compilation se
déroule hors réseau. La CI conserve le résumé TAP Debian, l'ABI,
le SDK et la vérification TLS 1.3 sur un transport en mémoire.

L'intégration produit dépend d'une revue indépendante du delta, du
résultat natif, de la vérification des paquets exacts dans l'image et
de son scan strict.
