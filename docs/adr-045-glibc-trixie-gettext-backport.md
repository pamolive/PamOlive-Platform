# ADR-045 — Qualification du backport gettext sur Debian Trixie

Les scans OS et compilé de PamOlive signalent CVE-2026-84243 dans
la glibc de Trixie. La qualification repart du source Debian
`2.41-12+deb13u5` déjà sélectionné par l'image. Le bloc correctif
amont dans `intl/dcigettext.c` correspond exactement à ce source.
Les patches Debian de cette version ne modifient pas ce fichier.
[Suivi Debian](https://security-tracker.debian.org/tracker/CVE-2026-84243)
· [Correctif glibc](https://github.com/bminor/glibc/commit/03067f3c5e39aec5ec250a44bc1b395a1afd45e8)

Le backport conserve la série 2.41 et la recette Debian. Il
maintient une version cohérente pour `libc6`, `libc-bin`,
`libc6-dev` et `libc-dev-bin`. Une montée de version vers une
autre distribution changerait l'environnement de compilation
et le chargeur du produit. Filtrer les variables de locale aux
seuls points d'entrée PamOlive laisserait les autres exécutables
de l'image exposés au code d'origine.

Le laboratoire récupère les matériaux Debian sur APT signé,
contrôle leurs empreintes et compile sous un UID non privilégié
sans réseau. Il installe d'abord les paquets stock puis les quatre
paquets du même build dans une image jetable. Il vérifie l'état
dpkg, les dépendances, les symboles versionnés et le chargeur,
puis exécute les contrôles fonctionnels avec des données de
locale et des noms réservés à la boucle locale.
Le résumé conserve les cas ignorés et les échecs que l'emballage
Debian tolère. Un `FAIL`, un `UNRESOLVED` ou un `XPASS` produit
`reported_failures`. Les détails `XFAIL` et `UNSUPPORTED` restent
visibles pour évaluer la couverture avant admission.

Cette qualification couvre le paquet Debian amd64 et sa
compatibilité observée dans le laboratoire. La chaîne de livraison
doit reproduire les paquets qualifiés avant de modifier la base
runtime et le SDK. La CI de l'image doit valider les consommateurs,
le SBOM, le scan exact, PostgreSQL, la restauration et PAM. Une
mise à niveau réelle doit conserver le digest précédent et la
sauvegarde restaurable pour permettre le retour arrière.
