# ADR-044 — Backport de ncurses-bin sur Debian Trixie

Les scans de la PR #72 incluent CVE-2025-69720 dans un groupe OS
de quatre paquets issus du même source Debian. L'avis concerne
l'utilitaire `infocmp` livré par `ncurses-bin`. Le correctif du
mainteneur tient dans deux modifications fonctionnelles de
`progs/infocmp.c`. Le paquet source Trixie `6.5+20250216-2`
est la base de compilation.
[Avis Debian](https://security-tracker.debian.org/tracker/CVE-2025-69720)
· [Correctif amont](https://github.com/ThomasDickey/ncurses-snapshots/commit/6f6db0e8fd14e40096a0ee6f8bdf32dedbd3fc9e)
· [Scan #72](https://github.com/pamolive/PamOlive-Platform/actions/runs/45163015819/artifacts/14818645061)

## Décision

Le backport produit `ncurses-bin` en version
`6.5+20250216-2+pamolive1` avec la recette Debian. Il
conserve le paquet Essential, les chemins attendus par dpkg et
les outils de maintenance terminal. Le paquet pré-dépend de
`libtinfo6` avec une borne minimale. `libncursesw6` et
`libtinfo6` gardent leurs versions Trixie exactement alignées.
`ncurses-base` conserve les données terminfo de la distribution.
[Paquet essentiel](https://packages.debian.org/trixie/ncurses-bin)
· [Dépendances de libncursesw6](https://packages.debian.org/trixie/libncursesw6)

Supprimer `infocmp` retirerait un outil d'un paquet Essential
installé et demanderait une preuve d'absence de toutes ses copies
dans l'image. Une mise à niveau depuis Forky modifierait aussi la
recette et les bibliothèques de terminal. Le backport réduit le
changement au paquet qui fournit le code concerné.

## Qualification

La campagne GitHub résout les entrées Debian sur APT authentifié.
Les empreintes épinglent le source, l'archive stock et les fichiers
avant et après l'application exacte du correctif. La compilation
s'exécute sans réseau sous un UID non privilégié. L'archive
candidate, le buildinfo et le résumé de construction sont liés
par un manifeste SHA-256.

Le laboratoire installe successivement le paquet stock et le
paquet candidat dans deux étapes de l'image. Il contrôle les
pré-dépendances et l'état dpkg, compare les programmes et leurs
alias, puis exerce `infocmp`, `tic` et `tput` sur des entrées
terminfo ordinaires de test. Le reçu concerne Debian Trixie
`linux/amd64` et le paquet vérifié.

La campagne `f860faf` a construit le paquet et validé les
deux autopkgtests Debian de terminal. Le test de références de
pages man et les exemples interactifs restent hors de cette
campagne. Le reçu compare aussi les outils, les alias et les
bibliothèques Trixie et valide les essais terminfo.
[Reçu de la campagne](https://github.com/pamolive/PamOlive-Platform/actions/runs/45206497423/artifacts/14834172560)

L'image reconstruit le paquet avec la même recette. L'installation
hors réseau exige l'empreinte du `.deb` qualifié. Le build
vérifie ensuite le binaire corrigé et les deux bibliothèques
Trixie par empreinte.

L'intégration au produit exige de reproduire le paquet qualifié, de
vérifier l'ELF installé dans le TAR final et d'exécuter les tests
SSH et la CI complète. Le rapport d'image doit encore associer
le groupe exact à un paquet local et aux trois paquets Trixie.
Cette campagne laisse le signalement High dans les scans bruts.
La procédure de restauration reposera sur le dernier digest
qualifié et sa sauvegarde. Le paquet stock est la référence
du laboratoire.

Les deux scans de la PR #80 remontent le même groupe High OS Debian
13.8. Le groupe contient le `ncurses-bin` local et les trois paquets
Trixie dont Grype reprend le même source Debian. La décision s'applique
uniquement à cette empreinte et exige les quatre identités dpkg, le
reçu de qualification embarqué, l'ELF `infocmp` corrigé et les ELF
et liens de `libncursesw` et `libtinfo` mesurés en laboratoire. Le
contrôle recherche aussi le SHA du binaire stock dans toutes les couches,
y compris sous un autre nom. Toute divergence garde le groupe bloquant.
Les rapports Grype conservent le signalement d'origine.
[Scan push](https://github.com/pamolive/PamOlive-Platform/actions/runs/45209780376/artifacts/14840299172) ·
[Scan PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/45209831612/artifacts/14841806964)
