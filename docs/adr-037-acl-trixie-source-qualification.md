# ADR 037 — Qualification de libacl 2.4.0 pour Trixie

Les deux groupes ACL du scan de référence concernent le paquet source Debian
`acl`. Debian classe la version de Trixie comme vulnérable et indique
`2.4.0-1` comme corrigée dans Forky. L'amont préserve toutefois le
comportement des anciennes fonctions par chemin et fournit des variantes
`*_at`. La protection des appels existants dépend donc aussi de
l'adoption de ces variantes dans les consommateurs.
[Suivi Debian](https://security-tracker.debian.org/tracker/source-package/acl) ·
[Annonce amont](https://www.openwall.com/lists/oss-security/2026/06/29/1)

Attendre une mise à jour Trixie maintient la chaîne de support Debian. Le
laboratoire prépare une reconstruction de la source Debian 2.4.0 pour
évaluer sa compatibilité avant toute intégration. Il utilise la même image
Trixie amd64 épinglée que le produit. APT authentifie l'index source Forky
et le contexte vérifie l'intégralité des quatre fichiers par SHA-256.
Le seul changement de source est l'entrée de changelog du rebuild. La
compilation s'exécute hors réseau avec un UID non privilégié.

Le contrôle exige le SONAME historique et la conservation de tous les
exports de l'ancienne bibliothèque, avec leurs versions. GNU tar restaure
une ACL utilisateur nommée sur un fichier synthétique dans les deux variantes.
La variante candidate exerce aussi les appels par descripteur sur un
fichier régulier. La CI conserve le paquet natif, son buildinfo et le reçu
qui relie leurs SHA-256. Le laboratoire est limité à Linux amd64.

L'intégration éventuelle porte sur la bibliothèque seule, avec ses
empreintes qualifiées. Elle devra vérifier les consommateurs de l'image
exacte et l'usage des API historiques. GNU tar déjà compilé reste à tester
en conditions produit. Une recompilation de GNU tar avec les nouveaux
en-têtes doit intégrer le correctif Debian de collision des noms.
Les outils ACL du runner LDAP restent disponibles pour la qualification.
[Compatibilité GNU tar](https://bugs.debian.org/1141146)

Le laboratoire laisse l'image de livraison et le seuil du scan inchangés.
Il n'établit aucune correction automatique des anciens appels ACL.

## Migration des appels GNU tar

L'inventaire de l'image amd64 relève cinq binaires consommateurs des
anciennes fonctions dans trois paquets. Le premier lot porte sur GNU tar
Trixie `1.35+dfsg-3.1`. Il utilise les descripteurs déjà détenus par tar
et, pour les métadonnées différées, ouvre chaque composant de chemin depuis
le répertoire sélectionné avec `O_NOFOLLOW`. Le chemin de lecture respecte
`--dereference` quand le descripteur correspond à l'inode sélectionné par tar.
[Inventaire de l'image de référence](https://github.com/pamolive/PamOlive-Platform/actions/runs/45223383511/artifacts/14854463532)

Le laboratoire vérifie les trois composants de la source Debian et les
empreintes des fichiers avant et après le correctif. La construction native
repose sur les mêmes binaires libacl que la qualification de la bibliothèque.
Le reçu relie l'ELF exécuté au paquet et au buildinfo. Le test synthétique
couvre une restauration des ACL d'accès et par défaut, ainsi que la lecture
avec `--dereference` sur des fichiers vides et non vides. La CI exige les
quatre variantes `*_at` et vérifie l'absence des imports historiques ciblés.

Une décision pour l'image de livraison exige encore la qualification de
`cp`, `install`, `mv` et `sed` et le contrôle des binaires dans l'image exacte.
