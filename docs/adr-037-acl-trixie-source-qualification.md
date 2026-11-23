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
le répertoire sélectionné avec `O_NOFOLLOW`. Avant de restaurer les ACL d'un
répertoire, il vérifie son type et son identité relevée lors de la planification.
La lecture conserve la sélection de chemins de tar, y compris `--dereference`,
et vérifie le type et l'inode avant de lire les ACL.
[Inventaire de l'image de référence](https://github.com/pamolive/PamOlive-Platform/actions/runs/45223383511/artifacts/14854463532)

Le laboratoire vérifie les trois composants de la source Debian et les
empreintes des fichiers avant et après le correctif. La construction native
repose sur les mêmes binaires libacl que la qualification de la bibliothèque.
Le reçu relie l'ELF exécuté au paquet et au buildinfo. Le test synthétique
couvre la restauration des ACL d'accès et par défaut, la suppression des ACL
par défaut héritées et la lecture de fichiers vides et non vides par les chemins
prévus par tar. La CI exige les quatre variantes `*_at` et vérifie l'absence
des imports historiques ciblés. Ce contrôle porte sur les appels POSIX ACL de
tar sous `--acls`. Le traitement général des attributs étendus reste séparé.

## Migration de l'édition en place GNU sed

Sur Trixie `4.9-2+deb13u1`, `sed -i` dispose déjà des descripteurs ouverts de
l'entrée régulière et du fichier temporaire. Le binaire Linux appelle les
fonctions ACL par descripteur. Le classement des erreurs et la détection des
ACL triviales restent partagés avec Gnulib. Le repli conserve les bits de mode
et les diagnostics existants. Le correctif Debian de sélection du fichier
d'entrée et les API génériques de Gnulib restent en place. [Source Debian](https://sources.debian.org/src/sed/4.9-2%2Bdeb13u1)

La CI vérifie les imports de l'ELF, un remplacement avec ACL utilisateur et
backup, le suivi explicite d'un lien ordinaire, la conservation du mode et la
suppression des permissions héritées par le temporaire. Le laboratoire
injecte `EOPNOTSUPP` à la lecture et `EPERM` à l'écriture dans deux processus
synthétiques. Un système de fichiers sans ACL reste à qualifier séparément.
La qualification native reprend les cas GNU tar avec le même paquet libacl.

## Écriture des ACL POSIX dans GNU coreutils

Les trois ELF de `coreutils` Trixie `9.7-3` qui importent les anciennes
fonctions d'écriture sont `cp`, `install` et `mv`. Les écritures réutilisent le
descripteur de données quand il existe. Pour une destination déjà sélectionnée
par coreutils, l'ouverture `O_PATH` vérifie le périphérique, l'inode et le type
avant toute écriture ACL. Cela préserve les alias de répertoire sélectionnés
par le programme. Les appels sans identité attendue parcourent les répertoires
sans suivre les liens. Les fichiers spéciaux sont ouverts pour métadonnées
uniquement. Le repli de mode reste lié au même FD, via `/proc/self/fd` sur les
noyaux qui ne prennent pas en charge `AT_EMPTY_PATH` pour `fchmodat`.
[Source Debian](https://sources.debian.org/src/coreutils/9.7-3/)

La comparaison avec Debian stock couvre les options `cp -p`, `--parents`,
les politiques de liens, un FIFO, le mode et les ACL héritées avec `install`,
et `mv` sur un et deux montages. Le laboratoire lie les trois ELF au DEB et
vérifie leurs imports. La copie Debian des attributs d'ACL POSIX et NFSv4
reste distincte. La compatibilité du repli avec les profils seccomp des hôtes
anciens et les opérations sur un montage NFSv4 restent à qualifier.

L'intégration à l'image de livraison requiert la vérification des cinq ELF
installés, du SBOM et du scan de l'image exacte.
