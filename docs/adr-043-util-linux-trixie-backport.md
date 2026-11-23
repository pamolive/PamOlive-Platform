# ADR-043 — Qualification du backport util-linux sur Debian Trixie

Le scan de l'image `b588ae0` signale quatre groupes High pour le paquet
source `util-linux`, installé depuis Debian Trixie en
`2.41.5-0+deb13u1`. Deux groupes concernent libmount, un groupe concerne
les descripteurs de nsenter et un groupe concerne un chemin de
libmount introduit dans la série 2.42 selon le suivi Debian.
[Artefact du scan](https://github.com/pamolive/PamOlive-Platform/actions/runs/45126161877/artifacts/14797486603) ·
[CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

L'import du paquet 2.42.4 construit pour Forky changerait la série native
et la chaîne de dépendances Debian. Son paquet source demande notamment
debhelper 14 et modifie la recette de compilation. La reconstruction sur
le source Trixie préserve la recette Debian et réduit le périmètre à
dix fichiers C et en-têtes.
[Paquet source Trixie](https://packages.debian.org/source/trixie/util-linux) ·
[Paquet source Forky](https://packages.debian.org/source/forky/util-linux)

Le candidat associe cinq changements de la branche stable 2.41.6 à la
fermeture explicite des descripteurs et à l'inclusion de l'en-tête
`fileutils.h` reprises de 2.42.4. Trixie contient
déjà le correctif de canonicalisation de la série stable. Pour le
changement 2.42.4, la première correction stable fournit déjà le hunk
`O_CLOEXEC`. Le script vérifie cette présence et l'empreinte exacte
du patch réduit qui ferme les descripteurs.
[Notes 2.41.6](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.6/Documentation/releases/v2.41.6-ReleaseNotes) ·
[Notes 2.42.4](https://raw.githubusercontent.com/util-linux/util-linux/v2.42.4/Documentation/releases/v2.42.4-ReleaseNotes) ·
[Correctif final de nsenter](https://github.com/util-linux/util-linux/commit/286dd3ff41526b582ef48830de239dffbaa61f90) ·
[Inclusion de l'en-tête](https://github.com/util-linux/util-linux/commit/a323dddbcd1ed05a10e7e870b3e1a48b4ed44a43)

La campagne compile les paquets avec les dépendances Trixie après
authentification APT, sous un UID non privilégié et sans réseau.
Les empreintes du source Debian, des correctifs et des fichiers avant
et après application sont requises. La recette conserve le verdict du
harnais, les cas ignorés et les échecs déclarés connus par Debian.
Elle publie neuf paquets
identifiés comme entrées de qualification, avec leur buildinfo et
leurs empreintes.

La qualification installe les neuf paquets Debian de référence puis les
neuf candidats dans un environnement jetable. Elle compare les exports
versionnés de cinq bibliothèques et vérifie leurs chemins chargés par
le processus. Les programmes sont examinés en lecture seule, dont
`findmnt` sur la table de montage du conteneur. L'admission exige
ensuite les vérifications des consommateurs PamOlive et le scan de
l'image exacte.

Le chemin de CVE-2026-78409 a été introduit dans la série 2.42.
Son applicabilité au binaire effectivement distribué reste à
documenter. Le laboratoire ne change aucune disposition de la
politique de scan.
[Introduction du chemin amont](https://github.com/util-linux/util-linux/commit/ae19f7546ccb038966fc121e287e1a1385ba94bb)
