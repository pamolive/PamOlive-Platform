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

La compilation complète a passé, puis `misc/setarch` a échoué sous
BuildKit sur un refus noyau `EPERM`. La suite amont exclut déjà ce test
dans Docker. Le port test-only ne l'exclut sous BuildKit qu'après avoir
observé le même refus sur les options utilisées par la suite. Ce cas
reste déclaré ignoré. Les tests et correctifs du code distribué ne
changent pas.
[Journal Debian](https://github.com/pamolive/PamOlive-Platform/actions/runs/45139725581)

La qualification installe les neuf paquets Debian de référence puis les
neuf candidats dans un environnement jetable. La compilation et la
suite Debian ont ensuite franchi le contrôle du harnais. L'installation
hors ligne s'est arrêtée lorsque APT a transmis un nom d'archive relatif
à dpkg. Le laboratoire vérifie désormais l'inventaire exact des neuf
archives et les installe directement avec dpkg dans le même conteneur
sans réseau. Les bibliothèques sont configurées avant le dépaquetage de
`mount` et `util-linux` pour satisfaire leurs pré-dépendances de version
exacte. Le contrôle `dpkg --audit` reste obligatoire.
[Journal de qualification](https://github.com/pamolive/PamOlive-Platform/actions/runs/45141236850)
· [Journal des pré-dépendances](https://github.com/pamolive/PamOlive-Platform/actions/runs/45142321044)

La qualification compare les exports
versionnés de cinq bibliothèques et vérifie leurs chemins chargés par
le processus. Les programmes sont examinés en lecture seule, dont
`findmnt` sur la table de montage du conteneur. L'admission exige
ensuite les vérifications des consommateurs PamOlive et le scan de
l'image exacte.

## Intégration au runtime produit

Le build a deux environnements de dépendances. Les SDK conservent les
paquets Debian pour satisfaire les versions exactes demandées par
`uuid-dev`. Le runtime installe les neuf paquets reconstruits après
la dernière opération APT. Les exports versionnés de cinq bibliothèques
ont été comparés au stock durant la qualification. Les tests natifs
du produit servent de contrôle sur les binaires exécutés avec les
bibliothèques du runtime.
[Artefact et ABI](https://github.com/pamolive/PamOlive-Platform/actions/runs/45143461959/artifacts/14803063902)

Le build vérifie les tailles et les empreintes des archives reproduites
avant leur installation hors réseau. Les bibliothèques sont configurées
avant `mount` et `util-linux`. `dpkg --audit` et `apt-get check`
contrôlent l'état du lot et de ses dépendances installées.
[Pré-dépendances Debian](https://www.debian.org/doc/debian-policy/ch-relationships.html#binary-dependencies)

La revue des neuf archives a comparé les chemins, les types, les modes,
les attributs de sécurité et les scripts de maintenance aux paquets
Debian de référence. Le build compare aussi les fichiers et répertoires
à mode set-ID, les capacités de fichier et les entrées spéciales sous
`/usr`, `/etc` et `/var` avant et après la transaction. L'inventaire
v4 vérifie les quatre fichiers setuid hérités dans le conteneur et le TAR
final. Il conserve aussi le statut dpkg, les versions avec epoch, les
neuf ELF et les cinq alias de bibliothèques.

Les preuves v1 à v3 et le chemin SDK sont conservés. L'inventaire v4
alimente le SBOM avec les reçus du lot `util-linux`. Les nouveaux
signalements restent soumis à la revue individuelle et au scan de
l'image exacte.

## Preuves par avis de sécurité

Deux revues indépendantes ont vérifié les archives Debian et les sept
correctifs épinglés. Le correctif de CVE-2026-76642 est `a15c00a`.
CVE-2026-78408 est couverte par `43ec8a8` et `286dd3f`.
CVE-2026-78410 est couverte par `9fcb98b` et ses prérequis
`4cccf4e` et `71ff1c9`. Sa correction de canonicalisation
`b21f4ce` est déjà dans les sources Debian de départ.
[Notes du mainteneur pour 2.41.6](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.6/Documentation/releases/v2.41.6-ReleaseNotes) ·
[Correctif final de CVE-2026-78408](https://github.com/util-linux/util-linux/commit/286dd3ff41526b582ef48830de239dffbaa61f90)

L'avis amont situe la voie concernée par CVE-2026-78409 dans la
série 2.42. Debian classe encore Trixie vulnérable. La recette vérifiée
reconstruit Trixie avec son implémentation antérieure. Aucun des onze
patches Debian ou des sept patches PamOlive n'introduit la nouvelle voie.
Le build contrôle les empreintes des deux fichiers concernés avant et
après compilation. Le contrôle de l'archive vérifie la cible SONAME de
`libmount`, son empreinte et l'unicité des bibliothèques partagées de ce
nom parmi les ELF et liens finaux. Cette preuve est limitée au chemin
examiné et au lot exact.
[Avis du mainteneur](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv) ·
[Commit d'introduction](https://github.com/util-linux/util-linux/commit/ae19f7546ccb038966fc121e287e1a1385ba94bb) ·
[Suivi Debian](https://security-tracker.debian.org/tracker/CVE-2026-78409)

Le contrôle accepte une décision `fixed_by_backport` pour chacun
des trois correctifs et `code_not_present` pour CVE-2026-78409
uniquement aux empreintes de paquets et de rapports observées. Toute
décision exige le TAR, le reçu v4, le SBOM et la revue datée. Les
avis restent ouverts dans la politique jusqu'au scan de l'image
produit qualifiée.
