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
La fixture vérifie le repli sous `C.UTF-8` et le chargement d'un
catalogue MO synthétique sous `fr_FR.UTF-8`. `localedef` produit
la locale dans le répertoire temporaire de la fixture, à partir
des sources du paquet déjà authentifié.
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

La commande `python -B -m qualification.glibc_trixie_backport.runtime_inventory`
prend le dossier de l'artefact et `--qualification-sha256` obtenu lors de sa
vérification indépendante. Elle revérifie les reçus et les quatre archives
runtime. Elle projette les chemins, types, modes, propriétaires, liens et
empreintes pour comparer les paquets stock et candidat. Le résultat sert à
attribuer les écarts de l'image finale quand son inventaire sera disponible.

Le run `45208518662` du commit `45f635a` a fourni les quatre paquets amd64
du build `2.41-12+deb13u5+pamolive1`. Le ZIP, le `.buildinfo`, le reçu et les
empreintes des archives concordent. Le relevé runtime contient 299 chemins
pour `libc6` et 58 pour `libc-bin`. Il compte respectivement 3 et 13 chemins
modifiés, sans ajout ni retrait. Le chargeur et `libc.so.6` correspondent
aux ELF du reçu natif. L'alias du chargeur conserve le même lien.
[Artefact natif](https://github.com/pamolive/PamOlive-Platform/actions/runs/45208518662/artifacts/14841015571)

La suite amd64 rapporte 6 123 `PASS`, 16 `XFAIL`, 104 `UNSUPPORTED` et 10
`XPASS`, avec zéro `FAIL` ou `UNRESOLVED`. La suite i386 rapporte 1 246
`PASS` et 15 `XFAIL`. Aucun `tests.sum` n'a été émis pour x32. Le résumé
d'origine classait les `XPASS` sans anomalie. Les marqueurs des dix tests
figurent bien dans la source authentifiée, quatre dans `sysdeps/x86/Makefile`
avec lld et six dans `debian/testsuite-xfail-debian.mk`. La vérification
ABI, le repli gettext, pthread, NSS local et DNS loopback ont réussi.
La nouvelle fixture de traduction reste à exécuter contre le paquet Trixie.
[Journaux du build](https://github.com/pamolive/PamOlive-Platform/actions/runs/45208518662) ·
[Source Debian 2.41-12+deb13u5](https://sources.debian.org/src/glibc/2.41-12%2Bdeb13u5/)

Dans le candidat produit, le build reprend les mêmes sources et vérifie
les octets des deux paquets runtime avant leur installation hors réseau.
Cette transaction intervient après les commandes APT qui modifient le
runtime. `dpkg --audit` et `apt-get check` contrôlent l'état obtenu. Les
stages de compilation conservent le quartet SDK Debian de référence pour
préserver leurs dépendances exactes. La CI du produit exerce les binaires
livrés avec le runtime corrigé.

Le reçu runtime V5 lie les deux paquets, les 13 ELF sélectionnés, la chaîne
de liens du chargeur, son mappage par Python et la configuration de l'image.
La comparaison live/archive précède la liaison au SBOM. Le scan valide ce
profil lorsqu'il recontrôle les décisions existantes. Toute décision pour
le finding glibc attend le scan de l'image réellement construite.
