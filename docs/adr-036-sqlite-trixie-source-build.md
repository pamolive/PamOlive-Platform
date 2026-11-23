# ADR 036 — Qualification d'une reconstruction SQLite pour Debian Trixie

Le candidat de livraison installe SQLite `3.46.1-7+deb13u2`. Debian signale
encore les CVE-2026-119373, CVE-2026-119374 et CVE-2026-119379 pour cette
version. Le changelog Debian associe les corrections à SQLite `3.54.1-1`,
disponible sous `3.54.1-2` dans Forky. Le profil PostgreSQL de PamOlive
conserve des consommateurs natifs de SQLite, dont `_sqlite3` et `liblastlog2`.
[Suivi Debian](https://security-tracker.debian.org/tracker/source-package/sqlite3) ·
[Changelog](https://sources.debian.org/src/sqlite3/3.54.1-2/debian/changelog)

Attendre un paquet officiel Trixie réduit la maintenance locale mais laisse
ces signalements ouverts. Installer directement le paquet binaire Forky
introduirait un binaire issu de l'environnement de compilation d'une autre
distribution. Le laboratoire choisit une reconstruction Debian sur Trixie
amd64 à partir des sources officielles, sans ajout de sources de paquets
binaires Forky. Les options Debian du moteur sont conservées. L'adaptation
remplace la dépendance de compilation Tcl secondaire 9.1 par Tcl 9.0 dans
les deux fichiers d'empaquetage concernés, et ajoute une entrée de changelog.

APT prend les sources dans l'index Forky authentifié et vérifie la chaîne
d'empreintes de l'archive. Les quatre fichiers du lot doivent ensuite
correspondre aux SHA-256 épinglés. L'extraction et la compilation se font hors
réseau. La compilation utilise un UID sans privilèges. Le paquet candidat
porte une version locale distincte et seul `libsqlite3-0` est installé
dans la variante du laboratoire.

La comparaison vérifie le SONAME, les symboles demandés par `_sqlite3` et
`liblastlog2`, la version et l'identité de la bibliothèque effectivement
chargée. Le test fonctionnel relit une base synthétique créée avec SQLite
3.46.1, dont les transactions et l'index FTS5, et vérifie les options FTS5 et
SESSION. Le reçu inventorie les binaires et les résultats. Il est limité à
ce laboratoire amd64.

Les deux constructions indépendantes du laboratoire reproduisent le même
SHA-256 du paquet et de la bibliothèque. La variante produit réutilise le
même procédé et exige ces deux empreintes avant d'admettre le remplacement.
Elle installe le paquet depuis un montage en lecture seule après le dernier
APT produit, sans réseau. Le package, les outils de compilation et l'index
APT des sources Forky restent dans les étapes de construction. Le contrôle
de la bibliothèque chargée est rejoué sur l'image exacte réimportée par la CI.
[Première qualification](https://github.com/pamolive/PamOlive-Platform/actions/runs/45113977157) ·
[Contrôle ELF renforcé](https://github.com/pamolive/PamOlive-Platform/actions/runs/45114107779)

Le scan de l'image produit reste requis avec la même politique. Le test de
laboratoire vérifie la présence de SESSION, la lecture de la base historique
et les écritures sur une base neuve. Une qualification complète de la fonction
SESSION et de l'API `liblastlog2` devra exercer les appels avec des données synthétiques.
