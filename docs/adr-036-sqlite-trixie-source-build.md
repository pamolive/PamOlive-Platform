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

L'adoption dans l'image PamOlive exige une revue du paquet et des imports
ELF de l'image entière, le scan de cette image, puis les contrôles habituels
de livraison. Le test vérifie la présence de SESSION et la compatibilité
courante. Une qualification complète de la fonction SESSION et de l'API
`liblastlog2` devra exercer les appels avec des données synthétiques.
