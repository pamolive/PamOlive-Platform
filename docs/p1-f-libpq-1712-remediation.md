# P1-F — Correctif ciblé libpq 17.12

Le scan OS du témoin B3r4, base Grype du 14 novembre 2026, conserve **136 occurrences High réparties en 69 groupes**, sans Critical. Par comparaison avec le témoin B2 scanné avec la base du 11 novembre, les 34 nouveaux groupes concernent tous `libpq5` `17.11-0+deb13u1`, rattaché au paquet source Debian `postgresql-17`. Les 35 anciens groupes restent présents. Les sorties historiques et leurs verdicts sont conservés ; ce changement de source ne reconstruit ni ne requalifie B3r4.

## Correctif disponible et portée réelle

PostgreSQL a publié la version corrective **17.12 le 12 novembre 2026**. Le [suivi officiel Debian de postgresql-17](https://security-tracker.debian.org/tracker/source-package/postgresql-17) indique `17.12-0+deb13u1` dans `trixie-security`. Les 34 nouveaux groupes du rapport portent tous `fix.state=fixed` et cette version corrective. L'[annonce officielle PostgreSQL](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/) confirme la publication amont.

Ces occurrences ne démontrent pas 34 chemins exploitables dans la bibliothèque cliente libpq. Le scanner rattache des avis du paquet source PostgreSQL aux paquets binaires correspondants. Beaucoup concernent le serveur ou ses modules ; les avis clients [CVE-2026-116314](https://www.postgresql.org/support/security/CVE-2026-116314/) et [CVE-2026-116330](https://www.postgresql.org/support/security/CVE-2026-116330/) concernent respectivement `pg_restore` et le contenu `restore.sql` produit par `pg_dump`, et non toutes les connexions psycopg. [CVE-2026-14661](https://www.postgresql.org/support/security/CVE-2026-14661/) comporte en outre une condition sur libpq 18 pour les serveurs de version antérieure à 18. Ces différences restent à distinguer dans l'analyse d'applicabilité ; elles ne créent aucune exception de politique ici.

La réponse retenue est la mise à jour disponible du paquet maintenu, avec un SDK cohérent. Aucune exclusion de scanner, décision High, attestation ni permission de publication n'est ajoutée.

## Épinglage et contrôle du pilote

Le Dockerfile définit une seule valeur globale `LIBPQ_DEBIAN_VERSION=17.12-0+deb13u1`, consommée explicitement par les stages `directory-builder` et `runtime` :

- Le builder installe `libpq-dev` et `libpq5` à cette même version exacte avant la construction de la roue psycopg-C.
- Le runtime installe `libpq5` à cette version exacte. Il ne reçoit pas les en-têtes ni le compilateur.
- Les instructions d'installation et leur argument changent, afin que leurs anciennes couches APT 17.11 ne satisfassent pas une nouvelle construction de ce Dockerfile. L'absence de la version demandée doit faire échouer APT.

Le contrôle `deploy/check_database_driver.py` conserve psycopg et psycopg-C `3.2.10` avec l'implémentation C. Il impose désormais :

- `pq.version()` et `pq.__build_version__` de type entier exact ; booléens, chaînes et flottants sont refusés.
- La branche majeure **17 seulement**, avec les deux versions publiques au moins égales à `170012`.
- L'égalité exacte de ces deux versions publiques : un runtime 17.13 et un SDK 17.12 sont refusés, même si leur ABI peut être compatible.

Un couple 17.13/17.13 satisfait ce contrôle de branche et de minimum ; cela ne constitue pas à lui seul une nouvelle qualification de sécurité. **Aucune version 18 ou autre branche n'est acceptée**, même supérieure numériquement à 17.12. Une future branche exige un profil, une analyse des avis et une qualification explicites. Cette règle remplace la condition antérieure « libpq 17 ou supérieur de même majeure » du gate.

Les contrôles existants restent applicables : absence de copies binaires embarquées, deux extensions ELF attendues, chemins et permissions de confiance, dépendances système dpkg, correspondance du libpq réellement chargé et de son empreinte, refus des injections de chargement, sortie exclusive sans divulgation. Le gate reste hors ligne ; `database_connection_tested=false` ne démontre ni TLS ni SCRAM.

## Validation et limites

Les tests autonomes couvrent 17.12, un patch ultérieur cohérent dans la branche 17, le refus de 17.11 côté runtime ou SDK, les désaccords de patch, les types invalides dans les deux positions, les branches inconnues et les paires de majeures différentes. Ils ne nécessitent ni PostgreSQL, ni réseau, ni exécution d'ELF. Leur résultat doit être conservé avec la revue du changement.

Ce correctif n'ajoute aucun matériau compilateur/SDK signé manquant au dossier ADR-021. L'épinglage Debian n'est pas une preuve complète de provenance du build. Une construction future de la source finale doit conserver les matériaux APT effectivement utilisés, puis vérifier les paquets installés et les versions publiques runtime/build dans cette même image.

Avant toute qualification d'une nouvelle image : construction contrôlée, inventaire réel du pilote et du libpq chargé, tests PostgreSQL synthétiques TLS/SCRAM et de restauration, régressions P0/transport, scan frais de l'archive exacte et revue indépendante. La version et les utilitaires de l'image serveur PostgreSQL constituent un sujet distinct à inventorier ; une mise à jour de libpq dans l'application ne corrige pas un autre conteneur serveur. Aucun serveur, build, scan, déploiement, commit ou push n'est exécuté par ce changement de source.
