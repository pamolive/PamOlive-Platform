# Pilote PostgreSQL — qualification du runtime Linux

Le runtime Linux impose `psycopg[c]==3.2.10`, construit depuis la source verrouillée avec les en-têtes libpq du builder et lié à libpq système. `PSYCOPG_IMPL=c` interdit le repli automatique. Le paquet binaire demeure une dépendance de développement pour les plateformes non Linux définies par le lock ; il n'est pas qualifié pour le runtime serveur.

Cette séparation évite de conserver en parallèle des copies Kerberos/LDAP/SASL/OpenSSL embarquées par psycopg-binary, que les mises à jour APT du runtime ne remplaceraient pas. Elle ne rend pas automatiquement les bibliothèques Debian exemptes de vulnérabilités. Le scan de l'image finale et le triage de chaque dépendance restent obligatoires.

## Gate hors ligne

Dans le conteneur Linux amd64 de qualification identifié par digest, rootfs readonly, réseau `none`, capacités retirées et `/tmp` en tmpfs :

```sh
python deploy/check_database_driver.py --output /tmp/database-driver.json
```

L'outil ne consulte aucune variable de connexion, ne lance pas Django, ne contacte aucune base et n'effectue aucune authentification. Il importe psycopg après ses contrôles de plateforme, d'environnement et d'absence physique des paquets binaires. Aucun argument ne permet de changer la racine, d'injecter un résultat de sonde, d'accepter Python/binary ou de sauter ldd/dpkg.

Le rapport est réservé avant les sondes avec `O_CREAT|O_EXCL` en mode0600. Un fichier existant ou un lien portant le même nom est refusé sans écrasement. En cas d'erreur, la réservation peut rester vide : ce n'est pas un rapport réussi. stdout ne contient que le verdict et un code d'erreur statique, jamais une exception brute, un environnement ou une sortie de sous-processus.

Contrôles réalisés :

- Versions publiques du cœur psycopg, de psycopg_c et de leurs métadonnées égales à3.2.10 ; `pq.__impl__ == 'c'`.
- `pq.version()` et `pq.__build_version__` sont des entiers libpq17 ou supérieur, de même version majeure. Une révision de sécurité différente entre build/runtime n'est pas confondue avec un changement majeur.
- Absence physique de `psycopg_binary*` et répertoires de bibliothèques psycopg `.libs` dans les chemins site-packages/dist-packages actifs, indépendamment des seules métadonnées PyPI.
- Métadonnées psycopg_c : exactement deux extensions ELF `_psycopg` et `pq`, sans chemin absolu/traversée/vendored.libs. Les extensions réellement importées doivent être ces fichiers ; les liens symboliques d'extension sont refusés.
- Fichiers et parents contrôlés par root et non inscriptibles par groupe/autres. HashSHA256 et décodage ELF par le helper d'inventaire natif existant, borné à64MiB par fichier. Aucun RPATH/RUNPATH n'est accepté pour les extensions du pilote, même ceux approuvés pour les moteurs Guacamole.
- Résolution ldd réelle des deux extensions par le helper natif existant, environnement limité, sans LD_PRELOAD, délai15secondes. Chaque dépendance transitive doit se résoudre sous `/usr/lib/x86_64-linux-gnu` après résolution des liens, appartenir sans ambiguïté à un paquet dpkg installé et avoir une version/hachage conservés. Cela couvre les bibliothèques effectivement liées, notamment libpq, TLS, Kerberos, LDAP/GSS/SASL ; leur présence n'est pas imposée si le libpq qualifié ne les utilise pas.
- libpq doit appartenir à libpq5 ; le chemin effectivement chargé selon `/proc/self/maps` doit correspondre exactement à celui de ldd et son hash doit rester identique. La lecture procfs est bornée à4MiB+1octet avant décodage et refuse le dépassement, sans se fier au st_size habituellement nul. Une seconde copie, un chemin supprimé ou une dépendance issue d'un ancien répertoire `/opt`/wheel bloque la vérification.
- Versions OpenSSL exposées par les API publiques `ssl.OPENSSL_VERSION` et `default_backend().openssl_version_text()` de cryptography inventoriées séparément, sans importer son module interne openssl.backend. Elles ne sont pas présentées comme la même copie que celle de libpq ni comme une analyse complète du code natif.

Le schéma est `pamolive.database-driver-runtime/1`. Le rapport distingue versions libpq de compilation/exécution, extensions, bibliothèques et paquets. `database_connection_tested` reste toujours `false` : la vérification d'un pilote chargé ne prouve ni TLS, ni validation de CA/hostname, ni SCRAM, migrations, transactions ou isolation d'une base réelle.

## Tests et portes complémentaires

`python -m unittest tests.test_database_driver` exécute des tests autonomes, sans Django, sans réseau, base ou exécution d'ELF. Les seuls doubles de sondes servent à tester les branches de refus et la sérialisation de rapport ; aucun mode de simulation n'existe au CLI livré.

Résultat local après revue du11novembre2026 : **25/25 tests réussis en0,057s**, aucun test ignoré ; Ruff et format vérifiés. Deux régressions supplémentaires couvrent la borne de lecture procfs indépendante du st_size et l'usage de l'API publique cryptography. Ce résultat Windows de tests autonomes n'est pas l'exécution du gate Linux sur l'image construite.

Les tests couvrent versions anciennes/mismatch, fallback Python/binary, environnement préchargé, fichiers binaires obsolètes, inventaire d'extensions incomplet ou traversant, ELF invalide, chemin de recherche interdit, propriétaire/permissions non fiables, résolution hors système y compris alias simulé, libpq chargée ancienne/multiple/supprimée, propriétaire dpkg ambigu/incorrect ou paquet désinstallé, timeout, erreur native, absence de fuite et sortie exclusive0600.

La qualification Linux de l'image construite doit encore exécuter cet outil réellement, puis PostgreSQL17 synthétique : connexion TLS avec CA/nom vérifiés, mauvais certificat refusé, SCRAM, migrations sous rôle restreint, restauration, transactions/concurrence et régressions applicatives/P0. Aucun résultat de tests unitaires n'est substitué à cette porte.

L'outil s'appuie sur ldd et dpkg du conteneur **de confiance**, pas sur un ELF fourni par un utilisateur. Il ne prouve pas la provenance de compilation à lui seul : source/hash, build CI, inventaire, attestation et digest final doivent rester liés. La couverture est LinuxELF64amd64 uniquement, sans qualification ARM/Synology implicite. Les restrictions de chargement et du système de fichiers doivent aussi être conservées lors du déploiement ; un rapport ancien n'atteste pas un environnement ultérieurement altéré.
