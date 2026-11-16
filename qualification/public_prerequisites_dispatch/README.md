# Qualification publique des prérequis Docker

Ce workflow de développement s’exécute sur une VM GitHub-hosted jetable Ubuntu 26.04. Il ne construit ni ne publie PamOlive. Le push et le lancement manuel sont limités à `agent/public-env-root-helper`, dans le dépôt canonique. Il ne s’exécute pas sur une PR, un fork ou `main`. Les contrôles complets Platform restent obligatoires et inchangés.

Les trois étapes sont séquentielles :

1. Deux lectures Docker (`version`, `info`), puis la lecture publique bornée des exports containerd et de leur système de fichiers. Le collecteur dérivé utilise le schéma distinct `W-A1-public-version-info-DATA/2`. Le collecteur Platform conserve ses quatre lectures et son schéma historique.
2. Un seul pull du manifeste public PostgreSQL 17.12 épinglé, avec une configuration Docker neuve sans authentification ni proxy. Un retour client réussi ne prouve pas à lui seul la fin de toute activité du daemon ; les sorties du pull ne servent jamais d’identité d’image.
3. Le propriétaire de sonde PostgreSQL R4 existant, réutilisé au même commit depuis le dossier voisin. Il vérifie manifeste, configuration et couches, puis crée uniquement son conteneur `getent`, réseau désactivé, racine et tmpfs PGDATA en lecture seule, sans capacités ni ports. Aucun serveur PostgreSQL, SQL ou `initdb` n’est exécuté.

Une étape refusée, incertaine ou incomplète empêche les suivantes. Le pilote n’ajoute aucun retry ni nettoyage forcé. L’ACK de création, le bail et le nettoyage relèvent exclusivement du propriétaire R4 ; `resources_released` couvre son conteneur, ses clients et son bail, sans certifier les volumes inconnus ni l’état global du daemon. Une disparition de VM ou un timeout ne constitue pas une preuve de nettoyage.

Le pilote capture les quinze sources et données fermées par taille et SHA-256 avant compilation. Le propriétaire R4 revérifie ensuite ses propres assets. Le workflow vérifie aussi les empreintes du pilote et des tests ; les sources épinglées gardent leurs octets exacts via `.gitattributes`. L’environnement enfant est fermé (`env -i`, Python `-I -S -B`), sans token, proxy ou configuration privée.

L’horizon est de 235 secondes, préparation comprise ; il faut conserver 190 secondes avant le pull et 130 avant la sonde. L’étape a une limite de 240 secondes et le job de cinq minutes. Une interruption externe reste incertaine. Les artifacts sont une liste fermée de contexte public, rapports et faits de cycle de vie ; journaux privés, baux, configuration Docker, Env, passwd et sorties brutes sont exclus.

Les observations restent des données de qualification : `operational_GO` et `profile_accepted` restent faux. Elles ne donnent aucune autorité de service, ne commissionnent aucun profil A1/W et ne qualifient pas une image de production. Les 35 groupes High et la provenance de build restent des portes indépendantes.

Les quatorze tests purs du dossier utilisent des doubles de processus et n’exécutent ni Docker, sudo, ctr, pull, SQL ou getent :

```sh
python -I -S -B qualification/public_prerequisites_dispatch/run_pure.py /chemin/vers/un/nouveau-dossier
```

Le test du workflow lit le fichier réellement déployé dans `.github/workflows/public-prerequisites.yml`. Son absence fait échouer le test, même si une copie préparatoire existe. Les tests purs réussis ne remplacent pas la réception des artifacts du run exact.

## ENV V2 source increment

The new exact bootstrap branch is `agent/public-env-root-helper`, based on
5c16fa8973b56a188a039f71d8fc797a622a1935. Push and manual dispatch remain closed
to that branch, repository and job; full Platform gates remain required.
The derived collector uses the same new helper bytes as the standalone
collector, accepts only `public-containerd-roots/3`, and measures
`/usr/lib/cargo/bin/coreutils/env`. Only env permits multiple stable hardlinks.
All eight tool fields, including `nlink`, are compared across the process.
The earlier V1 source is historical evidence, not current admission.

The two metadata queries, ctr queries, H1/permissions/time budgets, one fixed
PG pull, PG owner and 12 PG payload buffers remain unchanged. The new branch
does not commission a profile or authorize application/P0 operations. No real
root read or VM file attributes are inferred from source or pure test success.

ROOT3 now carries the exact package/version cli_identity from ADR029, with no
cli_version alias or historical ROOT1/ROOT2 fallback. Only the two engine rows
of payload.json change; all twelve PG rows, sorted Ulimits and START/cleanup
controls remain exact. Actual1e66 package is still redacted/unknown. No profile
or operational authority follows from this source/pure integration.
