# Mise à niveau contrôlée vers 0.2.0a13

Le schéma est inchangé de `0.2.0a13` à `0.2.0a17`. Pour changer de version dans cette plage, qualifier une sauvegarde avec l’image candidate et vérifier un plan vide ; ne pas lancer d’application de migration. Une fois des propositions avec preuves métier créées, ne pas redémarrer `a13` sans procédure de retour validée : il ne contrôle pas ces nouveaux rattachements. Le rattrapage d’événements d’`a17` conserve le format existant des notifications signées.

La version `0.2.0a13` ajoute les rôles métier versionnés et le parcours de mobilité interne. La mise à niveau depuis `0.2.0a8` à `0.2.0a12` doit préserver les comptes, les organisations, les secrets chiffrés, les observations et les décisions antérieures. Elle impose une interruption temporaire de toutes les instances applicatives ; PostgreSQL reste disponible.

## Périmètre accepté

`python -m deploy.controlled_upgrade` accepte vingt et une migrations relues, dont les trois migrations P0-2 de liaison des destinations, `access.0013`, `connectors.0011` et `pam.0004`, les quatre migrations P0-3 `access.0014`, `approvals.0004`, `pam.0005` et `pam.0006`, et les deux migrations P0-4 `access.0015` et `access.0016`. Le plan conserve les anciennes colonnes à l’identique. Les nouveaux champs des anciens mandats et secrets PAM restent vides. Les jetons SCIM restés en première révision reçoivent un sceau calculé sans modifier leur ciphertext. Les connecteurs historiquement révisés restent sans sceau et sont bloqués au moment de leur utilisation.

P0-3 ajoute cinq modèles de confiance, de reçus et de preuves d’action, ainsi que leurs contraintes PostgreSQL d’immutabilité et d’isolation. Les colonnes `pam_trust` sont vides sur les anciens mandats et votes : aucune promotion automatique de ces autorisations. La vérification des preuves historiques conserve les anciens formats. La reprise du PAM live exige le commissionnement décrit dans [Exploitation du registre PAM](pam-trust-operations.md). Sans ancres, registre et checkpoint indépendant courant, les nouveaux accès restent fermés.

P0-4 classe **toutes** les anciennes observations `legacy_unknown`, même si leur source textuelle est un UUID ou si leur audit n'a pas d'acteur. Les nouvelles colonnes de principal et d'empreinte restent vides sur ces lignes. La contrainte globale `(organisation, source, identifiant externe)` est remplacée par des unicités propres à chaque canal, et les nouvelles observations sont accompagnées de reçus V8. Les signatures V7 et les faits historiques ne sont pas réécrits. `access.0016` installe les gardes PostgreSQL qui refusent les nouvelles lignes `legacy_unknown`, les modifications de provenance et les liens entre organisations. Une migration en présence d'anciens rédacteurs HTTP, workers ou normalisateurs TeamViewer serait dangereuse : ils doivent tous être arrêtés avant le changement de schéma.

Les douze migrations antérieures couvrent `access.0010` à `access.0012`, `connectors.0004` à `connectors.0010`, `recertification.0002` et `identity.0008_business_roles_and_mobility`. Le plan exact dépend de la version installée et doit être examiné avant son application.

### Préparation spécifique aux destinations

Inventorier les connecteurs SCIM de révision supérieure à 1, leurs correspondances et les droits ou retraits restant à réconcilier. Leur URL d’origine peut manquer dans les preuves historiques. Terminer la réconciliation sur l’annuaire d’origine avant une migration réelle et préparer les nouvelles configurations explicites.

Prévoir la ressaisie des secrets PAM et de nouvelles demandes approuvées avec cible figée. Les anciens votes et captures sont conservés pour vérification historique. Arrêter et clôturer tous les relais puis retirer tous les anciens portails et workers du trafic avant la migration. Garder la même clé de chiffrement. Une ancienne version ignore les nouveaux contrôles et ne doit pas rejoindre une base migrée. Un retour d’exploitation requiert une procédure de restauration et de réconciliation, avec fencing des anciens nœuds.

Le plan contient les noms complets et empreintes SHA-256 des seules migrations restantes. Un changement de plan ou une migration non autorisée arrête l’opération. Cet outil n’est pas une procédure universelle pour les versions futures ni pour des extensions ayant leurs propres migrations.

Les migrations de cette livraison réalisent des changements transactionnels PostgreSQL, sans appel fournisseur ni effet externe. Le rôle applicatif doit être dédié, propriétaire de sa base, sans rôle hérité, `SUPERUSER`, `CREATEDB`, `CREATEROLE`, `REPLICATION` ou `BYPASSRLS`. Le contrôle vérifie la base réellement connectée et le schéma `public` ; un nom de base PostgreSQL PAM-olive est requis.

## Préparation de la livraison

1. Conserver l’image exacte de la version installée, ses fichiers de déploiement et les clés existantes. Ne pas régénérer `SECRET_KEY` ni `PAMOLIVE_ENCRYPTION_KEY`.
2. Construire l’image candidate avec le Dockerfile normal, sans la démarrer sur la base en service.
3. Produire une sauvegarde privée et qualifier sa [restauration isolée](backup-restore.md). Exécuter ensuite la migration candidate sur une copie restaurée peuplée. Une base synthétique de CI ne remplace pas cette sauvegarde.
4. Prévoir une fenêtre d’interruption : aucun relais PAM ni changement externe ne doit être en cours. Arrêter toutes les instances HTTP et leurs processus de tâches, y compris sur les autres VM. La sauvegarde finale et la comparaison doivent porter sur cet état arrêté.
5. Utiliser les mêmes clés, la même base et le rôle dédié pour les commandes de migration. Les fichiers `.env`, sauvegardes et rapports restent privés.

Le test automatisé `python -m deploy.check_upgrade_ci --postgres-container CONTENEUR_PG --ha-env-file ENV_HA_TEST` utilise uniquement une base jetable créée pour lui, avec un rôle réellement restreint. Il peuple le schéma historique, provoque un retour arrière, applique la migration puis vérifie l’audit et le déchiffrement. Le fichier HA doit désigner la base de qualification `test_pamolive_ha`, jamais la production. Le rôle et la copie créés par ce test sont supprimés à sa fin.

## Exécution hors ligne

Depuis les fichiers Compose de la livraison candidate, avec l’application arrêtée et la sauvegarde qualifiée, produire le plan avec l’image candidate et le conserver pour relecture :

```sh
docker compose run --rm --no-deps -T web python -m deploy.controlled_upgrade plan --database pamolive_platform > reviewed-upgrade.json
```

Adapter le nom de base à celui de l’installation. Employer les mêmes options `--env-file`, `-p` et `-f` que le déploiement lorsqu’il utilise un fichier NAS ou une image explicitement épinglée. Le fichier de plan ne contient ni mot de passe ni données métier. Le générer avec l’image Linux effectivement déployée évite une différence d’empreinte liée aux fins de ligne Windows.

Après relecture des entrées attendues pour la version installée, vérifier le retour arrière, puis appliquer exactement ce plan :

```sh
docker compose run --rm --no-deps -T web python -m deploy.controlled_upgrade probe-rollback --database pamolive_platform --reviewed-plan - --offline-ack < reviewed-upgrade.json
docker compose run --rm --no-deps -T web python -m deploy.controlled_upgrade apply --database pamolive_platform --reviewed-plan - --offline-ack < reviewed-upgrade.json
```

Ces redirections sont celles de `sh`, Bash ou d’un terminal NAS. Sous PowerShell, remplacer la redirection d’entrée par `Get-Content -Raw reviewed-upgrade.json | docker compose ...`, en conservant le reste de chaque commande. `--offline-ack` atteste l’arrêt préalable de toutes les instances ; le programme ne les arrête pas à la place de l’opérateur.

## Vérifications avant le commit

Un verrou de migration empêche une seconde exécution simultanée. Une transaction unique couvre les migrations, les permissions créées par Django et les contrôles de préservation. Les tables historiques sont verrouillées contre les écritures concurrentes ; un verrou occupé fait échouer l’opération après cinq secondes, plutôt que de forcer l’arrêt d’une connexion.

Le contrôle compare les anciennes colonnes, ligne par ligne dans l’ordre des clés, avec toutes les microsecondes des dates. Les catalogues Django peuvent seulement recevoir de nouvelles lignes ; leurs anciennes lignes ne peuvent pas changer. Les nouvelles tables métier doivent être vides : aucun exemple ni compte de démonstration n’est injecté.

Les colonnes ajoutées aux observations historiques doivent rester nulles pour la fin de session et le principal typé, ou vides pour les empreintes V8 ; leur canal est `legacy_unknown`. Les anciennes évaluations conservent un contexte vide, des empreintes et signatures vides et aucune nouvelle référence d’audit. Elles restent consultables comme historique, sans devenir rétroactivement des conclusions signées. Une nouvelle évaluation ajoute une preuve séparée, sans réécrire le fait source.

## Échec et réouverture

`probe-rollback` provoque volontairement l’annulation de toute la migration, puis vérifie le schéma et les anciennes données. Son résultat doit indiquer `committed=false` et `rollback_schema_and_rows_verified=true`. Des trous dans les séquences PostgreSQL sont possibles après une transaction annulée ; aucun ancien identifiant ni aucune ligne ne doit changer.

Pour `apply`, rouvrir uniquement après `committed=true`, puis vérifier l’image attendue, `/health/`, l’accès administrateur, les chaînes d’audit, l’absence de migrations restantes et le parcours natif. Un seul conteneur applicatif demeure en service.

En cas d’échec avant commit, l’outil vérifie le retour arrière. Ne reprendre l’ancienne image que si l’annulation du schéma et des données est établie. Si `rollback_not_verified` est signalé, conserver l’application arrêtée et examiner la base et la sauvegarde.

Après un commit réussi, **ne pas relancer aveuglément l’image a8** : l’ancien ORM n’écrit pas toutes les nouvelles colonnes obligatoires. Un échec de démarrage de l’image candidate exige une correction compatible vers l’avant, ou une restauration décidée explicitement avec prise en compte des écritures intervenues depuis la sauvegarde. L’outil ne remplace jamais la base en service par une copie.

Après la première observation P0-4, **ne pas revenir à un ancien binaire** : il peut interpréter une ligne manuelle et une ligne collecteur ayant le même texte `source` et le même identifiant externe comme un seul événement. Restaurer l'ancienne unicité demanderait aussi de résoudre ces doublons légitimes sans perdre de preuve. Un retour arrière exige donc une restauration isolée de l'état antérieur et une réconciliation explicite de toutes les observations, reçus, conflits et décisions intervenus depuis la sauvegarde. Un ancien événement `managed:teamviewer` sans lien signé reste bloquant pour la normalisation ; il n'est jamais adopté ou promu automatiquement.
