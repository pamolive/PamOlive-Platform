# Mise à niveau contrôlée vers 0.2.0a11

La version `0.2.0a11` ajoute la création initiale SCIM autorisée, ses preuves et l’activation après attribution confirmée, sans service permanent supplémentaire. La mise à niveau depuis `0.2.0a8`, `0.2.0a9` ou `0.2.0a10` doit préserver les comptes, les organisations, les secrets chiffrés, les observations et les décisions antérieures. Elle impose une interruption temporaire de toutes les instances applicatives ; PostgreSQL reste disponible.

## Périmètre accepté

`python -m deploy.controlled_upgrade` accepte uniquement dix migrations explicitement relues : `access.0010` à `access.0012` et `connectors.0004` à `connectors.0010`. Depuis `a8`, les dix sont en attente ; depuis `a9`, seules `connectors.0008` à `0010` doivent l’être. Depuis `a10`, seule `connectors.0010_scim_initial_accounts` ajoute quatre tables vides, un lien nullable des changements externes vers la preuve de création et les contraintes associées. Les anciennes opérations gardent ce lien nul. Le plan contient les noms complets et empreintes SHA-256 des seules migrations restantes. Un changement de plan ou une migration non autorisée arrête l’opération. Cet outil n’est pas une procédure universelle pour les versions futures ni pour des extensions ayant leurs propres migrations.

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

Les colonnes ajoutées aux observations historiques doivent rester nulles pour la fin de session. Les anciennes évaluations conservent un contexte vide, des empreintes et signatures vides et aucune nouvelle référence d’audit. Elles restent consultables comme historique, sans devenir rétroactivement des conclusions signées. Une nouvelle évaluation ajoute une preuve séparée, sans réécrire le fait source.

## Échec et réouverture

`probe-rollback` provoque volontairement l’annulation de toute la migration, puis vérifie le schéma et les anciennes données. Son résultat doit indiquer `committed=false` et `rollback_schema_and_rows_verified=true`. Des trous dans les séquences PostgreSQL sont possibles après une transaction annulée ; aucun ancien identifiant ni aucune ligne ne doit changer.

Pour `apply`, rouvrir uniquement après `committed=true`, puis vérifier l’image attendue, `/health/`, l’accès administrateur, les chaînes d’audit, l’absence de migrations restantes et le parcours natif. Un seul conteneur applicatif demeure en service.

En cas d’échec avant commit, l’outil vérifie le retour arrière. Ne reprendre l’ancienne image que si l’annulation du schéma et des données est établie. Si `rollback_not_verified` est signalé, conserver l’application arrêtée et examiner la base et la sauvegarde.

Après un commit réussi, **ne pas relancer aveuglément l’image a8** : l’ancien ORM n’écrit pas toutes les nouvelles colonnes obligatoires. Un échec de démarrage de l’image candidate exige une correction compatible vers l’avant, ou une restauration décidée explicitement avec prise en compte des écritures intervenues depuis la sauvegarde. L’outil ne remplace jamais la base en service par une copie.
