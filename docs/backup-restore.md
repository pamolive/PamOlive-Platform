# Sauvegarde et qualification de restauration

## Périmètre

Le conteneur applicatif reste unique. Le qualificateur utilise ponctuellement la même image comme client Python, sans Web, worker, moteur natif ni port publié. Il travaille avec les outils de la version PostgreSQL du serveur, puis retire sa base de test et son rôle temporaire. **Il ne remplace jamais la base en service et ne supprime jamais l'archive source.**

Cette première intégration d'exploitation cible PostgreSQL dans un conteneur Docker accessible à l'administrateur, comme sur le NAS. Le runtime PAM-olive reste compatible avec PostgreSQL sur un serveur distinct, y compris natif. Un PostgreSQL natif ou managé nécessite encore l'adaptation du transport administratif du qualificateur ; il ne faut pas ajouter une base Docker uniquement pour contourner cette limite.

Prérequis sur l'hôte d'administration : Python 3.8+, Docker Compose et un accès Docker autorisé. Django et les bibliothèques applicatives restent dans l'image. Le rôle applicatif n'a pas besoin de `CREATEDB` : seul le client administratif local crée le rôle et la copie temporaires.

## Ce qui est conservé et contrôlé

- Archive PostgreSQL au format custom, empreinte SHA-256 et source jamais écrasée.
- Manifeste de tous les modèles Django gérés, y compris les tables implicites de relations plusieurs-à-plusieurs et le journal des migrations. Les valeurs ne sont pas publiées : seules les empreintes et les quantités sortent du vérificateur.
- Pour une nouvelle sauvegarde, manifeste et `pg_dump` lisent **le même instantané PostgreSQL exporté**. L'application peut rester ouverte ; ne pas exécuter de migration pendant cette opération.
- Migration en attente ou migration appliquée absente de l'image : refus. Il faut conserver l'image et les paquets correspondant à la sauvegarde, pas seulement le code actuel du noyau.
- Chaînes d'audit par organisation, signatures des attestations/votes présents, reçus de provenance V8 des nouvelles observations, vérification V7 des évaluations historiques, déchiffrement des facteurs MFA, tokens de connecteurs, secrets de cibles et blocs de captures.
- Ordre, tailles, empreintes HMAC et fin scellée des captures. Une capture en cours au point de sauvegarde reste un préfixe non scellé, signalé comme tel ; elle n'est pas inventée comme complète.
- Garde PostgreSQL append-only exercée sur la copie dans une transaction annulée. Une erreur de permission ou un mode lecture seule ne compte pas comme la preuve que ce trigger fonctionne.
- Refus réel d'un mauvais mot de passe depuis le réseau applicatif, avant de charger les données, et refus d'une mauvaise clé de chiffrement après restauration.

Les identifiants de séquences, rôles globaux, propriétaires et ACL ne constituent pas un manifeste Django. `pg_dump` conserve les séquences dans l'archive ; la copie de qualification reçoit volontairement un autre propriétaire et aucune ACL d'origine. Ce contrôle n'est pas une certification des objets SQL externes aux modèles chargés, d'une sauvegarde physique/PITR ou de toute l'infrastructure.

## Protection des fichiers et des copies

P1-D ajoute la vérification des demandes et décisions d'exception Governance : signatures et ancres, tenants, acteur/MFA historiques, ordre et cardinalité des décisions, période et absence de preuve orpheline. Le compteur `governance_exception_proofs_checked` indique le nombre réellement présent, y compris zéro. Cette vérification ne réactive aucune autorité. Les attestations utilisent `PAMOLIVE_ENCRYPTION_KEY`, dont la valeur exacte doit être conservée ; le trousseau V7/V8 ne remplace pas cette clé. Le downgrade du registre peuplé est refusé.

L'archive, les clés de l'installation et les éventuels diagnostics sont sensibles. Utiliser un répertoire privé, hors du dépôt, du contexte Docker et de tout partage Web. Sur Linux/NAS, dossiers 700 et fichiers 600 ; sur Windows, vérifier les ACL NTFS : le mode POSIX ne suffit pas à prouver cette protection. Sur Synology, enlever les ACL héritées du **nouveau répertoire de rapport privé**, sans modifier les ACL d'un partage existant.

Les clés ne sont pas dans le dump : conserver `SECRET_KEY`, `PAMOLIVE_ENCRYPTION_KEY` et les paramètres nécessaires dans une sauvegarde séparée, protégée et restaurable. Un compagnon chiffré lié au SHA-256 de l'archive permet de vérifier la clé choisie. Pour une archive ancienne, ce compagnon créé au moment du test ne prouve pas à lui seul quelle clé était utilisée autrefois ; les valeurs chiffrées et signatures réellement présentes fournissent cette preuve. Le rapport indique leur nombre, y compris zéro.

Les reçus P0-4 sont scellés avec une clé d'installation identifiée. Après rotation de `SECRET_KEY`, conserver les anciennes clés dans `PAMOLIVE_EVIDENCE_VERIFICATION_KEYS` (tableau JSON fourni par variable d'environnement) pendant toute la durée de vérification des reçus V8, des évaluations V7, des preuves historiques de possession de certificat et de la chaîne signée TeamViewer ; protéger ce trousseau comme la clé active. La création de nouvelles preuves continue d'utiliser uniquement la clé active et les formats historiques ne sont pas modifiés. Ce trousseau est réservé aux preuves et ne réactive pas les anciennes signatures de session Django. Conserver séparément la clé de chiffrement nécessaire à la lecture des secrets et notes TeamViewer : le trousseau de vérification ne les déchiffre pas. Le qualificateur vérifie chaque reçu V8 et refuse une observation non historique dépourvue de reçu. Il vérifie aussi les preuves de possession de certificat et la chaîne TeamViewer, y compris les liens historiques signés. Les anciennes observations restent `legacy_unknown` et leurs évaluations V7 sont vérifiées séparément ; une restauration ne peut pas recréer un événement authentique jadis écarté par collision.

Une clé de chiffrement explicite doit contenir au moins 40 caractères imprimables et ne peut pas être composée uniquement d’espaces. Seule l’absence de la variable déclenche le repli sur `SECRET_KEY`. Conserver la valeur exacte des clés valides, y compris leurs espaces éventuels.

Une ancienne `SECRET_KEY` courte, admise par une version antérieure, peut être conservée dans le trousseau de **vérification seulement** pour lire les preuves déjà signées. Elle ne signe aucune nouvelle preuve ; sa faible entropie historique ne peut pas être réparée rétroactivement. Les clés de chiffrement P0-1 conservent leur validation stricte.

Pour une archive créée avec une clé désormais refusée, conserver l’archive d’origine et la configuration exacte. Restaurer une copie dans un environnement hors ligne, avec l’image historique correspondante, sans portail ni worker. Traiter ensuite la migration des données chiffrées et le renouvellement des secrets exposés dans une opération contrôlée avant la remise en service. Si la clé d’origine était vide, les HMAC produits avec cette clé restent des preuves de provenance non fiable. Remplacer la variable ou la supprimer change la clé de lecture.

Le rôle de restauration a un mot de passe aléatoire, aucun privilège administrateur et aucune appartenance à un autre rôle. Le code ne lui accorde aucun droit sur les bases existantes ; il devient propriétaire de sa seule copie. `PUBLIC` n'a pas accès à cette copie. Le mot de passe temporaire n'est jamais placé dans les arguments d'un processus. Aucun rôle de l'application en service n'est désactivé ou modifié.

Ne restaurer que des archives de confiance. [PostgreSQL rappelle qu'une restauration exécute du SQL issu de la source](https://www.postgresql.org/docs/17/app-pgrestore.html) ; un compte limité réduit le périmètre mais ne transforme pas une archive arbitraire en code sûr.

## Nouvelle sauvegarde avec test complet

Depuis la racine du dépôt, avec un répertoire privé **déjà créé** pour l'archive et un répertoire de rapport **qui n'existe pas encore** :

```sh
python3 -m deploy.check_restore \
  --docker /usr/local/bin/docker \
  --postgres-container pam-olive-postgres-1 \
  --database-network pam-olive_internal \
  --application-image pamolive-platform-web \
  --application-env /volume1/docker/pamolive-platform/.env \
  --source-database pamolive_platform \
  --archive /volume1/docker/pamolive-platform-backups/nouvelle-sauvegarde.dump \
  --report-directory /volume1/docker/pamolive-platform-backups/nouveau-rapport
```

Ce sont les noms de l'installation NAS de référence, pas des valeurs universelles. Sur une autre installation, remplacer le conteneur PostgreSQL, le réseau, l'image, le nom exact de la base et les chemins. Sous Linux/macOS avec Docker dans le PATH, omettre `--docker /usr/local/bin/docker`. Sous Windows, utiliser `py -m deploy.check_restore`, des chemins privés Windows et écrire la commande sur une seule ligne ou utiliser les continuations PowerShell. Ne pas rediriger une sortie binaire `pg_dump` avec `>` dans une ancienne version de PowerShell : le programme écrit lui-même le flux binaire sans conversion de texte.

L'outil refuse d'écraser une archive ou un rapport existant. Il utilise les options [de dump PostgreSQL](https://www.postgresql.org/docs/17/app-pgdump.html) et ne démarre ni migrations ni tâches métier sur la source. Un échec laisse éventuellement une archive partielle privée : elle ne doit pas être considérée comme qualifiée.

## Tester une archive existante

Reprendre la commande précédente, **sans** `--source-database`, et fournir l'archive existante. Ajouter `--expected-manifest /chemin/prive/manifest.json` si le manifeste correspondant est disponible. Aucun manifeste n'est déduit de la base actuelle, qui a pu évoluer depuis la sauvegarde.

Les anciens manifestes `pamolive-preservation/1` sont acceptés explicitement comme contrôles partiels : le rapport porte `full_managed_model_manifest: false`. Ils ne deviennent pas rétroactivement des inventaires complets des relations implicites. Sans manifeste, le contrôle restaure l'archive et vérifie les preuves disponibles, mais ne revendique aucune comparaison de données à une référence indépendante.

## Rapport et nettoyage

Le résultat ne contient ni mots de passe, ni secrets déchiffrés. `report.json`, `key-check.json`, le nouveau `manifest.json` éventuel et les diagnostics restent dans le répertoire privé. Contrôler `result`, les quantités vérifiées, les refus de mauvaise clé/mauvais mot de passe et les deux indicateurs de retrait de copie/rôle.

Avant suppression, l'outil vérifie les OID, le propriétaire et l'absence de session dans les seuls objets qu'il a créés. Il n'utilise ni `--clean`, ni `--create`, ni `DROP OWNED`, ni terminaison forcée des connexions. Si une identité a changé ou qu'une session est encore active, il garde la copie pour inspection ; une expiration d'observation n'autorise pas un deuxième test ou une suppression aveugle. La copie sensible est rendue non connectable par son rôle quand son identité a pu être vérifiée.

La CI ajoute un corpus synthétique contenant des facteurs MFA, un compteur anti-rejeu, un hash de récupération, une appartenance M2M, un token SCIM, un secret de cible, des attestations/votes signés et une capture chiffrée scellée. Elle exige des valeurs réellement présentes ; une base presque vide ne suffit pas à qualifier ces chemins.

Elle injecte aussi une écriture dans la source **après** le manifeste et **avant** le dump. Cette écriture doit être présente en source mais absente de la copie restaurée, qui doit correspondre au manifeste du point de sauvegarde. Retirer l'import de l'instantané ferait échouer cette porte.

## Ce succès n'autorise pas une bascule automatique

Le rapport indique toujours `safe_to_serve: false`. La vérification est **hors ligne**. Une copie restaurée peut ressusciter des sessions, tickets, codes de récupération, autorisations ou tâches qui ont été révoqués après la sauvegarde.

Pour P0-3, conserver les enveloppes publiques successives du registre et les anciennes clés publiques avec leurs dates de révocation. Le vérificateur de restauration contrôle aussi les preuves WebAuthn consommées, leurs registres historiques et les mandats associés. Il ne réactive aucune autorité : le checkpoint courant reste géré et signé hors de la sauvegarde applicative par le témoin indépendant. Toute différence de génération, de révision ou d’empreinte bloque le PAM live. Voir [la procédure de confiance et de reprise](pam-trust-operations.md).

Une reprise réelle exige encore un protocole validé : fencing des anciens nœuds et de l'ancienne base, traitement des sessions/tickets et preuves anti-rejeu, revalidation des connecteurs et cibles, réconciliation des effets externes, contrôle des clés, puis remise en service autorisée. Ne pas exposer directement la copie, relancer des workers ou effectuer une rotation destructive des clés pour « faire marcher » la lecture. La qualification de restauration ne remplace pas les tests de charge, de failover PostgreSQL, de deux VM ou de reprise métier.

Pour P0-4, rapprocher aussi les générations de justificatifs de collecteurs, les derniers reçus V8 et les conflits avec un point de contrôle extérieur à la sauvegarde avant de reprendre l'ingestion. Une archive peut restaurer un ancien jeton encore chiffré ou un état de révocation périmé ; la validité cryptographique d'un reçu historique ne réactive pas ce jeton. Les identifiants d'événements source ne doivent pas être rejoués vers un autre collecteur. Le qualificateur local ne remplace pas ce contrôle externe.
