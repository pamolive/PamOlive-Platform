# Recertification périodique des accès

La recertification permet au responsable d’une organisation de confirmer ou de retirer des droits existants. Chaque campagne conserve son périmètre au moment de la capture et des décisions signées liées à l’audit. Une confirmation ne crée, ne réactive et ne prolonge aucun droit.

## Configurer une règle

Dans **Recertification → Nouvelle règle périodique**, un administrateur choisit un identifiant stable, un responsable actif de l’organisation, une première échéance, une période et un délai de revue. Le responsable doit avoir le rôle technique `admin` ou `reviewer`. Un superadministrateur sans appartenance explicite ne peut pas être responsable d’une règle automatique.

Les filtres portent sur les ressources, les types d’identités et les types de comptes. Un filtre vide ne restreint pas cette dimension ; plusieurs filtres se combinent par intersection. Les comptes absents ne correspondent pas à un filtre de type de compte. Seuls les droits au **statut** actif sont capturés : cela ne signifie pas que leur fenêtre temporelle ou leur contexte les autorise encore.

L’enregistrement crée une révision **inactive**. Après vérification, l’administrateur active explicitement cette révision. Chaque modification, activation ou désactivation exige sa MFA personnelle récente, selon sa durée de 2, 5, 10 ou 15 minutes. Le challenge conserve le formulaire pour sa reprise. Une ancienne page ne peut pas activer une révision plus récente à l’insu de l’administrateur.

Modifier une règle suspend ses prochains déclenchements jusqu’à activation de la nouvelle révision. Cette activation ouvre un nouveau cycle de configuration : elle peut produire une nouvelle campagne dans la période courante même si une ancienne révision en a déjà produit une. Désactiver n’efface ni les campagnes ni les décisions ; cette action reste possible si le responsable a perdu son appartenance.

## Déclenchement et périodes manquées

Le traitement `runjobs` déjà présent dans le conteneur applicatif recherche les échéances. Il n’ajoute ni conteneur scheduler ni worker Compose. Les échéances et les captures utilisent l’horloge PostgreSQL ; les périodes sont des durées fixes de 24 heures et non des jours calendaires locaux. L’interface interprète les dates saisies dans le fuseau de l’application, configuré par `TIME_ZONE` ; les preuves normalisent les dates en UTC.

Le verrou organisationnel et l’unicité `(publication, scheduled_for)` empêchent deux instances actives d’ouvrir la même occurrence. La capture est préparée hors de ce verrou ; avant sa validation, le traitement revérifie l’organisation, les modules, la révision active et le responsable. La création de la campagne, du manifeste et des revues est atomique.

Après une interruption, seule la période courante donne lieu à une capture réelle. Le champ `missed_periods` indique les périodes sautées ; aucun instantané historique n’est fabriqué. Le délai de revue commence à la fin de la capture réelle. Une échéance de revue dépassée ne révoque pas automatiquement les droits et n’accorde pas non plus de prolongation.

Si le responsable est indisponible, la preuve de configuration invalide ou le périmètre trop volumineux, la règle affiche un motif de blocage et reprend après quinze minutes. Aucune campagne partielle n’est publiée. Les erreurs PostgreSQL inattendues restent des erreurs du traitement, pas des succès silencieux.

## Décider sur le périmètre figé

Une campagne ponctuelle nécessite une MFA récente et un rôle `admin` ou `reviewer`. Elle capture tous les droits au statut actif. Le responsable peut être choisi parmi les membres admissibles ; à défaut, l’auteur assume la revue.

Chaque revue affiche l’identité, le compte, la ressource, le droit, la justification et la validité **figés**. Seuls le responsable affecté et un administrateur de l’organisation peuvent décider, avec une MFA personnelle récente et un motif obligatoire. Aucun challenge n’est inséré dans une session SSH ou RDP en cours.

| Décision | Effet |
|---|---|
| Confirmer | Vérifie que le droit, sa révision et son contexte n’ont pas changé, que l’identité et le compte restent actifs et que la politique permet encore ce droit. N’écrit pas de nouvelle durée. |
| Retirer | Refuse une revue périmée si le droit actif ou son contexte a changé, puis utilise le service IAM de révocation et sa file de provisioning. |
| Retirer un droit déjà révoqué | Enregistre `already_revoked`, sans deuxième retrait ni incrément supplémentaire du droit. |

Un changement de droit ou de contexte exige une nouvelle campagne. Une revue déjà décidée ne peut pas être rejouée. Le résumé opérationnel de la revue n’est pas une preuve : l’interface vérifie la décision signée et signale les incohérences avec ce résumé.

Le retrait local est immédiat. Son exécution sur un fournisseur dépend du connecteur, de ses correspondances et des relectures de confirmation. La preuve de revue n’affirme jamais cette confirmation externe.

## Preuves et export

Les objets `SchedulePublication`, `CampaignRun`, `ReviewScope` et `ReviewDecision` conservent respectivement la règle publiée, l’origine de la campagne, le périmètre figé et la décision. Le manifeste SHA-256 ordonne les signatures de périmètre par identifiant de droit ; les attestations HMAC sont liées au noyau et à l’audit. Ce ne sont pas des signatures publiques vérifiables sans les clés de l’installation.

La capture provient d’une seule sélection PostgreSQL. `capture_started_at` et `snapshot_at` en donnent les bornes : ils ne prétendent pas identifier un instant historique exact. Les libellés historiques restent séparés de l’état actuel, et la preuve reste vérifiable après désactivation d’un module ou d’une règle.

La page de campagne et l’export JSON exigent une MFA récente et interdisent le stockage en cache. L’export `pamolive.recertification-evidence/1` fournit 25 périmètres par page, le nombre total de pages et le manifeste commun. `complete=false` indique qu’il faut récupérer les autres pages ; chaque page est un fragment, pas un dossier complet. Les attestations et la chaîne d’audit doivent être conservées avec les clés lors des sauvegardes.

Les campagnes créées avant cette version restent conservées en lecture seule. Elles ne reçoivent pas rétroactivement de faux périmètres signés ; une nouvelle campagne est nécessaire pour de nouvelles décisions.

## Limites et exploitation

Une règle accepte au plus 100 ressources et 100 valeurs par filtre. Une capture accepte par défaut 10 000 droits, 16 Mio cumulés de données canoniques et 64 Kio par droit. `PAMOLIVE_RECERTIFICATION_MAX_GRANTS` permet de fixer 1 à 50 000 droits et `PAMOLIVE_RECERTIFICATION_MAX_BYTES` 65 536 à 67 108 864 octets ; des valeurs hors de ces bornes échouent au contrôle `pamolive.E011`. Ces bornes empêchent les captures partielles ; elles ne constituent pas une qualification de charge.

PostgreSQL empêche la modification ou la suppression des preuves et le changement de l’identifiant stable d’une règle. Les clés étrangères composites protègent les liens entre organisation, campagne, revue et droit. Le contrôle de restauration vérifie les publications, manifestes, périmètres et décisions sur une copie isolée. Les tables de preuves, la base et les clés doivent suivre la [procédure de sauvegarde](backup-restore.md) et la [migration contrôlée](controlled-upgrade.md).

Les services passent par le contrat `identity.review/1` pour capturer les droits et appliquer une décision. Les notifications transactionnelles `recertification.schedule.published.v1`, `recertification.campaign.opened.v1` et `recertification.review.decided.v1` décrivent ces faits ; elles ne transfèrent aucune autorisation ni MFA aux consommateurs.
