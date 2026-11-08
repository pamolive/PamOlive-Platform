# API des systèmes métier

Plusieurs outils de ticketing, de gestion des changements ou de projets peuvent publier leurs lectures dans PAM-olive au format `pamolive.business-record/1`. Chaque intégration possède un jeton indépendant, limité à une organisation et à ses propres références. Les données restent dans PostgreSQL ; aucun nouveau service ni conteneur permanent n’est requis.

Cette API reçoit des **déclarations de sources authentifiées**. Elle ne contacte pas elle-même GLPI, Jira ou ServiceNow et ne certifie pas leur configuration. Un adaptateur dans l’outil émetteur, une automatisation existante ou un client d’intégration doit lire le système source et traduire ses champs. L’état source `approved` n’est jamais une approbation PAM-olive : l’API ne crée ni identité, ni compte, ni intention, ni droit et ne déclenche aucun provisioning.

Le [contrat OpenAPI](business-api.openapi.json) décrit les deux opérations destinées aux intégrateurs. Les opérations interactives de rattachement restent protégées par la session du portail et la MFA ; elles ne sont pas accessibles avec le jeton source.

Le rattachement à une intention est une déclaration humaine séparée, datée et protégée par MFA. Une référence texte identique dans deux systèmes n’établit aucun lien automatique.

## Configurer une intégration

Dans l’organisation concernée, activer Connecteurs puis ouvrir **Systèmes métier et API** avec le rôle administrateur. Créer par exemple `glpi-it`, `jira-projets` et `servicenow-production` comme trois sources distinctes. La création, la désactivation, la réactivation et le remplacement d’un jeton nécessitent une MFA personnelle récente. Le jeton n’est affiché qu’une fois ; seul son hash est conservé.

Les anciens jetons d’ingestion d’événements ne peuvent pas appeler cette API et les nouveaux jetons métier ne peuvent pas importer d’événement d’accès. Un cookie du portail ne remplace pas le jeton. Le nom et la clé de source ne sont pas une preuve de certification du fournisseur.

L’identifiant externe doit rester stable pour un même dossier dans une même source. Ne pas réutiliser une intégration pour un autre outil ou espace d’identifiants : créer une nouvelle source. Une rotation de jeton conserve l’intégration ; elle exige une nouvelle lecture sous la révision courante avant de présenter sa déclaration comme actuelle.

Pour une évaluation sur le réseau local, conserver l’adresse existante de l’application. HTTP ne chiffre ni le jeton ni les références : limiter cet usage au réseau de confiance. Employer HTTPS pour une exposition distante ou des échanges sensibles. Aucun changement DNS ni reverse proxy n’est nécessaire au développement local.

## Publier une lecture

`POST /api/v1/business-records/` exige `Content-Type: application/json` et `Authorization: Bearer <jeton métier>`. Le jeton détermine l’organisation et la source ; ces deux valeurs ne sont jamais acceptées dans le corps.

```json
{
  "schema": "pamolive.business-record/1",
  "external_id": "483",
  "sequence": 1,
  "kind": "incident",
  "reference": "INC-483",
  "state": "open",
  "title": "Maintenance du poste",
  "url": "https://tickets.example.org/ticket/483",
  "source_updated_at": "2026-11-08T08:00:00.123456Z",
  "observed_at": "2026-11-08T09:00:00.123456Z"
}
```

Remplacer les dates par celles de la modification et de la lecture réelles. `external_id` est l’identifiant stable dans le système source ; `reference` est le libellé métier. Deux intégrations peuvent employer le même identifiant sans partager leurs dossiers.

| Champ | Contrat |
| --- | --- |
| `schema` | Exactement `pamolive.business-record/1` |
| `external_id`, `reference` | Chaînes non vides, 180 caractères maximum |
| `sequence` | Entier de 1 à 2147483647, croissant pour chaque identifiant source |
| `kind` | `ticket`, `incident`, `change`, `maintenance`, `project`, `emergency`, `other` |
| `state` | `unknown`, `open`, `approved`, `closed`, `cancelled` ; toujours un état source |
| `title` | Facultatif, 240 caractères maximum ; éviter les données personnelles inutiles |
| `url` | Facultative, HTTPS, 500 caractères maximum, sans identifiants ni fragment ; jamais interrogée par le serveur |
| `source_updated_at` | Date déclarée de dernière modification dans le système source, avec fuseau |
| `observed_at` | Date déclarée de lecture par l’intégration, avec fuseau, postérieure ou égale à la modification |

Les champs inconnus, clés JSON répétées, nombres non finis, dates naïves et dates à plus de cinq minutes dans le futur sont refusés. La charge utile est limitée à 16 Kio. Ne pas envoyer de description complète, pièce jointe, mot de passe ou jeton de fournisseur.

Pour chaque nouvelle lecture, y compris d’un dossier inchangé, l’intégrateur incrémente sa séquence et conserve les dates source réellement observées. Une nouvelle lecture ne peut pas reculer les deux dates par rapport à la dernière séquence connue. Des séquences peuvent être sautées ; leur allocation doit être coordonnée entre les instances de l’intégrateur.

Une création retourne `201`. Le rejeu exact d’une séquence retourne `200` avec la même preuve et la même date de réception. Il ne rend pas une lecture ancienne plus récente. Réutiliser une séquence avec un autre contenu ou une autre révision de configuration retourne `409`. Après une rotation, publier une nouvelle séquence avec le nouveau jeton.

## Relire sa propre référence

`GET /api/v1/business-records/?external_id=483` retourne uniquement la dernière séquence de cette intégration. Il ne permet ni une liste globale ni la lecture des données d’une autre source ou organisation. Une référence absente retourne `404`.

La réponse contient les identifiants de preuve, le contenu reçu, sa date de réception, la vérification de signature et des indicateurs distincts :

- `source_configuration_current` : la source reste active et la lecture appartient à sa révision courante ;
- `source_read_recent` : la lecture déclarée et sa réception restent dans le délai configuré, de 60 à 86400 secondes, 900 par défaut ;
- `latest_for_record` : aucune séquence supérieure n’a remplacé cette lecture ;
- `current_source_assertion` : les trois conditions précédentes sont réunies. Ce champ ne signifie toujours pas que l’accès est autorisé dans PAM-olive.

Les indicateurs sont calculés ensemble sous le verrou de l’organisation, à l’instant `as_of`, avec une configuration source relue en base plutôt qu’un cache ORM ancien. La fraîcheur n’est ni une garantie de vérité ni une réservation de validité sur le système distant. Un rejeu ne la renouvelle pas. Une source désactivée perd son accès API ; ses preuves historiques restent consultables dans l’organisation. Les réponses portent `Cache-Control: no-store` et ne contiennent jamais le hash du jeton.

La limite de 60 appels par minute s’applique séparément à chaque source authentifiée, y compris aux corps refusés. La minute est celle de PostgreSQL commun, pas celle de chaque VM applicative. `429` indique d’attendre, avec `Retry-After: 60`. Cette limite applicative ne remplace pas une protection réseau contre le déni de service.

## Exemples de transport

Sous Linux, macOS ou NAS, charger le jeton depuis le gestionnaire de secrets de l’intégration, puis lire une référence :

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $PAMOLIVE_BUSINESS_TOKEN" \
  'http://192.168.0.25:8010/api/v1/business-records/?external_id=483'
```

Sous PowerShell :

```powershell
$businessHeaders = @{ Authorization = "Bearer $env:PAMOLIVE_BUSINESS_TOKEN" }
Invoke-RestMethod -Method Get -Headers $businessHeaders -Uri 'http://192.168.0.25:8010/api/v1/business-records/?external_id=483'
```

Une réponse `404` avec un jeton valide signifie que cette source n’a pas encore publié cet identifiant. Ne jamais inscrire la valeur du jeton dans un exemple Git, une capture d’écran ou une conversation.

## Rattacher une référence à une intention

1. Ouvrir l’intention dans le portail, puis **Références métier, sources et historique**.
2. Valider sa MFA personnelle et choisir **Associer une référence métier**. Le demandeur peut gérer ses propres intentions ; un administrateur de l’organisation peut gérer les autres. Les rôles de consultation ou d’approbation seuls ne peuvent pas publier ce rattachement.
3. Sélectionner la source et son identifiant externe exact, puis **Afficher la lecture source**. Examiner la référence, l’état, la date déclarée de lecture et la date de réception.
4. Renseigner pourquoi ce dossier concerne l’intention et confirmer la lecture sélectionnée. Une lecture historique peut être associée pour l’investigation ; elle ne devient pas actuelle pour autant.
5. Pour corriger le dossier ou la lecture choisie, publier une nouvelle association. Pour retirer le lien, fournir un motif depuis son état courant. Une commande issue d’une ancienne page est refusée si un rattachement plus récent l’a remplacé.

Plusieurs sources et dossiers peuvent être associés à la même intention. Le périmètre de l’intention est figé dans chaque attestation, sans changer son statut, ses votes, son bail PAM ou ses droits. Une modification ultérieure du périmètre invalide l’utilisation courante du rattachement mais conserve son ancienne preuve. Un changement de référence ou de type dans le système source demande aussi une revue explicite.

La vue présente séparément la lecture choisie lors du rattachement et la dernière lecture connue du même dossier. « Contexte source actuel » signifie seulement que la relation déclarée et la dernière déclaration source restent actuelles. Un ticket clos peut constituer un contexte actuel ; ce libellé ne dit pas que l’accès est autorisé. L’historique conserve les associations et retraits, avec export de leur preuve et du périmètre d’origine.

L’affichage est borné à 20 dossiers courants et 50 publications historiques par intention, avec avertissement si la liste est partielle. La limite d’affichage n’efface aucune preuve et ne constitue pas une revue exhaustive.

## Utiliser le contexte dans l’explication d’un accès

Le détail d’un accès propose les références des seules intentions rapprochées par une évaluation signée et encore compatible avec l’interprétation courante. Il n’effectue aucune recherche automatique par texte de ticket. Les accès justifiés par un droit permanent sans intention ne sont pas présentés comme dépourvus de justification parce que cette vue n’a pas de rattachement.

L’export d’accès ajoute `business_context` à côté des faits et de l’évaluation historique, sans réécrire celle-ci ni sa signature. S’il contient des preuves métier, une MFA personnelle récente est requise avant leur lecture, y compris à l’export. La consultation ordinaire de l’accès ne révèle pas les titres ou charges utiles des systèmes métier avant ce contrôle.

Les champs `association_known_before_access`, `pinned_read_known_before_access` et `association_known_before_evaluation` distinguent les éléments déjà connus des rattachements ultérieurs. Ces comparaisons utilisent l’heure d’accès déclarée et les dates de réception/publication dans la plateforme ; elles ne certifient pas l’horloge source. Elles concernent le début de l’accès, pas toute la durée d’une session. `included_in_historical_evaluation` et `observed_interval_evaluated` restent faux : ce contexte séparé n’est pas ajouté rétroactivement à la décision signée et ne prouve pas une autorisation externe pendant toute la session.

Un module Connecteurs désactivé rend ce contexte indisponible, sans supprimer son histoire ni inventer une conformité. Un jeton d’intégration ne peut ni publier un rattachement humain ni approuver une intention.

## Conservation des preuves

Les lectures sont signées avec tous leurs champs et leurs microsecondes, liées à l’audit de l’organisation et conservées sans réécriture. PostgreSQL refuse les modifications et suppressions des dossiers et lectures ainsi que les relations vers une autre organisation. Une correction ajoute une séquence ; elle ne remplace pas l’ancienne preuve. Les réponses et l’interface distinguent une déclaration source, une lecture récente et une autorisation locale.
