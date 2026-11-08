# API d’observation V1

Créer une source depuis **Connecteurs**. Le jeton n’est affiché qu’une fois ; seule son empreinte SHA-256 est conservée. Il autorise l’ingestion dans une seule organisation.

`POST /api/v1/events/`, `Content-Type: application/json`, `Authorization: Bearer <jeton>` :

```json
{
  "external_id": "event-2026-001",
  "occurred_at": "2026-11-07T14:32:00Z",
  "identity": "UUID de l’identité dans cette organisation",
  "account": "UUID du compte dans cette organisation",
  "resource": "UUID de la ressource dans cette organisation",
  "method": "SSH",
  "action": "session.start",
  "location": "192.0.2.10",
  "privilege": "Administrator",
  "result": "success",
  "evidence": "Référence publique vers la preuve source"
}
```

`identity`, `account`, `credential`, `location`, `privilege` et `evidence` sont facultatifs. `contract` peut contenir l’UUID d’un contrat de la même organisation et `country_code` le pays observé à deux lettres fourni par la source. Une identité absente reste inconnue. Aucun mot de passe, clé privée, jeton ou secret ne doit être envoyé dans les preuves.

### Acteur, compte et propriétaire : trois notions différentes

`identity` désigne **l’acteur rapporté par la source**, pas le propriétaire que PAM-olive retrouverait dans l’inventaire. `account` et `credential` peuvent appartenir à d’autres identités de la même organisation. Exemple : une source d’assistance rapporte Cyriel comme intervenant, `svc-radiology` comme compte utilisé et un certificat détenu par l’identité technique « Service radiologie ». Ces trois références restent séparées ; le rattachement du compte au service n’est pas modifié.

Si la source ne connaît que le compte ou le certificat, omettre `identity` : le fait est accepté, l’acteur reste inconnu et aucune intention personnelle n’est rapprochée par simple propriété du compte. L’identification d’un compte n’est pas une preuve qu’un humain, son responsable ou son propriétaire l’a utilisé. La source doit conserver sa preuve d’attribution dans `evidence` ; l’API ne certifie pas elle-même l’authentification rapportée.

Une intention de type **Justification et observation** peut déclarer séparément l’intervenant et le compte partagé précis. Le rapprochement exige l’acteur, le compte, la ressource, la méthode et la fenêtre applicables ; l’intention d’une autre personne utilisant le même compte ne vaut pas autorisation. Ce parcours d’observation ne permet ni provisioning IAM sur un compte d’une autre identité ni délégation du relais PAM. Ces actions nécessitent un contrat d’exécution distinct encore à implémenter.

L’export garde les identifiants reçus dans `facts`, dont `identity_attribution` (`source_reported` ou `unresolved`). Le bloc `inventory_context` fournit séparément les propriétaires **actuellement** renseignés, son heure `as_of` et la provenance `current_inventory_not_historical_ownership`. Il ne prétend pas reconstituer la propriété au moment de l’accès. Chaque évaluation `access-context/4` conserve son propre contexte d’inventaire daté ; une réévaluation ajoute un résultat sans réécrire le fait ou les anciennes explications.

Le pays déclaré dans une intention n’est jamais recopié comme pays observé. Si un contrat exige un pays et que la source ne le fournit pas, l’évaluation garde cette incertitude. Le contrat applicable est sa révision publiée à `occurred_at`, pas nécessairement sa révision actuelle. Une intention approuvée après `occurred_at` ne justifie pas rétroactivement cet événement. L’heure de la source doit donc être fiable et synchronisée.

La source est imposée par le jeton ; aucun `organization_id` ni `source` n’est accepté du client. Une nouvelle observation renvoie HTTP 201 ; son rejeu avec le même identifiant source renvoie HTTP 200 et le même UUID. Le fait initial n’est pas modifié.

Les dates des API sources exigent un fuseau explicite (`Z` ou un décalage ISO 8601). Aucune heure locale sans fuseau n’est interprétée silencieusement. Un fait daté de plus de cinq minutes dans le futur est refusé : les interventions prévues appartiennent aux intentions, pas aux observations.

Le détail de l’événement et son export `/api/v1/events/<uuid>/export/` nécessitent une session interactive autorisée dans l’organisation. Les sources d’ingestion ne peuvent pas lire les données ou approuver des accès.

## Contexte réseau et certificat

Les observations acceptent également :

```json
{
  "domain": "network",
  "network_switch": "UUID d’une ressource réseau de cette organisation",
  "network_port": "1/1/24",
  "network_vlan": "RADIOLOGY",
  "credential_observation": "identifier_only"
}
```

Ces champs complètent le corps d’événement précédent, ils ne le remplacent pas. `domain` vaut `physical`, `pam`, `remote`, `network`, `application`, `certificate`, `directory` ou `cloud`. Sans domaine connu, ne pas en inventer un. `credential_observation` vaut `identifier_only` par défaut, ou `possession_asserted` si la source déclare avoir une preuve de possession ; PAM-olive ne vérifie pas cryptographiquement cette déclaration. Aucun secret ou certificat privé n’est transmis. Un certificat gouverné reste distinct de l’identité machine qui le possède.

Une intention contenant un switch/port/VLAN précis utilise la suite « observation ». Ce parcours ne configure pas un NAC ou un switch et n’est pas converti en droit IAM générique, qui perdrait ces restrictions. L’intégration d’un provisioning réseau requiert un adaptateur capable de les faire appliquer.

Les exports d’événements incluent les UUID et champs structurés dans `facts`, ainsi que les constats et leur version. Une réévaluation ajoute une explication, elle ne modifie ni l’observation ni les évaluations précédentes.

## Rapports de couverture de collecte

L’administrateur active le module Graphe et investigations, puis crée un périmètre dans **Relations et couverture des sources** : source, domaine et ressource ou organisation entière explicitement confirmée. Le producteur utilise son jeton de source existant pour `POST /api/v1/collection-reports/` :

```json
{
  "scope": "UUID du périmètre attribué à cette source",
  "external_id": "coverage-2026-11-07T14:00Z",
  "covered_from": "2026-11-07T14:00:00Z",
  "covered_until": "2026-11-07T14:05:00Z",
  "state": "complete",
  "clock_uncertainty_seconds": 3,
  "detail": "Collecte et pagination terminées sur la période"
}
```

`Authorization: Bearer <jeton>` et `Content-Type: application/json` sont obligatoires ; HTTPS est requis hors évaluation privée. La source ne peut utiliser ni le périmètre d’une autre source ni celui d’une autre organisation. Les dates sont postérieures à la publication du périmètre et ne peuvent couvrir le futur. Les rapports sont bornés à 16 Kio.

`state` vaut `complete`, `partial` ou `unavailable`. Une fin de pagination non atteinte, une erreur fournisseur ou un trou de collecte impose `partial` ou `unavailable`, pas `complete`. L’incertitude d’horloge déclarée vaut 0 à 3600 secondes, ou reste inconnue si absente. Une source activée ou un simple heartbeat ne prouve pas une collecte complète.

Un nouveau rapport renvoie 201. Le même couple périmètre/identifiant renvoie 200 avec le rapport initial, sans réécriture. Pour corriger une déclaration, envoyer un nouvel identifiant : la séquence serveur détermine quelle déclaration l’emporte sur chaque sous-intervalle, même si deux réceptions ont la même heure. Les anciens rapports restent conservés.

L’absence d’événement n’est interprétable que pour les sources et périodes effectivement couvertes. Même une déclaration complète n’est pas une preuve universelle qu’aucun accès n’a eu lieu. Les événements arrivés tardivement conservent leur heure source et leur heure de réception ; la proximité horaire de deux activités n’établit pas leur causalité.
