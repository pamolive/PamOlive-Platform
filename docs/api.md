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

`identity`, `account`, `resource`, `credential`, `location`, `privilege` et `evidence` sont facultatifs. `contract` peut contenir l’UUID d’un contrat de la même organisation et `country_code` le pays observé à deux lettres fourni par la source. Une identité ou ressource absente reste inconnue ; aucune cible d’inventaire n’est inventée. Aucun mot de passe, clé privée, jeton ou secret ne doit être envoyé dans les preuves.

## Durée observée

Pour une session terminée, ajouter `ended_at`, par exemple :

```json
{
  "occurred_at": "2026-11-07T14:32:00Z",
  "ended_at": "2026-11-07T14:47:00Z"
}
```

Ces champs complètent l’événement précédent. `ended_at` absent ou `null` conserve la sémantique d’un fait instantané ; égal au début, il décrit une durée nulle. Une période positive est semi-ouverte, début inclus et fin exclue. Les dates nécessitent un fuseau explicite ; une fin antérieure au début ou à plus de cinq minutes dans le futur est refusée.

Depuis `access-context/6`, le moteur [évalue toute la période observée](observed-intervals.md), avec les changements de contexte et les références métier propres à chaque partie. `access-context/7` ajoute une [interprétation signée distincte des faits source](observation-context.md). L’export fournit `ended_at` et `duration_seconds`. Les anciens faits et évaluations ne sont pas réécrits ; un rejeu du même identifiant source conserve toujours le fait initial, même si une fin est ajoutée à la requête.

## Acteur, compte et propriétaire : trois notions différentes

`identity` désigne **l’acteur rapporté par la source**, pas le propriétaire que PAM-olive retrouverait dans l’inventaire. `account` et `credential` peuvent appartenir à d’autres identités de la même organisation. Exemple : une source d’assistance rapporte Cyriel comme intervenant, `svc-radiology` comme compte utilisé et un certificat détenu par l’identité technique « Service radiologie ». Ces trois références restent séparées ; le rattachement du compte au service n’est pas modifié.

Si la source ne connaît que le compte ou le certificat, omettre `identity` : le fait est accepté, l’acteur reste inconnu et aucune intention personnelle n’est rapprochée par simple propriété du compte. L’identification d’un compte n’est pas une preuve qu’un humain, son responsable ou son propriétaire l’a utilisé. La source doit conserver sa preuve d’attribution dans `evidence` ; l’API ne certifie pas elle-même l’authentification rapportée.

Une intention de type **Justification et observation** peut déclarer séparément l’intervenant et le compte partagé précis. Le rapprochement exige l’acteur, le compte, la ressource, la méthode et la fenêtre applicables ; l’intention d’une autre personne utilisant le même compte ne vaut pas autorisation. Ce parcours ne permet ni provisioning IAM sur un compte d’une autre identité ni ouverture de relais. L’exécution SSH/RDP exige un [mandat PAM distinct](pam-transport.md#personne-intervenante-compte-utilisé-et-mandat), lié explicitement à la personne connectée, au compte technique précis et à des votes de personnes indépendantes.

L’export garde les identifiants reçus dans `facts`, dont `identity_attribution` (`source_reported` ou `unresolved`). Le bloc `inventory_context` fournit séparément les propriétaires **actuellement** renseignés, son heure `as_of` et la provenance `current_inventory_not_historical_ownership`. Il ne prétend pas reconstituer la propriété au moment de l’accès. Depuis `access-context/4`, chaque évaluation conserve son propre contexte d’inventaire daté. `access-context/5` exige en plus les attestations de personne et votes signés lorsqu’une intention PAM est rapprochée ; un ancien statut « approuvé » sans ces preuves ne suffit plus. Une réévaluation ajoute un résultat sans réécrire le fait ou les anciennes explications.

Le pays déclaré dans une intention n’est jamais recopié comme pays observé. Si un contrat exige un pays et que la source ne le fournit pas, l’évaluation garde cette incertitude. Le contrat applicable est sa révision publiée à `occurred_at`, pas nécessairement sa révision actuelle. Une intention approuvée après `occurred_at` ne justifie pas rétroactivement cet événement. L’heure de la source doit donc être fiable et synchronisée.

La source est imposée par le jeton ; aucun `organization_id` ni `source` n’est accepté du client. Une nouvelle observation renvoie HTTP 201 ; son rejeu avec le même identifiant source renvoie HTTP 200 et le même UUID. Le fait initial n’est pas modifié.

Les dates des API sources exigent un fuseau explicite (`Z` ou un décalage ISO 8601). Aucune heure locale sans fuseau n’est interprétée silencieusement. Un fait daté de plus de cinq minutes dans le futur est refusé : les interventions prévues appartiennent aux intentions, pas aux observations.

Le détail de l’événement et son export `/api/v1/events/<uuid>/export/` nécessitent une session interactive autorisée dans l’organisation. Les sources d’ingestion ne peuvent pas lire les données ou approuver des accès.

## Observations normalisées

Les observations normalisées par un adaptateur interne utilisent un nom réservé `managed:` et un lien de provenance signé. L’export conserve leurs faits dans `facts` et leurs associations administratives dans `interpretation`. Une ancienne déclaration manuelle portant ce nom sans preuve n’est pas considérée comme normalisée. Le contexte de chaque analyse reste dans `evaluation.context` ; `current_interpretation_differs` indique qu’il ne décrit plus l’interprétation actuelle. Une ancienne analyse non signée n’est pas présentée comme une preuve actuelle vérifiée.

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

Ces champs complètent le corps d’événement précédent, ils ne le remplacent pas. `domain` vaut `physical`, `pam`, `remote`, `network`, `application`, `certificate`, `directory` ou `cloud`. Sans domaine connu, ne pas en inventer un. `credential_observation` vaut `identifier_only` par défaut ou `possession_asserted` si la source déclare disposer d’une preuve. Ce champ reste une déclaration de la source, distincte du constat cryptographique décrit ci-dessous. Un certificat gouverné reste distinct de l’identité machine qui le possède.

Une intention contenant un switch/port/VLAN précis utilise la suite « observation ». Ce parcours ne configure pas un NAC ou un switch et n’est pas converti en droit IAM générique, qui perdrait ces restrictions. L’intégration d’un provisioning réseau requiert un adaptateur capable de les faire appliquer.

Les exports d’événements incluent les UUID et champs structurés dans `facts`, ainsi que les constats et leur version. Une réévaluation ajoute une explication, elle ne modifie ni l’observation ni les évaluations précédentes.

### Vérification de la possession d’une clé de certificat

Enregistrer dans l’inventaire l’empreinte SHA-256 du certificat public en DER, puis publier l’événement avec `domain: "certificate"` et l’UUID de ce certificat dans `credential`. Seule la source Bearer qui a publié l’événement peut demander le défi. Un événement saisi à la main n’est pas éligible, même si sa source affichée porte le même nom. Utiliser HTTPS sur un nom ou une adresse approuvée ; un NAS configuré seulement en HTTP ne reçoit pas les preuves.

1. Appeler `POST /api/v1/events/<uuid>/certificate-challenge/` avec un objet JSON vide et le jeton de source. La réponse fournit `challenge`, `message_b64`, l’empreinte attendue et une durée de 120 secondes.
2. Sur le système qui détient la clé privée, vérifier le format `pamolive.certificate-possession/1`, l’organisation, la source, l’événement et l’empreinte du message avant de le signer. Décoder `message_b64` en octets et signer ces octets exacts. Le message commence par `PamOlive certificate possession v1` suivi d’un saut de ligne et d’un objet JSON. Les algorithmes acceptés sont Ed25519, ECDSA P-256/SHA-256 (signature DER) et RSA-PSS/SHA-256 (MGF1 SHA-256, sel de 32 octets, clé de 2 048 à 4 096 bits).
3. Appeler `POST /api/v1/events/<uuid>/certificate-proof/` avec le même jeton, le `challenge` intact, `certificate` (certificat public DER en base64) et `signature` (signature en base64). La clé privée ne quitte pas le système qui signe.

Une preuve acceptée renvoie HTTP 201 et sa référence d’audit. Une autre preuve pour le même événement renvoie 409 sans remplacer l’original. Les deux routes partagent une limite de 30 appels par minute et par source, y compris les tentatives invalides. Le résumé figure sous `certificate_possession` dans l’export interactif et dans le détail de l’événement.

La vérification atteste qu’une entité pouvait signer avec la clé correspondante au moment du défi. Elle ne valide ni une chaîne d’autorité, ni la révocation PKI, ni la localisation de la clé pendant l’accès historique. Elle ne change ni le fait, ni son évaluation, ni les droits.

#### Utiliser le client de signature détachée

Le client se lance depuis le dépôt sur un poste disposant de Python et de la dépendance `cryptography` du projet. Il n’ajoute aucun service sur PamOlive. Copier le [fichier cible d’exemple](../integrations/certificate-holder.example.json) en `cible.json` et renseigner l’origine HTTPS et les quatre UUID attendus. Fournir le jeton de source dans la variable `PAMOLIVE_CERTIFICATE_SOURCE_TOKEN` via le gestionnaire de secrets du poste. Ne pas le placer dans le fichier cible ni dans la ligne de commande.

```sh
python -m integrations.certificate_holder fetch --target cible.json --certificate public.der --bundle defi
```

Le client vérifie le périmètre et crée `defi/message.bin` et `defi/challenge.json`. Le répertoire doit être nouveau. Faire signer `message.bin` par le détenteur de la clé dans les 120 secondes, avec l’outil approuvé pour cette clé. Pour une **clé Ed25519 de test**, [OpenSSL](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/#ed25519-and-ed448-algorithms) peut produire la signature détachée :

```sh
openssl pkeyutl -sign -rawin -inkey cle-test-ed25519.pem -in defi/message.bin -out signature.bin
python -m integrations.certificate_holder submit --target cible.json --certificate public.der --bundle defi --signature signature.bin
```

Le client vérifie la signature localement avant d’envoyer le certificat public et la signature à PamOlive. Il n’utilise ni redirection ni proxy hérité. Pour une autorité interne, ajouter `--ca-file` avec son certificat public approuvé aux deux commandes Python. Si la soumission est interrompue, consulter l’événement avant de refaire un défi : le serveur a pu enregistrer la preuve avant la coupure.

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
# Contrat transverse de lecture P1

`GET /api/v1/access-contracts/<intent UUID>/` expose `pamolive.access-contract/1`
avec la session du portail. Les rôles admin, operator, reviewer et auditor de
l'organisation peuvent lire ; Identity et Access ainsi que leurs dépendances
doivent être actifs. Les autres domaines sont explicitement disponibles ou
indisponibles. Le service relit les autorisations après le verrou d'organisation.

Les sections séparent intention, décisions, droit demandé, droit local,
effets fournisseur confirmés, tentatives, baux/relais PAM, observations et preuves.
Elles ne créent aucune autorisation. Le contrat est une lecture non signée et
ne remplace pas les preuves historiques V7/V8. Une confirmation est un résultat
enregistré à une date, sans assertion d'inventaire distant actuel.

Les collections indiquent `availability`, `items` et `truncated` ; une section
`module_disabled` ne signifie pas qu'aucune activité historique n'existe. La
projection n'expose ni jeton, ni ciphertext, ni configuration de cible, ni
payload fournisseur arbitraire. Réponse `Cache-Control: no-store` ; `403` pour
capacité/rôle refusé, `404` pour UUID absent du tenant, `405` hors GET. Une
session absente suit le parcours de connexion du portail.

L'écran `/access/intents/<UUID>/contract/` et son export `/contract/export/`
utilisent le même service. Voir [ADR-015](adr-015-access-read-contract.md).

## Lectures Identity, Governance et Observe P1

Ces routes utilisent la session du portail et les rôles admin/operator/reviewer/auditor de l'organisation. Ce ne sont pas des points d'ingestion par jeton de collecteur. Les lectures sont GET uniquement, privées (`no-store`, `nosniff`), bornées et sans autorité nouvelle :

| Route | Contrat | Modules requis |
| --- | --- | --- |
| `/api/v1/identities/<UUID>/360/` | `pamolive.identity360/1` | Identity ; sections Access/Connect conditionnelles |
| `/api/v1/governance/workspace/` | `pamolive.governance-workspace/1` | Governance et ses dépendances ; sections conditionnelles |
| `/api/v1/observations/<UUID>/story/` | `pamolive.observation-story/1` | Identity, Access, Intelligence ; Connect pour collector/internal |

Les interfaces natives et exports partagent les mêmes services et contrôles sous verrou. Un UUID étranger au tenant n'est pas recherché globalement. Une capacité refusée retourne 403, un objet absent du tenant 404, une méthode non admise 405 ; une session absente suit le parcours de connexion. `compare_intent=<UUID>` sur Observe est une comparaison explicite dans le même tenant, sans causalité ni autorisation implicite. Les preuves et limites V7/V8 restent séparées du verdict et de la projection non signée.

`/identities/reconciliation/simulate/` accepte des fixtures synthétiques AD/LDAP/Entra via formulaire ou JSON, avec session, MFA récente, CSRF et Identity/Connect actifs. Ce prévisualiseur ne contacte aucun serveur, n'applique aucune correspondance et ne retire aucun droit. Les nouvelles actions de suivi d'exception sont des formulaires natifs MFA/CSRF ; aucune API de dérogation n'est ajoutée.
