# P1-C — Identity 360° et réconciliation synthétique

Le lot ajoute une lecture transverse `pamolive.identity360/1`, sans nouveau modèle ni migration. Il réutilise Identity, ExternalAccount, Grant, Resource, Credential, les décisions de mobilité attestées et l’audit existant. La fiche distingue personnes/prestataires et identités non humaines, comptes, droits locaux, ressources et leurs responsables, rôles métier issus d’une mobilité vérifiée, groupes configurés, références de source et chronologie JML. Une section bornée indique explicitement sa troncature.

## Lecture et confiance

Les routes `identities/360/`, `identities/360/<uuid>/`, `api/v1/identities/<uuid>/360/` et l’export JSON partagent les services. Le rôle organisationnel admin/operator/reviewer/auditor est exigé avec compte et organisation actifs. L’autorisation est rechargée sous verrou d’organisation, avant toute requête métier ; le contexte tenant est obligatoire. Le module Identity doit être activé. Les demandes d’accès sont indisponibles si Access est désactivé ; les correspondances de source/groupe sont indisponibles si Connect ou ses dépendances sont désactivés. Aucun de ces domaines désactivés n’est interrogé par la projection. Les surfaces de lecture sont GET uniquement, `no-store` et `nosniff`.

La fiche est non signée. Un rôle métier n’est présenté comme vérifié que si sa révision et la décision de mobilité passent leurs vérificateurs existants. Une preuve invalide ou référence absente donne `unverifiable`, sans adoption de contenu arbitraire. Aucun rôle IAM, compte ou rapprochement e-mail ne crée d’attestation d’identité PAM, de membre du registre P0-3 ou d’autorité de collecteur.

Un droit local ne confirme pas son exécution distante. Une correspondance SCIM/groupe est une référence configurée, pas une observation d’appartenance. Le parcours P1-B1 reste le lecteur demande/décision/exécution/observation/preuve. Les propriétaires sont du texte déclaré, sans attestation d’une personne responsable. Aucun token, ciphertext, clé privée, configuration d’URL ou payload fournisseur brut n’est projeté.

## Comptes sans responsabilité active et JML

ExternalAccount impose une identité non nulle par FK. Le signalement d’un compte « orphelin » couvre donc précisément un compte **actif** associé à une identité inactive, ou une identité non humaine sans propriétaire déclaré (chaîne vide ou espaces). Il ne prétend pas trouver tous les comptes d’un annuaire distant ni prouver une responsabilité humaine indépendante.

La création locale, les changements d’état et décisions de mobilité apparaissent dans la chronologie. Les formulaires existants de création, préparation/revue de mobilité et départ restent les seuls chemins d’écriture. Une mobilité crée des demandes selon ses contrôles habituels ; elle ne transforme pas une approbation locale en exécution confirmée. Un départ ne signifie pas que tous les retraits sont confirmés. Le suivi opérationnel des retraits reste dans les changements/proofs existants et le cockpit Governance. Aucun nouveau chemin de délégation, réinitialisation MFA ou provisioning n’est créé.

La revue contradictoire a reproduit un défaut préexistant de publication de rôle : un compte désactivé et privé de son statut superuser en base conservait son autorité à travers un objet Python périmé, et pouvait publier une révision signée. Le garde JML recharge maintenant acteur et organisation via `lock_authorized_actor`, après verrou, puis vérifie modules et MFA ; les quatre points d’entrée réutilisent ces objets frais. La publication d’un rôle, la proposition et la décision de mobilité, ainsi que l’autorisation d’une demande issue d’une mobilité, conservent leurs vérifications de personne, approbation et preuve existantes. Aucun format d’attestation n’est changé.

## Simulateurs AD, LDAP, Entra ID

`identities/reconciliation/simulate/` fournit un formulaire et un POST JSON de session, avec MFA récente, CSRF et activation Identity+Connect. Il ne possède aucun client réseau, URL, mot de passe ou fonctionnalité d’application. Il compare des fixtures déclarées synthétiques avec une correspondance **explicite** UUID distant → UUID du compte local. Cette correspondance n’est pas enregistrée et ne devient pas une preuve d’identité.

| Adaptateur | Identifiant stable | Login | État booléen | Groupes |
| --- | --- | --- | --- | --- |
| `ad` | `objectGUID` | `sAMAccountName` | `enabled` | `memberOf` |
| `ldap` | `entryUUID` | `uid` | `enabled` | `memberOf` |
| `entra` | `id` | `userPrincipalName` | `accountEnabled` | `groups` |

Les quatre propriétés exactes sont requises. Les identifiants UUID sont canonisés ; les noms restent des données de comparaison, jamais des clés de rapprochement. Les identifiants distants dupliqués sont refusés. Des logins identiques sur deux objets distincts imposent une revue humaine ; aucun rapprochement automatique n’est effectué. Une correspondance étrangère au tenant est refusée sans divulgation du compte. Les espaces de source sont inclus dans l’empreinte du scénario ; réutiliser le même UUID dans deux sources ne crée pas une identité globale.

Exemple JSON exclusivement synthétique (remplacer l’UUID local par celui d’un compte du laboratoire) :

```json
{
  "provider": "ad",
  "source_id": "synthetic-ad-A",
  "synthetic": true,
  "records": [{
    "objectGUID": "00000000-0000-4000-8000-000000000001",
    "sAMAccountName": "fixture-account",
    "enabled": true,
    "memberOf": ["Readers"]
  }],
  "mapping": {}
}
```

Le contrat `pamolive.directory-reconciliation-preview/1` marque `can_apply=false`, `read_only=true` et une provenance de fixture déclarée par l’appelant. Un objet absent d’une fixture peut simplement manquer dans un extrait incomplet : il demande une revue, jamais un retrait automatique. Les groupes sont comparés littéralement aux droits locaux actuellement valides, sans résolution de DNs ni calcul de droits effectifs. L’empreinte SHA-256 versionnée sert à identifier le scénario, sans signature ni preuve de réception P0-4.

Le service accepte au plus 1000 lignes et 32 groupes par ligne ; la lecture de droits est plafonnée à 32000 lignes et refuse au-delà. Le formulaire borne chaque champ JSON, et le corps HTTP est limité à 128 Kio. La longueur déclarée est validée avant la reprise MFA : syntaxe décimale ASCII canonique bornée, aucune valeur négative, signée ou avec zéro initial ; une syntaxe invalide retourne 400 et un volume excessif valide retourne 413. La revue Red Team a fait ajouter ce refus pour éviter une erreur 500 sur un en-tête malformé. Les sorties ne recopient pas les champs inconnus d’un JSON invalide. La limitation de ressources reste une protection de base ; un contrôle de débit global au frontal constitue un gate d’exploitation séparé.

## Validation et limites

Les tests `test_identity360` couvrent contrat/UI/API/export, rôles, compte périmé, contexte, deux organisations, modules désactivés sans requête au domaine, troncature, temporalité des droits, preuves de mobilité, champs sensibles, trois simulateurs, doublons et incertitude, absence de mutation, MFA/CSRF, tailles et en-têtes malformés sur GET/POST. `test_identity360_concurrency` vérifie sur PostgreSQL quatre courses réelles : désactivation Identity, révocation d’appartenance, désactivation du compte et désactivation Connect pendant l’attente du lecteur. `test_mover_authority` ajoute les refus d’acteurs/organisation périmés, le maintien de la MFA, les propositions/décisions JML après désactivation, et trois courses de publication (rôle, compte et module).

Validation dédiée du 11 novembre 2026 : **48/48 PostgreSQL réussis en 45,058 s**, aucun ignoré (les trois suites P1-C et la suite de régression Mover existante) ; **27 réussis et 7 courses explicitement ignorées sur SQLite en 1,720 s** (34 tests des trois suites P1-C). Ruff ciblé est vert. Bandit sur les quatre nouveaux modules, seuil moyen/haut, retourne 0 sans constat à ce seuil. Les bases de tests sont détruites en fin de campagne. La campagne intégrée, la revue indépendante et la CI hébergée restent consignées séparément dans le rapport coordonné ; ces tests dédiés ne les remplacent pas.

Ce lot ne qualifie ni protocole LDAP, ni Graph Entra, ni AD réel ; tout transport/authentification/source persistante nécessitera le lot Connect et une autorisation d’accès spécifique. Aucune donnée historique ni signature V7/V8 n’est réécrite. Le rollback de P1-C seul n’exige aucun changement SQL et ne rend pas possible un downgrade pré-P0-4.
