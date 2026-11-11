# ADR-015 — Contrat transverse de lecture des accès, version 1

Statut : réalisé dans le périmètre local P1-A/P1-B1 autorisé. Aucun nouveau service, schéma SQL, droit d'exécution ou format de preuve P0 n'est créé. Cette décision réutilise ADR-013/014 et leurs frontières de confiance.

## Problème et choix

Une intention approuvée, un droit local et une confirmation fournisseur sont actuellement stockés dans des domaines distincts. Les lire comme un unique état « accordé » inventerait une garantie. Nous ajoutons une projection JSON bornée `pamolive.access-contract/1`, commune à l'écran, à l'API de session et à l'export. L'autre option, un nouveau modèle de workflow et une seconde file, dupliquerait les mécanismes existants et demanderait une migration sans nécessité pour ce lot.

Le contrat est une lecture courante **non signée**, avec des références aux preuves existantes. Il ne devient ni une attestation indépendante ni une autorisation de connexion. Les modèles métier, écritures et formats V7/V8 restent la source des faits. L'agrégat racine est une `AccessIntent` résolue dans son organisation ; aucun rapprochement par nom, e-mail, compte ou ressource n'invente une association.

## Correspondance produit et code

La table versionnée `pamolive.product-modules/1` de `platform_core/product_modules.py` formalise la taxonomie ; le registre technique existant conserve seul l'autorité d'activation.

| Produit | Modules techniques | Périmètre actuel |
| --- | --- | --- |
| Identity | identity | Identités, comptes, droits, mobilité |
| Governance | governance, approvals, recertification | Politiques, décisions, revues |
| Privilege | access, pam | Mandats, registre, baux et relais de laboratoire |
| Vault | aucun module autonome | Conception ; stockage technique chiffré existant distinct |
| Observe | access, intelligence | Faits, évaluations, graphe et couverture |
| Connect | connectors | SCIM, TeamViewer et interfaces métier |
| Audit | noyau partagé | Chaîne par tenant et preuves historiques |
| Machine | identity, intelligence | Inventaire intégré partiel et certificats |
| Cloud | aucun | Cible ultérieure |
| Defense | aucun | Cible ultérieure |
| Posture | aucun | Cible ultérieure |

Une liste vide n'active aucune capacité ; `Audit` est un service du noyau, pas un module fictif à installer. Les huit applications Django existantes ne sont pas renommées.

## Sémantique des sections

| Section JSON | Source et garantie |
| --- | --- |
| intention | AccessIntent : statut et périmètre demandés, dates et justification |
| requested_right | Droit demandé ; aucune confirmation fournisseur |
| approval_decisions | Décisions enregistrées ; une décision n'est pas une exécution |
| local_grant | Grant lié explicitement ; état local, sans attribution externe présumée |
| provisioned_right | Effets add/remove issus de preuves d'exécution confirmées, jamais du seul statut succeeded |
| execution_attempts / confirmed_executions | ExternalChange et ExecutionEvidence, origine référencée, tentative et date ; ne décrivent pas l'inventaire actuel du fournisseur |
| pam_sessions | Bail local et état de relais, sans déduire du bail une connexion distante |
| observations | Référence explicite par évaluation V7 vérifiée, faits source et statut de provenance V8 séparés de la conformité |
| evidence | Références de preuves déjà existantes ; aucun payload fournisseur arbitraire ni secret |

Les collections portent `availability`, `items`, `truncated`. Une section indisponible ne signifie pas absence d'activité. Une lecture tronquée ne signifie pas inventaire complet. La limite est comprise entre 1 et 100. L'organisation et la version du contrat sont explicites.

## Autorisation et désactivation

Le service vérifie le contexte tenant, l'organisation active et un compte actif avec rôle admin/operator/reviewer/auditor. L'organisation est verrouillée, puis le compte et ses permissions sont relus pour ne pas conserver une autorité révoquée pendant l'attente. Identity et Access doivent être disponibles, dépendances comprises. Les données opérationnelles Approvals, Connect et PAM sont interrogées uniquement si leur capacité est disponible ; sinon les sections sont marquées indisponibles. Le contrat masque les observations de collecteurs/internal lorsque Connect est indisponible. Les routes UI, API et export appellent ce même service ; elles sont GET, sans cache et sans mutation.

**Désactiver une capacité n'efface pas l'histoire ni les contraintes de sécurité.** Les preuves Access/Audit déjà conservées restent accessibles sous les permissions de leur domaine propriétaire, notamment par les exports historiques existants. Les évaluations de sécurité publiées, l'expiration, les révocations et les retraits obligatoires continuent. Cela ne réactive ni un connecteur, ni une attribution, ni un vote. Les nouvelles actions d'attribution, vote et revue exigent leurs modules et une autorisation relue sous verrou. Les notifications d'un émetteur technique enregistré et les consommateurs asynchrones sont soumis à l'activation de leurs capacités et dépendances.

L'accès au secret reste dans la frontière applicative P0 existante ; la projection exclut tokens, clés, ciphertexts, configuration de cible et payload `observed` non filtré. Aucun nouveau pouvoir de déchiffrement n'est ajouté. Le verrou d'organisation donne une lecture cohérente avec les écrivains qui partagent ce protocole ; il n'est pas une qualification de débit et peut entraîner de la contention avec le PAM.

## Interfaces et compatibilité

- UI : `/access/intents/<uuid>/contract/`.
- Export : `/access/intents/<uuid>/contract/export/`.
- API de session : `/api/v1/access-contracts/<uuid>/` ; aucune nouvelle clé Bearer n'est créée.
- Service : `build_access_contract(intent_id, actor=..., organization=..., limit=100)`.

Le contrat ne remplace pas les exports V7/V8. Les nouveaux champs sont additifs dans la version 1 ; modifier leur sens ou retirer une section demande une nouvelle version et ses tests de consommateurs. Aucun changement de schéma n'est requis ; les migrations P0 restent intactes. Le retour arrière du code P1 ne rend pas possible un retour aux anciens binaires pré-P0-4 contre une base contenant les nouveaux espaces d'événements.

## Vérification

Tests service/API/UI/export pour deux tenants, rôle absent, compte désactivé, dépendances désactivées, collections bornées, absence de secrets et faux succès fournisseur. Tests PostgreSQL à connexions distinctes pour désactivation/révocation pendant une lecture, publication et actes d'autorité. Tests de pause/reprise d'un consommateur sans perte de file et de maintien des expirations de sécurité. La revue indépendante et les résultats sont consignés dans le bilan P1-A/P1-B1.
