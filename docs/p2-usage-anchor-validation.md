# Plan de validation W1 — réception réelle restant à exécuter

## Wheel W1 installée — 18 novembre 2026

La [CI installée](https://github.com/pamolive/PamOlive-Platform/actions/runs/44302067191)
du commit `de63044` construit la wheel W1 séparément et vérifie les 18 entrées
de l'archive, le `RECORD` installé et la relocalisation SQL. Les trois wheels
Vault conservées dans le transfert historique servent de base au consommateur.
Les 62 tests W1 existants passent depuis le paquet installé, sans échec,
exclusion ni tentative d'I/O externe. Le reçu public SHA-256
`e7d31f341396914841efeca051788fb9d61ddc09c6119941a66decf2a5b2431a`
est lié à la [PR nº 34](https://github.com/pamolive/PamOlive-Platform/pull/34).

Le profil W01 réserve six conteneurs et cinq volumes de fixtures. Les deux
clusters PostgreSQL utilisent chacun leur PGDATA dédié. Les deux précontrôles
de clusters vierges doivent être acceptés avant la première écriture. Les 21
tests de propriété des ressources, les 19 tests du provisionnement sous
doublures et les 13 régressions Vault passent. Le commissionnement réel,
les deux terminaux durables et leurs reprises, les rôles PostgreSQL et le mTLS
entre processus attendent la campagne W01. Les limites de 30 s et 40 s restent
celles du contrat existant.

## Plan des campagnes restantes

Source W1 implémentée localement. La régression HTTP a été exécutée sur
62 tests purs avant correction, avec un échec attendu, puis sur 62 tests après
correction sans failure, error, skip ni tentative d'I/O externe. Les 59 méthodes
existantes sont conservées ; les signatures synthétiques sont réellement
vérifiées. Ces résultats ne réceptionnent ni SQL/mTLS réel, ni service W installé,
ni durabilité, ni origine humaine ou indépendance d'hôte.

La tentative initiale du runner, alors bloquée par psycopg absent, conserve son
résultat historique 0 test reçu ; elle n'est pas réécrite par les réceptions
locales ultérieures. Les cas ci-dessous complètent les 24 scénarios du gel fb1b et
supplantent les attentes de quarantaine. Les golden restent des oracles statiques
de codec ; leurs placeholders ne deviennent pas des signatures autoritaires.
Les essais de laboratoire SQL/mTLS/concurrence restent à réaliser.

| Cas supplémentaire | Essai à réaliser avant réception | Résultat requis |
| --- | --- | --- |
| A01 Erreur compteur avant signature | Vraie fonction webauthn3.0.1 avec doubles comme AppSec, puis véritable signature synthétique dans campagne séparée |9→9/8/0 refus générique ; exception n'est pas étiquetée signature valide ; aucune quarantaine/activation/counter modifiés |
| A02 Ordre global | Inventaire de tous chemins, puis deux workers+admin sur vrai SQL | Contexte→quota→lease→op→activationsASCII→audit, même pour premier INSERT, révocation et audit négatif ; aucun lock de localisation inverse ; classer aussi triggers/FK/uniques |
| A03 Concurrence légitime | A5 et B6 partent de4/v1, B commit avant A | A409stale sans quarantaine ; état B terminal ; aucun avancement A ni compensation |
| A04 Refus unique | Un seul reviewer.refuse habilité du draft, aucun requester.launch ni quorum d'approbation |200 refused_no_release authorizedfalse, seul compteur/challenge de ce membre consommé ; bundle/hash/terminal/audit atomiques |
| A05 Sponsor refuse | Sponsor exact de la cible/draft, un refus valide seul | Même terminal ; un faux sponsor, requester/refuse ou alias requester échoue403 sans effet |
| A06 Tous inclus valides | Refus valide accompagné d'une approbation à mauvaise signature ou mauvais rôle |403générique, aucun membre committé, état encore pending ; pas de fermeture globale ou suspension |
| A07 Mixte négatif complet | Refus plus plusieurs approbations/launch tous valides | Tous les membres inclus consommés atomiquement, terminal négatif ; absents inchangés ; personne canonique jamais double voix |
| A08 Zéro et multi-rôles | Reviewer.refuse et sponsor.sponsor même credential0→0, challenges distincts | Deux usages/challenges, un state_version avancé et compteur0 ; terminal refusé ; rejoue même bundle statut seulement |
| A09 Nonzéro multi-rôles | Compteurs5,6 sur baseline4, rôles différents ; inverser les membres reçus hors ordrecanonique | Bundle canonique traité numériquement5puis6 ; écriture finale6 ; ordre externe noncanonique400 ; doublon de nonzéro403sans effet |
| A10 Terminal retry négatif | Perdre réponse après commit réel W ; retry exact, enlever/ajouter/remplacer un membre ensuite |200 même réponse canonique originale sans appeler vérificateur compteur ; variante409 ; jamais pending/positif/release |
| A11 Terminal ancien | Réessayer après expiry/leaseclose avec identité actuelle autorisée à observer |200statut terminal exact sans prolongation ; client non autorisé403 ; aucun bypass de mapping d'observation |
| A12 Baseline absents négatif | Snapshot d'un membre non inclus dans le bundle négatif devenu stale |409stale sur snapshot global, aucun terminal ni compteur ; pas d'acceptation partielle ni recalcul |
| A13 Artefact RO et pin | Changer un rawdoc, cp, ordre, longueur, suffixe, identitéfile/parent, lien symbolique, pin ou contexte V1 | Refus fermé avant liaison ; W reconstruit/hash les bytes locaux et vérifie API V1 ; digest client/DTO insuffisants |
| A14 Bornes corpus |1/256docs,2MiB/doc,32MiBsum,65536cp puis +1/troncature/overflow/count0/257 | Bons budgets acceptables au codec, mauvais refus avant allocation/parsing excessif ; aucune chaîne32MiB dans bindHTTP |
| A15 Sources policy/credential | JSON V forge policy_revision/hash/seuil/sponsor/credentialversion live, registry cibleabsente ou bootstrapseul | Refus par comparaison au slot et aux vrais champs signés ; jamais approvedtrue/HMAC ; vrai required_reviewers calculé, aucun seuil tronqué |
| A16 Contrat requis | target.contract_id non vide, même si V affirme no contract | W1 refuse bind : profil contrat non reçu ; aucun abaissement d'obligation P0 |
| A17 Golden byte exact | Comparer assembleurs futurs aux préimages/hashes statiques GOLDEN-CODEC | Aucune régénération des attendus avec code produit ; changements membre/ordre/framing/domaines visibles ; placeholders restent non autoritaires |
| A18 Canonicalité | Duplicatekey/clééchappée/whitespace/nullouter/boolouter/float/paddingbase64/idrawIddiff/fieldunknown |400structure avant vérification ; WebAuthn userHandle null/crossOriginfalse seulement aux emplacements documentés ; E/B/F nouveaux budgets distincts d'ADR022 |
| A19 Nonce autorisé | W0 mTLS authentifié et canal de confirmation approuvé vs appel anonyme/erreur/log/terminal-status | Transcript complet avec nonce présent pour recalcul du challenge autorisé ; nonce absent des surfaces publiques ; aucun secret ni capacité implicite |
| A20 Crash atomique refus | Crash réel avant/après commit négatif, SQL conservé et puis rollbackV même incarnation dans30s | Avant : aucun compteur/terminal partiel ; après : refusedterminal conservé et retry statut seul ; aucune réactivation ni nouveau nonce |

## Régressions R2 obligatoires sur le laboratoire réel

- Même intention ID/hash, demandeur substitué, quatre signatures synthétiques
  encore valides : bind403 avant toute transaction. Slot sans le pin W-only
  du demandeur : refus, sans migration implicite du contexte partagé.
- Sur les chemins `Service` passant par `PostgresLedger.transaction`, dépasser
  l'échéance après l'audit mais avant le contrôle final : rollback des
  compteurs/usages/terminal/audit. Mutation enregistrée sans callback : rollback.
  Le retry pending garde son contrôle final. La fermeture/révocation admin
  hors ligne garde son circuit distinct et reste utilisable après expiration.
- Retry terminal ancien : réponse conservée sans mutation ni nouvelle
  vérification des preuves/compteurs/fraîcheur d'admission ou callback mutateur ;
  DER/purpose courant, slot/principal valide, contexte/tenant/propriétaire,
  instance et bundle/hashes exacts restent contrôlés.
- Perdre l'ACK après le contrôle final :503/uncertain, puis statut idempotent ;
  ne pas attribuer au callback une garantie de durabilité physique à l'heure.
- Sous rôle réel, prouver que les probes refusées annulent aussi un succès
  SQL inattendu ; distinguer trigger monotone positif1→0/P0001 et plage23514.
  Vérifier trois formes terminales incomplètes par contraintes réelles.
- Préflight indépendant des deux bases W/V fraîches avant seeding : les deux
  commits ne sont pas atomiques ; seed partiel reste non admis, sans réparation.

La tranche suivante doit réaliser le trajet V réservé → W réel mTLS/SQL propre → baseline et transcript W → nouvelles confirmations V2 synthétiques → terminal positif **et négatif** W → miroir V, sans secret. Elle doit produire des observations SQL directes sous rôles réels, contrôles DER par connexion, concurrence/admin, crash/retry, expiryattendue et rollbackV ; aucun lot de DTO ou mock de commit ne suffit à son reçu. Les limites OS/mêmehôte, humanité indépendante des fixtures, garde KMS et restauration W restent des portes séparées.


## C01 — interopérabilité signée

A18 vise la canonicalité des wrappers E/B/F et du wrapper d’assertion. Ajouter
deux clientDataJSON sémantiquement équivalents avec ordre/espaces différents,
chacun signé validement : tous deux doivent être vérifiables sur leurs bytes
originaux. Aucun parseur ne doit les réécrire ou exiger leur recanonicalisation.
Un doublon, une mauvaise valeur ou une signature de l’autre sérialisation refuse.
