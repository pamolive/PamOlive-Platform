# ADR-026 — Témoin synchrone des usages Vault V2

Statut : accepté pour implémentation le 15 novembre 2026, après confrontation
architecture/cryptographie et AppSec indépendante. Le service, ses transports et
sa durabilité ne sont pas encore réceptionnés. Aucune remise de secret autorisée.

## Problème et frontière de confiance

ADR-024 réserve un nonce, une opération et une expiration dans V, mais une tête
PAM fraîche ne démontre pas qu'une opération V2 n'a jamais été consommée. Une
restauration du ledger V sous la même incarnation, même avant 30 secondes, peut
restaurer un état local cohérent. L'anti-rejeu doit survivre à cette restauration.

Ajouter W, une autorité synchrone des usages et compteurs V2 dans le domaine du
témoin indépendant, avec stockage, identités, administration et restauration
distincts. Deux bases ou conteneurs sur le même hôte ne démontrent que la
séparation fonctionnelle N0 ; root, le superutilisateur du cluster ou un
restaurateur commun peuvent contourner cette frontière. La qualification sur
deux hôtes demeure exigée avant toute revendication correspondante.

## Alternatives examinées

| Modèle | Garantie et dépendance | Décision |
| --- | --- | --- |
| Contraintes, compteurs et audit dans V | Sérialise les appels honnêtes ; état restaurable avec V | Insuffisant contre le rollback de V |
| Export signé périodique | Détection ultérieure ; fenêtre de rejeu entre exports | Complément d'audit |
| Deux bases sur un hôte | Limite certaines erreurs et compromissions de processus | Banc N0, pas indépendance d'administration |
| W synchrone, SQL propre et compteurs uniques | Retient les usages malgré rollback V ; indisponibilité bloquante | Retenu |
| Quorum de témoins / compteur matériel | Étend la menace à W fautif ; exploitation et reprise complexes | Autre ADR si cette menace est requise |
| KMS/HSM seul | Protège des clés, ne connaît pas automatiquement l'usage métier | Futur point d'application, ne remplace pas W |

## Décision et tranche verticale

W reçoit sur un canal mTLS propre une réservation V déjà committée. Il vérifie
les matériaux publics P0 bruts depuis son artefact RO administré et son contexte
indépendant, sélectionne ses activations V2 et conserve baseline, FullTranscript,
hash et échéance immuables. Les contrats V2 et le vérificateur V1 existants sont
réutilisés ; aucun modèle Django ni résultat d'autorité déclaré par V ne devient
une autorité W. Le registre vivant et son policy/target réels font foi.

La tranche doit traverser V réservé → W mTLS/SQL → baseline/transcript W →
nouvelles confirmations V2 valides → consommation W → miroir V. Elle doit couvrir
les terminaux positif `consumed_no_release` et négatif `refused_no_release`,
avec de vraies signatures synthétiques, sans KMS, SDK d'enveloppe ni plaintext.
Ces terminaux ne deviendront jamais des permissions en activant une option.

Chaque mutation suit contexte → quota principal → lease → opération → activations
en ordre ASCII → audit. N0 sérialise les écritures par contexte tenant. Le CAS
compare toutes les versions et tous les compteurs du snapshot, y compris les
personnes absentes d'un refus partiel, avant les signatures et le commit. Les
compteurs inclus, usages, terminal, bundle exact et audit sont atomiques. Un refus
valide d'un reviewer/sponsor habilité suffit sans quorum positif ; tout membre
inclus invalide fait refuser le bundle entier sans effet partiel.

Le retry terminal exact renvoie la réponse initiale sans reconsommer les preuves.
Un autre body/bundle donne409 ; baseline stale donne409 sans quarantaine. Un
commit inconnu reste503/uncertain ; aucune compensation ne réarme un usage. Aucun
fallback legacy ou offline n'autorise une consommation si W n'est pas disponible.

Les nouveaux credentials sont dédiés au RP `confirm.pamolive.invalid`, inscrits
dans une chaîne P0 contiguë cosignée après enrôlement/possession, puis activés
avec un nouveau défi W. Une ancienne ligne de compteur SQL Web n'est pas une
baseline indépendante. Le profil0→0 est explicite et conserve un state_version
et une consommation durables, sans prétendre détecter un clone. Aucun credential
V2 n'est utilisé parallèlement dans les cérémonies vivantes P0. La réception de
la frontière de confirmation navigateur/OS est distincte de signatures simulées.

## Arbitrages contradictoires obligatoires

Il n'existe **aucune quarantaine automatique W1** : la bibliothèque WebAuthn peut
refuser un compteur avant de vérifier la signature. Une telle exception n'est
pas une preuve de clone et ne peut suspendre d'autres opérations.

La canonicalité byte-exacte s'applique aux nouveaux objets B/E/F et au wrapper
JSON d'assertion. **Elle ne s'applique pas au `clientDataJSON` signé décodé.**
Celui-ci est analysé strictement, sans doublons, avec bornes et champs fermés ;
challenge, origin et crossOrigin sont validés, puis ses octets originaux sont
transmis à la bibliothèque WebAuthn maintenue. Des ordres de propriétés ou espaces
signés valides ne sont pas refusés implicitement ; aucune réécriture avant
vérification. Deux sérialisations équivalentes exigent chacune leur signature.

`policy_binding_id` est un UUID de liaison administré W, pas une révision UUID
imaginaire dans la policy P0. La policy effective est reconstruite des seuils
signés, de la cible et de minima indépendants qui ne peuvent que renforcer.
W1 active un contexte synthétique sans contrat ; contrat non vide ou champ
policy/target inconnu ferme le bind. Ce périmètre ne remplace pas le moteur
Governance et ne migre aucune cible existante en écartant ses contrôles.

Le nonce peut circuler dans W0/confirmation authentifiés où il est nécessaire.
Il reste absent des logs publics, erreurs et réponses terminales. `authorized:false`
décrit le résultat ; l'absence structurelle de route/provider de remise est le
contrôle effectif.

## Restauration, compatibilité et limites

W garde les tombstones ; expiration ne supprime pas une clé consommée. Restaurer
V ne restaure pas W. Une reprise déclarée fence la lease et change le slot V sans
réinitialiser les compteurs W. W restauré ne s'ouvre jamais automatiquement :
continuité durable vérifiée hors sauvegarde, nouvelle incarnation et invalidation
des anciennes leases ; si les compteurs ne sont plus fiables, réactivation
indépendante requise. Le rollback clandestin de W et la collusion V+W restent
hors de cette garantie, explicitement.

Un V compromis disposant d'un unwrap KMS générique peut ignorer W. Avant remise,
une garde indépendante devra imposer chaque usage W avec claim d'émission unique,
tenant/destination/broker/version/certificat exacts et aucun chemin générique
accessible à V. W1 ne crée pas ce service et ne revendique pas sa garantie.

P0-1 à P0-4, vérificateurs V1, preuves V7/V8, Fernet et ancien chemin PAM restent
préservés. Aucune migration automatique de secrets, de credentials ou de
compteurs existants. Les 35 groupes High et la provenance de build incomplète
continuent à bloquer main/image ; cet ADR ne les arbitre pas.

## Contrats et validation

Les octets, tailles, états, sources, verrous et HTTP sont normatifs dans
[le contrat W1](p2-usage-anchor-contract.md). Les cas complémentaires sont dans
[le plan de validation](p2-usage-anchor-validation.md). Exiger tests purs, vraies
signatures, rôles PostgreSQL restreints, mTLS/DER par connexion, concurrence,
révocation/fencing, commit perdu, crash, idempotence et rollback V dans30s.
Les succès unitaires ne réceptionnent ni durabilité, ni origine humaine, ni
indépendance d'hôte. La qualification installée ADR-025 reste une porte distincte.

Filiation locale conservée : proposition architecture `fb1bcf5b…`, addendum
`94257dc0…`, revue AppSec `9c932c70…`. La revue clôt A–E au niveau conception,
avec la précision clientDataJSON ci-dessus ; aucun test SQL/TLS/signature du
nouveau service n'a encore été exécuté à cette décision.
