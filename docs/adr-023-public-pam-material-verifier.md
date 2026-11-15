# ADR-023 — Vérification indépendante des matériaux publics PAM V1

15 novembre 2026. **Acceptée pour P2-R1b.1, bibliothèque sans autorité de remise.**
La réception installée et les revues du candidat concret restent obligatoires.
Cette décision complète [ADR-020](adr-020-isolated-vault-envelope.md) et
[ADR-022](adr-022-vault-operation-contract.md), sans modifier P0 ni ses appelants.
Périmètre N0, données synthétiques, aucun NAS ou compte privilégié réel.

## Problème et alternatives

Le futur Vault doit vérifier des preuves sans importer Django, ses réglages,
ses accès SQL ou une déclaration d'approbation du frontal. Les formats
d'opération existants ne vérifient aucune autorité. Importer tout le chemin
P0 mêlerait règles publiques, consommation d'enrôlement, compteurs et mutations.

| Modèle | Garantie et limite | Décision |
| --- | --- | --- |
| Booléen, résumé ou HMAC fourni par Web | Même autorité que le frontal compromis | Rejeté |
| Import des services Django dans le Vault | Réutilisation courte, dépendances SQL/configuration et doubles consommations non résolues | Rejeté pour cette tranche |
| Nouveau service complet immédiatement | Exigerait simultanément mTLS, contexte commissionné, compteurs, ledger, KMS et reprise | Différé |
| Bibliothèque pure vérifiant seulement registre/checkpoint publics | Sépare les règles publiques, conserve les octets V1 ; ne fournit aucune permission métier | Retenu |

## Contrat retenu

`components/pam-trust-verifier`, distribution `pamolive-pam-trust-verifier`,
expose deux familles distinctes : vérification archivale d'une chaîne et
inspection de matériaux courants avec checkpoint et heure UTC explicites.
Les entrées sont des octets et un contexte immuable construit par l'appelant.
Aucun fichier, URL, découverte de clé, variable applicative, SQL ou réseau
n'est accepté par l'API. Les primitives maintenues Ed25519, WebAuthn et COSE
sont réutilisées ; aucun algorithme cryptographique nouveau n'est introduit.

Le contexte doit venir d'un provisionnement indépendant de la requête :
installation, organisation, génération, révision, engagement de tête et clés
externes attendus. La bibliothèque ne réalise pas ce provisionnement ni son
administration, distribution, rotation ou stockage anti-retour arrière.
Restaurer ensemble preuve et contexte depuis le même backup ne rétablit pas
une fraîcheur indépendante.

La chaîne commence au bootstrap et reste contiguë dans l'ordre fourni ; ni
suffixe, tri SQL implicite ou comparaison lexicale des générations. Les cinq
tables de propriétaires historiques persistent à travers un recommissionnement.
Éligibilité des anciens dépositaires, exclusion des personnes affectées,
signatures de commissionnement et checkpoints sont contrôlées explicitement.

Les corps signés V1, champs inconnus, Unicode NFC/NFD distincts, domaines et
engagements des deux cartes de signatures sont conservés. L'égalité historique
des révisions de checkpoint accepte une valeur flottante ou booléenne
**correctement signée** équivalente ; révisions de registre et contexte restent
des entiers stricts. Les bornes de parsing/sérialisation et un TTL courant
éventuellement plus court constituent un profil supplémentaire documenté,
sans déclarer corrompues les archives P0 situées hors de ce profil.

Les résultats sont des DTO immuables constructibles en Python. Ils ne sont pas
des capacités : aucune preuve de possession, MFA, indépendance des personnes,
action V2, habilitation live, compteurs, anti-rejeu durable ou permission de
remettre un secret ne découle du type ou d'un résultat favorable. Aucune
fonction du Vault ou du broker ne reçoit ce seul résultat comme autorisation.

## Compatibilité et qualification

Aucun modèle, migration, clé, capture, preuve V7/V8, signataire, dépendance
runtime Web ou chemin legacy n'est modifié. Aucun ancien document n'est
réécrit ou resigné. L'identifiant d'installation opaque de P0 n'est pas converti
en UUID Vault ; leur future liaison doit être commissionnée indépendamment.

La duplication bornée des règles publiques est temporaire et explicite :
matrice de correspondance, oracles signés statiques, cas adverses et témoin
figé de fonctions P0 servent aux comparaisons. Ils ne prouvent pas les effets
SQL, l'enrôlement ou le cycle complet d'autorisation. Le parseur de dates
adapté conserve sa notice BSD Django ; les fixtures de projet sont publiques
et synthétiques, sans clé privée persistée ni générateur exécuté en CI.

Le coordinateur accepte leur diffusion avec le code sous la licence
AGPL-3.0-or-later du projet, avec leurs notices et attribution conservées.
Cette acceptation de la proposition `FIXTURES-NOTICE.md` ne supprime aucun
droit de tiers et n'est pas une qualification des identités simulées.

La réception comprend revue AppSec/cryptographique indépendante, trente tests
de bibliothèque installée hors sources, zéro exclusion, bornes adverses,
origines/distributions minimales et `pip check`. Treize wheels publics
exactement hashés ferment les matériaux de qualification ; l'audit de leurs
versions reste distinct de la qualification du wheel produit.

L'acquisition HTTPS explicite précède une exécution Linux sans réseau, nonroot,
rootfs/entrées RO, capacités nulles, NNP et ressources bornées. Les tests
vérifient les origines installées et les tentatives d'IO avant import du package.
Les hooks Python ne sont pas un confinement natif. Les rapports doivent être
exportés avant disparition du tmpfs, avec nettoyage borné des seuls objets
possédés ; un état inconnu reste inconnu. Un succès ne qualifie ni le build de
la base, ni son attestation, ni un service P2 ou la production.

## Suite et récupération

Le lot suivant doit traiter séparément le contexte commissionné et les preuves
d'action liées au transcript V2, puis les compteurs et le ledger transactionnel.
La remise réseau, le KMS, la fermeture réelle des transports et la résistance
à Web compromis nécessitent leurs propres essais intégrés. Le chemin existant
reste explicite jusqu'à qualification de sa migration. Retirer cette nouvelle
bibliothèque sans appelant n'exige aucune restauration de données ; aucune
capacité ou secret ne doit avoir été créé par sa présence dans le dépôt.
