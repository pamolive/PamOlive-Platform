# W1 — livraison de source et limites de qualification

Cette tranche implémente localement le témoin d'usage d'[ADR-026](adr-026-independent-usage-anchor.md).
Elle ne livre aucun service W installé ou opérationnel, ni aucune remise de secret.
Le [contrat](p2-usage-anchor-contract.md) et le
[plan de validation réelle](p2-usage-anchor-validation.md) conservent leurs portes SQL/mTLS.

## Comportement implémenté

- Matériaux publics P0 lus depuis un artefact RO indépendant et vérifiés par le
  vérificateur V1 existant ; aucun DTO ou digest client ne fournit l'autorité W.
- Demandeur de l'intention fixé indépendamment dans le slot W. Un même identifiant
  d'intention et des signatures valides n'autorisent pas une autre personne.
- Activations WebAuthn fraîches, liaison de réservation V, baseline complète,
  contrôle des preuves V2 et chemin PostgreSQL pour compteurs, usages, terminal
  et audit atomiques. Les terminaux sont exclusivement `consumed_no_release` ou
  `refused_no_release`, avec un miroir SQL V séparé.
- Identité DER mTLS par connexion et quatre routes fermées. Le client émet des
  en-têtes explicites sans Accept-Encoding automatique ; le serveur n'est pas
  élargi pour accepter des en-têtes de provenance ou d'identité.
- Contrôle final des mutations Service après écritures et audit. Administration
  de fermeture/révocation distincte ; relecture terminale sous identité et contexte
  courants, sans nouvelle consommation. Aucun callback ne prétend garantir
  l'instant physique de durabilité du COMMIT.

Les bibliothèques partagées, modèles Django, chemins PAM existants, autorités P0,
preuves V7/V8 et données historiques ne sont pas modifiés par ce composant.
Aucun ancien slot W incomplet n'est enrichi automatiquement.

## Vérifications locales reçues

- Régression HTTP durable sur les vrais client, framing stdlib, h11 et parseur W :
  avant correctif, 62 tests avec un échec attendu ; après correctif, 62 réussites,
  zéro failure/error/skip et aucune tentative d'I/O externe. TLS, sockets,
  ordonnanceur et dispatch métier restent simulés pour ces essais.
- Les 59 méthodes précédentes restent présentes. Les signatures synthétiques
  sont réellement vérifiées ; elles ne prouvent ni des personnes indépendantes,
  ni une cérémonie navigateur/matérielle réelle.
- L'INSERT des opérations utilise maintenant une requête fixe, identique aux
  octets de l'ancien assemblage de constantes : 19 colonnes, 19 paramètres liés,
  même ordre des valeurs. Le signalement Bandit B608 initial ne démontrait pas
  une injection par l'appelant. Aucune exclusion du scanner n'a été ajoutée.
  Après ce delta, les 62 tests sont rejoués avec les mêmes résultats ; Ruff et
  Bandit runtime au seuil medium/high réussissent.
- Wheel construite hors ligne sur copie isolée, sous Windows : 29 701 octets,
  SHA256 `075bf607b57fe89d5b33b6b979d1f3ec6541e95b36444a70b2d9c2c30bbcb7a8`.
  Les 18 membres comprennent les 12 modules, le SQL W, la notice et les metadata ;
  sources et RECORD sont contrôlés. Aucun import ou installation de cette wheel
  n'est réalisé. La wheel précédente, antérieure au SQL fixe, reste historique.
- Déclarations de dépendances alignées sur le lock existant : psycopg 3.2.10,
  psycopg-c sous Linux et psycopg-binary hors Linux. La compilation et l'exécution
  du pilote dans une installation W Linux restent à recevoir.

La CI ajoute les 62 tests purs avec timeout et garde anti-I/O existante, et étend
le gate Bandit applicatif au runtime W. Les anciens contrôles restent conservés.
La CI du nouveau sujet devra être reçue ; ces essais locaux ne la remplacent pas.

## Installation et portes encore ouvertes

Les schémas SQL sont explicites, jamais créés par le runtime. W exige une base
neuve dédiée, un propriétaire de migration distinct et un rôle runtime restreint.
L'extension `sql/mirror.sql` concerne V : elle reste disponible dans le dépôt et
n'est pas installée par la wheel W. Aucune migration Django ni donnée existante
n'est modifiée pour cette livraison de source.

Avant réception fonctionnelle : deux nouveaux clusters PostgreSQL, rôles réels,
TLS/mTLS et DER réels, terminaux positif/négatif, permissions et contraintes,
isolation des organisations, concurrence, fencing, expiration, crash/retry,
perte d'ACK, rollback V, restauration et retour arrière synthétiques.
Le laboratoire préparatoire reste hors de cette livraison tant que sa capsule
et son cycle de vie n'ont pas reçu leur revue indépendante.

Deux bases sur un hôte ne démontrent pas l'indépendance de W face à un
administrateur commun. Deux hôtes et une garde de remise KMS indépendante
restent nécessaires aux garanties correspondantes. Aucun fournisseur KMS,
unwrap générique, secret, appelant Django ou nouveau chemin PAM n'est branché.
Les 35 groupes High et la provenance de build incomplète continuent à bloquer
la promotion main/image ; aucune action NAS n'est autorisée par cette tranche.
