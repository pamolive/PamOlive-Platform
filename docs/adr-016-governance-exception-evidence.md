# ADR-016 — Justifications d'exception sans dérogation exécutable

Date : 11 novembre 2026. Décision locale P1-D, publication en PR de revue.

## Problème et alternatives

Governance doit suivre les exceptions et leurs mesures compensatoires sans réintroduire un chemin permettant de contourner les destinations P0-2, le registre PAM P0-3, la provenance P0-4 ou les règles SoD existantes.

Un simple commentaire mutable ne conserve pas une décision vérifiable. Une exception qui désactive un contrôle à l'exécution introduirait une nouvelle autorité d'accès, exigerait une gouvernance indépendante et n'est pas autorisée par ce lot. La solution retenue est un registre durable **non dérogatoire** : il constate une justification et sa revue ; il n'est consulté par aucun moteur pour accorder un accès ou ignorer un refus.

## Décision

`ExceptionCase` et `ExceptionDecision` utilisent les preuves immuables et ancres d'audit du noyau, avec espace de signature versionné `pamolive.governance.exception/1`. L'organisation, le véritable acteur, les faits et l'assurance MFA récente sont scellés. La demande expire dans trente jours au maximum. Un autre compte reviewer/admin décide ; le demandeur ne peut approuver sa propre demande. Une clôture anticipée et l'expiration bornent le suivi. Aucune identité IAM ou revue de risque ne commissionne une autorité du registre PAM.

Les permissions, l'activité du compte et le module Governance sont revalidés sous verrou d'organisation. PostgreSQL interdit la réécriture/suppression, les références entre organisations et les doubles décisions ; le service vérifie en plus les signatures, l'état, les rôles et la fraîcheur MFA. Ces contrôles applicatifs ne protègent pas contre un propriétaire PostgreSQL ou une clé applicative compromis. Deux comptes distincts ne prouvent pas deux personnes indépendantes : cette limite est exposée et n'affaiblit aucun quorum PAM puisque le registre n'accorde aucun droit.

Le catalogue requestable est dérivé des révisions de rôles métier signées. Un groupe distant configuré, un droit local ou une justification acceptée ne devient pas automatiquement une habilitation demandable. Les opérations de retrait continuent d'utiliser la destination enregistrée et leur confirmation historique distincte.

## Migration, récupération et conséquences

`governance.0003_exception_register` ajoute deux tables vides, contraintes et fonctions/triggers appartenant au rôle dédié du schéma. Aucun ancien fait n'est modifié. Le plan contrôlé accepte explicitement cette migration ; ses empreintes sont examinées avec le reste de la livraison. Un superuser PostgreSQL n'est pas requis.

Retour arrière permis seulement avant toute preuve d'exception. Dès que le registre est peuplé, un downgrade destructeur est refusé : préparer restauration isolée, clés et audit cohérents, réconciliation et décision d'exploitation. Les gardes de rollback P0-4 restent indépendantes. Les anciennes installations n'ont pas besoin d'un IdP externe pour consulter le registre ; sa revue utilise l'authentification MFA locale existante. Aucun mécanisme d'urgence ne transforme une justification en autorisation.

## Vérification

Les attestations d'exception utilisent le mécanisme du noyau fondé sur `PAMOLIVE_ENCRYPTION_KEY`. Conserver sa valeur exacte avec les données et sauvegardes ; le trousseau `PAMOLIVE_EVIDENCE_VERIFICATION_KEYS` concerne V7/V8 et ne permet pas de tourner cette clé d'attestation. Aucune rotation ni re-signature automatique de ces preuves n'est livrée.

Tests dédiés : demande/revue/clôture/expiration, MFA/CSRF, auto-revue, SoD toujours refusée malgré suivi accepté, absence d'interprétation comme droit, isolation, désactivation et révocation concurrentes, double revue, gardes SQL, migration aller/retour vide et refus du retour peuplé. Revue indépendante IAM/IGA et Red Team, campagne PostgreSQL restreinte et régressions P0 complètent ces tests ; les résultats réels figurent dans le rapport de livraison.
