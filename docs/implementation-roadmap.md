# Ordre d’implémentation après validation

## Phase 0 — Contrats

- valider les ADR ;
- valider le schéma du noyau et celui d’IAM Foundation ;
- valider le [modèle de menace et les frontières de confiance](security-boundaries.md) ;
- figer le manifeste et les contrats d’événements V1.

## Phase 1 — Noyau uniquement

- compte personnalisé et MFA ;
- organisations et appartenances ;
- rôles techniques et permissions ;
- registre de paquets et activations ;
- audit chaîné, outbox et jobs ;
- paramètres typés et références de secrets ;
- coque ERP PAM-olive et API `/api/v1/` ;
- tests multi-organisation et sécurité.

Critère de sortie : aucun modèle IAM ou PAM dans le noyau et aucune migration non déterministe.

## Phase 2 — Module IAM Foundation

- identités et comptes externes ;
- annuaires, groupes et appartenances ;
- applications, droits et rôles métier ;
- attributions d’accès ;
- import/export et API ;
- événements versionnés.

## Phase 3 — Modules de gouvernance

- Approbations ;
- Connecteurs et provisioning ;
- Recertification ;
- Reporting.

## Phase 4 — Intégration PAM

- connecter progressivement le PAM historique par API et événements ;
- ne pas copier ses modèles directement dans le noyau ;
- préparer une migration fonctionnelle explicite lorsque la plateforme couvre les capacités nécessaires.

## Publication et qualité de livraison

La publication du dépôt `PamOlive-Platform` a été autorisée. Une publication du code en développement ne constitue pas une qualification de production. La porte de livraison stable reste :

- validation explicite des ADR ;
- résolution des questions ouvertes du schéma ;
- suppression ou refonte du prototype incompatible ;
- tests du noyau sur PostgreSQL réel ;
- CI, analyse de sécurité, politique de contribution et documentation d’installation.
