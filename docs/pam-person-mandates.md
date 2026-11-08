# Mandats PAM liés à une personne

Cette livraison étend le relais SSH/RDP existant ; elle n’ajoute ni conteneur permanent ni base. Les tables restent dans PostgreSQL et les huit modules restent activables par organisation.

## Relations et preuves

```text
Compte de connexion du portail (rôle technique, MFA personnelle)
  └─ LoginIdentityBinding signé, vérifié par un administrateur, propre à l’organisation
      └─ Personne IAM intervenante
          └─ AccessIntent PAM : compte + propriétaire + ressource + fenêtre + motif figés
              ├─ ApprovalDecision signées par des personnes IAM indépendantes
              └─ SessionLease → RelayConnection → capture chiffrée et scellée

Compte externe utilisé → identité propriétaire (personne ou identité technique)
                       ≠ nécessairement la personne intervenante
```

Le lien est un objet du module IAM, pas une fusion du compte de connexion avec l’identité. Plusieurs comptes du portail peuvent représenter la même personne ; le contrôle d’indépendance se fait sur son identifiant IAM. Les comptes personnels d’un autre humain ne sont pas empruntables. Le compte partagé appartient à une identité machine, service, workload, application ou API.

Le HMAC couvre l’organisation, les identifiants et les dates, la référence de vérification et la MFA pour le lien ; le périmètre exact et l’identité de l’approbateur pour le vote. PostgreSQL impose aussi les tuples organisation/personne/compte liés et interdit la mutation du corps des attestations et des décisions. Un administrateur contrôlant l’hôte et la clé applicative n’est pas exclu de ce modèle de confiance.

## Ce qui est autorisé

- Demande après MFA récente par la personne effectivement liée au compte connecté.
- Compte externe privilégié ou technique actif, protocole SSH/RDP et ressource précise.
- Droits natifs complets de ce compte, explicitement nommés `native_full_account` : aucun filtrage fin des commandes ou actions OS n’est fourni.
- Approbations signées de personnes indépendantes, selon la politique et le contrat applicables.
- Fenêtre limitée et nouvelle vérification à l’ouverture, puis contrôle continu sans demander de MFA au milieu du flux.

## Révocation et historique

Révoquer le lien de l’intervenant révoque ses intentions et baux. Le relais constate la perte d’autorité et ferme le transport. Le compte partagé, le compte global du portail et les autres organisations ne sont pas désactivés. Un vote historique ne change pas si le lien de son approbateur est révoqué plus tard.

La relecture par l’opérateur exige un lien actuel valide vers la même personne ; les administrateurs/auditeurs autorisés peuvent examiner les captures historiques après MFA, y compris les captures anciennes sans attestation. Ni les faits source ni les anciennes évaluations ne sont réécrits. Les nouveaux rapprochements PAM utilisent `access-context/5`.

Le [guide d’exploitation](pam-transport.md) décrit la configuration, la migration des anciennes demandes et les limites. Cette extension reste une étape de la plateforme alpha : elle ne qualifie pas encore la charge, le basculement actif-actif, tous les Windows/RDS, la rétention ni la rotation des clés.
