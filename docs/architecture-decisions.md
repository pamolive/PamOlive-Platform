# Décisions d’architecture proposées

Ces décisions doivent être acceptées ou amendées avant une livraison stable.

## Écart entre proposition et alpha livrée

Les statuts de validation ci-dessous ne sont pas des validations acquises par la seule
publication du code. Le dépôt et l’alpha sont désormais publiés ; les décisions encore
ouvertes restent à arbitrer avant une livraison stable.

La contrainte d’exploitation actuelle est un conteneur applicatif par instance avec
PostgreSQL externe. L’alpha applique les principes de monolithe modulaire, d’isolation
organisationnelle, d’installation contrôlée et d’audit PostgreSQL, mais **n’intègre pas
Redis (ADR-003)**. Les sessions, tâches et verrous actuellement livrés utilisent PostgreSQL.
Conserver ce fonctionnement ou ajouter Redis demande une décision explicite ; cela ne doit
pas être déduit du schéma cible ni imposer une pile de services à l’utilisateur.

L’API d’extension communautaire est livrée. La séparation juridique et la distribution
des modules commerciaux (ADR-010) restent ouvertes : charger du Python dans le processus
AGPL ne garantit pas à lui seul une indépendance de licence. Aucun entitlement commercial
n’est actuellement accepté par le contrat de module.

| ID | Décision | Statut proposé | Motif |
|---|---|---|---|
| ADR-001 | Monolithe modulaire Python/Django en V1 | À valider | Transactions simples, exploitation raisonnable, extraction future possible |
| ADR-002 | PostgreSQL 16+ obligatoire en production | À valider | Contraintes, JSONB, verrous, intégrité et HA éprouvés |
| ADR-003 | Redis pour tâches, cache et verrous courts | À valider | Les instances Web doivent rester sans état local |
| ADR-004 | Multi-organisation logique dès la V1 | À valider | Évite une migration structurelle très coûteuse plus tard |
| ADR-005 | Compte de connexion distinct de l’identité métier | À valider | Nécessaire pour un IAM correct et les comptes de service |
| ADR-006 | Modules détectés par points d’entrée Python | À valider | Paquets séparés, découverte contrôlée et compatibilité vérifiable |
| ADR-007 | Installation pendant le déploiement, activation dans l’UI | À valider | Empêche l’installation Web de devenir une RCE |
| ADR-008 | Services synchrones + outbox asynchrone | À valider | Contrats explicites et événements fiables |
| ADR-009 | API `/api/v1/` dès le noyau | À valider | Automatisation et intégrations sans dépendre de l’HTML |
| ADR-010 | AGPL pour le noyau, modules commerciaux séparés | À valider | Transparence du socle et modèle économique clair |
| ADR-011 | Audit chaîné et protégé par PostgreSQL | À valider | Détection de modification et valeur probante renforcée |
| ADR-012 | Vues serveur et JavaScript léger pour la V1 | À valider | Simplicité, sécurité et expérience cohérente type ERP |

## Conséquence pour le prototype

Le prototype historique reste un démonstrateur distinct. Le dépôt publié utilise désormais
des migrations versionnées ; une mise à niveau d’une installation existante conserve ses données.
Une recréation de base est réservée à un environnement de développement jetable explicitement
désigné, jamais à une installation NAS ou à une procédure de mise à jour standard.
