# Décisions d’architecture proposées

Ces décisions doivent être acceptées ou amendées avant que le prototype devienne la base du nouveau dépôt.

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

Le prototype sert de démonstrateur visuel, pas de migration de production. Après validation des ADR, le schéma local de développement peut être recréé afin d’introduire correctement UUID, organisations, compte personnalisé et frontières de modules.
