# Déploiement à un seul conteneur applicatif

La plateforme est un monolithe modulaire. L’activation d’un module n’ajoute aucun conteneur. Un seul runtime supervise le Web Gunicorn et un processus léger de tâches durables. Si un processus meurt, le runtime arrête son compagnon et le conteneur est redémarré par Docker.

PostgreSQL 16+ reste externe au conteneur applicatif. La même installation PostgreSQL peut héberger d’autres bases ; PAM-olive utilise une base et un rôle dédiés. Les migrations s’exécutent une fois pendant la livraison. Les images et le schéma doivent être identiques entre les instances actives.

Les opérations concurrentes verrouillent l’organisation dans PostgreSQL et les événements sources sont dédupliqués par contrainte unique. Le traitement des expirations est rejouable : une seconde instance ne produit pas une seconde expiration auditée. Redis n’est pas requis par l’implémentation actuelle ; un backend distant pourra être ajouté pour les besoins de volumétrie mesurés.

Cela ne qualifie pas automatiquement toute la plateforme en haute disponibilité. La reprise du PostgreSQL, les sessions de transport et les futurs connecteurs doivent disposer de leurs propres tests et procédures.

## Installation actuellement dédiée sur le NAS

- Code : `/volume1/docker/pamolive-platform`.
- Projet Compose : `pamolive-platform`, service unique `web`.
- Accès LAN : `http://192.168.0.25:8010`.
- PostgreSQL : instance existante, base et rôle `pamolive_platform` ; ancienne base PAM inchangée.
- Secrets locaux : `.env` ; identifiant initial de l’installation : `.bootstrap-admin` (permission propriétaire uniquement).
- Base de tests : `test_pamolive_platform`, séparée des données de l’application.

Le fichier `deploy/compose.nas.yml` raccorde seulement la nouvelle application au réseau de la base existante. `deploy/bootstrap-nas.sh` est spécifique à ce NAS et vérifie son chemin exact ; il ne doit pas être utilisé comme script d’installation universel.
