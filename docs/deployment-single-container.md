# Déploiement à un seul conteneur applicatif

La plateforme est un monolithe modulaire. L’activation d’un module n’ajoute aucun conteneur. Un seul runtime supervise le Web ASGI/Uvicorn, un processus léger de tâches durables et le moteur natif privé SSH/RDP. Si un processus meurt, le runtime arrête ses compagnons et le conteneur est redémarré par Docker.

Le superviseur démarre en root avec seulement `SETUID`, `SETGID` et `KILL`. Le Web et les tâches tournent ensuite en UID 1000, le moteur natif en UID 1001, sans capacité effective. Le moteur reçoit un environnement assaini sans URL PostgreSQL ni clés applicatives. Son port 4822 écoute uniquement sur la boucle locale du conteneur ; seul le port applicatif 8000 est publié. Ce cloisonnement limite l’exposition des secrets au moteur natif ; il ne constitue pas une isolation contre une compromission de Django, du noyau ou de l’hôte.

PostgreSQL 16+ reste externe au conteneur applicatif. La même installation PostgreSQL peut héberger d’autres bases ; PAM-olive utilise une base et un rôle dédiés. Les migrations s’exécutent une fois pendant la livraison. Les images et le schéma doivent être identiques entre les instances actives.

Les opérations concurrentes verrouillent l’organisation dans PostgreSQL et les événements sources sont dédupliqués par contrainte unique. Le traitement des expirations est rejouable : une seconde instance ne produit pas une seconde expiration auditée. Redis n’est pas requis par l’implémentation actuelle ; un backend distant pourra être ajouté pour les besoins de volumétrie mesurés.

Cela ne qualifie pas automatiquement toute la plateforme en haute disponibilité. La reprise du PostgreSQL et les futurs connecteurs doivent disposer de leurs propres tests et procédures. Un relais SSH actif appartient à un processus et ne migre pas vers une autre instance : une panne coupe le transport et la capture est marquée partielle. Une nouvelle ouverture nécessite une nouvelle autorisation et un nouveau ticket. Le reverse proxy doit conserver une connexion WebSocket sur la même instance pendant toute sa durée.

La configuration des cibles, des proxys, des enregistrements et leurs limites est décrite dans [Transport PAM](pam-transport.md). La mise à niveau introduit des noms de cookies propres à la plateforme pour ne pas entrer en conflit avec le PAM historique ; une reconnexion au portail peut être nécessaire.

## Installation actuellement dédiée sur le NAS

- Code : `/volume1/docker/pamolive-platform`.
- Projet Compose : `pamolive-platform`, service unique `web`.
- Accès LAN : `http://192.168.0.25:8010`.
- PostgreSQL : instance existante, base et rôle `pamolive_platform` ; ancienne base PAM inchangée.
- Secrets locaux : `.env` ; identifiant initial de l’installation : `.bootstrap-admin` (permission propriétaire uniquement).
- Base de tests : `test_pamolive_platform`, séparée des données de l’application.

Le fichier `deploy/compose.nas.yml` raccorde seulement la nouvelle application au réseau de la base existante. `deploy/bootstrap-nas.sh` est spécifique à ce NAS et vérifie son chemin exact ; il ne doit pas être utilisé comme script d’installation universel.
