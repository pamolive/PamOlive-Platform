# Présentation architecture sur le NAS

Hébergement statique indépendant du PAM en production. Aucune base de données,
clé privée ou configuration applicative n'est montée dans ce service.

- Dossier NAS : `/volume1/docker/pamolive-architecture`
- Projet Compose : `pamolive-architecture`
- URL Wi-Fi local : `http://192.168.0.25:8020/architecture-platform.html#parcours`
- Source HTML : `../../docs/architecture-platform.html`

Le dossier de déploiement du NAS contient le HTML, `compose.yml` et `Caddyfile`.
Le fichier est monté en lecture seule dans un conteneur non privilégié. Le service
redémarre après un redémarrage du NAS et n'expose que ce document, sans listing
de répertoire. L'image est celle déjà présente sur ce NAS, épinglée par digest.

Le port est lié à l'adresse LAN du NAS. Il n'y a ni publication DNS ni règle de
redirection Internet ajoutée. L'accès depuis un iPhone nécessite le même réseau
local ou un VPN existant. HTTP est utilisé sur le LAN ; pour un accès public,
prévoir une publication HTTPS et une politique d'accès séparées.

## Commandes NAS

```sh
cd /volume1/docker/pamolive-architecture
docker compose config --quiet
docker compose up -d --pull never
docker compose ps
```

Pour arrêter uniquement cette présentation, sans volumes ni données PAM :

```sh
cd /volume1/docker/pamolive-architecture
docker compose stop
```

Après remplacement du fichier HTML sur le NAS, recréer uniquement ce service
pour garantir le rechargement du montage :

```sh
cd /volume1/docker/pamolive-architecture
docker compose up -d --pull never --force-recreate web
```
