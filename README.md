# PAM-olive Platform

Gouverner et expliquer chaque accès : **Qui ? Quoi ? Où ? Quand ? Comment ? Pourquoi ?**

PAM-olive rapproche une identité, ses comptes et ressources, une autorisation ou intention métier et les faits observés. L’interface conserve la simplicité d’un espace d’applications : chaque organisation active ses propres modules.

**Version en développement : 0.2.0 alpha.** [L’état réel des fonctions et le travail restant](docs/implementation-status.md) distinguent le code opérationnel de l’architecture cible. Le PAM historique reste un produit séparé pendant cette évolution.

## Un seul conteneur applicatif

L’image contient Django, l’interface, tous les modules livrés et le traitement des expirations. Aucun conteneur worker, scheduler, Redis ou proxy n’est nécessaire à cette version. Les tâches durables et verrous utilisent PostgreSQL. Plusieurs instances applicatives peuvent partager la même base ; la validation HA complète reste à effectuer.

PostgreSQL 16+ doit être disponible sur un serveur existant, éventuellement une autre VM. `compose.yml` contient **un seul service**, `web`. Si vous souhaitez une base locale distincte, le fichier optionnel `compose.local-db.yml` ajoute un second conteneur PostgreSQL.

## Installation Linux, macOS ou NAS Synology

Prérequis : Git, Docker Engine et Docker Compose v2. `make` n’est pas nécessaire. Sur Synology, utiliser Container Manager et son moteur Docker. Le rôle PostgreSQL dédié doit posséder la base PAM-olive, sans être superutilisateur.

```sh
git clone https://github.com/pamolive/PamOlive-Platform.git
cd PamOlive-Platform
cp .env.example .env
```

Modifier `.env` avant le démarrage :

- `SECRET_KEY` : une valeur aléatoire longue, par exemple générée avec `openssl rand -hex 48` ;
- `DATABASE_URL` : `postgresql://utilisateur:mot-de-passe@serveur:5432/pamolive?sslmode=require` ; encoder les caractères réservés du mot de passe dans l’URL ;
- `ALLOWED_HOSTS` : le nom DNS ou l’IP de l’application ;
- `CSRF_TRUSTED_ORIGINS` : son URL complète, avec schéma et port ;
- `PAMOLIVE_PORT` : port d’écoute de l’hôte, par exemple `8010` ;
- `DEBUG=false` pour un serveur ; `SECURE_COOKIES=true` avec HTTPS, ou `false` pour une évaluation HTTP privée.

```sh
docker compose build
docker compose run --rm web python manage.py migrate --noinput
docker compose run --rm web python manage.py createsuperuser
docker compose run --rm web python manage.py setup_organization --key mopacy --name Mopacy --admin cyriel
docker compose up -d
```

Remplacer `cyriel` par le nom de superutilisateur choisi. Ouvrir l’hôte et le port configurés, par exemple `http://192.168.0.25:8010`. `/health/` indique l’état de connexion à la base. Les migrations sont exécutées une fois pendant la livraison, avant le démarrage des instances.

## Installation Windows

Installer Git et Docker Desktop, puis utiliser PowerShell :

```powershell
git clone https://github.com/pamolive/PamOlive-Platform.git
Set-Location PamOlive-Platform
Copy-Item .env.example .env
notepad .env
docker compose build
docker compose run --rm web python manage.py migrate --noinput
docker compose run --rm web python manage.py createsuperuser
docker compose run --rm web python manage.py setup_organization --key mopacy --name Mopacy --admin cyriel
docker compose up -d
```

Dans Docker Desktop, `host.docker.internal` permet de joindre un PostgreSQL écoutant sur Windows. Sur un NAS, utiliser le DNS/IP du serveur PostgreSQL ou son réseau Docker ; `localhost` dans le conteneur désigne le conteneur lui-même.

## Premier parcours

1. Dans **Paramètres**, ajouter un opérateur et un approbateur distincts.
2. Dans **Identités**, créer l’identité, la ressource et les comptes liés.
3. Créer une intention avec motif, méthode et période.
4. L’approbateur décide dans **Approbations**.
5. Enregistrer un fait dans **Gouvernance des accès**, ou l’importer depuis une source de **Connecteurs**.
6. Ouvrir **Expliquer cet accès** et exporter ses preuves.

Les droits permanents motivés peuvent justifier un accès sans ticket. Un fait insuffisamment documenté reste « contexte insuffisant ». Les révocations locales ne valent pas confirmation de retrait sur un système externe.

## Développement et tests

Python 3.12+, `python -m venv .venv`, puis installer `requirements-dev.lock`. Utiliser `python manage.py test` et `ruff check .`. SQLite est réservé aux tests rapides locaux ; la CI et les contrôles de contraintes utilisent PostgreSQL réel.

## Documentation

- [Vision produit](docs/product-vision.md) et [atlas visuel autonome](docs/architecture-platform.html)
- [Architecture](docs/architecture.md), [données](docs/data-model.md) et [sécurité](docs/security-boundaries.md)
- [API d’observation](docs/api.md), [modules](docs/modules.md), [PostgreSQL](docs/postgresql.md)
- [Provisioning SCIM et confirmations externes](docs/provisioning.md)
- [Roadmap](docs/implementation-roadmap.md), [décisions](docs/architecture-decisions.md), [état livré](docs/implementation-status.md)

## Licence et gestion du projet

Le noyau et les modules communautaires de ce dépôt sont sous **AGPL-3.0-or-later**. Les extensions commerciales prévues seront distribuées séparément, avec leurs propres contrats. Une clé de licence n’empêche pas la modification d’un code open source.

Projet géré par **Mopacy** — [mopacy.be](https://mopacy.be) · [GitHub](https://github.com/pamolive) · [Discord](https://discord.gg/RqUBXjc7HE) · [LinkedIn](https://www.linkedin.com/company/pam-olive).
