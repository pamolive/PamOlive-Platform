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

## Contrats fournisseurs et politiques

Le module optionnel **Contrats et politiques** s’active dans le catalogue de l’organisation. Il est livré dans la même image, sans autre conteneur.

1. Ajouter, dans **Paramètres**, un responsable ayant le rôle administrateur ou approbateur de l’organisation.
2. Créer la société fournisseur, puis un contrat : période datée (fuseau de l’installation, stockage UTC), responsable, ressources, privilège, méthodes, plages locales avec fuseau IANA, pays et origines éventuels. Une porte ou zone nécessite aussi l’autorisation physique explicite.
3. Inscrire chaque identité intervenante au contrat. Une société n’est pas un compte de connexion. L’inscription commence lors de sa publication, jamais rétroactivement.
4. Publier la politique d’approbation : 1, 2 ou 3 approbateurs distincts, seuil spécifique pour les ressources critiques, contrat obligatoire pour les prestataires et validation du responsable du contrat.
5. Créer une intention liée au contrat, avec une référence métier et une fenêtre entièrement autorisée. Choisir la suite IAM pour attribuer un droit temporaire, ou PAM pour un bail privilégié.
6. Les votes restent visibles. Aucun effet IAM n’est demandé avant le seuil requis ; une attribution future n’est envoyée qu’au début de sa fenêtre.
7. Retirer un intervenant ou un contrat révoque les droits et autorisations liés. Seul un compte explicitement **dédié au contrat** est désactivé globalement ; les comptes partagés et droits indépendants sont conservés. Le suivi des changements externes indique si le retrait est réellement confirmé.

Publier une politique impose le parcours d’approbation pour les nouvelles attributions : le formulaire de droit direct ne permet pas de contourner les votes. Les règles de séparation des tâches interdisent une combinaison de deux droits sur des fenêtres qui se chevauchent, y compris des intentions déjà approuvées. Elles ne suppriment pas arbitrairement un des droits existants : les conflits sont signalés dans les évaluations et doivent être revus.

Une révision de contrat conserve les précédentes ; les événements sont évalués selon la révision publiée au moment de l’accès. Une approbation ou un droit créé plus tard ne justifie jamais un événement passé. Les intervalles sont semi-ouverts : début inclus, fin exclue. Une plage de nuit est rattachée au jour d’ouverture ; les heures inexistantes ou ambiguës lors du changement d’heure n’élargissent jamais une autorisation.

Les pays et lieux déclarés dans une demande ne sont pas des preuves d’origine. Le pays observé doit venir de la source ; s’il manque alors qu’il est exigé, le résultat reste indéterminé. Une référence de ticket n’est pas vérifiée tant qu’aucun connecteur ticketing n’apporte cette preuve. Les plages horaires sont contrôlées pour la fenêtre demandée et les observations ; SCIM ne rend pas automatiquement les applications tierces capables de bloquer chaque connexion hors horaires.

Les publications et retraits nécessitent une MFA récente personnelle. Les contrôles publiés restent applicables si l’interface du module est désactivée : cette désactivation ne constitue pas un contournement de politique. Aucun challenge MFA n’est injecté au milieu d’une session SSH/RDP.

## Graphe et investigations

Activer **Graphe et investigations** dans le catalogue de l’organisation. Aucune base graphe ni aucun conteneur supplémentaire : les relations et preuves restent dans PostgreSQL.

1. Sélectionner une identité et une période pour afficher son graphe et sa chronologie. Contexte déclaré, autorisations locales, intentions approuvées et observations sont quatre couches différentes ; une flèche ne constitue pas à elle seule une permission ou une preuve de causalité.
2. Dans **Relations et couverture des sources**, publier une relation avec sa provenance : identité qui possède un appareil, serveur situé dans une zone, porte gérée par une application, certificat attendu sur un hôte, ou topologie réseau déclarée. La confiance « vérifiée » désigne la vérification du déclarant, pas une certification cryptographique de PAM-olive.
3. Publier les switch, port et VLAN attendus d’une identité machine. Les observations réseau fournissent ces trois champs. Un changement autorisé précise aussi ces valeurs dans son intention ; une autorisation générique ne justifie pas un déplacement vers n’importe quel port.
4. Configurer les périmètres des sources de collecte puis envoyer des [rapports de collecte](docs/api.md). Une couverture de ressource ne vaut pas couverture de toute l’organisation. Une panne, un trou ou une limite de lecture interdit de conclure à une collecte complète.
5. Utiliser les quatre investigations prédéfinies. L’intersection physique/privilégié exige des droits datés et un placement vérifié dans la zone. La recherche fournisseur/production exige un contrat applicable et une ressource explicitement classée « Production ». Un compte sans intention ponctuelle peut toujours disposer d’un droit permanent légitime.
6. Ouvrir un événement pour ses preuves et ajouter une réévaluation sans réécrire le fait source. Les arrivées tardives et incertitudes d’horloge restent visibles. L’usage d’un certificat sur un autre hôte est un écart à examiner, jamais à lui seul une preuve de copie de clé privée.

Ces fonctions exploitent les objets et événements disponibles. Elles ne branchent pas automatiquement TeamViewer, un badgeur ou un switch sans collecteur adapté à son API. Aucun jeu de données de démonstration n’est ajouté pendant l’installation.

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
