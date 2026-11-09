# Installation avec une image Docker qualifiée

Utiliser cette procédure lorsqu’une référence `ghcr.io/pamolive/pamolive-platform@sha256:…` a été publiée. L’image Linux amd64 contient le Web, le traitement des tâches et le relais PAM privé. Compose démarre un seul service, `web`, sur un PostgreSQL 16+ déjà disponible. Pour construire depuis le code ou utiliser une autre architecture, voir le [README](../README.md).

## Installer sans compilation

1. Relever la référence complète et la révision dans le résumé GitHub du workflow **Publish qualified Docker image**. Télécharger [compose.registry.yml](../compose.registry.yml) et [.env.example](../.env.example) à cette révision. Docker Engine et Compose v2 suffisent sur le serveur ; Git et les outils de compilation ne sont pas nécessaires.
2. Copier `.env.example` en `.env`. Configurer PostgreSQL, les clés d’application et l’adresse d’accès comme dans le README, puis ajouter `PAMOLIVE_IMAGE=ghcr.io/pamolive/pamolive-platform@sha256:…`. Utiliser l’empreinte publiée, pas le tag `latest`.
3. Vérifier la [provenance GitHub de l’image](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) depuis un poste équipé de GitHub CLI. Remplacer `EMPREINTE` par les 64 caractères du résumé :

   ```text
   gh attestation verify oci://ghcr.io/pamolive/pamolive-platform@sha256:EMPREINTE -R pamolive/PamOlive-Platform
   ```

4. Télécharger l’image et, **pour une nouvelle base uniquement**, initialiser l’installation. Les commandes sont identiques sous PowerShell, Bash et sur un NAS compatible :

   ```text
   docker compose -f compose.registry.yml pull web
   docker compose -f compose.registry.yml run --rm web python manage.py migrate --noinput
   docker compose -f compose.registry.yml run --rm web python manage.py createsuperuser
   docker compose -f compose.registry.yml run --rm web python manage.py setup_organization --key mopacy --name Mopacy --admin cyriel
   docker compose -f compose.registry.yml up -d --no-build
   docker compose -f compose.registry.yml ps
   ```

Remplacer `cyriel` par le compte créé. Les commandes d’initialisation utilisent le même service `web` dans un conteneur temporaire. À la fin, seul le conteneur applicatif permanent demeure. Sur une installation existante, conserver la configuration, le nom de projet et les clés ; appliquer la [procédure de mise à niveau contrôlée](controlled-upgrade.md) avant de remplacer l’image. Ne pas relancer l’initialisation sur une base en service.

Si le registre répond `denied`, vérifier [les droits et la visibilité du paquet](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility). GitHub rend les nouveaux paquets GHCR privés par défaut ; le dépôt source public ne rend pas automatiquement l’image téléchargeable sans compte. Ne pas inscrire de jeton dans Compose ni dans le dépôt.

## Publier une image qualifiée

La CI construit une fois l’image de production et l’utilise notamment pour le contrôle du runtime, le relais SSH et les essais de restauration. L’image de test RDP est distincte et n’est pas publiée. Une fois les contrôles terminés, la CI exporte l’image de production et son empreinte d’archive. Un envoi sur `main` conserve ce lot sept jours dans les artefacts GitHub.

Dans **Actions → Publish qualified Docker image**, lancer le workflow sur `main` avec l’identifiant de la CI réussie du **même commit**. Le workflow refuse une autre branche, une pull request, un autre dépôt ou une archive modifiée. Il recharge l’image testée, la publie sans la reconstruire, puis vérifie son empreinte en la récupérant du registre. Le résumé donne la référence par digest ; l’attestation porte sur ce digest de publication.

Pour permettre le téléchargement anonyme, un administrateur du paquet doit vérifier sa visibilité dans GHCR. Cette décision est séparée de l’exécution de la CI. Une référence privée peut servir à la qualification avec un compte autorisé.
