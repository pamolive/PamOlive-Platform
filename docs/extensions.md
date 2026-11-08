# Extensions communautaires dans une seule image

Le catalogue distingue désormais trois opérations : **livrer du code**, **valider ses migrations**, puis **activer ses fonctions pour une organisation**. Le navigateur ne lance jamais pip, n’importe pas un nom fourni dans un formulaire et ne charge pas une archive téléversée.

Les huit modules intégrés restent disponibles sans configuration supplémentaire. Une extension est une distribution Python séparée, ajoutée à la même image applicative. Elle n’ajoute aucun conteneur permanent. L’exemple `examples/notes-extension/` n’est ni installé ni activé automatiquement, et aucune donnée de démonstration n’est créée dans une installation cliente.

## Contrat HTTP V1 effectivement disponible

Une extension expose un point d’entrée de distribution `pamolive.modules`, un manifeste JSON et un `AppConfig` Django :

```text
Distribution wheel py3-none-any
  pamolive_ext_<nom>/
    __init__.py
    apps.py                  name = package ; label = clé du module
    manifest.json            descripteur signé, UTF-8
    manifest.py              objet ModuleManifest public
    models.py
    services.py              contrôles côté service
    views.py
    migrations/
    templates/<package>/
```

Consulter le [manifeste complet de l’exemple](../examples/notes-extension/pamolive_ext_notes/manifest.json). Le contrat impose une clé propre, une version canonique PEP 440 de 30 caractères maximum, une plage de compatibilité du noyau, la version d’API `1`, le package, l’AppConfig, les dépendances, les permissions et les routes. Les objets de contrat Python sont immuables.

Les clés des modules intégrés sont réservées. Le package d’une extension commence par `pamolive_ext_`. Ses vues sont montées uniquement sous `/extensions/<clé>/`, dans leur espace de noms `ext-<clé>`. Le noyau construit les routes depuis le manifeste et ajoute son contrôle d’accès ; l’extension ne fournit pas une racine URL libre. GET/HEAD et POST sont pris en charge ; une route POST exige une permission sensible. Les WebSockets et hooks d’outbox ne sont pas encore des contrats d’extension livrés.

Une permission s’écrit `module.ressource.action`. Elle déclare les rôles techniques autorisés dans l’organisation et son caractère sensible. Le contrôle vérifie aussi le paquet livré, son empreinte et l’activation organisationnelle. Les actions sensibles passent par la MFA personnelle existante, avec reprise du formulaire après challenge.

```python
from platform_core.extensions import api

def list_objects(*, actor, organization):
    api.authorize(actor, organization, "my_module.object.view")
    return MyModel.objects.filter(organization=organization)
```

Chaque service d’écriture doit appeler `api.authorize()` et utiliser une transaction ; le décorateur de la vue ne suffit pas. `api.audit()` écrit un événement versionné appartenant au module dans l’audit de l’organisation. **Cet audit n’est pas une outbox ni une promesse de livraison d’événements à d’autres modules.** Le code d’exemple montre la lecture, l’écriture, l’audit et le filtrage organisationnel.

Un module Python possède les privilèges du processus applicatif. La signature établit sa provenance et son intégrité, pas sa sûreté : revue du code, tests adverses, contraintes de données et dépendances verrouillées restent obligatoires. Il n’existe pas de sandbox Python par organisation.

## Signature et inventaire

Le canal de livraison utilise une attestation Ed25519 avec séparation de domaine `pamolive.extension-release.v1`. Le payload signé lie la distribution, sa version, l’empreinte SHA-256 de la wheel, le point d’entrée, le manifeste et l’inventaire SHA-256 des fichiers. Les clés publiques de confiance sont choisies par l’exploitant, pas par le paquet.

Avant tout import d’extension, le démarrage vérifie la signature, la compatibilité, les fichiers installés, le manifeste embarqué et le chemin réellement résolu par Python. Un fichier ajouté, modifié ou absent, du bytecode non signé, un lien symbolique ou un package masquant l’extension provoquent un refus. Les wheels comportant des hooks `.pth`, des scripts d’entrée supplémentaires, des bibliothèques natives ou du code hors de leur package sont refusées par ce contrat initial.

Installer avec `--no-compile` et conserver `PYTHONDONTWRITEBYTECODE=1`. Ne pas monter le code d’une extension en volume modifiable. Le runtime doit rester en lecture seule : la vérification au démarrage n’est pas une surveillance continue des fichiers et ne protège pas contre un administrateur qui contrôle l’hôte et les clés.

La découverte s’appuie sur les [points d’entrée de distribution Python](https://packaging.python.org/en/latest/specifications/entry-points/) et [`importlib.metadata`](https://docs.python.org/3.12/library/importlib.metadata.html). La signature utilise [Ed25519 fourni par cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

## Préparer une livraison

Ces commandes se lancent dans l’environnement Python de construction, sous Windows, Linux ou macOS ; elles ne demandent pas make. Les outils de construction de wheel s’installent dans un environnement de développement distinct du runtime. L’exploitant doit verrouiller et revoir ces dépendances de construction.

1. Construire la wheel du module. Pour l’exemple, depuis son dossier, utiliser `python -m build --wheel` avec l’outil de construction installé. Ne jamais exécuter un backend de construction inconnu sur un serveur de production.
2. Sur une machine de signature hors runtime, créer une clé protégée par phrase secrète :

```sh
python -m platform_core.extensions.release keygen --private-key publisher-private.pem --public-keys public-keys.json --key-id publisher-2026
```

La clé privée est chiffrée et n’est jamais imprimée. Sous Windows, protéger également son fichier par les ACL du compte ; un mode POSIX ne prouve pas une ACL Windows privée. Garder cette clé **hors du contexte Docker, du NAS applicatif et de Git**. Il s’agit d’une clé de signature de paquets, pas d’une clé de licence commerciale.

3. Signer la wheel après revue. Le mot de passe est demandé de manière interactive, pas passé dans la ligne de commande :

```sh
python -m platform_core.extensions.release sign --wheel pamolive_example_notes-1.0.0-py3-none-any.whl --manifest examples/notes-extension/pamolive_ext_notes/manifest.json --private-key publisher-private.pem --key-id publisher-2026 --output notes-release.json
```

4. Préparer le catalogue et le verrou des wheels depuis les attestations signées :

```sh
python -m platform_core.extensions.release catalog --release notes-release.json --public-keys public-keys.json --output catalog.json --lock-output requirements.lock
```

Répéter `--release` pour plusieurs modules. Le verrou contient les versions exactes et hashes des wheels ; il n’autorise aucun téléchargement automatique de dépendance. Le contrat initial accepte jusqu’à 32 extensions, chacune avec un inventaire borné. Les clés privées ne sont nécessaires ni pour construire l’image cliente ni pour l’exécuter.

## Construire l’image applicative enrichie

Créer un contexte contenant seulement :

```text
extension-build/
  Dockerfile                 copie de deploy/Dockerfile.extensions
  public-keys.json
  catalog.json
  requirements.lock
  wheels/
    pamolive_example_notes-1.0.0-py3-none-any.whl
```

Depuis ce dossier :

```sh
docker build --build-arg PAMOLIVE_BASE_IMAGE=pamolive-platform:base -t pamolive-platform:extensions .
```

`pamolive-platform:base` désigne ici l’image de base construite depuis un commit validé du dépôt, pas une image publique présumée existante. En livraison, conserver la révision et une référence d’image vérifiable. Le Dockerfile vérifie toutes les attestations **et la correspondance exacte du verrou avec le catalogue** avant pip : aucune URL, option d’index ou wheel supplémentaire n’est admise. Il installe hors réseau avec `--require-hashes --no-deps --no-compile`, vérifie les dépendances installées, les modèles et les points d’entrée, puis retire les wheels temporaires. Les bibliothèques Python nécessaires doivent déjà être présentes et verrouillées dans l’image choisie ; une dépendance absente fait échouer la construction.

Le runtime hérite du port unique, du superviseur, des UID séparés, du moteur PAM privé et des contrôles de santé. Ne pas copier une clé privée ou un fichier `.env` dans ce contexte.

## Migrer puis activer

Utiliser l’image enrichie pour le même service Compose `web`, par exemple avec une surcharge :

```yaml
services:
  web:
    image: pamolive-platform:extensions
```

1. Vérifier l’absence de relais actifs, sauvegarder la base dédiée et conserver la clé de chiffrement. Prévoir une fenêtre pour le code et les migrations ; ne pas arrêter une session de manière inattendue.
2. Arrêter l’application pendant la migration contrôlée. Avec les fichiers Compose et l’environnement habituels, exécuter dans l’image enrichie `python manage.py migrate --noinput`.
3. Exécuter `python manage.py pamolive_extensions verify`, puis `python manage.py pamolive_extensions deliver --actor <superadministrateur>`.
4. Redémarrer le même service avec `docker compose ... up -d --no-build web`. Le nombre de conteneurs applicatifs permanents reste identique.
5. Dans **Catalogue des modules**, choisir l’organisation, puis activer le paquet après MFA personnelle. Une autre organisation reste inactive jusqu’à sa propre activation.

`deliver` est une commande d’infrastructure locale, pas une API Web. Elle refuse les migrations en attente, les modèles sans migrations et la divergence entre code et état de migration. Elle atteste la livraison globale sans activer d’organisation. L’interface explique si cette étape manque.

Chaque activation conserve la version **et l’empreinte de livraison exacte**. Même un paquet reconstruit sous le même numéro de version nécessite une nouvelle activation si son empreinte change. Les dépendances doivent être activées dans la même organisation et satisfaire leurs plages de versions.

Désactiver retire l’accès aux routes et services sans supprimer les tables ni les données. La suppression physique n’est pas proposée. Un retrait de paquet doit être préparé : enlever du code installé ne constitue pas une migration de ses données.

Toutes les instances actives doivent disposer du même catalogue, des mêmes clés approuvées et des mêmes paquets. Les migrations restent uniques par livraison. Les déploiements multi-version simultanés et le rolling upgrade ne sont pas qualifiés : une empreinte incohérente ferme l’accès au module, elle ne prouve pas la disponibilité HA.

## Vérifications

```sh
python manage.py test tests.test_extensions --noinput
python -m deploy.check_extensions
python -m deploy.check_extensions --postgres
```

La dernière commande exige une connexion PostgreSQL explicite et une base de tests dédiée `test_pamolive_extensions`. Le rôle de tests doit pouvoir la créer, ou l’exploitant doit la préparer avec le bon propriétaire. Elle n’exécute pas de migration sur la base métier. Le test installe une vraie wheel dans un répertoire temporaire, démarre Django avec son AppConfig, applique ses migrations dans la base de tests, puis vérifie activation indépendante, permissions de service, MFA/reprise, CSRF, audit et conservation des données. Un dernier démarrage avec un fichier falsifié doit échouer avant exécution de son initialiseur.

La signature, les chemins, les imports masqués et les fichiers supplémentaires ont des tests adverses séparés. Ces portes ne certifient pas la sûreté de n’importe quel module tiers : chaque éditeur doit ajouter les tests métier et organisationnels de son propre code.

## Frontière communautaire/commerciale

Cette livraison charge uniquement les extensions déclarées **communautaires**, compatibles avec la distribution du projet. L’exemple est AGPL. Elle ne prétend pas qu’un import Python constitue une séparation juridique du noyau AGPL et elle refuse actuellement un manifeste commercial.

La distribution de modules propriétaires dans le même processus, leur licence adaptée, les entitlements et les éventuels services distants restent un chantier explicite. Une signature ne transforme pas une licence de code et ne rend pas un projet open source non modifiable. Les contrats d’outbox/consommation et de tâches tierces sont également à livrer séparément ; aucun champ de manifeste ne simule ces fonctions.
