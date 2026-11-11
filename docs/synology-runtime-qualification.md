# Qualification réelle du packaging Synology — procédure locale

État au 11 novembre 2026 : **qualification finale du candidat corrigé en cours**. Quatorze tests ciblés de préflight réussissent. La première exécution TLS sur Compose 2.20.1 a validé migrations, démonstrateur, Web/worker, confiance proxy exacte, redémarrage, preuves V7/V8, restauration sur copie et healthcheck HTTPS avec CA vérifiée depuis le PC. Le client HTTP a aussi validé connexion, enrôlement MFA normal, refus du mot de passe seul et CSRF, puis révélé un module Governance absent de la démonstration. Le correctif et sa régression UI/API/export sur deux organisations sont prêts ; une nouvelle image et une nouvelle base sont nécessaires pour terminer le parcours complet. Aucun succès global du candidat corrigé n'est annoncé avant cette reprise.

Les CI complètes de `d247ed5639bc326b28331a791fdb0eca605fb955` qualifient le précédent packaging générique. L'ancienne topologie Web/PostgreSQL a passé des étapes runtime mais son HTTP loopback était inaccessible sur Docker29 ; la passerelle TLS corrige l'architecture sans ouvrir l'egress Web. Aucun reset, suppression de volume ou redémarrage global n'est une étape du présent runbook. L'inventaire NAS autorisé reste en lecture seule ; aucune installation n'est autorisée par ce document.

Ce document prépare une exécution future lorsque le Docker **local** est sain. Il n'autorise aucune connexion ou écriture NAS. Voir [préparation N0](synology-p1-preparation.md), [image qualifiée](image-distribution.md), [restauration](backup-restore.md), [déploiement](deployment-single-container.md) et [démonstrateur](p1-e-observe.md).

## 1. Conditions d'entrée et arrêt

Utiliser un Engine Linux local identifié, jamais un contexte distant : vérifier `docker context show`, puis la destination du contexte en privé et `docker version`. Ne publier ni l'inspection complète ni des variables d'environnement. En cas de blocage, arrêter la qualification ; demander une remise en état locale séparée. Ne pas basculer vers le NAS pour contourner le problème.

Inventorier les projets, conteneurs, volumes, réseaux, ports et ressources locaux avant toute création. Choisir un nom inédit `pamolive-p1-runtime-<suffixe>` et vérifier l'absence du projet, de son volume et de son réseau. Réserver un port loopback libre, une durée et des budgets CPU/RAM/disque. Aucun service existant ne doit être arrêté. Conserver la baseline et comparer après l'essai.

Les commandes suivantes sont un **runbook à paramètres**, pas un script déjà validé. Les blocs utilisent Bash dans un environnement Linux local avec Docker Compose v2 ; sous Windows, employer un terminal Linux local avec des fichiers privés sur son filesystem Linux, ou traduire explicitement les commandes. Remplacer les paramètres avant exécution. Ne pas lancer un bloc incomplet. Toutes les commandes Compose utilisent le fichier versionné exact, sans override de sécurité.

```sh
# Répertoire du checkout contrôlé, nom de projet neuf et chemins privés absolus.
COMPOSE_FILE=/chemin/checkout/deploy/synology-test/compose.yml
CONFIG_FILE=/chemin/prive/config
export PAMOLIVE_TEST_APP_ENV=/chemin/prive/application.env
PROJECT=pamolive-p1-runtime-SUFFIXE_UNIQUE
dc() { docker compose --env-file "$CONFIG_FILE" -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }
```

Ne jamais exécuter `down -v`, `volume rm`, `prune`, `system reset`, une suppression récursive, ni restaurer sur la base source. Arrêter seulement les services de ce projet en cas d'anomalie ; garder les volumes et preuves pour revue.

## 2. Obtenir et identifier les images

La branche de revue n'a pas conservé l'archive de production : l'étape de rétention est réservée à `main`. Ne pas inventer un digest à partir du SHA Git. La promotion officielle décrite dans [image-distribution.md](image-distribution.md) reste soumise à revue, protections, accord final de fusion et workflow de publication. Aucun contournement de cette porte n'est prévu ici.

À défaut d'archive récupérable, une construction locale constitue **un nouveau candidat de qualification**, même si son code correspond à d247ed5 : les paquets système peuvent différer. Construire depuis un export Git contrôlé, excluant les deux diagnostics locaux et tout fichier privé ; inspecter `.dockerignore`, l'état Git et le contexte avant build. Ne pas utiliser de secret de compilation. Relever Dockerfile, locks et révision complète. Exemple de construction locale :

```sh
docker build --platform linux/amd64 --target production \
  --label org.opencontainers.image.source=https://github.com/pamolive/PamOlive-Platform \
  --label org.opencontainers.image.revision=REVISION_GIT_COMPLETE \
  --tag pamolive-platform:qualification-REVISION_COURTE /chemin/export-git-controle
```

Le préflight exige une référence `référentiel@sha256:...`. Un simple tag de build ou un `sha256:...` de configuration ne satisfait pas ce contrat. Pour le candidat local, préparer un registre de laboratoire exclusivement loopback, nommé et isolé, sans exposer de secret ; approuver séparément ses ressources et son image par digest. Y pousser uniquement l'image contrôlée, puis la tirer par son **digest de manifeste** et utiliser cette référence dans le fichier privé. Ne pas modifier le préflight pour accepter un tag. Ce registre local est un outil de qualification, pas une publication GHCR ou une source accessible au NAS.

Distinguer et enregistrer : SHA Git, SHA256 de l'archive éventuelle, ID de configuration Docker, digest de manifeste/plateforme et digest d'index multiarchitecture éventuel. Comparer l'ID de l'image démarrée à l'ID de l'image tirée par digest ; ne pas comparer des objets de nature différente. Un rebuild ne reproduit pas automatiquement l'image de la CI. Le pipeline existant exporte Linux amd64 ; aucune compatibilité ARM n'est déclarée sans build et tests dédiés.

Pour PostgreSQL, sélectionner une image **17 Debian**, architecture vérifiée et UID postgres 999, puis tirer et noter son digest. Ne pas choisir Alpine ou une autre version en supposant les mêmes UID, chemins et outils. Vérifier les plateformes des deux images et l'architecture effective de l'Engine. L'émulation éventuelle ne vaut pas qualification native du futur NAS.

## 3. Configuration et secrets synthétiques

Créer un répertoire privé hors dépôt/contexte de build. Copier [config.example](../deploy/synology-test/config.example) et [application.example](../deploy/synology-test/application.example). Générer localement des clés distinctes et aléatoires et deux mots de passe distincts, exclusivement synthétiques. Le mot de passe applicatif comprend exactement 64 caractères hexadécimaux minuscules. Ne jamais les passer littéralement dans une ligne de commande, les imprimer ou enregistrer un inspect/config complet.

Renseigner les trois références d'images par digest (application, PostgreSQL17Debian, Nginx unprivileged Alpine UID101), projet neuf, port TLS loopback et plafonds CPU/RAM approuvés pour ce seul test local. Préparer certificat synthétique localhost/127.0.0.1 et clé privée sous le nouveau répertoire protégé, lecture effective UID101, clé mode0400 propriétaire101:101. Ne pas désactiver la validation de certificat du client externe. Conserver `DATABASE_URL` sur utilisateur `pamolive_test`, serveur `postgres`, base `test_pamolive_p1`. L'application ne reçoit jamais le mot de passe propriétaire initial PostgreSQL.

Sur le filesystem Linux privé : répertoire 0700, environnement applicatif et secret propriétaire 0600 ; **seul** le nouveau fichier du mot de passe applicatif doit être propriétaire 999:999, mode0400. Vérifier cette lecture depuis un conteneur ponctuel avec la même image PostgreSQL et UID999, en retournant seulement succès/échec. Vérifier le refus pour un UID sans droit. Un bind Windows ne démontre pas ces permissions ni celles de DSM. Ne changer aucune ACL ou propriété existante.

```sh
python -m deploy.synology_preflight --env-file "$CONFIG_FILE" \
  --application-env "$PAMOLIVE_TEST_APP_ENV"
```

Succès attendu : topologie validée sans afficher les secrets. Le chemin explicite `--application-env` est forcé dans l'environnement d'interpolation Compose et sert également au contrôle anti-alias. Conserver le même export absolu `PAMOLIVE_TEST_APP_ENV` pour **toutes** les commandes Compose de cette procédure ; ne pas modifier le fichier ou l'export entre validation et démarrage. Cette approche fonctionne sans l'option `config --environment`, absente de Compose2.20.1. Échec : corriger uniquement la configuration privée ; ne pas élargir les contrôles. Le préflight ne prouve ni ressources disponibles, ni disponibilité du port, ni santé Docker.

## 4. PostgreSQL, migrations et données de démonstration

```sh
dc up -d --wait --wait-timeout 90 postgres
dc exec -T postgres pg_isready -U pamolive_test_owner -d test_pamolive_p1
dc run --rm --no-deps --user 1000:1000 web python manage.py migrate --noinput
dc run --rm --no-deps --user 1000:1000 web python manage.py check
dc run --rm --no-deps --user 1000:1000 web python manage.py showmigrations --plan
dc run --rm --no-deps --user 1000:1000 \
  -e PAMOLIVE_SYNTHETIC_DEMO=1 web \
  python manage.py pamolive_observe_demo --synthetic-only
```

Exécuter migrations et démonstrateur **avant le démarrage du superviseur** : `runjobs` peut échouer et faire arrêter le conteneur sur schéma vierge. La commande de démonstration refuse toute base contenant déjà une organisation ou un compte. Ne pas la relancer sur une base peuplée et ne pas supprimer des lignes pour contourner ce refus.

Conserver le manifeste sans secrets : deux organisations, mêmes identifiants distants, PC-483 conforme, PC-991 en écart, identité non résolue indéterminée ; collision manuel/collecteur sans remplacement ; étapes provisioning/retrait et reprise simulés. L'adaptateur est en mémoire, sans réseau. Ce manifeste ne démontre pas que le daemon tourne : ce contrôle suit.

Vérifier via une connexion applicative que le rôle effectif est `pamolive_test`, sans SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS. Vérifier l'intégralité du journal de migrations et l'exécution de `governance.0003_exception_register`. Relever propriétaire et mode du nouveau volume PostgreSQL sans afficher de données.

## 5. Application, worker et parcours humain

```sh
dc up -d --no-build --pull never --wait --wait-timeout 120 web
dc ps
dc exec -T web python -m deploy.check_runtime
```

La confiance proxy reste vide lors de ce bootstrap. Démarrer ensuite la seule passerelle : `dc up -d --no-build --pull never --wait --wait-timeout 120 gateway`. Inspecter uniquement son adresse sur `${PROJECT}_frontend`, inscrire ce peer exact `/32` (ou `/128`) dans le fichier applicatif privé, puis `dc up -d --no-build --pull never --force-recreate --wait --wait-timeout 120 web`. Recharger Nginx avec `dc exec -T gateway nginx -s reload` pour renouveler sa résolution de Web sans recréer la passerelle. Vérifier de nouveau son peer et la confiance effective côté Web. Ne pas utiliser une plage réseau ni un IP supposé. L'accès HTTPS n'est validé qu'après cette porte opérationnelle ; le préflight accepte le vide seulement pour le bootstrap fermé aux en-têtes transmis.

Contrôler explicitement la présence du **Web et de `manage.py runjobs`**, UID1000 et sans capacités effectives ; moteur natif UID1001, sans secrets applicatifs. Le vérificateur de runtime actuel groupe les processus applicatifs : compléter la vérification distincte du worker. Contrôler santé HTTP, connexions PostgreSQL et absence de boucles d'erreurs/OOM/restarts. Ne publier que des extraits de logs revus et expurgés. Un healthcheck HTTP sain ne démontre pas la progression des files ; utiliser une tâche synthétique connue et suivre son résultat, sans cible réseau réelle.

Les comptes du démonstrateur ont des mots de passe inutilisables. Préparer ensuite un **nouveau compte opérateur synthétique** par les commandes/formulaires existants, l'affecter explicitement aux organisations de test avec le rôle minimal, définir son mot de passe interactivement et enrôler sa MFA via le parcours applicatif. Ne pas extraire les graines MFA des comptes de fixture, supprimer leur MFA, ni fabriquer une indépendance de quorum PAM. Garder mots de passe, graines et codes de récupération hors rapport et dépôt.

Le Compose impose DEBUG=false et les cookies sont Secure par défaut. La passerelle fournit une terminaison **TLS privée loopback**, avec certificat et origine explicitement configurés avant de déclarer l'accès humain utilisable. Le client doit vérifier la CA synthétique et le nom, les cookies Secure/HttpOnly/SameSite, CSRF et MFA, ainsi que le refus d'en-têtes transférés depuis un peer non approuvé. Ne pas exposer HTTP sur toutes les interfaces ni désactiver MFA/CSRF/cookies Secure pour contourner un échec de login. La configuration localhost ne qualifie pas un accès à l'IP du NAS ; un nom/certificat/port réseau privé NAS exigera son propre plan approuvé.

Avec le navigateur sur le poste de test : login et MFA, sélection explicite du tenant, `/identities/360/`, `/governance/workspace/`, `/observe/`, détails PC-483/PC-991, exports et liens de preuves. Confirmer séparation intention/décision/droit/exécution/observation, provenance collector et manual distinctes, et historique de retrait. Tester deux organisations et le refus de Recertification dans celle où le module est désactivé. Refaire les lectures via API de session ; refus d'un UUID étranger et d'une session anonyme. Ne pas considérer les seuls codes200 comme une validation fonctionnelle.

## 6. Ressources, redémarrage et persistance

Contrôler les champs ciblés de HostConfig pour CPU, mémoire, swap égal à mémoire, PID, filesystem readonly, tmpfs et rotation json-file3×5Mio. Vérifier les trois réseaux : ingress réservé à la passerelle, frontend interne pour passerelle/Web, database interne pour Web/PostgreSQL ; ni Web ni PostgreSQL ne rejoignent ingress et la passerelle ne rejoint pas database. Seul TLS8443 est publié sur loopback ; aucun port HTTP Web/PostgreSQL ou socket hôte. Ne pas exporter l'inspect complet qui contient les environnements.

Relever `docker stats --no-stream` pour les trois seuls conteneurs nommés, espace du nouveau volume et taille des logs pendant le parcours fonctionnel. Aucun test de charge. Le Compose n'impose **aucun quota dur de stockage ou d'IO** ; quota filesystem, budget, surveillance et seuils d'arrêt restent à approuver et qualifier. Une limite RAM ne remplace pas ces garanties.

Enregistrer les identifiants/empreintes des lignes et preuves, le volume monté et les compteurs de migration. Puis :

```sh
dc stop -t 20 gateway web postgres
dc up -d --wait --wait-timeout 90 postgres
dc up -d --no-build --pull never --wait --wait-timeout 120 web
dc up -d --no-build --pull never --wait --wait-timeout 120 gateway
dc exec -T web python -m deploy.check_runtime
```

Vérifier mêmes lignes, reçus et journal de migrations, même volume, preuves vérifiables, nouveau login et lectures fonctionnelles. Aucun remigration/reset du démonstrateur. `restart: no` est intentionnel : cette étape valide un redémarrage manuel, pas une reprise automatique après boot NAS. Tester séparément l'arrêt d'un seul processus enfant synthétique si prévu au plan local ; le superviseur doit arrêter le conteneur, pas laisser un faux service sain.

## 7. Sauvegarde et restauration sur copie

Réutiliser l'outil existant plutôt qu'un `pg_restore` sur la base source. Identifier le **nouveau conteneur PostgreSQL** et son réseau exact, créer répertoire privé de rapports neuf et chemin d'archive encore inexistant. Les clés restent strictement identiques pour la copie. Exemple paramétré :

```sh
python -m deploy.check_restore \
  --postgres-container ID_DU_POSTGRES_DE_CE_PROJET \
  --database-network "${PROJECT}_database" \
  --application-image REFERENCE_APPLICATION_PAR_DIGEST \
  --application-env /chemin/prive/application.env \
  --source-database test_pamolive_p1 \
  --archive /chemin/prive/neuf/demo.dump \
  --report-directory /chemin/prive/rapports-neufs
```

L'outil prend un snapshot cohérent et crée une nouvelle base/copie avec rôle restreint ; il ne remplace pas la source. Le corpus Observe ne contient **aucune capture PAM scellée**. Le flag `--require-populated` est réservé au corpus complet incluant ces captures : il n'est pas adapté à cette seule démonstration. Ne pas modifier ce contrôle du produit pour faire passer le corpus Observe.

Avant sauvegarde, vérifier une population réelle : au moins six évaluations V7 signées et vérifiables, au moins huit reçus V8 vérifiables et exactement un reçu par événement du démonstrateur. Le helper local de qualification impose ces assertions, mais son existence ne constitue pas une preuve d'exécution. Dans le rapport de restauration, exiger `result=OK`, `pending_migrations=0`, au moins trois valeurs chiffrées vérifiées, le même nombre de reçus V8 que dans la source et un nombre de preuves signées vérifiées au moins égal à la somme des compteurs V7/V8 source. Exiger aussi les indicateurs vrais d'audit valide, compagnon de clé vérifié, garde PostgreSQL append-only testé, manifeste complet comparé, refus de mauvaise clé et de mauvais mot de passe, archive source inchangée et suppression de la copie et du rôle temporaires. La comparaison du manifeste complet doit couvrir les empreintes de tous les modèles gérés, et non seulement des compteurs.

Le compteur de captures scellées doit rester zéro pour ce corpus : inscrire explicitement **restauration de captures PAM NON EXERCÉE par le démonstrateur Observe**. Le test de captures du corpus complet réalisé par la CI générique est une preuve distincte ; il ne doit pas être présenté comme exécuté sur cette topologie Synology locale.

Conserver les rapports privés et leurs hash. La suppression contrôlée de la base et du rôle temporaires fait partie du vérificateur ; aucun volume n'est supprimé. Vérifier ses indicateurs de nettoyage ; en cas d'échec, inventorier et conserver, sans commande de nettoyage global. Refaire le parcours source après sauvegarde pour confirmer son intégrité. Un résultat du CLI sans les assertions de population et les preuves correspondantes ne suffit pas à qualifier la restauration du démonstrateur.

## 8. Sortie et rapport d'acceptation

Arrêter uniquement ce projet avec `dc stop` si le laboratoire ne doit pas rester actif. Conserver volume et données ; tout nettoyage ultérieur demande un inventaire précis et une autorisation distincte. Comparer l'état des services locaux préexistants avec la baseline.

Rapporter chaque contrôle : réussi/échoué/non exécuté, commande, heure, durée, preuve expurgée ; révision complète et références/digests, plateforme effective, rôles/UID, migrations, login/MFA, trois verdicts, isolation, daemon, limites réellement appliquées, mesures et restauration. Ne pas annoncer l'objectif terminé si une étape reste non exécutée.

Avant NAS, demander et confirmer modèle/DSM/CPU/RAM, volume/filesystem/espace, sauvegardes et restaurabilité, services/ports, adresse et administration autorisée, puis périmètre du premier état des lieux en lecture seule. Présenter ensuite un plan exact d'installation et attendre l'accord avant toute écriture. Aucun résultat local, ancienne observation NAS ou accord de revue GitHub ne remplace cette autorisation.
