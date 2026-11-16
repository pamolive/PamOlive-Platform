# Qualification Linux du correctif Expat

Ce laboratoire construit une base candidate dans un job GitHub-hosted isolé. Il ne modifie pas le Dockerfile produit et ne publie aucune image GHCR. Le workflow se déclenche uniquement sur `agent/expat4-linux-qualification`, dans le dépôt canonique ; un lancement manuel reste limité à cette même branche.

Le correctif reconstruit Expat 2.10.0 depuis les sources Debian sur trixie, puis **les deux** modules CPython 3.12.16 `pyexpat` et `_elementtree` avec le même SDK. Le contrôle de version de la capsule C reste intact. Le résolveur ABI distingue les symboles par défaut `@@` des symboles non par défaut `@`.

La liste `source-checksums.sha256`, elle-même épinglée dans le workflow, lie les sources du laboratoire au contexte Git exact. Le contexte exclut les fichiers locaux non suivis. Les fichiers `Dockerfile.candidate` et `Dockerfile.diff` sont des documents historiques ; seul `Dockerfile.lab` est exécuté par ce job.

Le parcours du laboratoire est séquentiel :

1. Installer les outils trixie et acquérir dix matériaux publics par taille et SHA-256.
2. Exécuter les 36 tests purs et vérifier réellement les signatures GPG, hors réseau et sans privilèges. Les tests purs peuvent lire les archives comme données en mémoire ; ils n’exécutent pas leur contenu.
3. Reconstruire les bibliothèques et modules, hors réseau après installation des outils. Chaque builder revérifie lui-même les signatures avant extraction et compilation.
4. Vérifier les tests amont narrow/wide, UBSan sur le corpus borné, les ABI, les cas C/Python et les suites XML de la version exacte de CPython.
5. Exporter uniquement les preuves et journaux publics des étapes de cette VM.

La confiance initiale distingue les clés primaires et les sous-clés signataires, avec des usages et bundles fermés par `Root-bootstrap-decision.json`. Les pins ont été examinés à partir des publications officielles ; ils ne constituent pas une vérification GPG déjà réussie. La vérification Linux réelle reste une condition de passage. Une signature valide atteste son matériau, pas la sécurité de tout le produit.

Les processus de compilation et d’oracles conservent leurs délais et sorties bornées. Le job dure au maximum 60 minutes. Le conteneur GPG utilise un compte non privilégié, un réseau désactivé, une racine en lecture seule, aucune capacité, 1 CPU, 512 Mio et 64 PID. Son nettoyage vise seulement le CID enregistré avec les labels du run et du commit. Toute ambiguïté échoue et bloque la suite ; la disparition de la VM ne prouve pas une libération.

Les artifacts excluent les homes GPG, les copies de matériaux, les arbres de travail, les paquets et l’image produit. En cas d’échec d’une couche BuildKit, ses journaux internes peuvent manquer : le log de build et le préflight disponibles ne permettent pas de déclarer cette étape réussie. Un export manquant reste inconnu.

Validation préparatoire : 36 tests purs sans échec ni exclusion, revue cryptographique et contre-tests indépendants, vérification statique du YAML et des commandes shell. L’intégration adapte uniquement les imports, les longues lignes et une chaîne de test aux règles Ruff du dépôt ; les arbres syntaxiques hors imports et chaîne littérale restent équivalents. La liste des empreintes est recalculée explicitement après ces changements.

Le run Linux `6997322` a réellement validé l’acquisition, les 31 tests alors présents et les trois signatures GPG hors réseau, avec neuf enfants terminés et drainés, puis le nettoyage du conteneur d’authentification. La construction a refusé la lecture stricte de `/etc/os-release` avant extraction/compilation Debian. Le correctif suivant lit le chemin fournisseur explicite `/usr/lib/os-release`, en conservant le lecteur régulier, le plafond et la garde trixie. Deux nouveaux tests refusent les liens, répertoires et autres distributions avant authentification ; les 33 tests passent localement. Sa nouvelle exécution native reste requise.

Le run `142675c` a confirmé le franchissement de cette garde puis l’échec de `dpkg-buildpackage` après environ 79 secondes. Ses journaux internes manquaient dans la couche BuildKit échouée ; la cause du sous-processus restait inconnue. Le wrapper de cette seule commande publie désormais, sur échec uniquement, les 8 Kio de fin de chaque flux et le reçu de processus de 4 Kio maximum, encodés en Base64 dans un JSON de diagnostic. Aucune sortie brute ni commande de workflow n’est relayée. Les lecteurs stricts, délais, plafonds, authentifications et contrôles H1 restent inchangés ; l’exception initiale est relancée, y compris si la sortie est fermée. Le succès ne lit ni ne publie ces journaux. Trois tests supplémentaires portent la suite locale à 36 cas ; ils ne constituent pas une compilation réussie.

Les quatre groupes High concernés ne seront pas déclarés corrigés par ces seuls tests préparatoires. Après succès du laboratoire, une livraison distincte devra intégrer le runtime produit, relancer les scans/SBOM et les consommateurs, puis toutes les régressions P0/PostgreSQL/SSH/RDP/restauration/Compose. Les 35 groupes High et la provenance de build restent des portes de promotion indépendantes.
