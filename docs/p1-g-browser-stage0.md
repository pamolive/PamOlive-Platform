# P1-G — qualification préalable du navigateur, stage0

Cette tranche prépare un témoin sur runner GitHub Linux éphémère. Elle ne
modifie aucun service métier, modèle, migration, vérificateur P0 ou profil PAM.
Elle n'exécute pas le JavaScript du portail : elle vérifie les prérequis avant
la future tranche navigateur. Aucun navigateur ou contrôle graphique du PC,
NAS, serveur réel ou compte privilégié réel n'est utilisé.

Le parent `a57350fe` possède deux CI complètes terminées : 1 439 tests généraux
comptés, 1 397 réussites et 42 exclusions dans chacune. Les portes SSH/RDP,
HA/partition sur un même hôte, restauration et retour arrière passent. Les
35 groupes High non arbitrés restent le seul échec final et bloquent la
promotion. Les tests d'extension conservent aussi leurs exclusions contextuelles.
Ces résultats ne qualifient pas le prochain commit ni ses images.

## Entrées fermées et responsabilités

`qualification/b0_pre` contient un contrôleur standard-library, deux assets
(JS et pins), un manifeste, leurs régressions pures et leurs empreintes de
revue. Le workflow dédié vérifie les cinq empreintes concrètes avant exécution
des outils ; le contrôleur vérifie le manifeste puis les mêmes buffers des
assets avant d'interpréter les pins. Les fichiers irréguliers, liens, doublons
JSON et valeurs non finies sont refusés sous limites de taille.

Le conteneur ne reçoit que le spool neuf des deux assets en lecture seule et
un répertoire de preuves synthétiques. Aucun dossier de sources entier,
`.git`, socket Docker, secret, environnement applicatif ou donnée PostgreSQL
n'est monté. Le daemon du runner est sélectionné explicitement par son socket
Unix ; configuration Docker neuve/vide, aucun login et overrides refusés.

Le pin Linux/amd64 MCR provient de la revue des métadonnées publiques de
Playwright 1.64.1. L'image est acquise par digest exact, jamais par fallback
vers un tag ; son config ID doit également correspondre. Aucun npm, TGZ,
import Playwright, serveur TLS ou image PamOlive n'est nécessaire au stage0.
Le pin établit l'identité des octets, pas une attestation indépendante d'éditeur.

## Phases et refus

1. `prepare` vérifie Linux GitHub-hosted nonroot, mémoire disponible d'au moins
   3 Gio (borne cgroup comprise), 8 Gio libres sur le travail et sur le stockage
   réellement retourné par Docker. Si containerd est actif sans racine établie,
   `B0_PRE_CONTAINERD_STORAGE_UNPROVEN` refuse avant tout pull ; aucune racine
   n'est devinée. Une observation publique typée est conservée.
2. `pull` acquiert explicitement l'image publique une seule fois, délai 480 s,
   stdout/stderr non conservés. Timeout ou résultat incertain ne prouvent pas
   l'arrêt côté daemon ; aucun stage suivant ou retry implicite.
3. `stage0` utilise `--pull never`, même UID/GID nonroot que le runner,
   rootfs RO, capacités supprimées, NNP, réseau none, IPC privé, 256 Mio sans
   swap supplémentaire, 0,5 CPU, tmpfs 64 Mio noexec/nosuid/nodev, shm 16 Mio,
   limite de processus et journaux. Le profil est inspecté avant démarrage.
4. Le JS utilise seulement les builtins Node. Il vérifie Node >=20, les
   attributs UID/RO/capacités/NNP, certutil et un NSS neuf vide, puis le
   `--version` de Chromium attendu. Arrêt au premier prérequis absent.
   Une mesure non atteinte reste `null`, distincte d'une absence constatée.
5. `cleanup` réconcilie l'intention durable créée avant la requête Docker.
   Nom, label, image, utilisateur et CID doivent correspondre ; un timeout
   n'efface pas l'intention. Objet étranger, absence tardive ou daemon
   inaccessible restent indéterminés, sans suppression ni fausse libération.

Les caches d'image publics restent sur le runner jetable. `resources_released`
vise les objets possédés et l'absence de pull inconnu ; ce champ ne signifie
pas que toutes les ressources ou images du daemon ont été supprimées. La
marge disque est mesurée ; aucun quota disque dur n'est revendiqué.

## Validation préparatoire et limites

Les six fichiers de qualification sont byte-identiques au gel r2 revu indépendamment.
18 régressions pures mockées et 24 contrôles adverses indépendants passent,
sans Docker/PG/réseau ou exécution du JS. Ruff/format passent avec la
configuration du projet ; Bandit ne signale aucune erreur ou finding au seuil
high du déploiement. `node --check` passe sur le JS gelé : syntaxe seulement.
La première version, dont cinq défauts ont été identifiés en contre-revue,
reste conservée hors dépôt avec son verdict bloquant.

Le premier déclenchement du commit `423adc49` a ensuite été refusé par GitHub
avant tout job : `runner.temp` n'est pas disponible dans `jobs.<job_id>.env`.
La syntaxe YAML locale avait passé sans détecter cette contrainte de contexte.
Le dossier est maintenant initialisé par une étape sur le runner via ses
variables d'environnement, puis transmis aux étapes suivantes par `GITHUB_ENV`.
Les deux assets, leur contrôleur, les pins et les contrôles restent inchangés.
La reprise CI du correctif demeure une mesure distincte ; le refus initial
ne constitue pas un lancement Docker ou un succès des prérequis.

Le workflow vérifie les régressions et les mêmes seuils statiques avant toute
acquisition. Ses outils hôte reprennent les versions de sécurité du projet
et Ruff 0.14.3 ; leur provenance n'est pas fermée par un nouveau manifeste de
wheels hashées. Le bootstrap pip garde son verrou hashé. Cette limite reste
distincte du pin MCR et ne donne aucune attestation de build.

La mesure CI réelle du nouveau commit reste à effectuer. Un succès stage0
prouverait seulement présence/version/profil/NSS vide. Il ne prouverait ni
sandbox Chromium actif, ni confiance TLS/CA, ni CDP, WebAuthn, JavaScript du
portail, transport PAM ou indépendance humaine. Un NSS neuf n'efface pas le
Chrome Root Store système. Les futures phases TLS/sandbox/CDP restent hors
de ce lot ; elles devront inclure les refus CA inconnue et mauvais SAN avant
le parcours applicatif. Aucun contournement TLS, `--no-sandbox`, capability
SYS_ADMIN, seccomp unconfined ou IPC hôte n'est introduit.

Seul `public-report.json` est publié : codes, états, versions et observation
stockage bornée. Aucun profil navigateur, clé privée, cookie, ticket, page,
HAR ou capture. P1-G complet, services P2, image publiable et NAS restent
des réceptions distinctes.
