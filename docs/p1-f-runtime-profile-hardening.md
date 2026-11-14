# P1-F — Durcissement du profil runtime N0

Travail local du 14 novembre 2026, repris après l’interruption du correctif
partiel du 12 novembre. Ce lot applique les contrôles proposés dans
[la contre-revue des 22 risques OS](p1-f-os-runtime-profile-review.md).
La [preuve historique](../.github/qualification/evidence/p1-f-os-runtime-profile.v1.json)
reste inchangée : aucun statut CVE, seuil scanner, inventaire binaire, exception
CI ou contrôle PAM n’est modifié par ce lot.

## Commande et séparation des rôles

Le préflight refuse une commande web différente de
`["python", "deploy/runtime.py"]`, un entrypoint explicite, un utilisateur
différent de root et un répertoire de travail différent de `/app`. Une commande
absente hérite encore du CMD de l’image : le plan Compose seul ne permet pas de
vérifier cette valeur héritée. Les configurations Compose montées dans le
service web sont également refusées, comme ses volumes et secrets déjà refusés.

`validate_image_runtime()` permet de vérifier séparément l’objet **Config**
d’une image qualifiée : CMD exact, entrypoint absent, utilisateur root,
répertoire `/app`, environnement explicite sans doublon, locale C.UTF-8,
chemins système approuvés et les deux préfixes natifs fixes. Cette vérification
est pure ; elle ne prouve ni le digest ni le contenu des layers.

Le CLI accepte facultativement `--image-config /chemin/absolu/config.json`
(objet Config, pas une sortie complète de `docker inspect` ni un manifeste
OCI ; taille maximale 1 Mio). Sans ce fichier, il indique explicitement que
la commande et l’environnement hérités de l’image restent non vérifiés.
Le CLI conserve son unique appel daemonless `docker compose config --format json`.
Un Config fourni invalide est refusé avec un diagnostic générique.

Le superviseur conserve la validation des clés P0 et de PostgreSQL avant tout
enfant. Il lance web et jobs UID/GID1000 et le moteur UID/GID1001, sans groupes
supplémentaires. Le moteur conserve exactement ses quatre variables initiales
PATH, LANG, LD_LIBRARY_PATH et PYTHONUNBUFFERED ; son lanceur natif ajoute
ensuite HOME et GUACAMOLE_HOME vers son répertoire privé.

## Montages temporaires bornés

Le préflight impose les destinations suivantes et leur présence exacte.
La taille positive peut être inférieure au plafond. Seuls `size`, `mode`, les
propriétaires explicitement requis et les flags restrictifs facultatifs `rw`,
`noexec`, `nosuid`, `nodev` sont admis. Options inconnues, doublons, `exec`,
`suid`, propriétaire inattendu, destination alternative ou forme ambiguë sont
refusés avant lancement.

| Service | Destination | Plafond | Mode | UID/GID imposés |
| --- | --- | --- | --- | --- |
| web | `/tmp` | 64 Mio | 1777 | aucun override |
| gateway | `/tmp` | 16 Mio | 1777 | aucun override |
| postgres | `/tmp` | 32 Mio | 1777 | aucun override |
| postgres | `/var/run/postgresql` | 8 Mio | 0775 | 999/999 |

Le Compose versionné reste compatible. Les flags restrictifs facultatifs ne
sont pas présentés comme présents lorsqu’ils sont absents de ce Compose.

## Environnement avant et après l’interpréteur

Le préflight examine l’environnement web résolu par Compose **avant le
démarrage du Python du conteneur**. Le contrôle optionnel du Config complète
cette vérification pour l’environnement de l’image. Les variables `LD_*`
(sauf LD_LIBRARY_PATH égal aux deux préfixes natifs), les commutateurs Python
non approuvés, GCONV_PATH, GLIBC_TUNABLES et les chemins de chargement GIO/GI
sont refusés, même vides. PYTHONUNBUFFERED et PYTHONDONTWRITEBYTECODE ne sont
admis qu’à `1` ; PYTHON_VERSION et PYTHON_SHA256 sont des métadonnées inertes
du parent officiel Python. Une vérification dans `runtime.py` seule serait
trop tardive pour empêcher une injection avant l’exécution de Python.

LANG et LC_* fournis doivent être C.UTF-8. LANGUAGE, LOCPATH, NLSPATH, DISPLAY,
XAUTHORITY et les familles FONTCONFIG* et XDG_* sont refusés au préflight.
Pour les enfants web/jobs, le superviseur retire ces variables et toutes les
LC_* héritées, puis impose LANG=LC_ALL=C.UTF-8, HOME=/home/pamolive, PATH
système minimal et LD_LIBRARY_PATH fixe. Les variables applicatives non
concernées, leurs valeurs et les secrets restent inchangés ; les tests
couvrent notamment clés, URL PostgreSQL, MFA, LDAP, SCIM et paramètres de
connecteurs. Aucun diagnostic ne restitue les valeurs reçues.

Cette liste traite les mécanismes identifiés dans ce profil. Elle ne
transforme pas les extensions Python approuvées en sandbox et ne ferme pas
toutes les capacités possibles de chaque bibliothèque native.

## Sonde effective en lecture seule

`python -m deploy.check_runtime` et `python deploy/check_runtime.py` fonctionnent
sans PYTHONPATH supplémentaire. Les imports de runtime et de la sonde ne
démarrent ni service, ni SQL, ni lecture de `/proc`. L’entrée `runtime.py`
conserve `__main__` et le `<run_path>` attendu par les régressions des clés P0.

Sur Linux, la sonde exige le superviseur root et son parent PID1/init attendu,
ainsi que les vrais processus uvicorn, runjobs et guacd directement supervisés.
Le vecteur uvicorn doit correspondre exactement à celui du superviseur, sans
suffixe ni option supplémentaire ; seul le nombre de workers peut varier,
en entier décimal positif de 1 à256. Cette borne est celle du profil contrôlé
par la sonde, sans changement du paramétrage fonctionnel du superviseur.
Elle vérifie, pour les processus des deux rôles, les quatre UID/GID, l’absence
de groupes supplémentaires, NoNewPrivs=1 et CapEff/CapPrm/CapInh/CapAmb=0.
Ses sous-sondes lisent les environnements sous l’UID du rôle concerné ;
le moteur doit être incapable de lire ceux de web/jobs. HOME natif doit être
un vrai répertoire UID/GID1001 mode0700 sous `/tmp/pamolive-engine-*`.

La sonde contrôle aussi les environnements approuvés, le tmpfs `/tmp` borné à
64 Mio et mode1777, la racine en lecture seule, les ancres de polices/HOME
sans lien symbolique ni écriture par un autre rôle, et l’absence d’ombrage du
code, des bibliothèques et des configurations de polices. Un montage sur un
ancêtre comme `/etc`, `/home` ou `/var` est également refusé. Les options VFS
et de superbloc sont distinguées : un superbloc overlay `rw` ne contredit pas
un montage racine `ro`, et un superbloc `ro` ne masque pas un montage racine
`rw`. Les lectures `/proc`, environnements et montages sont bornées.
La sonde termine par le contrôle HTTP de santé existant.

### Init Docker et frontière de confiance hôte

L’essai effectif B3r5-r2 du14novembre a révélé un refus de la sonde sur le
montage légitime de Docker Desktop29.6.1 : `--init` ajoute un fichier externe
en lecture seule à `/usr/sbin/docker-init` sur cette base usrmerge. Le sujet
B3r5, commit `df8acff`, conserve ce refus `runtime_shadow_mount` dans sa preuve ;
ses tests fonctionnels ne constituent pas un succès de cette sonde.

Le correctif maintient `--init` et les protections générales de `/usr`. Sa seule
exception est ce chemin de fichier exact, avec un unique montage VFS `ro`
sans `rw`, après vérification du vrai PID1. Les UID/GID complets de PID1 et du
superviseur doivent être root, NoNewPrivs doit être1, les parentés doivent être
0 puis1, et l’argv de PID1 doit correspondre à l’init Docker attendu suivi du
vecteur exact du superviseur déjà reconnu. Aucun simple basename, chemin ou
booléen fourni à la sonde ne vaut preuve d’approbation.

La cible doit être un fichier régulier root:root, exécutable par son
propriétaire, sans écriture groupe/autres ni bit spécial. La résolution du
lien noyau `/proc/1/exe` doit aboutir au même chemin canonique et son device,
inode, mode, UID et GID doivent correspondre à ceux de la cible. Copie d’un
autre fichier, lien symbolique cible, autre PID, mauvais argv/propriétaire/mode,
montage inscriptible/dupliqué, ancêtre ou autre sous-chemin restent refusés.
Sans init réel vérifié, aucune exception n’est accordée.

Ce binaire appartient au Docker/host de confiance et constitue donc une
partie explicite du TCB local ; il ne fait pas partie des layers attestés de
l’image. L’identité fichier/exécutable établit qu’il s’agit du même objet,
pas sa provenance constructeur face à un hôte root compromis. Les capacités
nulles sont exigées pour web/jobs et le moteur ; aucune affirmation de
CapEff=0 n’est ajoutée pour l’init ou le superviseur root.

## Vérifications et limites de qualification

Contrôles locaux exécutés avec Python3.12.10 sous Windows :

```powershell
.venv/Scripts/python.exe -m unittest tests.test_runtime_environment tests.test_synology_preparation tests.test_key_configuration -q
.venv/Scripts/ruff.exe check deploy/runtime.py deploy/check_runtime.py deploy/synology_preflight.py tests/test_runtime_environment.py tests/test_synology_preparation.py
.venv/Scripts/ruff.exe format --check deploy/runtime.py deploy/check_runtime.py deploy/synology_preflight.py tests/test_runtime_environment.py tests/test_synology_preparation.py
```

Résultat : **52 tests réussis, aucun ignoré** ; Ruff et format ciblés réussis.
Les tests incluent les cinq mutations initiales (commande, utilisateur, tmpfs
fonts, locale non-C, DISPLAY), les montages ancêtres, options inconnues,
variables de chargement inconnues, Config d’image invalide, compatibilité du
Compose versionné, rôles effectifs simulés et régressions des clés P0.
Les adverses init couvrent également permissions, UID/GID/parentés/argv,
résolution du vrai exécutable, inode/device, montage RO unique et maintien du
refus de tous les autres ombrages. Le correctif init nécessite un nouveau
commit et une nouvelle image avant un verdict effectif de sonde depuis celle-ci.
Le parsing Compose est local et daemonless. Les lancements Python des tests
d’import ne lancent aucun service applicatif. Les invocations script et module
de la sonde atteignent le refus plateforme générique sur Windows, sans erreur
d’import ni divulgation d’environnement.

**La copie de sources de l’image R4 a été figée avant ces correctifs. Cette
image ne les contient pas.** Aucun résultat smoke/SSH/RDP de cette image ne
qualifie le nouveau superviseur ou la nouvelle sonde. Ce lot n’a démarré ni
Docker Engine, ni PostgreSQL, ni environnement NAS et ne revendique aucune
exécution effective de la nouvelle sonde dans l’image finale. Il reste à
construire une nouvelle image identifiée, contrôler son Config et ses sources,
exécuter la sonde Linux et les non-régressions natives/PAM sur cette image,
puis rattacher les résultats à son digest et à son scan exact.

Les 22 risques historiques restent ouverts selon leurs conditions propres.
La fermeture des chemins cJSON/Expat, les sources Debian exactes, les nouveaux
consommateurs, l’acceptation GSS/Kerberos, les omissions makecheck et les
qualifications multi-hôtes/production sont des travaux distincts.
