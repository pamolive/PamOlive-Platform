# Mesure publique commune W/A1 — DATA seulement

Source proposée pour le job Platform existant. Root intègre/revoit/publie et
décide ensuite l'exécution. Aucun Docker, CLI, réseau, SQL ou image exécuté par
l'auteur. Les tests utilisent seulement un faux runner. Pas de nouveau workflow.

Quatre argv fixes, via `/usr/bin/docker --host unix:///var/run/docker.sock
--config <nouveau dossier vide>` : version, info, image inspect du PG17.12
manifest6f7593…, image inspect de `pamolive-platform:ci` construit par le job.
Zéro create/start/load/stop/pull/tag/exec/container inspect. Une image absente
reste une non-réception ; aucun téléchargement ou repli.

TCB explicite : image GitHub-hosted runner, actions checkout/setup épinglées
déjà admises par Platform, Docker CLI/daemon et stdlib hôte. Le binaire public
est lu/hashé en chunks64KiB sous128MiB, identité FD/path avant/après, avant
et après les quatre requêtes. Aucun SHA inconnu n'est pris pour une attestation.
Le type régulier, UID, GID et les bits de permission du fichier sont aussi
rapportés. UID/GID participent aux contrôles d'identité FD/path ; ces observations
ne constituent ni une approbation de propriétaire ni une admission de profil.
Le postcheck est incorporé avant l'unique écriture du rapport : tool changé ou
non relisible empêche `four_queries_received`, sans reclassifier les données.

Chaque commande est exécutée par le helper reçu byte-exact `98233…`, timeout15s,
stdout32KiB/stderr4KiB bornés AVANT rétention, stdin fermé. H1 inconnu (PID,
reap/drain/cleanup, exception, kill/timeout) arrête les commandes suivantes.
Un simple exit non nul avec H1 confirmé permet les autres lectures. Le compteur
ne représente pas les requêtes HTTP internes/plugins éventuelles du CLI.

Env enfant fermé : PATH système, HOME neuf privé, LANG/LC_ALL=C ; pas de token,
config Docker utilisateur, proxy, contexte ou override API ambiant. Pas de
`DOCKER_API_VERSION` forcée : la version effective est précisément la donnée
à observer. Le dossier Docker neuf ne contient que auths/proxies vides.
Le script ne lit aucun environnement applicatif ni PG et ne reçoit aucun
credential. Le daemon local est la seule cible construite par les argv.

Les projections n'incluent ni hostname/proxy de `docker info`, ni Config.Env.
La configuration image ne demande que huit champs publics. Valeurs inattendues,
labels hors des trois clés publiques et namespaces RepoDigests non publics
deviennent **redacted** sans valeur, hash ou longueur. Les stderr sont seulement
classés en enums (`empty`, `local_image_absent`, `template_error`,
`engine_access_failed`, `unclassified`), jamais enregistrés bruts ou hashés.
Les observations de processus omettent aussi les tailles stdout/stderr brutes.
Les empreintes du binaire public Docker et les identifiants/digests des images
et couches publiques restent présents ; aucune empreinte de valeur masquée
ou de stderr n'est publiée.

Le template image utilise range/index de `.Config` pour conserver la présence
des clés. Contrat primaire précis CLI29.6.1 : TemplateInspector tente le type
puis `tryRawInspectFallback` relit le raw JSON avec UseNumber en map et rejoue
le template ; le buffer typé en échec est jeté. ImageInspectWithRawResponse
fournit ce raw. Ce n'est pas une supposition de map universelle. Un autre CLI
incompatible doit produire `template_error` et une non-réception, pas un profil
normalisé. Références données par NSS : docker/cli/v29.6.1,
`cli/command/inspect/inspector.go` et `cli/command/image/inspect.go`.

Le rapport `public-report.json` est le seul fichier à publier. Ne pas publier
home/docker-config, fichiers temporaires ou stdout/stderr Docker. Il ne donne
ni getent, UID/GID postgres, ownerPGDATA, sandbox, permission, SQL, profil admis,
W installé ou autorité de build. Root recevra les données avant un nouveau
commit fixant le profil ; aucune auto-acceptation dans la même campagne.

Position : après le scan final, `if: always()`, avant l'upload/cleanup existant,
sans continue-on-error. Les anciennes portes s'exécutent donc avant cette mesure.
Le fragment n'ajoute ni permission ni job. Checkout doit conserver
`persist-credentials: false` et les actions existantes épinglées.

Tests : `CorePython -I -B -X utf8 <dossier>/run_pure.py`, sept méthodes et audit
subprocess/socket/sqlite, zéro skip. Aucun test n'exécute le vrai collecteur main.
