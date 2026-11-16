# Sonde PG publique R3 — owner Linux CI concret

Increment separe du laboratoire W/V R3. Aucun Docker, SQL, NAS ou reseau reel
execute par l'auteur ; aucun checkout modifie. La campagne proposee ne depend
pas d'un stockage containerd qualifie ni d'une propriete PGDATA deja connue.
Elle lit seulement `/usr/bin/getent passwd postgres` dans une instance isolee de
l'image PG17.12 deja presente dans le job, sans installer/pull une image.
Root doit revoir et integrer les pins/fragment avant cette nouvelle campagne DATA.

## Contrat exact de cette source

CLI `/usr/bin/docker` regulier, root:root0755,45 526 415octets, SHA
`3e898b1e7498b1bf98ec29a3d2ce77f9f09dd357e0b8dbf6ca69b463a871de88` : faits
publics recus sur les deux runs d47. Controle metadata, FD/path, ctime et hash
avant/apres **chaque** commande. CLI/Engine29.4.2 Linux/amd64 seulement, API
operationnelle imposee1.52 ; max serveur1.54/min1.40. L'API1.54 de decouverte
d47 est une reference historique, pas une nouvelle requete de decouverte.
Store exact overlayfs + `io.containerd.snapshotter.v1`, DockerRootDir/var/lib/docker.
Ce dernier champ ne donne aucune racine content/snapshotter : la mesure NSS
Plugins/statvfs demeure distincte et n'est ni devinee ni dupliquee ici.
ServerGitCommit n'est pas deduit de la version et reste hors de cette sonde.

Identites strictement separees : manifest6f7593 est image inspect.Id et
container.Image ; config140936 est le config OCI lie par les vrais octets du
manifest public. Les14diffIDs viennent du config, pas des layers compressees.
Le descripteur inspect doit etre le manifest OCI6f7593/3628octets. Les presences
et valeurs de tous les champs Config sont exactes. User absent dans l'image ne
donne aucun UID effectif et n'est pas normalise. Aucun profil classic configure
sur config140936 n'est admis comme alternative. Les quatre sources Moby tag
[29.4.2](https://github.com/moby/moby/tree/docker-v29.4.2), copiees et hashees
sous primary/, relient image target.Digest, creation img.ID et inspect ctr.ImageID.
Les historiques de build du config public ne sont pas un recu passwd.

## Un owner ferme et raccordable

`owner.py run --assets-sha <SHA Root> --work <RUNNER_TEMP/pamolive-pg-identity-ID-ATTEMPT>`

Le fragment fournit les vrais pins owner/assets apres gel. Le owner verifie les
10 buffers avant de compiler probe et les helpers exacts. Aucun import produit,
site-package ou repository. `bindings.json` conserve seulement tailles/SHA,
sans origine locale. Le point d'entree exige Linux nonroot GitHub-hosted CI,
le chemin exact du run et l'absence de DOCKER_*, proxies ou loaders Python
ambiants. Le subprocess a son env ferme, son Docker config neuf auths/proxies
vides et son home prive. Le owner impose umask077 ; work/home/config/journal
sont0700/0600. Aucun ancien work n'est reinitialise ni reutilise pour run.

Chaque argv doit appartenir au cycle ferme version/info/image inspect,
recherche par nom nonce exact, create getent exact, inspect d'ownership,
start --attach unique, stop5s/rm CID strictement possede pour cleanup. Aucun
exec, shell, pull, install, force-rm, volume-delete, label-filtre masquant les
collisions ou commande generique accepte par le owner. Le CLI ne propose aucun
parametre image, UID/GID, entrypoint, commande ou profil arbitraire.

Les vrais corps reserve_create/reconcile/named/remove/owns et Lease recus
restent byte-exacts. La classe Lease est extraite de son fichier pinne et reliee
au lecteur de fichier regulier borne, sans reimplementer ses operations. Son
intention/token et son identite/held sont persistants, meme si acquire echoue.
La reservation historique nomme `image_config` la valeur comparee a
container.Image. **Seule la vue privee legacy_reservation utilise ce nom ancien
pour manifest6f7593** ; le journal canonique image_config reste config140936 et
image_manifest reste6f7593. Les callbacks reels synchronisent cette vue avant
chaque commande et sur exception. Aucun global du helper n'est patche.

H1 conserve l'intention IO durable avant Popen, les32 entrees maximum et
l'incertitude monotone. Travail90s/cleanup30s, CLI15s maximum, stdout metadata
32768B/getent4096B et stderr4096B bornes avant retention. `owner.py cleanup`
permet au plus deux reprises explicites sur le **meme** journal/token/CID ;
elle ne reexecute pas getent, n'efface aucune incertitude et produit un nouveau
rapport numéroté. Un create perdu sans CID suivi de deux cleanup reste UNKNOWN,
lease held ; aucune absence tardive n'est reclassifiee comme liberation.
Une collision ou metadata foreign ne donne aucune suppression.

## Empreinte du seul getent

Un conteneur : CPU0.10, RAM=swap64MiB,16PIDs, nofile64/core0, shm4MiB,
logs json-file16KiB x1. Network none, rootfs RO, user0:0 explicite, caps0,
NNP, IPC/cgroup prives. Aucun bind, socket, volume anonyme ni port hote.
Le VOLUME PGDATA est couvert par tmpfs RO4MiB,nosuid/nodev/noexec,mode0700 ;
/tmp est tmpfs RO1MiB,nosuid/nodev/noexec. L'entrypoint PG est remplace par
getent, arguments fixes passwd postgres ; aucun demarrage de PG ni SQL.
Ces contraintes sont demandees et verifiees dans l'inspect avant start et
cleanup. Une forme inattendue refuse ; aucun defaut appris depuis le run.
Cela n'est pas une mesure independante de l'etat kernel ni une qualif stockage.

## Recu uniquement DATA

Parsing ASCII d'une ligne/sept champs, postgres/x, UID/GID canoniques non nuls,
aucune valeur presume999 ou autre. Seuls UID/GID sont publies, apres sortie0,
stderr vide, conteneur arrete nonOOM, suppression et H1/lease confirmes.
Aucun passwd brut, home/shell, hash/longueur du passwd, Env, journal, token,
config/home Docker ni log n'est publie. Les faits IO publics ont une liste de
cles fermee, sans stdout/stderr/tailles. `ok`, `resources_released` et
`commissioned` sont distincts ; commissioned/authority/operational_GO restentfalse.
Le resultat ne cree aucun profil Root PG, chown, PGDATA ou permission. Une
comparaison Root independante reste necessaire apres la vraie reception.
Le gros labo W/V garde ses HOLD stockage/getent/PGDATA jusqu'a revue ulterieure.

## Verification

`CorePython -I -B -X utf8 <capsule>/run_pure.py` :26methodes,zero erreur/echec/
skip/tentative externe. Les16contre-cas R2 sont adaptes au seul modele
containerd, puis10tests owner. Le cycle owner complet compile les vrais buffers,
utilise les vrais wrappers/journal et la vraie classe Lease sur des fichiers
temporaires synthetiques ; seul run_capped est remplace par un Fake. Ce chemin
verifie succes synthetique et create perdu suivi de deux reprises owner reelles,
sans transformer ces tests en recu Linux/Engine. Les quatre helpers sont rehashes
et byte-exacts. Ruff ne porte que sur les nouvelles sources actives ; aucun
ignore de code ou de scan n'est ajoute.

Le capsule.json historique contient des origines locales et est donc omis du
nouveau payload. Son SHA reste dans le gel R2 de reference ; manifest/config/
profile/index publics et les quatre helpers conserves ne sont pas reecrits.
