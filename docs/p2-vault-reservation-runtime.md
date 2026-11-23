# Runtime de réservation Vault : sources et réception N0

État du 15 novembre 2026. Intégration de développement depuis le parent
`bd8d2283a2c27c81eef3652fa0e4e5e02ba99216`, sur une branche dédiée. Le composant
[`components/vault/runtime`](../components/vault/runtime/README.md) applique
[ADR-024](adr-024-vault-reservation-boundary.md) : slot administré indépendant,
vérification V1 publique, DER mTLS par connexion et réservation PostgreSQL durable
`pending_proofs`, toujours `authorized:false`. Aucun modèle, migration ou
appelant Django/P0, format AEAD, quorum ou transport natif existant n'est remplacé.

## Périmètre source intégré

Le manifeste source R2 de 16 fichiers porte le SHA-256
`c748969b9ec223af405991aa205453b14593efe0e97bfa935487ae6755641907`.
Dans la copie initiale, les huit modules runtime, les deux fichiers d'intégration, le schéma SQL et les
trois autres fichiers de tests/helpers restent byte-identiques au candidat R2
et au payload reçu par le contrôleur R9. Le README est réconcilié ; le seul delta
du quatrième fichier de test est la constante de chemin `OLD`. Ce paragraphe
décrit la copie initiale, conservée dans son manifeste de revue ; le delta bind
ciblé ci-dessous est une modification fonctionnelle ultérieure explicite.

Deux modules historiques R1 sont ajoutés dans `tests/history/r1/`, byte-identiques
aux contre-fixtures gelées. Ils reproduisent les anciens défauts JSON/H11 fermés
en R2 ; aucune production ne les importe. Les méthodes et assertions du test
R2 restent identiques hors ce chemin. L'absence d'une fixture échoue : aucun
fallback absolu vers `output/` ni skip. Le manifeste d'intégration et la preuve
AST sont conservés avec le bilan de revue hors dépôt, sans logs privés publiés.

Le schéma SQL est celui d'un laboratoire neuf et séparé, exécuté par un owner de
migration distinct. Aucune migration Django, création automatique de service ou
nouvelle dépendance installée ne découle de cette copie. Aucun Dockerfile,
workflow de livraison, garde produit ou appelant P0 n'est changé par ce lot source.

## Réceptions distinctes

| Sujet | Résultat reçu | Limite |
| --- | --- | --- |
| Bibliothèque publique V1 `bd8d228` | 30 tests installés sans exclusion dans chacune des CI [push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43690947578) et [PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43690955625) ; 20 comparaisons de corpus concordantes | Aucun transfert vers l'installation de ce runtime Vault |
| Sources runtime R2 puis bind N0 strict | 51 purs d'origine puis une méthode de bind supplémentaire, soit 52 cas dans les trois modules | Mocks POSIX/SQL et callbacks TLS ; pas un handshake ou un sandbox OS |
| Laboratoire N0R7, contrôleur R9 | 10 méthodes mTLS/PostgreSQL réelles, zéro échec/erreur/exclusion, 4,668 s | Sources montées dans une image de test existante, pas une image Vault minimale ni une wheel runtime qualifiée |
| Laboratoire process N0R1, contrôleur recovery R2 | 2 nouveaux cas réels : restart du service avec PG conservé ; writer client jetable sorti après commit, puis retries mTLS durables | Ne rejoue pas les dix cas historiques ; pas un crash du serveur ou PG power-loss, ni une CI Vault réelle |
| Platform `bd8d228` | Deux CI passent régressions, transports, HA même hôte et restauration, puis refusent le scan final | 35 groupes High et provenance de build incomplète bloquent la promotion |

Le N0R7 vérifie concurrence/idempotence avec une ligne durable et son audit,
refus SQL directs sous runtime non-owner et rôles Web/worker de laboratoire,
conflit sur rotation de certificat, quota conservant les lignes expirées,
retry après commit et perte de réponse simulée, fermeture/incarnation, handshake
sans certificat/CA inconnue/certificats expirés ou futurs, DER propre à chaque
connexion parallèle, keepalive et refus d'un en-tête d'identité forgé.

Les 178 clients CLI sont récoltés et drainés ; six transferts stdin sont complets.
Les 19 codes non nuls concernent uniquement les sondes de disponibilité avant
leur succès. Nettoyage confirmé : quatre conteneurs, trois volumes et un réseau
supprimés, lease libérée. Client final exit 0 ; holder/serveur/PG exit 137 après
les trois `kill` de nettoyage prévus, aucun OOM. Ce nettoyage n'est pas un test
de crash. Les deux observations des 19 champs du PG historique sont identiques.

Les preuves publiques sont référencées par empreinte, sans recopier les IO/logs :

| Preuve | SHA-256 |
| --- | --- |
| Gel contrôleur R9 | `b2b9489c953efe52381d28e2ffd3ca9eb70dbb4c7c8a5f124d67381b05d29192` |
| Reçu public N0R7 | `8d6bd3e27c494e8f3f449c440db3e39372fd9ea252ae024c663c36542d731ac8` |
| Réception infra indépendante | `e4f6f11668f97b35a5b6d1acfbc6b67bcab1b8989db6e11ca3f8b931100de58c` |

La décision Root `ACCEPT_EXACT_N0_SOURCE_RUNTIME_TLS_POSTGRES_TEN_TESTS` accepte
uniquement ce périmètre. Les refus antérieurs restent conservés avec leurs plans,
états et récupérations distinctes ; aucun ancien échec n'est reclassé.

### Deux nouveaux cas de reprise de processus

Le lot process N0R1 est reçu séparément : même CID serveur détenu, mais PID et
StartedAt changés après un véritable restart, tandis que PostgreSQL reste actif.
Une nouvelle connexion mTLS retrouve la même réservation, les dates et le digest
privé du nonce, avec une seule ligne et un audit. Le second cas utilise un
nouveau writer dans le client de test jetable : `os._exit(73)` intervient seulement
après retour réussi du vrai commit/close du driver. Le parent attend/récolte le
worker, valide les faits H1 réels et le marker lié au PID, puis le retry TLS
conserve la même ligne/dates/nonce privé/audit. Ce writer n'est pas le serveur.

Les faits transmis observent exit 73, reap/drains complets, aucun kill du worker,
stdout 78 octets et stderr vide. Les trois étapes retournent leur paquet fermé
PASS. Le contrôle SQL des lignes, nonce et audit ainsi que les contraintes
checkpoint 40 s / TTL au plus 30 s ont réussi dans le code épinglé. Les lignes
SQL, nonces et dates du checkpoint ne sont pas exportés après nettoyage : la
contre-réception recoupe les observations retenues et les assertions de ce code,
sans nouvelle requête SQL ni reconstruction indépendante de l'expiration absolue.

190 clients CLI sont récoltés et drainés et six transferts stdin sont complets.
18 codes non nuls sont des sondes de disponibilité avant succès. Nettoyage :
quatre conteneurs, trois volumes et un réseau supprimés, lease libre et PG
historique inchangé sur les 19 champs. Les quatre PID1 encore actifs sont tués
pour ce nettoyage : exits 137 sans OOM, distincts du worker exit 73 antérieur.

| Preuve de ce lot distinct | SHA-256 |
| --- | --- |
| Gel recovery R2 | `e0af2d349023ad6cbe80b5b5e1e386b4b97b503a5a76cb6cb4a8d6e09fb254a7` |
| Reçu public des deux cas | `cb66ddf68593b6534cf680314e24f90791509d92031535801ad1b39ef846ccb5` |
| Contre-réception infra indépendante | `974d2143baa339a5be950e673f5591124a3e9e3a171f3743e189b9ac26b12c64` |

Les dix méthodes N0R7 précédentes ne sont ni rejouées ni requalifiées par ces deux
cas. Les 52 purs du checkout restent une porte distincte ; aucune CI Vault réelle
n'est encore reçue. Aucun log privé ou packet avec credentials n'est publié.

## Tests purs depuis le checkout

```sh
python -I -B qualification/vault_reservation/run_pure.py
```

Le runner résout ses chemins à partir de son fichier, depuis toute CWD. Il
charge les sources de contrats et du vérificateur déjà intégrées et les trois
modules de tests runtime. Il exige exactement 52 cas, zéro exclusion et zéro
tentative de processus, réseau ou SQL. Il ne crée pas de bytecode ni de log dans
le dépôt, n'installe rien et ne lance jamais les dix tests réels. Ses gardes de
test ne constituent pas une frontière de sécurité OS. La CI Platform lance cette
commande après `pip check` et étend son analyse Bandit au runtime courant ; la
nouvelle CI de cette branche reste à recevoir séparément.

## Delta de bind N0 après la réception initiale

Le finding Bandit B104 de l'ancien wildcard conduit à une restriction réelle,
sans suppression de règle : `transport.configuration` et `serve_lab.lab_inputs`
acceptent seulement les chaînes exactes `127.0.0.1` et `10.253.249.3`. Wildcard,
IPv6, noms DNS, autres IPv4 privées/publiques et types incorrects refusent. La
configuration conserve l'adresse fournie, sans normalisation ni résolution.
Les autres flags TLS/H11, SNI/DNS/certificats clients et le schéma SQL restent
inchangés. Ce profil est propre au laboratoire N0, pas une politique de bind
générale de production.

Les deux modules opérationnels diffèrent donc explicitement du payload reçu
N0R7 ; les prochains fixtures doivent fournir `bind_host=10.253.249.3`. Les dix
méthodes historiques de N0R7 utilisaient le wildcard dans le réseau privé sans
port hôte. Leur réception est conservée et ne qualifie pas ce nouveau delta.
La nouvelle méthode pure couvre les deux gardes ; le lot process N0R1 reçoit
ensuite ses deux cas avec le bind `10.253.249.3`, corroboré par les sources
épinglées et les connexions TLS réussies. Aucune table de listeners kernel n'a
été interrogée indépendamment par la contre-réception.

## Réception CI exacte du candidat 6c17536

La [PR #6](https://github.com/pamolive/PamOlive-Platform/pull/6) est en brouillon.
Les jobs PR utilisent la fusion temporaire `91243b7` des parents exacts `bd8d228`
et `6c17536` ; les jobs push utilisent `6c17536`. Neuf ZIP d'artefacts sont liés
par leurs digests dans la réception
`066e674b78e871eaeb9b0ae8abf8bbc757beff674e8ebd8bec2751ad88c8a198`.

La [CI PR Platform](https://github.com/pamolive/PamOlive-Platform/actions/runs/43707126018)
passe les 52 purs Vault, 1 439 tests généraux dont 42 exclusions, portes dédiées
130/166/22, SSH 10/RDP 9, HA/partition sur le même hôte et restauration restreinte
23 migrations/374 lignes. Deux suites distinctes de 20 ont chacune une exclusion.
Seul le scan final refuse : 35 groupes High non triés, 102 correspondances High
sur 349 OS, zéro Critical, compiled 0, aucun match ignoré. Le
[vérificateur installé](https://github.com/pamolive/PamOlive-Platform/actions/runs/43707125940)
reçoit ses 30 tests sans exclusion et 20 comparaisons ; ce n'est pas le runtime Vault.

Le [push Platform](https://github.com/pamolive/PamOlive-Platform/actions/runs/43707121106)
passe les purs et la suite générale, puis échoue pendant l'acquisition d'un
matériau Python : délai de négociation TLS, BuildKit exit 1. Les assertions
post-build d'exclusion des credentials et les portes image suivantes ne sont
pas reçues sur ce run. Aucun défaut de compilation ou fuite n'est établi par
ce log ; l'endpoint précis n'est pas identifié. Pas de relance ni de garde assoupli.

## Réception CI du candidat suivant 67ee7c9

Les [Platform PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43713258395)
et [push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43713256970)
passent toutes les portes exécutées avant le scan final, y compris l'acquisition,
le build et l'assertion d'exclusion des credentials. Chacune reçoit 52 purs Vault
sans skip ; la suite générale annonce 1 457 tests et 42 entrées Skip, composées
de 40 méthodes et deux exclusions setUpClass. Deux autres suites de 20 gardent
chacune une exclusion. Le scan refuse toujours 35 groupes High non arbitrés,
102 correspondances High sur 349 OS, zéro Critical et aucun match ignoré.
Le [vérificateur installé PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43713258465)
reçoit séparément 30 tests sans skip et 20 comparaisons. Aucun succès de runtime
Vault réel ou installé n'est transféré depuis cette porte de bibliothèque.

Réception : `1352eef85222a261faabc3300bd49aa6a3377be87a307f6e62b61663d9c616d6`.
Le correctif borne les retries des matériaux publics ; aucun déclenchement réel
de retry n'est déduit d'un build réussi. Pour le parent `6c17536`, les logs exacts
confirment aussi 40 méthodes et deux exclusions de classe parmi 42 entrées Skip.
Le précédent calcul de 1 397 exécutés, et celui de 1 415 sur le sujet courant,
sont retirés : les compteurs de classes et méthodes ne se soustraient pas ainsi.
Les addenda `3edad87793c9f3405e0ee320611ed70831b49c7f6adc26c302f679534fe0a49d`
et `d7a3e7b19118032180443da4511d5dd9cc0ad5bda1e14e5f93c38a38b0a5914e`
préservent les reçus scellés et les verdicts historiques. Main, image et NAS
restent inchangés ; les High et la provenance de build bloquent la promotion.

## Premier essai de restauration : réception partielle seulement

Le contrôleur backup/restore R2, gel
`08164d6a64b486b054690e2fac4fa93d236a239f7a1d80dec530eb5d1bc646fe`,
a reçu ses revues AppSec/PG et 77 tests purs sans exclusion. Root exécute ensuite
le seul essai `vault-restore-n0r1`. Un dump de la base synthétique neuve est
restauré dans une seconde base neuve du même cluster jetable, sous propriétaire
NOLOGIN via un login restreint ; les grants courants sont réappliqués.
L'observation après restauration confirme propriétaires exacts, lignes/audits
identiques, source explicitement fermée et ancien contexte ouvert refusé 403 par
le nouveau slot scellé hors sauvegarde. Le SQL de commissionnement explicite
retourne son marqueur, mais **la probe finale échoue**. Aucun résultat complet
de conflit, requête fraîche ou dénis runtime/Web/worker n'est reçu.

Rapport public : `9f902fef7a5f9afc8d601db614458473561fe7f14e385dbf5f421ac7fdfbe3c8`.
183 CLI récoltées/drainées, 12 stdin complets, nettoyage des quatre conteneurs,
trois volumes et réseau sans OOM ; lease libre et 19 champs PG historique
inchangés. Les dumps, SQL et snapshots privés ne sont pas publiés.
Conserver cet échec et diagnostiquer avant un nouveau test, sans renouvellement
automatique des matériaux ou prolongation 40 s / 30 s. Une restauration logique
sur un cluster ne qualifie ni PITR, ni panne PostgreSQL, ni reprise multi-hôte,
ni détection d'un rollback clandestin sous la même incarnation.

## Restauration logique dans le laboratoire CI installé

Le [run Vault installé](https://github.com/pamolive/PamOlive-Platform/actions/runs/44289749907)
du commit `58e9ec7` établit le démarrage sur PostgreSQL 17.12 et les dix tests
SQL et mTLS sans échec ni exclusion. Le workflow Vault propose en plus le
scénario de restauration avec les trois entrées `transfer_verified_wheels`,
`run_synthetic_lab` et `run_synthetic_restore`. Cette variante sélectionne une
nouvelle allocation synthétique dans le même job que la construction des wheels.

Le client reçoit un nouveau slot scellé, avec une nouvelle incarnation. Le dump
reste en mémoire et porte uniquement sur le schéma `vault_reservation`. Un
login restreint réimporte dans une seconde base neuve, sous le rôle propriétaire
NOLOGIN, après fermeture explicite de la source. Le test compare réservations,
audit et propriétaires et vérifie les refus avant et après le commissionnement
de la cible.
Il vérifie ensuite que le runtime peut ajouter une réservation en attente et que
les rôles Web et worker restent privés de connexion. Seul le reçu public borné
peut être publié. Le résultat de restauration dépend de l'exécution réelle de
ce scénario, avec les fenêtres de 40 s pour le contexte et 30 s pour la réservation.

## Limites et lot suivant

Ni la bibliothèque V1 ni une réservation pending ne sont une capacité de remise.
Pas de secret/nonce dans la réponse, FullTranscript, baseline de compteur inventée,
preuve d'action, KMS, unwrap ou administration du contexte indépendant. Le slot
et le ledger sont commissionnés hors Web ; la tête PAM fraîche ne détecte pas
une restauration clandestine du ledger sous la même incarnation. Une reprise
déclarée doit rester fermée jusqu'à barrière administrée hors sauvegarde et
nouvelle incarnation ; aucun ancrage indépendant d'usage n'est encore livré.

Le restart réel du service avec PG conservé et la sortie réelle du writer
jetable après commit sont désormais reçus dans leur lot distinct. Restent le
crash réel du serveur avant/après commit, PG power-loss/fsync, perte réseau réelle,
expiration attendue, backup/restore avec barrière et nouvelle incarnation et
frontière OS/volumes/réseaux depuis un Web hostile. Les dix cas historiques
reconstruisaient des objets, simulaient la perte de réponse et seedaient
l'expiration via owner ; leur sens ne change pas rétroactivement.

Pas de package Vault installé reçu, image minimale, reproductibilité/attestation
de build, qualification multi-hôte/production ou migration d'appelant. Les deux
CI Platform du parent `bd8d228` conservent 35 groupes High non arbitrés, zéro
Critical ; leurs tests généraux comptent 1 439 cas dont 42 exclus, les portes
130/166/22 sont séparées et la restauration porte sur 23 migrations/374 lignes.
Aucun accès réel, NAS, publication d'image ou merge main n'est autorisé par cette
intégration de source. P2 reste en cours.
