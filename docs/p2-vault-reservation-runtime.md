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
