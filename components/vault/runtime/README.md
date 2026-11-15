# Réservation Vault sans remise — ADR-024

Cette source de développement intègre le candidat R2 et sa réception N0
synthétique. Elle prépare uniquement un état durable `pending_proofs` avec
`authorized:false`. Aucun secret, nonce, ciphertext, clé KMS, FullTranscript,
compteur fictif ou capacité de remise ne sort de ce chemin. Aucun appelant P0,
modèle ou migration Django, API AEAD ou chemin SSH/RDP existant ne change.

La [décision ADR-024](../../../docs/adr-024-vault-reservation-boundary.md) et le
[bilan de réception](../../../docs/p2-vault-reservation-runtime.md) distinguent
les sources intégrées, le laboratoire reçu et les qualifications encore ouvertes.
Ce répertoire n'est ni une wheel installée reçue ni une image Vault minimale.
Il est exclu du contexte runtime applicatif actuel ; aucun service n'est démarré
par son import ou par son ajout au dépôt.

## Contexte indépendant et réservation

Le démarrage administré fournit `SlotFile(Path, expected_sha256, owner_uid=0)`.
Le slot RO fixe l'installation P0 opaque UTF-8, son mapping UUID Vault explicite,
tenant, génération, tête exacte, clés et périodes de confiance, références et
principals broker. Aucune requête ne choisit un fichier, une clé, une horloge ou
une incarnation. Le pin est une entrée de commissionnement externe ; aucun
TOFU, hot-reload ou administration du contexte par Web n'est implémenté.

Sous POSIX, la lecture bornée refuse aliases/hardlinks, propriétaires/modes
incorrects et substitutions de fichier ou d'ancres. Le snapshot, ses octets et
son identité sont revérifiés pour chaque demande et avant INSERT/commit. Les
matériaux publics V1 sont réellement vérifiés par la bibliothèque autonome avec
contexte indépendant et horloge serveur ; les claims métier restent des demandes.

`POST /v1/reservations` accepte seulement le draft ADR-022, la chaîne publique V1
et son checkpoint. JSON et champs sont fermés, avec bornes avant parsing. Le
petit adaptateur H11 est spécifique à Uvicorn **0.54.0** : le DER leaf provient du
vrai objet TLS de chaque connexion après `CERT_REQUIRED`, jamais d'un en-tête ou
d'un état global. Le certificat et le mapping sont revalidés par requête, y
compris en keepalive. Pas de parser HTTP recopié ni de support ASGI TLS natif
prétendu. Le bind N0 est limité exactement à `127.0.0.1` ou `10.253.249.3`,
sans résolution DNS ni wildcard. Cette seconde adresse appartient au serveur
du seul laboratoire privé prévu ; ce profil n'autorise pas d'autres réseaux ou
serveurs publics. Les noms DNS/SNI et certificats du client restent inchangés.

Le ledger PostgreSQL est séparé de Django. Un owner de migration distinct crée
`sql/schema.sql` ; le runtime non-owner n'a ni DDL, rôle owner, UPDATE/DELETE de
réservation ni grants Web/worker. Le singleton commissionné est verrouillé pour
sérialiser quota et INSERT ; seul son `lock_marker` sans autorité métier est
modifiable pour ce verrou. Tenant/service viennent du slot et du peer authentifié.

Même clé d'idempotence, principal, certificat et draft : même réservation, nonce
interne et dates. Une divergence refuse ; la rotation de certificat ne transfère
pas la réservation. Réservation et audit commitent ensemble ; une réponse
incertaine reste explicite. Expiration au plus 30 s, bornée par les matériaux et
le certificat. Les lignes expirées restent dans le quota N0 de 1 à 64 lignes par
tenant/installation/service ; elles ne rendent ni clé ni quota réutilisable.

## Réception et tests

Le 15 novembre 2026, le laboratoire N0R7 a réellement passé dix méthodes mTLS et
PostgreSQL en 4,668 s : concurrence/idempotence, refus des privilèges SQL,
rotation DER, quota/expiration seedée par owner, commit puis perte de réponse
simulée, fermeture/incarnation, mauvais certificats, connexions concurrentes,
keepalive et refus d'un header d'identité. Nettoyage reçu, PG historique inchangé.
Cette réception porte sur les sources R2 montées dans des conteneurs de test ;
elle ne qualifie pas un package installé ou une image Vault de production.

Un laboratoire distinct, process N0R1, reçoit ensuite **deux nouveaux cas** :
redémarrage réel du même service serveur avec PostgreSQL conservé, puis sortie
réelle `os._exit(73)` d'un writer client jetable après le commit du driver. Le
retry mTLS conserve la même ligne, les dates, le digest privé du nonce et l'audit.
Les faits H1 observés du worker sont conservés et validés, pas reconstruits depuis
un marqueur PASS. Le bind privé exact est corroboré par les sources épinglées et
les requêtes TLS réussies ; ces deux cas ne rejouent pas les dix anciens.

190 clients CLI sont récoltés/drainés, six transferts stdin complets ; les 18
codes non nuls sont des sondes de disponibilité avant succès. Les quatre PID1
encore actifs sont tués pour nettoyage, exit 137 sans OOM, puis les quatre
conteneurs, trois volumes et réseau sont supprimés ; lease libérée, PG historique
inchangé. Aucun de ces deux cas n'a encore été exécuté en CI Vault réelle.

Les **52 tests purs** des trois modules se lancent depuis le checkout :

```sh
python -I -B qualification/vault_reservation/run_pure.py
```

Le runner utilise les sources du vérificateur et des contrats déjà présentes
dans `components/`, les dépendances du venv existant et des gardes de processus,
socket et SQL. Il exige 52 cas, zéro exclusion et zéro tentative externe ; aucun
fallback vers un prototype `output/` ou installation implicite. Ce sont des
gardes de test, pas un sandbox OS ni une réception de transports réels.

Les signatures utilisent des identités publiques synthétiques ; les seeds de
test déterministes ne doivent jamais devenir des identités réelles. Les objets
de clés privées restent en mémoire de test. Aucun matériau privé du laboratoire,
manifest avec credentials, certificat, nonce ou log brut n'est ajouté au dépôt.

## Historique R1/R2 conservé

R1 avait deux défauts refusés par revue : allocation JSON avant la borne de
nœuds, et callback H11 de fermeture avant initialisation du transport. R2 ajoute
le prépass JSON borné avant UTF-8/`json.loads` et initialise le lifecycle H11
avant refus, avec une application fermée jusqu'à liaison du peer.

Les deux modules dans `tests/history/r1/` sont les contre-fixtures historiques
byte-identiques, défectueuses par construction et chargées seulement par
`test_r2_boundaries.py`. Aucun import de production ne les utilise. Le seul
delta de code de test d'intégration est le chemin `OLD` relatif à ces fixtures ;
les cas et assertions sont conservés, sans skip si un fichier manque.

Après l'intégration R2, la revue B104 retient un resserrement fonctionnel :
`transport.configuration` et le manifest de `integration/serve_lab.py` refusent
tout bind sauf les deux chaînes N0 exactes. Une nouvelle méthode teste les deux
positifs et les refus dans les deux frontières, sans changer TLS/H11. Les 51
cas d'origine restent présents. Aucun `nosec`, seuil ou suppression de finding.
Le N0R7 reçu utilisait historiquement le wildcard sur son réseau privé sans port
hôte ; il n'est pas requalifié avec ce nouveau bind. Le lot process N0R1 reçoit
ensuite les deux nouveaux cas avec `bind_host=10.253.249.3` ; les 52 purs restent
une preuve distincte.

## Limites encore ouvertes

Les dix cas historiques reconstruisaient des objets, simulaient la perte de
réponse après commit et seedaient l'expiration via owner. Les deux nouveaux cas
reçoivent le restart réel du service et la sortie du writer jetable après commit,
pas un crash réel du serveur ni une panne électrique de PG. Ceux-ci, la perte
réseau réelle, l'expiration attendue, le backup/restore et les refus depuis les
vrais principals OS Web/worker restent à qualifier séparément. Les refus SQL de
rôles de laboratoire ne prouvent pas cette frontière de déploiement.

Une restauration déclarée doit rester fermée jusqu'à une barrière administrée
hors backup et une nouvelle incarnation. Une restauration clandestine avec même
incarnation et tête PAM encore fraîche n'est pas détectée par cette seule tête.
Un UUID n'est pas un compteur monotone. Avant toute remise, l'ancrage indépendant
des usages et l'autorité des compteurs restent à décider et recevoir.

Les 30 tests installés du vérificateur public, reçus séparément deux fois au
head `bd8d228`, ne qualifient pas ce runtime. Les 35 groupes High et la provenance
de build incomplète bloquent toujours la promotion de l'image applicative.
Aucun NAS, déploiement, accès réel ou merge main ne découle de cette intégration.
