# ADR-024 — Contexte Vault indépendant et réservation sans remise

15 novembre 2026. Acceptée par Root pour P2-R1b.2a local synthétique.
Cette décision autorise le développement et les tests préparatoires. La réception
exige les essais réels de TLS, PostgreSQL et séparation ci-dessous. Elle ne
déclare ni P2 terminé, ni un Vault autorisé à délivrer un secret.

## Sources et confrontation

Conserver ADR-013, ADR-020, ADR-022 et ADR-023. Proposition indépendante :
`1be868157740cd3aea64a7e778b670e963e3b47a6eb3c754fa61b915892bdb32` ;
contre-revue : `8f6d5af93472a59c05708d1828d09079636cd98a6264b2e64b2b5c8df138783b`.
Les trois réserves sont retenues : rollback clandestin du ledger non détecté par
la tête PAM, autorité des compteurs absente, identité TLS non fournie par Uvicorn
stock au scope ASGI. Aucun booléen Web ne résout ces points.

## Options et décision

| Option | Garantie et coût | Décision |
| --- | --- | --- |
| Slot Vault administré hors Web | Fixe attentes et liaison d'installations dans le périmètre du futur coffre ; dépend de sa garde administrative | Retenue pour N0 |
| Nouvelle propriété cosignée du registre PAM | Audit et gouvernance réutilisés ; exige sémantique de mutation, rotation et récupération explicite | Possible ensuite, sans réinterpréter les archives V1 |
| Nouveau document ou service de commissionnement | Nouvelle hiérarchie de clés, distribution, fraîcheur et reprise à qualifier | Différé, aucun besoin démontré ici |

La couche d'assemblage reste dans `components/vault/runtime/`, distincte de l'API
publique AEAD et des formats distribués. Réutiliser les bibliothèques existantes,
les dépendances maintenues et PostgreSQL ; aucun nouveau service de contexte,
format de signature, JWT/HMAC de permission ou microframework.

## Commissionnement et identité

Un slot RO chargé par le processus Vault fixe la paire exacte installation P0
opaque UTF-8 / UUID Vault, tenant, génération, tête attendue, clés publiques et
périodes de confiance, références synthétiques et principals broker autorisés.
Pas de conversion implicite, normalisation Unicode, dérivation ou tri d'UUID.
La requête ne choisit aucun fichier, clé, contexte, horloge ou incarnation.

Les matériaux publics V1 sont vérifiés par la bibliothèque autonome, avec
attentes indépendantes et horloge du serveur. Le checkpoint reste frais et la
tête exactement épinglée. Une rotation exige un nouveau snapshot cohérent et
un commissionnement explicite ; les anciennes preuves restent vérifiables.
Les fichiers et les clés privées de fixture ne sont pas accessibles à Web/worker.

Le broker s'authentifie par un véritable handshake mTLS, `CERT_REQUIRED` et CA
de test distincte. L'identité vient du DER leaf exact observé dans TLS, puis du
mapping administré ; aucun en-tête, claim de JSON ou état global de connexion.
Uvicorn stock ne fournit pas ce DER à ASGI. Un petit adaptateur H11 par connexion
est permis via le point d'extension de la version épinglée, sans recopier son
parser. Il doit être qualifié contre keepalive, connexions concurrentes, headers
forgés, certificats absents/erronés/expirés et changements de certificat. Pas de
revendication de support ASGI TLS natif ou de serveur de production qualifié.

## Réservation et limites d'autorité

Un seul endpoint de préparation accepte un `OperationDraft` ADR-022 borné.
Les claims métier demeurent des demandes, pas des décisions vérifiées.
Le serveur vérifie son tenant, installation, contexte et principal commissionné
avant d'écrire. Aucun ciphertext, credential, provider KMS, unwrap ou API AEAD
n'est accessible par ce chemin. L'état est explicitement `pending_proofs`.

Réserver durablement : clé opaque d'idempotence, tenant, service authentifié,
opération, DER exact, draft canonique/hash, nonce interne CSPRNG32B, contexte,
incarnation et dates originales avec expiration au plus30s. Même clé et même
principal/certificat/draft : même état et expiration ; divergence :409. La
rotation de certificat ne transfère pas une réservation. Concurrence SQL réelle,
quota transactionnel et reprise ne doivent pas générer une nouvelle réservation
ou prolonger une expiration. Les erreurs et états incertains restent explicites.

L'autorité des compteurs n'est pas encore décidée. Donc **aucun FullTranscript,
défi personnel ou hash fictif de baseline de compteurs n'est produit**. Le nonce
reste interne. La réponse de réservation ne crée pas une capacité. Le format
d'assemblage des matériaux/assertions et l'autorité durable des compteurs seront
décidés avant les preuves d'action V2 et toute consommation.

## SQL, isolement et récupération

Base/schema de laboratoire séparés, rôle de migration distinct, runtime
non-owner sans DDL/CREATEROLE/BYPASSRLS. Web/worker n'ont aucun grant sur le ledger
ou la configuration. Les mappings tenant/principal ne viennent pas de variables
SQL définissables par le client. Tester SQL direct et principals réels, puis les
conteneurs/réseaux et montages dédiés ; une séparation logique Python ne suffit
pas. Aucun modèle ni migration Django P0 n'est réécrit.

La restauration normale reste fermée jusqu'à une barrière administrée hors de
la sauvegarde et une nouvelle incarnation ; les anciennes réservations ne sont
pas réactivées. Un UUID ne constitue pas un compteur monotone. Une restauration
clandestine ou altération par l'administrateur du ledger ne peut pas être
détectée par la seule tête PAM inchangée : cette garantie n'est pas livrée.
Avant toute remise, un ancrage indépendant des usages et sa stratégie de panne
seront obligatoires, avec tests de rollback dans la fenêtre30s. Le présent lot
ne possède aucun chemin de remise susceptible de masquer cette limite.

## Réception et publication

Tests automatisés : configuration malformée/substituée, tête et checkpoint,
tenant/caller/certificat/headers, permissions POSIX et SQL, concurrence/quota,
crash avant/après commit, retry et rotation, redémarrage et restauration sur copie,
absence de secrets dans Web/worker/réponses/logs. Employer des identités et
autorités synthétiques. Réutiliser les campagnes P0 sans remplacer leurs chemins.

Les essais purs ne qualifient pas mTLS, rôles SQL, Docker ou récupération réelle.
Ne pas déclarer ce lot reçu avant leur exécution. Ne pas résoudre l'absence de
permissions en ajoutant un privilège global ou un fallback legacy.

La préparation source peut avancer pendant les refus des gates indépendants.
L'installation de la bibliothèque30 reste à recevoir ; les35High et la provenance
de build incomplète interdisent la promotion de l'image applicative. Aucun NAS,
secret réel, déploiement de production ou merge main ne découle de cette ADR.

## Réception historique N0R7 du 15 novembre 2026

Le texte de décision initiale ci-dessus conserve son état préparatoire. Depuis,
la bibliothèque publique a reçu ses 30 tests installés dans deux CI du head
`bd8d228` ; cela ne qualifie pas l'installation du runtime Vault.

Root accepte le périmètre exact N0R7 : dix méthodes réellement exécutées sur
mTLS et PostgreSQL synthétiques, sans échec ni exclusion, en 4,668 s. La revue
indépendante recoupe les sorties de test, les 178 clients CLI récoltés/drainés,
le nettoyage des quatre conteneurs, trois volumes et réseau, la libération de
la lease et les 19 champs inchangés du PostgreSQL historique. Les sources R2
correspondantes sont intégrées pour revue ; 51 tests purs passent séparément.
Voir [le bilan détaillé](p2-vault-reservation-runtime.md).

Cette première réception ne clôt pas toutes les conditions de l'ADR : reconstruction
d'objets seulement, perte de réponse après commit simulée et expiration seedée
par owner. À ce stade, redémarrage/crash de processus, attente d'expiration,
backup/restore et frontière OS Web/worker hostile restaient à recevoir. Aucun secret, preuve
d'action, compteur, commissionnement d'autorité, image Vault minimale ou
attestation de build n'est livré. La limite du rollback clandestin demeure.

Le bind N0 est resserré après ce reçu historique aux deux adresses exactes
`127.0.0.1` et `10.253.249.3`, dans la configuration et son manifest administré,
sans DNS/wildcard ni modification de TLS/H11. Une méthode pure supplémentaire
porte le total à 52 ; le nouveau profil attendait une réception réelle distincte.
Le N0R7 sur réseau privé ne devient pas une observation de ce nouveau bind.

## Réception distincte des processus et du bind restreint

Le lot `vault-process-n0r1` reçoit ensuite deux cas réels sur les sources au bind
restreint : redémarrage du processus serveur avec PostgreSQL conservé, puis sortie
réelle d'un writer client jetable après commit. Une nouvelle connexion TLS retrouve
dans chaque cas la réservation d'origine, ses dates, son nonce comparé seulement
en privé et un audit unique. Le second cas n'est ni un crash du serveur Vault,
ni une panne de PostgreSQL. Les dix méthodes historiques ne sont pas rejouées.

La contre-réception indépendante recoupe les faits H1 du worker (exit 73,
récolte/drains), les changements PID/StartedAt du serveur, 190 clients CLI,
six stdin complets et le nettoyage complet sans OOM, avec PG historique inchangé.
Reçu public : `cb66ddf68593b6534cf680314e24f90791509d92031535801ad1b39ef846ccb5` ;
revue indépendante : `974d2143baa339a5be950e673f5591124a3e9e3a171f3743e189b9ac26b12c64`.

Attente d'expiration réelle, crash du serveur/perte PostgreSQL, backup/restore,
frontière OS Web hostile, image minimale et ancrage indépendant des usages restent
à qualifier. Aucun secret ni autorité d'action ne découle de ces deux réceptions.
