# P2 — revue des frontières de confiance et premier contrat opérationnel

11 novembre2026. **Préparation en lecture seule du code produit ; proposition à confronter avant implémentation.** Aucun composant P2, appel KMS, test réseau ou qualification multi-hôte n’est réalisé par cette note. Elle complète [ADR-013](adr-013-pam-quorum-trust.md), [ADR-014](adr-014-event-provenance.md) et la [roadmap](implementation-roadmap.md), sans refaire l’inventaire commercial.

## Constat vérifié dans le code

| Élément actuel | Protection conservée | Limite pour P2 |
| --- | --- | --- |
| `deploy/runtime.py`, `deploy/native_runtime.py` | Web/worker UID1000, moteur natif UID1001 sans environnement applicatif, capacités réduites | Web et worker reçoivent le même environnement applicatif et accès SQL. La séparation UID du moteur ne crée pas une autorité d’exécution indépendante. |
| `platform_core/security.py:cipher` | Fernet de la bibliothèque maintenue, matériel distinct de la signature de session, validation P0-1 | Le processus Django possède le matériel dérivant la clé de chiffrement. Un nouveau conteneur utilisant la même clé conserverait ce pouvoir. |
| `pam/broker.py:Relay.start`, `pam/sessions.py:endpoint_credentials` | Double contrôle après sonde, P0-2, preuve de lancement P0-3, clôture sur perte d’autorité et captures durables | Le broker ASGI fonctionne dans le processus applicatif ; Django déchiffre puis transmet les credentials au moteur natif. Une exécution arbitraire dans ce processus peut contourner son propre chemin normal. |
| `pam/target_binding.py`, `pam/sessions.py:_check_authority` | Organisation, cible, compte, génération, protocole, hôte/port et identité SSH/RDP liés ; contrôle continu | Ces contrôles doivent être évalués à nouveau dans le nouveau broker, pas remplacés par un champ `approved=true` émis par Web. |
| `pam/trust_registry.py`, `pam/trust_auth.py` | Registre cosigné, personnes canoniques, preuves WebAuthn réellement revérifiées, checkpoint externe borné | Le code vérifie déjà des signatures indépendantes : ne pas le décrire comme un simple HMAC falsifiable. P2 doit rendre son vérificateur et son stockage d’usage unique indépendants de Web. |
| `platform_core/events.py`, `management/commands/runjobs.py` | Outbox PostgreSQL, handlers livrés/signés, consommation bornée, absence de MFA interactive héritée, reprise DB | Un worker compromis possède encore des pouvoirs applicatifs. Un message métier signé dans cette base ne doit pas devenir une capacité Vault. |
| V7/V8 et attestations du noyau | Faits et réception attestés ; anciens formats et provenance typée préservés | Une preuve d’acceptation serveur ne prouve ni la vérité distante ni l’intégrité d’un serveur entièrement compromis. Le témoin ajoute une autre autorité de conservation. |

Le risque prioritaire est l’exfiltration des secrets accessibles au processus Web, puis l’ouverture d’un transport en contournant les vérifications locales. Il ne faut pas prétendre que la compromission Web permet de fabriquer les signatures des dépositaires ou des authentificateurs indépendants.

## Plus petit lot P2 proposé

Une tranche verticale **d’un seul secret technique synthétique, une cible SSH synthétique et une session** : Web/worker orchestrent ; broker autonome vérifie le mandat et ouvre le transport ; Vault autonome libère seulement le secret prévu ; gestionnaire de clés distinct protège la DEK ; témoin conserve les reçus. RDP, coffre utilisateur et migration générale suivent après qualification de cette tranche.

| Principal authentifié | Opérations permises | Opérations interdites |
| --- | --- | --- |
| Web | Proposer une session, afficher son état et les preuves expurgées | Déchiffrer, signer seul une autorisation privilégiée, émettre un checkpoint, modifier la politique Vault |
| Worker | Soumettre un travail typé, demander clôture/révocation et consulter son statut | Hériter une MFA interactive, choisir un credential arbitraire ou lire un secret |
| Broker | Vérifier les preuves indépendantes, demander une libération bornée, injecter le secret, contrôler et clôturer le transport | Obtenir KEK/DEK, appeler un déchiffrement générique, changer le registre de confiance |
| Vault technique | Stocker les versions chiffrées, vérifier indépendamment la libération autorisée, utiliser son périmètre KMS | Accepter une seule assertion Web/Broker, servir des credentials au navigateur, interpréter un groupe LDAP comme approbation PAM |
| Gestionnaire de clés | Générer/envelopper/désenvelopper des DEK selon tenant/domaine/opération | Autoriser Web/worker/broker directement, exposer la KEK, fournir une interface universelle non bornée |
| Témoin | Accepter un hash d’événement et émettre un reçu/checkpoint signé avec sa clé propre | Déchiffrer, approuver une session ou certifier la vérité des données reçues |

Un service qui déchiffre côté serveur n’est pas zero knowledge. Le coffre utilisateur aura son contrat et ses clés distincts ; il ne doit pas être ajouté implicitement à cette API de secrets techniques.

### Transport et identité de service

TLS mutuel direct entre composants, vérification CA/SAN/identité exacte, rôles de service explicitement autorisés ; aucune confiance fondée sur une IP Docker ou un en-tête HTTP transmis. Secrets de service et certificats propres à chaque processus, fichiers privés séparés, aucune CA privée ou clé de signature d’autorité montée dans Web. Pas de 0-RTT sur les opérations de sécurité. TLS1.3 est spécifié par [RFC9846](https://www.rfc-editor.org/info/rfc9846/), successeur publié de RFC8446 ; sa disponibilité effective reste à tester sur les runtimes retenus.

L’identité stable du service survit à la rotation du certificat, mais une capacité courte liée à l’ancien certificat ne change pas silencieusement de porteur. Si OAuth/JWS est utilisé, appliquer la liaison au certificat présentée dans [RFC8705](https://www.rfc-editor.org/rfc/rfc8705) ; ne pas accepter un bearer volé depuis un autre client. mTLS authentifie le processus appelant : il n’atteste pas, à lui seul, le droit métier de libérer un secret.

### Enveloppe d’opération versionnée

Contrat à figer dans une ADR et un schéma strict avant le premier endpoint :

```text
schema = pamolive.privileged-operation/1
issuer / audience / operation / caller_service_id / client_certificate_binding
installation_id / trust_generation / organization_id
request_id / idempotency_key / operation_nonce / session_id / broker_instance_id
requester_person_id / canonical_approver_person_ids
intent_id / intent_scope_hash / policy_revision / registry_revision / registry_hash
target_id / destination_epoch / destination_scope_hash
protocol / hostname / port / SSH_public_key_or_RDP_certificate_identity
credential_reference / credential_version / crypto_profile
issued_at / not_before / expires_at
independent_checkpoint_reference / independent_proof_bundle_hash
```

L’organisation est vérifiée contre l’identité de service et toutes les références, pas simplement lue dans JSON. Distinguer les nonces de capacité, les nonces AEAD, les défis WebAuthn et les IDs de retry. Leur usage et leur persistance sont différents.

Une capacité technique peut utiliser JWS avec une bibliothèque JOSE maintenue, algorithme explicitement autorisé et clés publiques commissionnées hors Web. `kid` référence une liste locale liée au but ; pas de `jku`/`x5u`/clé embarquée fournie par l’appelant. Ne pas définir une primitive de signature maison ou réutiliser la clé Fernet/HMAC globale comme autorité P2. Le message doit rejeter doublons JSON, champs inconnus et nombres non finis.

Le dépôt possède déjà PyJWT dans son lock : vérifier son API et ses algorithmes supportés avant de retenir une autre dépendance. Un contrat applicatif versionné n’est pas une nouvelle primitive cryptographique.

### Circuit d’autorisation, nonce et révocation

1. Vault réserve un nonce et le hash de l’opération précise, tenant/session/cible/version inclus, avec une durée maximale proposée de30secondes. Il refuse références inconnues et générations obsolètes avant toute opération de clé.
2. Le broker construit la demande à confirmer et vérifie le registre cosigné, les personnes canoniques, les authentificateurs, le demandeur, les approbateurs et le sponsor exactement comme P0-3. Il vérifie les **preuves brutes** sur ce contexte, pas seulement une ligne PostgreSQL ou un résumé HMAC envoyé par Web.
3. Le défi frais lie aussi le nonce réservé par Vault, l’audience et le broker destiné à ouvrir cette session. La page de confirmation sensible doit provenir d’une origine de confiance indépendante de Web, ou d’un canal de confirmation équivalent. Une signature WebAuthn ne garantit pas que la page compromise a montré à l’humain le vrai périmètre : cette limite UX ne disparaît pas avec mTLS.
4. Le broker sonde la cible et vérifie son identité P0-2 avant la demande de secret. Vault revérifie le même faisceau de preuves indépendantes, le contexte et le nonce ; une signature de broker seule est insuffisante. Il consomme le nonce dans son propre ledger transactionnel avant libération vers le seul broker mTLS autorisé.
5. Le broker conserve le secret uniquement pour l’authentification du transport concerné. Il ne possède ni DEK ni KEK. Les contrôles continus, révocations, fins de lease et fermetures réelles SSH/RDP restent actifs. Aucune reprise silencieuse par l’ancien chemin.

Le nouveau défi constitue une action v2, pas l’ajout a posteriori d’un nonce à une ancienne assertion. Un changement d’origine/RP ID WebAuthn suit la procédure protégée d’enrôlement/registre ; ne pas élargir l’allowlist d’origine pour rendre un ancien facteur compatible silencieusement. L’interface de confirmation indépendante doit aussi refuser le cadrage/clickjacking et les cérémonies cross-origin non prévues. Si le broker sert lui-même cette interface et qu’il est compromis, la fidélité de l’affichage devient une limite supplémentaire ; une autorité de décision distincte est requise pour un modèle protégeant aussi cette compromission.

La remise autorisée expose nécessairement ce credential à la mémoire du broker. Un broker compromis peut tenter de divulguer le secret de sa session ; une restriction réseau et des comptes/certificats distants bornés réduisent ce risque sans fournir une garantie universelle. Le secret ne doit apparaître dans aucune réponse Web, log ou capture créée par notre injection ; un pair distant malveillant peut toutefois refléter des données dans sa sortie.

Le ledger Vault reste hors droits SQL Web/worker. Un nonce est tenant/session/audience/génération/version/corps : même clé et même opération rendent le statut/reçu existant, un corps divergent rend409 audité. Un retry ne doit pas restituer automatiquement du plaintext ni transférer une remise au second broker. Si le résultat est incertain après perte réseau, fermer et recommencer un circuit explicitement borné ; aucune promesse d’exactly-once de bout en bout entre bases et transports.

Conserver les bornes P0 actuelles : cérémonie120secondes maximum, registre24heures maximum, checkpoint60secondes maximum ; elles ne prolongent pas les30secondes proposées pour la capacité. Le contrôle de session actuel surveille chaque seconde, avec deadline globale de4secondes ; toute modification doit être mesurée et justifiée, jamais un allongement pour masquer une panne. Les baux prennent le minimum des expirations applicables. Certificat révoqué, checkpoint périmé, registre plus récent, cible/version modifiée, Vault/KMS indisponible ou décision non vérifiable : refus de nouvelle libération, puis clôture au délai existant.

## Chiffrement à enveloppe et domaine des clés

Proposition technique à revoir par cryptographe : DEK aléatoire256bits **nouvelle à chaque version de secret**, chiffrement AEAD AES-GCM via la bibliothèque `cryptography`, nonce96bits unique pour cette DEK. Le schéma authentifie les AAD immuables : version de format, installation, tenant, domaine technique, ID/ version du secret, ID de DEK et hash de destination. Le nonce et le ciphertext sont stockés ; la DEK en clair ne l’est jamais. La bibliothèque documente l’authentification des AAD et le danger de réutiliser un nonce dans [sa documentation AEAD](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/).

La DEK est enveloppée sous une KEK de tenant/domaine gérée hors Vault. L’enveloppe stocke format/algorithme, référence **et version** de KEK, DEK enveloppée, contexte de wrapping, nonce, ciphertext et référence d’audit. La référence de KEK n’est pas une permission. L’AAD attendu est reconstruit depuis le contexte autorisé ; ne pas faire confiance aux seules métadonnées de la ligne déplacée.

Utiliser l’API d’un KMS maintenu pour le wrapping. Exemple de contrat, sans dépendance AWS imposée : `GenerateDataKey` fournit une DEK aléatoire et sa copie enveloppée, selon [l’API officielle](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html). Le contexte d’encryption du fournisseur doit correspondre exactement au tenant et au domaine autorisés ; il n’est pas secret et peut figurer dans les logs du fournisseur, donc aucun nom de personne ou secret dans ce contexte. [Documentation du contexte KMS](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html).

Rotation de KEK : rewrap de la DEK par API de fournisseur, sans rechiffrer obligatoirement le payload. La version KEK appartient au wrapping, pas à l’AAD du payload si l’on veut ce rewrap. Garder le lien entre versions et journal ; ne pas changer l’AAD immuable en silence. [ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html) illustre cette opération dans un fournisseur précis. Rotation du secret ou de sa destination : nouvelle version, nouvelle DEK, nouvelle validation et retrait effectif de l’ancien credential sur la cible lorsque disponible.

Un Vault unique avec un principal KMS autorisé sur tous les tenants reste une concentration de confiance. Pour annoncer une réduction de ce risque, les identités/politiques KMS doivent empêcher le principal compromis d’un périmètre d’ouvrir les KEK d’un autre. Le premier laboratoire ne démontrera pas automatiquement une politique KMS/HSM de production. Python ne garantit pas l’effacement physique de toutes les copies de buffers ; minimiser durée et copies, isoler processus, interdire core dumps et limiter la conservation, sans prétendre à un effacement prouvé.

## Témoin, journal et restauration

Le témoin possède sa propre clé et son propre stockage append-only ; Web n’obtient que ses clés publiques. Reçu signé sur tenant, émetteur authentifié, type/ID/hash d’événement, génération, séquence et hash précédent. Il peut attester qu’un message a été conservé, pas que la cible a accepté un login ou qu’un fait est vrai. V7/V8 et inventaire Directory conservent leurs formats et leur sens ; ajouter un lien vers le reçu externe, ne pas les réétiqueter rétroactivement.

Réserver et enregistrer la demande avant la remise ; publier le résultat via outbox propre à Vault/broker. Si crash entre consommation et retour client, conserver l’état incertain. Un reçu préalable n’est pas une preuve que le secret a effectivement été reçu ou qu’un accès s’est produit. Conflit d’ID/hash :409, jamais écrasement. Saturation, tailles et rétention bornées ; témoin indisponible ou checkpoint expiré bloque la prochaine capacité selon la politique choisie, sans réécrire les preuves passées.

Après restauration : vérifier toutes les anciennes preuves et clés, comparer la génération/révision au témoin externe et réconcilier les effets. Invalider sessions, tickets, capacités et nonces restaurés ; recommissionner une génération si la continuité ne peut pas être établie. Aucun retour à un ancien minimum de confiance lu uniquement depuis la sauvegarde restaurée. Le rôle runtime n’a pas de DDL ; rôle de migration et lecteur de récupération ont leurs permissions distinctes, la récupération ne conférant jamais une autorisation live.

## Migration du chemin actuel

Maintenir explicitement `legacy_fernet_v1` et `vault_envelope_v2` comme profils de cible/version durant la transition. Les cibles v2 ne retombent jamais sur `endpoint_credentials` ou le moteur natif piloté par Web en cas d’erreur. Une session ouverte garde son profil de départ ; clôturer pour bascule, ne pas changer son autorité au milieu.

Importer le secret vers Vault par un processus de migration séparé, sans remettre la clé maîtresse à Web. Vérifier la nouvelle lecture sur une cible synthétique, migrer les références et rendre l’ancien chemin inexécutable pour cette cible. **Une ancienne copie Fernet lisible par Web peut encore contenir le même credential valide** : supprimer une référence ou déplacer une colonne ne suffit pas. Pour cette tranche, renouveler le credential synthétique sur la cible puis confirmer l’ancien refusé ; garder les archives nécessaires hors accès Web. Les credentials des cibles non migrées restent exposés au modèle actuel : ne pas annoncer un confinement global prématuré.

Dans le laboratoire, placer la cible v2 sur un réseau rejoint uniquement par le broker ; ni Web, ni worker, ni ancien moteur natif ne doivent pouvoir ouvrir sa socket. Isoler aussi Vault/KMS/témoin et leurs bases : les services autorisés passent par leurs API mTLS, pas par des identifiants PostgreSQL partagés. Tester cette impossibilité par une véritable connexion TCP depuis le processus Web compromis simulé. Une allowlist Python modifiable par ce même processus n’est pas une interdiction réseau indépendante.

La fin de P2 exige davantage que cette première tranche : retirer `PAMOLIVE_ENCRYPTION_KEY` de Web **et du worker** et supprimer leur accès SQL aux ciphertexts/MAC legacy concernés. Le rôle runtime ne doit posséder ni les tables, ni les fonctions de garde, ni un rôle propriétaire ; utiliser vues ou grants de colonnes appropriés, sans privilège table global contradictoire. Le contrôle doit être testé en SQL direct, pas seulement par l’ORM. Les tests P1 avec un propriétaire de base restreint qualifient les migrations ; ils ne prouvent pas ce rôle runtime sans DDL/lecture secrète.

Cela implique de médiatiser les opérations MFA et celles des consommateurs SCIM/TeamViewer/Directory encore dépendants de la clé globale, ou de les migrer vers des clés et identités de service distinctes. Leur retirer la clé avant adaptation casserait des fonctions ; conserver la clé et les anciennes colonnes accessibles ne fournirait pas le confinement annoncé. Un vérificateur legacy isolé peut exposer seulement des opérations de vérification archivale avec buts et formats autorisés ; jamais `decrypt(bytes)` ou une API de signature générique. Après compromission passée d’une clé HMAC, une signature ancienne seule ne permet pas de dater ni de prouver l’innocuité d’un document : conserver les ancrages et limites de preuve, sans réécrire l’histoire.

Conserver les clés exactes et vérificateurs legacy dans le périmètre de récupération isolé tant que des données/captures/preuves en dépendent. Ne pas re-signer V7/V8, les attestations HMAC ou les captures historiques avec une nouvelle identité. Les témoins et la nouvelle enveloppe sont additifs ; la migration ne fait pas disparaître les limites de rollback P0-4.

## Alternatives confrontées

| Option | Apport | Décision proposée |
| --- | --- | --- |
| Extraire Web/worker mais conserver clé/DB et endpoint `decrypt` générique | Isolation de processus, déploiement plus clair | Insuffisant contre Web compromis ; étape d’exploitation seulement |
| Mettre un proxy mTLS devant le broker actuel | Authentifie le service appelant | Insuffisant si le service authentifié choisit librement la cible ou signe seul la permission |
| Broker et Vault vérifient preuves indépendantes et nonce Vault, clés séparées, témoin séparé | Première tranche refusant des requêtes Web arbitraires et limitant la libération | Recommandée en laboratoire ; plus de dépendances et disponibilité à qualifier |
| Autorité de décision dédiée, KMS/HSM réel, hôtes administrés séparément | Confinement et garde des clés plus solides | Cible production ; nécessite procédures et infrastructure supplémentaires, pas une preuve fournie par Docker local |

## Réception locale réalisable et limites

Tests Docker réels à écrire après décision, exclusivement sur conteneurs/réseaux/volumes synthétiques neufs :

| Scénario | Résultat exigé |
| --- | --- |
| Faux certificat, mauvais SAN/issuer/audience/service, clé du Web copiée vers Worker | Refus mTLS ou d’opération avant secret ; aucune clé d’autorité commune |
| Web/worker compromis dans la fixture, payload/approbation JSON forgés, ancien HMAC seul | Aucune libération sans preuves personnelles indépendantes et nonce Vault |
| Même nonce sur deux brokers simultanés, retry après coupure, corps divergent | Un ledger autoritaire, résultat déterministe ou incertain explicite,409 divergent, aucun transfert implicite du plaintext |
| Tenant/secret/session/destination/credentialversion changés | Refus avant unwrap ; déplacement de ciphertext/AAD intertenant échoue |
| Mauvaise CA/pin SSH/RDP, remplacement de cible après sonde | Aucune remise à une destination incompatible ; P0-2 conservé |
| Révocation, expiration checkpoint/certificat, pertes PostgreSQL/Vault/KMS/témoin | Refus et fermeture bornée, captures marquées incomplètes si nécessaire, aucun fallback legacy |
| Capture HTTP/API/logs/outbox/DB Web et environnement de chaque conteneur | Aucun credential technique v2 ni DEK/KEK dans Web/worker/navigateur ; secrets présents seulement dans leurs consommateurs autorisés |
| Rotation/rewrap, anciennes versions, mauvaise clé/contexte, restauration d’un vieux ledger | Historique vérifiable, anciennes capacités inutilisables, génération anti-retour arrière, restauration sur copie et rôles restreints |
| Capacité/événements/ciphertext trop grands, saturation/quota et disque témoin plein | Refus borné, refus audité selon quota, aucune suppression automatique de preuves ni ressource hôte illimitée |

Ces tests peuvent établir le comportement du logiciel et des réseaux sur un hôte Docker local. Ils ne qualifient ni HSM matériel, ni administrateurs indépendants, ni garde humaine des clés, ni panne de deux hôtes, ni compromission de l’Engine/hôte. Ces campagnes sont des prérequis de production séparés ; aucune qualification post-quantique n’est revendiquée.

**Ordre recommandé :** figer contrat et revue contradictoire → extraire le vérificateur de preuves sans autorité Web → petit Vault/KMS de laboratoire par tenant avec enveloppes versionnées → première session SSH synthétique par broker indépendant → témoin/recovery et attaques de compromission → seulement ensuite RDP, rotations étendues et qualification multi-hôte. Le chemin legacy demeure couvert par les régressions, avec sélection explicite des cibles encore non migrées.
