# ADR-020 — Enveloppes et autorité du Vault isolé

**12 novembre 2026 · Acceptée par le coordinateur pour la primitive N0 et son double de test.** Cette décision suit la proposition cryptographique et sa contre-revue architecture/backend indépendante, avec les six précisions consignées ci-dessous. Aucun Vault, provider KMS réel, service TLS ou migration P2 n'est livré par ce document. Elle reprend les [revues des frontières](p2-trust-boundary-review.md) et [cryptographique](p2-cryptography-review.md), ADR-013/014 et la feuille de route *Architecture & Roadmap 2026–2029*, pages26–27. Le périmètre d'essai reste N0, sans NAS, compte privilégié ou secret réel.

## Problème et garantie visée

`platform_core.security.cipher` protège les données historiques par Fernet avec le matériel applicatif. Les sceaux de destination et plusieurs preuves utilisent aussi ce matériel pour leurs MAC. `pam.sessions.endpoint_credentials` revalide réellement la confiance et la cible avant de déchiffrer, mais reste dans le processus applicatif. Un Web compromis dispose donc encore du pouvoir de déchiffrer les ciphertexts qu'il peut lire. P0-1 refuse une configuration vide ; ce contrôle n'isole pas les clés.

P0-3 vérifie déjà un registre cosigné, un checkpoint et de vraies assertions WebAuthn. La possession du matériel Fernet/HMAC ne permet pas de fabriquer les signatures de dépositaires ou d'authentificateurs indépendants. P2 doit conserver ces autorités et déplacer leur vérification hors du Web, plutôt que les remplacer par une déclaration `approved` du frontal.

La première réception portera sur **un nouveau credential technique, une destination SSH synthétique et une session**, avec Vault, broker, gestion des clés, ledger et témoin distincts. Sa garantie est limitée à cette cible : Web/worker ne peuvent obtenir son credential ni utiliser le chemin legacy. Le broker autorisé connaît nécessairement le credential de sa session ; il ne reçoit aucune DEK ou KEK et ne peut demander arbitrairement un autre secret. La résistance au root d'un hôte partagé n'est pas revendiquée.

## Choix et alternatives

| Option | Garantie et dépendances | Décision proposée |
| --- | --- | --- |
| Autres conteneurs, clé Fernet et SQL partagés | Séparation d'exploitation, même pouvoir de déchiffrement pour Web/worker | Insuffisant pour la garantie P2. Conserver seulement pour les cibles explicitement legacy. |
| Nouveau secret chiffré directement sous une clé commune de service | Format simple, mais rayon de compromission global et rotations couplées | Écarté pour le nouveau format. |
| Enveloppe AEAD, DEK par version, KEK par tenant/domaine et provider séparé | Sépare données, clés et autorisation ; exige contrats et récupération multi-version | Retenu comme contrat. |
| Double KMS en mémoire ou à clés synthétiques injectées | Reproductions déterministes des substitutions, pannes et rotations | Fixture de tests uniquement, jamais backend implicite d'un service. Aucune qualification KMS/HSM. |
| KMS logiciel maintenu sur un périmètre dédié | Permet un vrai laboratoire local avec TLS, politiques et persistance propres | Prochain adaptateur N0 à qualifier séparément. Ne pas créer un protocole cryptographique maison. |
| KMS/HSM maintenu et autorités/hôtes distincts | Peut imposer garde et non-exportabilité des KEK ; dépend des permissions et de la reprise réelles | Cible de production. Aucun choix de fournisseur ou de matériel imposé par ce premier contrat. |

La primitive doit accepter un **provider explicite** avec un contexte authentifié, sans SDK réseau par défaut. Les API publiques [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) et [ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html) illustrent un mécanisme maintenu de génération/enveloppement/réenveloppement ; elles ne justifient ni appel AWS réel ni dépendance AWS du premier lot. Une adaptation fournisseur doit identifier ses clés et vérifier ses politiques, au lieu d'interpréter un handle fourni par le client comme une permission.

## Contrat d'enveloppe proposé

Le profil de cible `vault_envelope_v2` est distinct du format d'enveloppe initial `pamolive.vault-envelope/1`. Ces versions ne sont pas des reclassements des preuves V7/V8. La primitive est indépendante de Django, de `settings`, de la base Web et des endpoints HTTP. Elle ne possède aucune autorité d'accès métier.

Le payload utilise AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM` : DEK aléatoire de32octets neuve par version de secret, nonce de12octets, tag complet de16octets. Aucun couple DEK/nonce n'est réutilisé pour une autre encryption. Les retries lisent le résultat déjà conservé. L'API maintenue authentifie l'AAD et refuse un tag, une clé, un nonce ou une AAD incompatibles. [Documentation AESGCM](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM), [NIST SP800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

L'unicité persistante `(tenant, secret, version)` et les reprises de création relèvent du service de stockage transactionnel, pas d'AESGCM ni d'une liste mémoire dans la primitive. Un retry ne rappelle pas `seal_new_version` sur la version déjà conservée. La primitive seule ne démontre donc pas l'idempotence multi-processus ; son essai de non-réutilisation concerne les nouvelles DEK, et le service devra tester les écrivains concurrents.

Champs fermés, à valider avant toute opération de clé :

| Partie | Champs |
| --- | --- |
| Enveloppe | `schema`, `payload_algorithm`, `binding`, `dek_id`, `payload_nonce`, `payload_ciphertext`, `wrapping` |
| `binding` | `installation_id`, `organization_id`, `domain`, `secret_id`, `secret_version`, `purpose`, `destination_scope_hash` |
| `wrapping` | `schema`, `provider_id`, `kek_id`, `kek_version`, `wrapped_dek`, `context_hash` |

`payload_algorithm` vaut exactement `AES-256-GCM`. Le wrapping initial vaut `pamolive.kms-context-wrap/1` : `wrapped_dek` est un blob opaque du provider, pas un format AES inventé par PamOlive. Le provider doit authentifier le contexte attendu ; un provider sans cette garantie est incompatible avec ce profil. Ses paramètres cryptographiques internes appartiennent à un profil fournisseur revu, sans négociation arbitraire depuis l'enveloppe.

Les domaines reconnus sont `technical-credentials`, `user-vault`, `recordings` et `evidence-signing`, avec clés indépendantes. **La première tranche n'active que `technical-credentials`.** Les clés de signature de preuves/capacités et celles du TLS sont distinctes des clés AEAD. Le domaine `evidence-signing` ne transforme pas une clé de signature en credential que le broker pourrait recevoir.

### Sérialisation et budgets

Le contrat `vault-aad/1` sérialise un objet à clés fixes en JSON UTF-8, clés triées, séparateurs `,` et `:`, `ensure_ascii=True`, sans flottant, nombre non fini ni conversion implicite. Les métadonnées acceptées sont des chaînes ASCII ou entiers stricts ; `bool` n'est pas un entier valide. Les UUID sont des chaînes canoniques minuscules avec tirets. `secret_version` et `kek_version` sont des entiers strictement positifs, au plus `2^63-1`. Une version fournisseur opaque doit recevoir un autre profil documenté, pas une conversion silencieuse.

Les IDs de provider/clés/buts sont des références opaques bornées, prises dans des registres serveur autorisés, sans URL à résoudre, chemin arbitraire, accès réseau ou lookup dynamique induit par le document. Le contexte ne contient aucun nom humain, login, secret ou chemin privé. Les métadonnées/AAD ne sont pas confidentielles ; certains providers les journalisent. [Contexte authentifié KMS](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html).

| Limite de première implémentation | Valeur maximale |
| --- | ---: |
| Enveloppe JSON UTF-8 avant parsing |128KiB |
| Profondeur JSON / nombre total de membres |8 /128 |
| Plaintext technique / ciphertext avec tag, après décodage |65536 /65552octets |
| Blob enveloppé, après décodage |16KiB |
| AAD canonique de chaque couche |4096octets |
| Référence provider / référence KEK / but |64 /128 /64caractères ASCII |

Les secrets techniques nouveaux sont non vides. Base64url sans padding, alphabets et longueurs exacts, puis réencodage identique requis ; rejeter les encodages équivalents non canoniques. `destination_scope_hash` est un SHA-256 de64caractères hexadécimaux minuscules, sans valeur vide pour un credential technique. Rejeter clés JSON dupliquées, champs inconnus ou manquants, `null`, types inattendus et dépassements avant allocation volumineuse ou appel KMS. Aucun auto-upgrade de schéma/algorithme. Les limites sont une décision locale initiale, non les limites générales de la bibliothèque.

### Deux AAD distinctes

L'AAD de payload est l'objet canonique suivant :

```text
schema = pamolive.vault-payload-aad/1
envelope_schema = pamolive.vault-envelope/1
payload_algorithm = AES-256-GCM
binding = contexte immuable complet ci-dessus
dek_id = UUID de cette DEK
```

`destination_scope_hash` engage le document de destination exact comprenant les éléments P0-2 : organisation, endpoint/epoch, ressource, compte et username, protocole, hôte/port, domaine, méthode d'authentification et clé SSH ou certificat RDP. Son contrat de normalisation doit être figé avec les tests du scope P0-2 existant, sans réinterpréter ses anciens octets. Le hash ne prouve pas la possession de la clé cible : broker et sonde gardent cette vérification avant émission d'un credential.

L'AAD/contexte de wrapping engage un autre objet canonique :

```text
schema = pamolive.vault-wrap-aad/1
installation_id / organization_id / domain
secret_id / secret_version / dek_id
payload_aad_sha256
provider_id / kek_id / kek_version
```

`context_hash` est SHA-256 de ces octets. Ce hash facilite l'identification ; sa présence seule n'authentifie rien. Le provider doit vérifier le contexte complet au désenveloppement. Les AAD attendues sont reconstruites depuis **le contexte de l'opération autorisée et le registre Vault**, puis comparées à l'enveloppe ; déplacer une enveloppe complète avec ses métadonnées dans un autre tenant ne doit pas créer un contexte valable.

La référence/version de KEK ne figure pas dans l'AAD du payload. Un réenveloppement conserve donc exactement `binding`, `dek_id`, nonce et ciphertext du payload, et crée une nouvelle révision de wrapping liée au même hash d'AAD. Il ne constitue ni une nouvelle version du secret, ni un changement sur la cible distante. Une rotation de DEK, du secret ou de destination crée une version et une DEK neuves. Une ancienne version restaurée n'est pas automatiquement la version live : le registre autoritaire et la génération indépendante empêchent son réemploi silencieux.

Conserver les révisions de wrapping et les clés nécessaires aux archives autorisées ; ne retirer aucune KEK tant qu'une sauvegarde conservée en dépend. Dans un KMS à rotation interne opaque, la version locale ne doit pas prétendre identifier une version interne non exposée par le fournisseur : cet adaptateur doit figer son mapping/versionnement propre avant d'être accepté.

Nonce AEAD, nonce d'opération Vault, défi WebAuthn et clé d'idempotence ont des usages distincts. Ne mettre ni nonce Vault, ni TTL de session, ni certificat éphémère du broker, ni révision mutable de confiance dans l'AAD persistante du payload : ces données appartiennent à l'autorisation courte. Leur ajout imposerait un rechiffrement à chaque session sans empêcher, seul, le rejeu d'une autorisation.

## Configuration et interface interne du provider

| État de configuration du nouveau profil | Comportement obligatoire |
| --- | --- |
| Provider absent et V2 explicitement désactivé | Profil indisponible, aucun accès V2 ; les seuls chemins legacy explicitement sélectionnés conservent leur comportement. |
| Provider absent et V2 activé | Échec de configuration avant mise en service. |
| Valeur fournie vide, blanche, malformée, alias non résolu ou profil inconnu | Erreur explicite ; aucun défaut vers Fernet, `SECRET_KEY`, clé générée au démarrage ou fixture mémoire. |
| Référence valide, credentials/service/provider indisponibles | Pas de remise ; erreur bornée de disponibilité, pas de déchiffrement local de secours. |
| Matériel de clé du double N0 | `bytes` de32octets, sinon refus ; aucune conversion de chaîne, dérivation de mot de passe ou assertion d'entropie fondée sur sa seule longueur. |

Les réglages P0-1 existants ne changent pas : variable Fernet historique absente, vide et valide restent interprétées par leur vérificateur actuel. Les nouvelles références ne doivent pas accéder aux clés applicatives historiques.

Contrat de bibliothèque à implémenter séparément après décision :

```text
seal_new_version(plaintext_bytes, expected_binding, approved_kek, explicit_provider) -> Envelope
open_authorized_version(envelope, expected_binding, expected_kek, explicit_provider) -> bytes
rewrap(envelope, expected_binding, expected_source_kek, approved_destination_kek, explicit_provider) -> Envelope
```

Ces méthodes sont internes au domaine Vault. Elles testent la cryptographie, pas les droits métier ; elles ne deviennent jamais des endpoints `decrypt(bytes)` ou une capacité confiée à Web/worker/broker. Le type `expected_binding` est produit par le chemin d'autorisation Vault, pas désérialisé comme autorité depuis un champ utilisateur. Le provider réserve les opérations à l'identité du Vault et aux tenants/domaines autorisés. Une identité KMS wildcard sur tous les tenants conserve un rayon global de compromission malgré la présence d'IDs distincts.

La référence de clé est un type immuable `KeyRef`, contenant provider, KEK et version, lié au tenant/domaine attendus. `Binding`, `Envelope` et les retours de wrapping sont aussi immuables. Avant tout unwrap, la primitive compare **à la fois** le binding et la référence provider/KEK/version attendue, fournis par le registre serveur. Une ancienne enveloppe valide ne devient donc pas courante parce qu'elle est déchiffrable ; le futur registre choisit explicitement la référence historique autorisée lors d'une récupération.

La tranche1 limite `rewrap` au même provider, avec source et destination explicites. Elle désenveloppe la DEK, authentifie le payload par AESGCM, puis enveloppe la même DEK sous la destination approuvée. Le payload reste byte-identique ; aucune API fournisseur ReEncrypt distante n'est prétendue exercée. Changer de provider demande un contrat ultérieur. La révision transactionnelle d'un wrapping demeure dans le futur registre avec contrôle de concurrence/CAS ; elle n'est pas confondue avec la version de KEK. Les retours du provider doivent contenir exactement la référence approuvée, une DEK `bytes` de32octets ou un blob opaque `bytes` borné à16KiB, selon l'opération. Aucun booléen `authorized` ne remplace ces contrôles.

Implémentation initiale dans un package indépendant `components/vault/src/pamolive_vault_envelope`, avec tests propres : aucun import Django, réglage applicatif, enregistrement de module, endpoint HTTP, adaptateur réseau implicite ou import depuis Web. Sa disponibilité dans le dépôt n'active aucun chemin de déchiffrement. La configuration opérationnelle et l'isolation de processus restent des livraisons distinctes.

DEK en clair de32octets uniquement dans le processus Vault pendant une opération ; jamais stockée, sérialisée, loguée ou renvoyée au broker. Le provider peut la générer/envelopper ou envelopper celle obtenue par le CSPRNG maintenu ; aucune KEK n'est remise au Vault dans le profil cible. Le double N0 peut détenir des KEK synthétiques en mémoire, avec cette limite nommée. Python ne garantit pas l'effacement de toutes les copies : limiter durée, copies, dumps et accès au processus sans annoncer un effacement physique prouvé.

Un résultat d'intégrité invalide ne retourne aucun plaintext partiel et conserve un code d'erreur constant, sans clé, ciphertext ou diagnostic brut. Timeout et quotas d'appels provider sont imposés par l'adaptateur/service ; la primitive seule ne qualifie pas la disponibilité réseau.

## Autorisation indépendante avant une remise

mTLS doit vérifier réellement CA, SAN, EKU et certificat puis mapper côté serveur l'identité stable, le tenant, l'audience et l'opération. Un nom dans JSON, un en-tête HTTP ou une IP Docker ne joue pas ce rôle. Une rotation du certificat ne transfère pas les capacités liées à l'ancien certificat. Le modèle de jeton lié au certificat de [RFC8705](https://www.rfc-editor.org/rfc/rfc8705.html) peut être employé si des jetons sont introduits ; il ne remplace pas la décision PAM.

Broker **et** Vault revérifient les preuves brutes du registre P0-3, signatures et personnes canoniques indépendantes, demandeur/sponsor/approbateurs, révisions, checkpoints, cible P0-2 et version du credential. Le nouveau service ne fait pas confiance à une ligne `approved`, un booléen MFA ou un HMAC Web. Les clés publiques de commissionnement/checkpoint et leur plancher de génération sont épinglés hors Web. Un authentificateur n'atteste pas à lui seul une personne indépendante.

Une action `pamolive.privileged-operation/2` doit engager réellement : installation/génération, tenant, opération/audiences, identités de service et empreinte du certificat broker, session/broker-instance, personnes canoniques et intention/périmètre, politique/registre/checkpoint, destination/epoch/hash, référence/version du credential, nonce réservé par Vault, `issued_at`, `not_before` et `expires_at`. Le nonce Vault est aléatoire, borné et à usage unique, avec **TTL maximal30secondes**, sans tolérance ajoutée qui l'allonge. Les limites P0 de120s/action,24h/registre,60s/checkpoint sont conservées ; appliquer la borne la plus courte.

Les anciennes assertions `pamolive.pam.action-challenge/1` ne signent pas automatiquement ce nouveau transcript. Préserver leurs vérificateurs historiques et créer une action V2 distincte, sans champs ajoutés après signature. L'origine de confirmation sensible doit être indépendante de Web ou passer par un client de confiance équivalent, avec RP/origines commissionnés, protections de cadrage et affichage du vrai contexte. La vérification [WebAuthn](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion) ne démontre pas, à elle seule, ce qu'un frontal compromis a montré à l'humain.

Extraire une vérification cryptographique indépendante ne consiste pas à rappeler deux fois la mutation Django V1 : le protocole V2 doit spécifier les états et compteurs d'authentificateurs, leur vérification par chaque autorité et leur reprise sans double consommation contradictoire. Le ledger Vault reste l'autorité durable d'usage du nonce de remise. Ce raccord est une porte d'intégration distincte, non une propriété fournie par la primitive d'enveloppe.

Si un JWS devient utile, employer PyJWT déjà verrouillé, avec algorithmes/émetteurs/audiences/types explicitement autorisés et règles distinctes par but. Pas de clé embarquée ni `jku`/`x5u` du demandeur. Un JWS de transport ne se substitue pas au faisceau de preuves. [RFC8725](https://www.rfc-editor.org/rfc/rfc8725.html).

## Ledger, pannes et restauration

Le ledger appartient à Vault, dans une base et un rôle non-owner distincts sans accès SQL Web/worker. Les migrations utilisent une autre identité. L'unicité de l'idempotence est tenant + principal authentifié + opération + clé ; corps identique donne un statut/reçu existant, corps divergent donne409 audité et borné. Un replay ne restitue jamais automatiquement le plaintext.

Sous transaction, verrouiller le nonce, vérifier contexte/expiration/état vivant puis enregistrer et **committer sa consommation durable avant toute remise**. Déchiffrer et émettre une seule réponse sur le canal broker autorisé ; journaliser ensuite le résultat. Une réservation modifiée seulement dans une transaction qui pourrait être annulée après émission ne satisfait pas cette garantie. Après panne entre consommation et résultat, garder un état `uncertain`, ne pas redistribuer le secret ; fermer/recommencer sous une nouvelle autorisation courte. Aucun exactly-once global n'est revendiqué entre KMS, SQL et transport cible.

Les révocations et expirations connues sont revalidées avant remise et avant authentification cible ; le contrôle continu du transport reste borné par les délais P0 actuels. On ne peut retirer des octets déjà remis au broker ou au pair. Vault/KMS/témoin indisponible : refus, puis clôture conformément au contrôle existant ; aucun fallback legacy.

Après restauration/PITR, les anciennes enveloppes peuvent redevenir lisibles dans le contexte de récupération autorisé, mais aucun ancien nonce/session/ticket ne redevient live. Comparer le plancher de génération/révocations à un état indépendant des sauvegardes restaurées ; sinon recommissionner sous l'autorité partagée ADR-013 avant remise en service. Les procédures KMS/HSM natives doivent restaurer leurs clés ; ne pas inventer un partage de secret, unseal ou quorum cryptographique de remplacement. Le break-glass cible garde son autorité hors portail et ne change ni registre ni quorums.

## Migration et conséquences pour les installations

Pas de remplacement global de `cipher()`, de rotation de la clé Fernet ou de réécriture de preuves P0 dans ce lot. Conserver octets, formats, clés nécessaires, vérificateurs V7/V8, sceaux et captures. Une nouvelle enveloppe ne rend pas publique une ancienne clé HMAC ; un détenteur d'une clé de vérification HMAC peut aussi produire des MAC. Une nouvelle signature d'archive atteste un nouvel ancrage à sa date, pas la vérité rétroactive des données.

Migrer d'abord une nouvelle cible synthétique : credential réellement neuf/renouvelé, référence V2 explicite, test de refus de l'ancien credential, puis retrait du routage legacy. Web, worker et ancien moteur ne doivent plus pouvoir joindre cette cible, par réseau réellement séparé, pas seulement par une allowlist modifiable en Python. Une ancienne copie Fernet lisible par Web contenant encore un mot de passe valide annulerait la garantie pour cette cible.

La fin de P2 exige de retirer les clés/global-ciphertexts legacy de Web **et** du worker, ce qui impose de traiter MFA, SCIM, TeamViewer, Directory et signatures encore dépendants de ce matériel. Un vérificateur legacy isolé expose des opérations archivales par but/format, sans oracle de déchiffrement ou de signature générique. Les cibles non migrées conservent leurs limites actuelles, sans revendication de confinement global. Un rollback ne réactive jamais d'ancien credential ni un ancien écrivain incompatible ; les sauvegardes anciennes restent conservées sous accès de récupération séparé.

## Réception falsifiable et étapes d'implémentation

| Livraison | Essais obligatoires avant réception |
| --- | --- |
| Primitive sans HTTP | Vecteurs connus AEAD, round-trip, formats/types/budgets, mauvaises clés/nonces/tags/AAD, altération de chaque champ, transposition tenant/domaine/destination/version, pas de plaintext partiel, provider explicite, absent/vide/invalide, aucun log de secret. |
| Versionnement et rewrap | Nouvelle DEK par version, pas d'encryption répétée sur retry, payload byte-identique après rewrap, ancienne KEK conservée pour archives autorisées, panne/retrait de clé, ancienne version refusée comme live après rotation. |
| Vault et KMS de laboratoire | Vrais processus/mTLS, politiques tenant/domaine et erreurs de CA/SAN/EKU/certificat/identité/audience, refus avant unwrap, quotas et timeouts ; double mémoire non accepté comme preuve de KMS réel. |
| Ledger PostgreSQL | Rôles sans DDL/lecture interdite testés en SQL direct, deux consommateurs/brokers concurrents, consommation commit avant réponse, crash aux frontières,409 divergent, retry sans plaintext, génération anti-rollback après restauration peuplée. |
| Tranche SSH isolée | Preuves P0-3 réelles et action V2, tentative Web/worker/broker compromis, nonce/transcript substitué, remplacement de cible, mauvais pin avant secret, révocation et fermeture mesurée, aucune clé ni credential dans Web/worker/navigateur/logs/captures d'injection. |
| Compatibilité et extension | Suites P0-1..4, témoins V7/V8/Fernet/captures historiques, migrations/restauration/rollback sur copies ; puis RDP/NLA, coffre utilisateur/partage/export et reprise multi-hôte dédiés. |

La première implémentation proposée est la **primitive et son double de test**, suivie du vérificateur de preuves indépendant et du ledger, puis du laboratoire complet. Une réussite de primitive n'autorise pas une route de remise de secrets ni une qualification de P2. Les domaines utilisateur et technique ont des autorités et interfaces distinctes : pas de partage de credential par un simple identifiant identique entre domaines. Aucun zero knowledge, sécurité post-quantique, HSM réel, indépendance humaine ou haute disponibilité multi-hôte n'est annoncé par ce contrat.

Validation de cette ADR : confrontation documentaire du code et des revues existantes, sources primaires consultées, cohérence des champs/budgets et limites explicitée. Aucun test produit, migration, appel KMS réel, build Docker ou connexion NAS exécuté par son auteur. La contre-revue a précisé la sélection KEK à la création, sa comparaison au registre à l'ouverture, le même-provider initial, la validation du tag au rewrap, les types/retours bornés et la révision transactionnelle séparée. Le coordinateur accepte ces choix pour une implémentation de primitive suivie d'une revue cryptographique indépendante. Aucune qualification de P2 ou autorisation de remise réseau n'en découle.
