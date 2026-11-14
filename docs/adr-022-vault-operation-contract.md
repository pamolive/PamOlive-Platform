# ADR-022 — Formats d'opération Vault sans autorité de remise

Date : 14 novembre 2026. Statut : **acceptée par le coordinateur pour les contrats
P2-R1a seulement**, sous contre-revue Root et reviewer indépendant avant toute
extension d'autorité. Périmètre local N0 ; ce nom ne correspond à aucun niveau
de qualification NAS. La proposition plus large de registre/ledger N1 dans le
rapport externe du même jour est supersédée pour cette tranche.

## Problème et limites actuelles

[ADR-020](adr-020-isolated-vault-envelope.md) et `components/vault` livrent la
primitive AEAD explicite, sans autorité, sélection de version live, nonce métier
ou état durable. Appeler `open_authorized_version` présuppose une autorisation
que cette primitive ne vérifie pas. Un booléen Web, un HMAC Web ou un certificat
de broker ne crée pas cette autorisation indépendante.

P0-3 vérifie réellement registre cosigné, checkpoint, personnes canoniques et
assertions WebAuthn. Ses anciens défis ne signent pas automatiquement un nonce
Vault, une audience ou une version de credential ajoutés après signature. Les
modules actuels mêlent aussi ces règles à Django/ORM/configuration applicative.
Leur import par le nouveau coffre ne fournirait pas l'isolation recherchée.

Un service complet devrait encore vérifier ces autorités indépendantes,
authentifier le transport, choisir les références depuis son registre,
réserver/consommer durablement, gérer les compteurs, restaurations, clés, pannes
et révoquer les transports. Aucune de ces propriétés ne découle d'un DTO bien formé.

## Alternatives et décision

| Option | Apport | Décision |
| --- | --- | --- |
| Service complet immédiatement, registre/ledger/KMS et remise SSH | Première tranche verticale si toutes ses autorités, rôles SQL et pannes sont qualifiés | Différée : surface trop large avant figer les octets et responsabilités |
| JWT/HMAC Web ou `approved=true`, puis appel direct à la primitive | Intégration courte, même autorité que Web | Rejetée : ne résiste pas à Web compromis |
| Importer les mutations Django V1 pour deux vérificateurs | Réutilise des appels existants | Rejetée pour cette tranche : couplage applicatif et double consommation ambiguë des compteurs |
| Package autonome de formats immuables non autorisés et golden indépendants | Fige les objets/digests sans créer de chemin de remise | **Retenue : P2-R1a**, bibliothèque standard uniquement |

Les seuls nouveaux chemins sont `components/vault-registry/**` et cet ADR.
Le package distribué se nomme `pamolive-vault-contracts`, import
`pamolive_vault_contracts`. Il n'est pas ajouté au runtime Web. Il n'expose aucun
`AuthorizedRelease`, `verify_authority`, registre, ledger, SQL, listener,
provider, signature ou fonction de remise. La primitive existante et Django
restent inchangés. Une propriété `authorized=False` explicite le statut des DTO ;
elle n'est pas une permission ni un garde dont un futur service pourrait se contenter.

## Draft, transcript et reprise future

`OperationDraft` est la demande canonique sans nonce, dates d'opération ni
snapshot serveur des compteurs. Il contient : installation/tenant, génération
et incarnation demandées ; request/idempotency/session/broker-instance ; claims
de personnes et services/audiences, empreinte du certificat broker ; intention,
politique/registre/checkpoint, matériaux publics ; cible/epoch/scope ; référence
et version du credential, révision du wrapping, profil et opération.

La clé d'idempotence est un UUID opaque indépendant. Elle ne doit jamais être
calculée comme le hash du draft qui la contient. Les claims de service parsés
depuis JSON ne sont pas un `AuthenticatedCaller`. L'empreinte de certificat est
SHA-256 du **DER exact du certificat leaf broker**, ni PEM ni SPKI ; ce champ ne
vérifie pas CA, SAN, EKU, expiration, révocation ou possession de clé.

Le futur Vault constituera `FullTranscript` avec le draft inchangé, son nonce
réservé de 32 octets, le hash du snapshot de compteurs choisi et les dates.
Le parser actuel accepte seulement leur forme : il ne prouve ni origine serveur,
réservation, CSPRNG, signataires, fraîcheur ni adéquation à un appelant.

Le futur ledger devra indexer la clé avec tenant/installation/principal
authentifié/opération, comparer **draft hash et appelant authentifié** lors d'un
retry, conserver le **body hash complet séparément**, puis relire le transcript
déjà réservé. Même requête : statut/reçu existants, expiration originale, sans
plaintext ; corps divergent : conflit 409 audité. Une reprise ne doit jamais
réémettre un nonce, prolonger l'expiration ou recalculer un snapshot pour la
faire paraître identique. Ces réponses et transactions ne sont pas implémentées
ici. La consommation commit avant émission, état incertain après panne et
absence de redistribution du plaintext restent des obligations ultérieures.

Les dates sont des entiers de secondes UTC depuis l'époque Unix. La relation
structurelle est `issued_at <= not_before < expires_at <= issued_at + 30`.
Un transcript ancien peut donc être correctement formé, mais reste non autorisé.
Le futur service devra vérifier son horloge et appliquer la plus courte des
expirations, sans prolonger les bornes P0 120 s/action, 24 h/registre et
60 s/checkpoint ni les 30 s du nonce.

## Digests et absence de cycle

Les encodages V2 utilisent UTF-8, `ensure_ascii=True`, clés triées et séparateurs
`,`/`:`. Les domaines sont distincts :

```text
DRAFT_DOMAIN = pamolive.vault.operation-draft.v1\0
BODY_DOMAIN = pamolive.vault.operation-body.v2\0
CONFIRMATION_DOMAIN = pamolive.vault.confirmation-challenge.v2\0
ASSERTIONS_DOMAIN = pamolive.vault.final-assertions.v1\0

draft_hash = SHA256(DRAFT_DOMAIN || canonical(OperationDraft))
body_hash = SHA256(BODY_DOMAIN || canonical(FullTranscript))
challenge = SHA256(CONFIRMATION_DOMAIN || canonical({
  schema: pamolive.vault.confirmation-challenge/2,
  body_hash, person_id, role, decision
}))
final_assertions_digest = SHA256(ASSERTIONS_DOMAIN || raw_final_assertions_bytes)
```

Le hash des matériaux publics dans le draft porte seulement sur les octets
préexistants de registre/checkpoint/politique/identités. Il exclut draft, body
hash, nonce, snapshot réservé et assertions finales. Le futur contrat de bundle
devra figer son assemblage ; ce package n'en vérifie aucune preuve.

Le hash du bundle final est conservé hors du corps que ces assertions signent.
Les champs `body_hash`, `challenge` et `final_proof_bundle_sha256` sont refusés
dans draft/transcript. Le graphe reste matériaux publics → draft → réservation
complète → body hash → défi personnel → assertions → digest final séparé.
`confirmation_challenge` est un formateur de défi, sans vérification de
signature, de rôle, de personne canonique, de quorum ou de décision effective.
`final_assertions_digest` hashe des octets opaques ; un hash ne les authentifie pas.

## Champs fermés et types

La seule famille activée syntaxiquement est
`technical-credential.release.prepare`, profil `vault_envelope_v2`, format de
destination `pamolive.pam.target-scope/1`. Elle n'autorise pas import, register,
rewrap ou état consommé ; ces opérations devront avoir leurs propres futurs
contrats et décisions. Aucun champ `approved`, résumé MFA/HMAC Web, clé publique,
`kid`, `jku`, `x5u`, URL de provider ou lookup induit n'est accepté.

Génération et incarnation sont des UUID : égalité avec une future tête autorisée,
jamais ordre numérique ou lexical. La révision d'autorité de politique P0 est
également un UUID ; révision du registre, epoch de destination, version du
credential et révision de wrapping sont des entiers stricts positifs bornés à
`2^63-1`. Le hash de snapshot de compteurs est dans le transcript, pas dans le draft.

Les listes d'approbateurs sont 1–16 UUID déjà triés et sans doublon. Ce tri ne
représente aucun ordre d'autorité ; des IDs distincts ne démontrent pas des
personnes distinctes. Aucun tri ou dédoublonnage silencieux n'est effectué.
L'absence de sponsor est la chaîne vide. Services : références ASCII opaques
1–64 caractères ; hashes SHA-256 : 64 hexadécimaux minuscules.

Budgets V2 : 16 KiB/draft, 32 KiB/transcript avant parsing ; profondeur 8,
512 nœuds, chaîne 4096 caractères. JSON fermé, sans clé dupliquée/alias échappé,
null, booléen, flottant ou non-fini, conversion implicite ou Unicode dans V2.
Nonce : base64url canonique non paddé, exactement 32 octets décodés. Bundle final
opaque : 1 octet–2 MiB. Les erreurs constantes ne contiennent pas les entrées.

## Compatibilité P0 limitée et restauration

Les encodeurs de compatibilité P0 préservent les octets des valeurs admises :
`ensure_ascii=False`, aucun NFC/NFD ajouté, UUID canoniques et dates converties
en UTC `isoformat(timespec="microseconds")`, suffixe `+00:00`. Les domaines restent
exactement `pamolive.pam.trust-registry.v1\0` et
`pamolive.pam.trust-checkpoint.v1\0`. Les scopes golden SSH/RDP ont les douze
champs historiques, sans `schema` injecté dans l'ancien objet. Les AAD de la
primitive enveloppe restent un autre encodage et ne sont pas modifiées.

Ces encodeurs sont un **sous-ensemble borné d'encodage**, pas un remplacement de
`platform_core.attestations.canonical` ni un vérificateur P0 : 2 MiB, profondeur
16, 8192 nœuds, chaînes 65536 caractères sans NUL, entiers signés 64 bits.
Les flottants finis historiquement encodables restent distincts du profil V2.
Aucun ancien appelant ou document historique n'est changé ou re-signé.

L'identifiant d'installation du contrat Vault est un UUID conformément à
ADR-020. Le P0 actuel accepte au contraire un identifiant opaque non vide,
borné à 128 caractères, et conserve ses octets exacts. Une future coexistence
exigera une **liaison commissionnée indépendante entre ces deux espaces**,
vérifiable hors Web. Aucune conversion UUID, dérivation par hash, troncature,
équivalence implicite même si le texte ressemble déjà à un UUID, ni réécriture
historique ne réalise cette liaison. P2-R1a n'en fournit ni port ni autorité.

Les budgets d'encodage s'appliquent aussi aux objets Python avant production du
JSON complet. `JSONEncoder.iterencode` émet des chunks dont chaque chaîne a déjà
été bornée par le parcours structurel ; chaque chunk est compté en octets UTF-8
**avant** d'être ajouté au buffer de sortie. Une référence répétée compte à
chaque occurrence sérialisée. Le refus intervient dès le dépassement, sans
construire d'abord plusieurs centaines de MiB, et conserve les octets golden.

Le stockage anti-rollback n'est pas livré. Un futur registre ne pourra pas
réactiver une ancienne enveloppe parce qu'elle est déchiffrable. Une
restauration devra rester fermée jusqu'à comparaison avec une tête indépendante
et réconciliation ; une incarnation indépendante nouvelle invalidera anciens
nonces/sessions. Un UUID ne fournit pas un compteur monotone. Un checkpoint du
backup ou un booléen Web ne rétablit pas la fraîcheur. Les rôles PostgreSQL
non-owner, compteurs WebAuthn autoritaires et concurrence/crash seront soumis à
une autre décision et à des essais SQL réels ; aucun double mémoire ne les prouve.

## Vérification et extension

Les fixtures golden sont statiques, construites sans le code produit. Elles
fixent Unicode NFC/NFD distincts, date avec offset vers UTC microseconde, UUID,
domaines P0, scopes SSH/RDP, draft/transcript V2, hashes et défi personnel.
Les tests ne régénèrent pas ces oracles. Les mutations de chaque champ doivent
changer les engagements ou être refusées, sans devenir autorisées.

La suite pure couvre types/budgets, doublons et clés échappées, URI/key lookup,
imports sans Django/app/réseau/stockage/crypto, nonces et temps structurels,
séparation des familles d'opérations et absence de capacité. Aucun PostgreSQL,
Docker, KMS, NAS ou service réel n'est nécessaire ou qualifié par ces tests.
La contre-revue Root et indépendante est obligatoire avant toute extension
vers preuve, autorité, ledger ou remise. Un succès de ces contrats seuls ne
qualifie ni P2, ni un service isolé, ni la résistance à Web compromis.
