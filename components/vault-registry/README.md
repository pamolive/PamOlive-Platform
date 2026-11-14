# Contrats Vault P2-R1a

Ce package autonome **ne fournit que des formats non autorisés**. Il n'est pas
un registre, un ledger, un service ni un vérificateur de preuves. Aucun import
Django/applicatif, réseau, stockage, provider, signature, déchiffrement ou remise
de secret n'est livré. La proposition initiale de registre N1 est supersédée,
pour cette tranche, par P2-R1a, laboratoire local N0 ; aucun lien avec un niveau
NAS nommé N1. Voir [ADR-022](../../docs/adr-022-vault-operation-contract.md).

`OperationDraft` et `FullTranscript` sont immuables et portent une propriété
`authorized` toujours fausse, absente de leur JSON fermé. Cette propriété rend
leur portée explicite ; elle n'est pas un garde d'autorisation utilisable par un
service. Il n'existe aucun type ou convertisseur `AuthorizedRelease`.

`parse_draft(bytes)` / `serialize_draft(draft)` et
`parse_transcript(bytes)` / `serialize_transcript(transcript)` vérifient seulement
la structure. Des références inventées, une personne sans habilitation ou un
transcript ancien peuvent être bien formés : ces objets restent non autorisés.
Le parsing de service/audience/certificat n'authentifie jamais un appelant.

## Deux identités distinctes

Le draft conserve la demande complète sans nonce d'opération, horodatage ni
snapshot de compteur serveur. Sa clé d'idempotence est un UUID opaque choisi
indépendamment ; ne jamais la définir comme le hash de ce même draft.

Le futur Vault construira le transcript complet après résolution indépendante
du demandeur et réservation durable : draft inchangé, nonce de 32 octets,
hash du snapshot de compteurs, dates et schéma V2. Ce package ne génère ni ne
réserve ces données ; son parser ne prouve ni leur origine serveur ni l'aléa.
Les dates sont des entiers de secondes UTC depuis l'époque Unix. Le contrôle
`issued_at <= not_before < expires_at <= issued_at + 30` est structurel ; aucun
appel à l'horloge ni vérification de fraîcheur live n'est effectué.

`draft_hash` et `body_hash` ont des domaines distincts. Le futur ledger devra
comparer **draft hash + appelant réellement authentifié** lors d'un retry,
conserver séparément le body hash complet, et relire la réservation existante.
Il ne devra jamais régénérer nonce, snapshot ou expiration pour rendre un retry
identique. Aucun comportement PostgreSQL ou réponse HTTP 200/409 n'est implémenté.

Le `authority_materials_sha256` engage seulement les matériaux publics existants
avant le draft : registre, checkpoint, politique et identités. Il exclut ce
draft, body hash, nonce/snapshot réservés et les assertions finales. Le digest
du bundle final est calculé séparément avec `final_assertions_digest(bytes)` ;
cette fonction hashe des octets opaques bornés et **ne valide aucune preuve**.
Les champs qui créeraient un cycle (`body_hash`, `challenge`, hash du bundle
final) sont refusés dans les deux documents.

`confirmation_challenge(transcript, person_id=..., role=..., decision=...)`
formate un défi de 32 octets lié au body hash et à ces trois claims. Il ne
vérifie ni personne canonique, quorum, rôle, WebAuthn ou signature. Une assertion
V1 ne devient pas une assertion V2 par ajout de ces champs.

## Types et budgets

Les champs complets sont définis par les deux dataclasses fermées. La seule
opération est `technical-credential.release.prepare` ; aucun import, register,
rewrap, decrypt ou état consommé n'est admis. Ces opérations demanderont leurs
propres contrats, preuves et décisions. Le profil est exactement
`vault_envelope_v2` et le scope de destination `pamolive.pam.target-scope/1`.

UUID canoniques minuscules pour génération, incarnation et révision d'autorité
de politique : **égalité seulement**, aucun ordre sémantique. La révision du
registre, l'epoch de destination et les versions de credential/wrapping sont des
entiers stricts positifs jusqu'à `2^63-1`. `bool`, chaîne numérique et flottant
ne sont pas des entiers. Les approbateurs sont 1–16 UUID déjà triés et uniques,
sans déduplication ou tri automatiques ; cela n'atteste aucune indépendance
humaine. L'absence de sponsor est la chaîne vide, pas `null`.

Services : références ASCII opaques de 1–64 caractères, sans résolution de
chemin/URL. SHA-256 : 64 hexadécimaux minuscules. Le hash du certificat broker
désigne **le DER exact du certificat leaf**, pas son PEM ni son SPKI ; cette
convention ne remplace aucune validation mTLS. Les clés, `kid`, `jku`, `x5u`,
URLs de provider, champs `approved` ou HMAC Web sont absents du contrat et refusés.

JSON V2 UTF-8 : champs fermés, ASCII, clés triées, séparateurs `,`/`:`,
`ensure_ascii=True`, sans conversion implicite, booléen, flottant/non-fini,
null ni clé dupliquée (y compris un alias échappé). Les espaces et l'ordre des
clés à l'entrée ne changent pas le hash canonique. Limites : draft 16 KiB,
transcript 32 KiB avant parsing, profondeur 8, 512 nœuds, chaîne 4096 caractères.
Nonce base64url sans padding, 43 caractères, décodage exactement 32 octets et
réencodage identique. Bundle final opaque : 1 octet–2 MiB, jamais parsé comme
preuve. Les erreurs constantes `invalid_operation_contract` n'exportent pas les
entrées brutes.

## Compatibilité d'encodage P0 et golden

`p0_canonical`, `p0_registry_message` et `p0_checkpoint_message` sont uniquement
des **encodeurs sur un sous-ensemble borné**, pas une extraction du vérificateur
P0 ni un remplacement global de son encodeur. Ils préservent `ensure_ascii=False`,
les domaines exacts avec octet NUL final, UUID et dates UTC à six décimales
`+00:00`. Unicode NFC/NFD reste distinct ; aucune normalisation n'est ajoutée.
Les flottants finis du codec P0 restent encodables, contrairement à V2.
Les limites propres à ce sous-ensemble sont 2 MiB, profondeur 16, 8192 nœuds,
chaîne 65536 caractères sans NUL, entier signé 64 bits. Les appelants legacy
et leurs vérificateurs ne sont pas modifiés.

L'installation Vault est un UUID ; l'installation P0 historique peut être une
référence opaque non vide de 128 caractères au plus. Leur future correspondance
devra être commissionnée indépendamment de Web. Aucune conversion, dérivation par
hash ou réécriture historique implicite n'est définie par ces formats.

L'encodage utilise `JSONEncoder.iterencode` et compte les octets UTF-8 de chaque
chunk avant ajout au buffer borné. Les chaînes individuelles sont déjà limitées
par le parcours ; les références Python partagées comptent à chaque occurrence
sérialisée. Les tests instrumentent un objet partagé qui produirait plus de
500 MiB avec un encodage intégral, et vérifient le refus après quelques chunks,
sans cette allocation ni changement des octets golden.

Les vecteurs fixes sous `tests/golden` ont été produits sans importer le package,
par un constructeur de JSON de référence indépendant ; P0 contient également
une chaîne attendue littérale Unicode/date. Les tests ne régénèrent jamais ces
fichiers. Les scopes SSH/RDP golden gardent exactement les douze champs P0,
sans ajouter de champ `schema` au document historique. Ces vecteurs ne sont pas
des registres ou signatures valides et ne prouvent aucune autorisation.

## Vérification locale

```powershell
python -B -m unittest discover -s components/vault-registry/tests -v
python -m ruff check components/vault-registry
python -m ruff format --check components/vault-registry
```

La bibliothèque standard suffit aux tests ; Ruff est un outil de développement
distinct. Aucun serveur, base, réseau ou provider n'est nécessaire. Les tests
couvrent les golden indépendants, substitutions de chaque champ, séparation
draft/body/confirmation/bundle, doublons et aliases JSON, types/budgets,
Unicode, nonce/TTL, références URI et import sans application/réseau/crypto.
Les garanties de stockage durable, autorité indépendante, concurrence,
restauration fail-closed, mTLS et remise SSH restent à implémenter et qualifier
dans des tranches ultérieures après contre-revue et décision du coordinateur.
