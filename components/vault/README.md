# Primitive interne d'enveloppe Vault

Implémentation N0 d'ADR-020 : package Python indépendant de Django, sans HTTP,
base, configuration applicative, registre, SDK réseau ni provider par défaut.
Le package n'est pas ajouté aux dépendances ou imports de l'application Web.
Sa présence dans le dépôt ne constitue ni un service isolé ni une activation P2.

Qualification du package au 14 novembre 2026 : construction d'une wheel dans un
environnement temporaire, sans réseau pendant le build, avec les trois outils
de `requirements-native-build.lock` téléchargés et vérifiés par SHA-256. La wheel
ne contient que les deux modules de la primitive et ses métadonnées ; aucun
provider synthétique ni test n'est distribué. Les 25 tests ont réussi sur cette
wheel installée, sans exclusion. Cet environnement temporaire rendait les
dépendances locales existantes visibles : ce résultat ne qualifie pas une
nouvelle installation indépendante de cryptography. Le premier essai avait
réussi 24 tests et échoué à l'import dans un sous-processus, faute de package et
de dépendances installés dans cet environnement ; il est conservé comme échec
de préparation. Aucun environnement applicatif ni donnée historique modifié.

## Périmètre

Le seul domaine actuellement accepté est `technical-credentials`. Les domaines
`user-vault`, `recordings` et `evidence-signing` demandent leurs futurs profils ;
ils sont refusés ici. Aucun format Fernet, reçu V7/V8, sceau de destination ou
enregistrement historique n'est lu, modifié ou re-signé.

Les opérations sont internes au futur processus Vault :

```python
seal_new_version(plaintext_bytes, expected_binding, approved_kek, explicit_provider)
open_authorized_version(envelope, expected_binding, expected_kek, explicit_provider)
rewrap(envelope, expected_binding, expected_source_kek, approved_destination_kek,
       explicit_provider)
```

`Binding`, `KeyRef`, `Wrapping` et `Envelope` sont des dataclasses immuables à
slots. Le registre **de l'appelant** doit sélectionner binding et références de
clé depuis son état autorisé. La primitive compare ces attentes avant unwrap ;
elle ne résout jamais un ID ou une URL reçue dans une enveloppe pour choisir un
provider. Une référence de clé lie installation, organisation, domaine, provider,
ID local KEK et version entière positive.

Le nom `open_authorized_version` présuppose une autorisation déjà vérifiée ;
**la fonction ne vérifie pas cette autorisation**. Aucun booléen `authorized`,
capacité HTTP, rôle Django ou preuve métier n'est interprété ici. La primitive
ne choisit pas la version live. Pour une récupération historique, le futur
registre doit fournir explicitement la référence ancienne autorisée ; une
ancienne enveloppe ne passe pas avec la référence courante différente.

Les valeurs `purpose`, `provider_id` et `kek_id` sont des IDs locaux opaques,
non vides, sans espace, limités à `[A-Za-z0-9][A-Za-z0-9._:-]*`, de longueurs
maximales 64/64/128. Un adaptateur mappe ces IDs à ses références fournisseur
commissionnées ; aucun ARN/alias externe n'est deviné ou résolu par la primitive.
UUID canoniques minuscules, versions entières strictes entre 1 et `2^63-1`, hash
de destination SHA-256 hexadécimal minuscule obligatoire. L'exactitude sémantique
du document de destination P0-2 appartient au futur raccord, pas à ce hash seul.

## Provider injecté

```python
class KeyProvider(Protocol):
    provider_id: str

    def wrap_key(self, dek: bytes, key_ref: KeyRef, context: bytes) -> WrappedKey: ...
    def unwrap_key(self, blob: bytes, key_ref: KeyRef, context: bytes) -> UnwrappedKey: ...
```

Le provider authentifie **tous les octets du contexte fourni**, à l'enveloppement
comme au désenveloppement. Un backend qui ignore ce contexte est incompatible.
L'adaptateur doit imposer ses politiques tenant/domaine/opération, identité,
timeouts, quotas et garanties de transport. La bibliothèque ne prouve pas ces
contrôles par l'existence de méthodes Python.

`WrappedKey` retourne exactement la référence attendue et un blob `bytes` de
1 à 16 KiB. `UnwrappedKey` retourne la même référence et une DEK `bytes` de
32 octets. Les références divergentes, retours dictionnaire, buffers mutables,
DEK mal dimensionnée et blobs trop grands sont refusés. Ces objets sont
internes à l'implémentation du provider ; ils ne sont pas une réponse destinée
au broker. Leurs champs sensibles sont exclus de leur représentation standard.

Aucun provider concret n'est livré dans `src`. Le double `SyntheticMemoryProvider`
est défini uniquement dans les tests : KEK synthétiques explicitement injectées,
wrapping via AESGCM maintenu, aucune clé chargée depuis l'environnement, aucun
réseau. Ce double n'est ni une qualification KMS/HSM ni un backend de service.

## Chiffrement, format et réenveloppement

AES-256-GCM utilise l'API publique `cryptography` : DEK aléatoire neuve par appel
de création, nonce CSPRNG de 12 octets, tag complet de 16 octets. Le JSON
`pamolive.vault-envelope/1` et les deux AAD suivent les champs fermés d'ADR-020.
JSON canonique des AAD : clés triées, séparateurs `,`/`:`, `ensure_ascii=True`,
UTF-8, sans flottant ni conversion implicite. L'AAD payload lie le binding et
la DEK ; le contexte wrap lie aussi la référence KEK et le hash de l'AAD payload.
Le champ `context_hash` n'est jamais traité comme une authentification autonome.

`parse_envelope(bytes)` et `serialize_envelope(Envelope)` bornent le document à
128 KiB. Le parser refuse doublons, champs manquants/inconnus, types inattendus,
nulls, nombres flottants/non finis, profondeur supérieure à 8 et plus de
128 valeurs structurales. L'allocation JSON est précédée du plafond de taille
brute. Les valeurs binaires sont en base64url non paddé, validées avant décodage
puis réencodées pour refuser les alias non canoniques. Nonce exactement 12 octets,
plaintext 1–65 536, ciphertext avec tag 17–65 552, blob wrap 1–16 384, chaque AAD
au plus 4 096 octets. Un parsing réussi ne vérifie pas le tag ou le provider.

`rewrap` exige un provider identique, source et destination explicites. Il unwrap
la DEK, authentifie réellement le payload AESGCM, puis wrap **la même DEK** sous
la destination. Binding, ID DEK, nonce et ciphertext restent byte-identiques.
Aucun rechiffrement de payload ni appel réseau ReEncrypt n'est prétendu effectué.
Le résultat est une nouvelle valeur immutable ; le futur registre doit effectuer
le CAS et conserver ses révisions de wrapping. `kek_version` n'est pas cette
révision transactionnelle.

Les erreurs de format/intégrité sont constantes `invalid_envelope`, les échecs
de provider `provider_failure`. Aucun plaintext partiel, exception fournisseur
brute, ciphertext ou matériel de clé n'est logué par ce package. L'adaptateur
reste responsable de ses propres logs ; le package ne peut effacer ce qu'un
provider compromis aurait déjà capturé. Python ne garantit pas l'effacement
physique de toutes les copies de DEK/plaintext.

## Tests autonomes

Depuis la racine du dépôt, sans installer de package dans Web :

```powershell
$env:PYTHONPATH = (Resolve-Path components/vault/src).Path
.venv/Scripts/python.exe -m unittest discover -s components/vault/tests -v
.venv/Scripts/ruff.exe check components/vault
.venv/Scripts/ruff.exe format --check components/vault
```

Le chemin ajouté au processus de tests est temporaire. En POSIX :
`PYTHONPATH=components/vault/src python -m unittest discover -s components/vault/tests`.
Le module ne doit pas être importé par le Web pour exécuter ces tests. Une future
CI autonome et le packaging du vrai service restent à intégrer séparément.

Les tests couvrent vecteur connu AES-256-GCM, round-trip, AAD exactes, substitutions
de tenant/destination/version/clé, refus avant KMS, types et formats fermés,
quotas, JSON/base64 ambigus, bitflips, panne/clé retirée/retours provider malformés,
absence de logs/chaîne d'exception brute, rewrap authentifié, payload inchangé et
récupération explicite multi-KEK. Le test d'import s'exécute dans un processus
Python neuf et vérifie l'absence de Django/applications/SDK réseau chargés.

Références primaires : [AESGCM public](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM),
[validation GCM NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes),
[ADR-020](../../docs/adr-020-isolated-vault-envelope.md).

Résultat local du 12 novembre 2026 : **25/25 tests réussis en 0,172s**, aucun
ignoré, sous Python du venv existant et `cryptography 50.0.2`. Ruff et format
réussis. Ces résultats sont des unités Windows autonomes, sans base, réseau,
build ou provider réel ; ils ne sont pas des preuves d'intégration P2/Linux.

La revue cryptographique indépendante est favorable à cette primitive seule :
25/25 unités rejouées en0,162s et8/8 essais adverses distincts en0,012s, sans
réseau. Un oracle AESGCM distinct vérifie les octets d'AAD ; les substitutions,
références de clé, rewrap et erreurs sont contre-vérifiés. Le test d'exception
TimeoutError a été renommé : il ne mesure pas une deadline, responsabilité du
futur adaptateur. Les frames/debug peuvent conserver des données ; aucune
zeroization physique n'est revendiquée.

## Limites de réception

Un appel répété à `seal_new_version` crée une nouvelle DEK ; le package ne peut
déterminer si `(tenant, secret, version)` existe déjà. Les retries doivent relire
une enveloppe persistée, et le futur service doit faire respecter l'unicité et la
concurrence. Aucun état global mémoire ne prétend assurer cette unicité.

Aucun rôle SQL, ledger, anti-rollback, nonce d'opération, preuve P0-3, mTLS, témoin,
autorisation de remise, capture, SSH/RDP ou frontière contre Web compromis n'est
livré. La conservation/reprise des anciennes KEK reste une obligation du futur
registre et de l'opérateur ; la primitive n'empêche pas la suppression prématurée
d'une clé. Les images/conteneurs séparés et l'absence du package dans le runtime
Web doivent être qualifiés lors de cette future livraison, pas déduits de
l'arborescence source. Aucun zero knowledge, PQC, HSM ou service de production
n'est revendiqué.
