# Acquisition de l'index source Kerberos

Le run PR `27cf3b4` a été refusé pendant la construction, à l'assertion composée
d'unicité de l'entrée SHA256 et de cohérence de `Sources.xz` avec le Release signé.
Les signatures, origine et dates précédentes ont passé. La sonde d'exclusion des
fichiers privés, les tests d'image et les scans finaux restaient à exécuter.
Les octets du builder n'étant pas conservés, ce reçu ne distingue pas entrée
absente/dupliquée et hash différent ; une rotation de miroir reste une hypothèse.
Le [run refusé](https://github.com/pamolive/PamOlive-Platform/actions/runs/43753095371)
et les 52 tests installés reçus séparément restent des preuves distinctes.

## Correction ciblée

L'acquisition de l'index intervient maintenant après la vérification gpgv du
InRelease et les contrôles existants d'origine, codename, date et statut de
signature. Le Release doit annoncer `Acquire-By-Hash: yes` et contenir exactement
un tuple SHA256/taille/chemin pour `main/source/Sources.xz`. Le digest et la taille
sont bornés avant la requête. L'URL garde l'origine constante et le chemin
`main/source/by-hash/SHA256/<digest>` ; aucune URL fournie par les métadonnées
n'est utilisée. Cette construction suit le
[format du dépôt Debian](https://wiki.debian.org/DebianRepository/Format#Acquire-By-Hash).

Le même curl et ses limites HTTPS/TLS, 120 secondes et 32 Mio sont conservés,
sans shell supplémentaire, redirect, retry ou repli vers un index mutable/stale.
La fraîcheur est revérifiée après acquisition ; taille et empreinte sont contrôlées
avant décompression. Des erreurs fermées distinguent unicité, forme, hash et
taille, sans publier le contenu. Un mismatch reste un refus.

Le parseur, les bornes XZ, la version et le répertoire source, les quatre fichiers
attendus, leurs empreintes, le keyring, les patchs et toute la compilation restent
inchangés. Aucune nouvelle dépendance, donnée de provenance ou migration n'est
ajoutée. Le nom logique de l'index dans les preuves historiques reste conservé ;
le vérificateur hors ligne ne requalifie pas les anciennes preuves selon ce
nouveau mode d'acquisition.

## Validation et portée

Les 22 tests durables exécutent le vrai bloc PYCHECK du script, avec SHA256 et XZ
réels, mais fichiers, curl et horloge virtuels. Les pins source attendus viennent
du module d'inventaire séparé. Le cas de rotation utilise deux versions
synthétiques ; il ne reproduit pas les octets non conservés du builder.
Avant correction : 22 tests, 15 failures et une error, sans skip. Après : 22
réussites, zéro failure/error/skip et aucune tentative externe. Les cinq suites
acquisition/inventaire/SBOM/recipe/contexte totalisent 82 réussites, sans skip.
La contre-revue indépendante confirme le delta, les tests et l'ajout du module à
la suite CI ; les commandes de construction/exclusion restent intactes.

Ces essais purs ne réalisent pas de vérification gpgv, acquisition, compilation
ou test d'image réels. À leur issue, la nouvelle CI restait à recevoir ; elle
calcule recipe, contexte Git et digest d'image depuis les vrais octets du build.

## Réceptions push et PR exactes `acd8bc3`

Le [run push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43759420683)
et le [run PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43759468105)
du commit `acd8bc38ffc92f257f2f4bb6e1a495cbf01ee2f5` ont passé construction et
exclusion des fichiers privés. PostgreSQL 17.12, régressions, transports natifs,
restauration et Compose sont corroborés par les artefacts et journaux reçus
indépendamment. Les 303 tests du job sécurité passent ; le rapport général compte
1 479 tests avec 40 exclusions de méthodes et deux de classes, conservées comme
exclusions. Ces réceptions ne démontrent pas la cause du refus historique `27cf3b4`.

Le seul échec de chacun des runs est le scan final : 35 groupes High non triés
et zéro finding ignoré. La provenance de build reste incomplète. Les deux
réceptions vérifient séparément leurs ZIP, journaux et checkout exacts ; aucun
succès n'est transféré. Aucune exception, fusion main ou publication d'image n'en découle.
