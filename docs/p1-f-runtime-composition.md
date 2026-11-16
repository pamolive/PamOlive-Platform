# Candidat commun de qualification P1-F

Le candidat `agent/p1-f-runtime-composition` assemble les corrections revues
d'Expat (`ffdccf5`, PR #14), des observateurs ROOT3/PostgreSQL (`043d5e6`, PR #15),
de Jansson (`a6b7ec9`, PR #16) et de restauration (`f66dc73`, PR #18).
Il ne constitue pas une nouvelle version livrée. Les anciens commits et leurs
preuves restent conservés ; les fusions locales ne modifient pas `main`.

## Recette et frontières conservées

La construction et le snapshot Expat restent ceux d'ADR-031 : runtime et SDK
2.10.0, deux extensions CPython reconstruites, ABI, tests amont et gardes négatives.
Les étapes consommateurs héritent de ce SDK et conservent leurs contrôles de
version avant compilation. Les changements Jansson d'ADR-030 sont appliqués à
ces étapes par hunks : aucun ancien Dockerfile entier ne remplace le snapshot.
Le runtime final reste une copie vérifiée de `runtime-build` vers `scratch`.

L'inspecteur TAR expose ensemble `archive_stream`, `forbidden_elf_sha256` et
`reject_cjson_elf`. Les SHA des anciens ELF sont refusés physiquement même si
une couche ultérieure les masque ; le contrôle des symboles cJSON couvre aussi
les ELF renommés. Un contrôle facultatif ne neutralise pas l'autre. Six tests
adverses de composition parcourent de vrais TAR synthétiques, avec chemins et
FD détenus, masquage par whiteout et remplacement ultérieur.

Le SBOM conserve les métadonnées Jansson du composant FreeRDP et ajoute les
composants/preuves Expat. Les deux inspections consomment l'archive de l'image
qualifiée. L'étape de preuve Jansson est désormais obligatoire dans chaque run
Platform, y compris pour cette branche et `main` : sa condition limitée à la
première branche d'essai est retirée. Aucun seuil, règle Grype, contrôle positif,
validateur de schéma, propriété de provenance ou contrôle P0 n'est relâché.

Les quatorze pins produit Jansson restent fermés. Trois pins changent à la
composition : Dockerfile, SBOM natif et inspecteur TAR. Ils sont dérivés des
blobs Git de la source assemblée et exigent une nouvelle revue ; aucun résultat
de scanner ou de runtime n'est auto-appris comme autorité. Les 35 pins du
laboratoire Expat, les propriétaires PostgreSQL et les inputs ROOT3 sont conservés.

La fermeture/drainage de restauration reste indépendante : seules la copie et
le rôle synthétiques identifiés sont susceptibles de suppression. Un résultat
tardif, une identité changée ou une session active restent fatals. Les limites
du transport et de la confiance dans l'administrateur de laboratoire sont
documentées dans [backup-restore](backup-restore.md).

## Validation et portée

Sur les sources assemblées : 123 tests purs couvrent les deux migrations et
leurs six nouveaux cas de composition. Les 65 tests métadonnées, 42 PostgreSQL,
14 tests courts et 25 tests de restauration passent également ; leurs sources
sont identiques à celles testées avant le second merge. Total : 269 tests,
aucune erreur, aucun échec, aucune exclusion ni tentative d'IO externe.
Ruff passe. Les exclusions de portée sont explicites : le test Expat de fusion
CycloneDX stricte et la suite native-SBOM complète ne sont pas exécutés sous
Windows ; ils demeurent obligatoires dans la CI Linux du candidat exact.

Les modèles ne prouvent ni construction, ni ABI, ni signature GPG, ni sessions
natives, ni fermeture réelle PostgreSQL. Il faut recevoir une nouvelle image
et tous ses résultats Platform : migrations, retour arrière synthétique,
restauration, P0, SSH/RDP, Compose, consommateurs, scans OS/compilé et contrôles
positifs. Les succès de branches isolées ne qualifient pas cette combinaison.

Le scan réel Jansson `2f772e7` conservait 31 groupes High non traités ; ROOT3
`043d5e6` en conservait 35. Ce ne sont pas les résultats du nouveau candidat.
L'absence de contrainte de version fiable dans certains avis interdit de prédire
le nombre après composition. Les corrections sources n'ajoutent aucune exception
automatique. Les preuves de provenance de construction et les risques résiduels
restent aussi des conditions de livraison. Aucun push de `main`, publication
d'image, déploiement NAS ou qualification de production n'est induit.

Le parcours UI P1-G reste dans PR #17. Son premier Chrome a été refusé avant
TLS/SQL pour un binaire observé en mode0777 ; bootstrap authentifié et scénario
SSH navigateur sont des travaux distincts. Il n'existe pas de démonstration
complète P1-G reçue pour ce candidat.

### Final-copy metadata comparison diagnostic

The SDK C-header correction passed its install gate, and the runtime verifier
completed, in both the 3ceb Expat and 21ea composed PR runs. The final clean COPY
then refused snapshot_metadata_changed. No qualified image, native tests, SBOM
or CVE disposition is inferred from those builds. The specific differing path
or metadata field has not yet been received.

The follow-up leaves metadata(), all exclusions, equality and the refusal code
unchanged. On refusal only, it emits one bounded diagnostic line (24 records,
16KiB), with closed path classes, path SHA256 values and numeric metadata. File
contents, symlink targets, free paths and unknown fields are excluded. A failed
diagnostic cannot replace or heal the original refusal. This does not prove
content hashes, hardlink topology, source origin, image qualification or serving
authority. Existing fourteen Expat pure methods and four added adversarial cases
are preserved; the composed selection of127 pure tests passes without external
attempts or skips. Full strict schema/native/build/scans still require Linux.

### Correctif du sujet de comparaison des métadonnées

Le diagnostic0f confirme que seuls /proc et /sys diffèrent entre le snapshot
image0755 et le worker0555. Le correctif compare désormais deux racines d'image
montées en lecture seule dans un stage séparé. Le runtime conserve son COPY
scratch et n'importe que le reçu de succès ; aucun root de worker n'est copié.
Le helper, ses exclusions et tous les refus restent inchangés, y compris pour
une vraie dérive /proc ou /sys entre images. Voir ADR031 pour le graphe et les
limites ; le nouveau build/config/archive/native/restore/scan reste à recevoir.
