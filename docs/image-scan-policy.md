# Politique de qualification des scans d’image

État initial : **promotion bloquée**. La politique contient 35 empreintes High observées, toutes `untriaged`, sans aucune exception acceptée. Elle ne transforme pas les 102 correspondances High du témoin en résultat vert.

## Entrées et identité

`deploy/qualify_image_scan.py` utilise uniquement la bibliothèque standard. Il ne lance aucun scanner, Docker, binaire d’image ou appel réseau. Il réutilise les vérifications en lecture seule de `deploy/qualified_image.py` pour le bundle exact : archive, checksum, configuration, labels source/révision/licence et plateforme Linux amd64.

```sh
python -m deploy.qualify_image_scan \
  --bundle "$RUNNER_TEMP/pamolive-qualified-image" \
  --revision "$GITHUB_SHA" \
  --os-report "$PROOF/reports/os.json" \
  --compiled-sbom "$PROOF/combined.cdx.json" \
  --compiled-report "$PROOF/reports/compiled.json" \
  --positive-report "$PROOF/reports/positive.json" \
  --scanner-archive "$TOOLS/grype-linux-amd64.tar.gz" \
  --policy .github/qualification/image-scan-policy.v1.json \
  --output "$PROOF/policy-result.json"
```

Le bundle ne contient que `qualified-image.json` et `pamolive-linux-amd64.tar`. Le gate exige le hash de configuration `qualified-image.json.image_id`, celui du rapport Grype OS et les mêmes octets de configuration. Il vérifie aussi que le SBOM a déclaré `image-digest-kind=image_config`. Il ne confond pas cette valeur avec un digest de pull du registre. Le `manifestDigest` recalculé par Grype depuis une archive Docker peut différer du manifeste OCI identifié par le moteur : il ne sert pas de substitut au config ID.

Les cibles de scan SBOM doivent correspondre aux chemins hôte réels ou aux deux montages fixes du wrapper CI : `/combined.cdx.json` et `/control.cdx.json`. Le workflow doit monter les fichiers correspondants en lecture seule, puis conserver leurs hashes et les rapports. Les rapports Grype ne contiennent pas eux-mêmes un hash cryptographique de tout SBOM d’entrée : cette association dépend également du workflow revu et de sa chaîne d’artefacts. Le gate ne prétend pas prouver mathématiquement l’exécution du scanner.

## Outil, base et contrôle positif

Le pin est `.github/qualification/grype-0.121.3-linux-amd64.json` : Grype 0.121.3 Linux amd64, archive SHA-256 `e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85`. La politique référence le hash de ce fichier. Les checksums officiels et la release ont été vérifiés par HTTPS ; le bundle Sigstore est recensé sans revendiquer une vérification cryptographique qui n’a pas été effectuée. [Release officielle](https://github.com/anchore/grype/releases/tag/v0.121.3), [vérification Anchore](https://oss.anchore.com/docs/installation/verification/).

Les trois rapports doivent provenir de cette version de Grype, de la même base valide de schéma v6, âgée au plus de 48 heures. Les scans doivent dater de moins de 24 heures ; une avance d’horloge supérieure à cinq minutes est refusée. La validation d’âge et de hash de base reste activée ; mise à jour automatique et enrichissement externe sont désactivés pendant les scans. L’actualisation explicite préalable de la base publique est une étape séparée du wrapper.

Le gate refuse les filtres `only-fixed`, `only-notfixed`, `ignore-wontfix`, toute liste `ignore`, `exclude` ou VEX non vide et un matcher CPE désactivé. `match-upstream-kernel-headers=true` évite les quatre règles automatiques que Grype ajoute sinon, même avec `ignore:[]` fourni. `include-matcher-suppressions=true` rend visibles les suppressions internes ; des résultats ignorés dans un rapport réel restent bloquants. Le champ optionnel `ignoredMatches` peut être omis lorsque sa liste est vide dans le format Grype épinglé ; cette omission est alors interprétée comme zéro, après validation des options strictes. Une valeur `null` ou un type invalide est refusé. Les erreurs, JSON vide/incomplet, version inattendue, base périmée ou rapports de bases différentes échouent avant décision de risque. [Configuration primaire Anchore](https://oss.anchore.com/docs/reference/grype/configuration/).

La fixture `.github/qualification/native-positive-control.cdx.json` est synthétique : FreeRDP 3.15.0 et Guacamole 1.5.5, avec tuples CPE qualifiés auprès de NVD. Elle n’est jamais présentée comme l’inventaire installé et ne doit pas être copiée dans l’image. Son hash est référencé dans la politique. Le rapport positif doit retrouver **les deux** CVE attendues, CVE-2026-45700 et CVE-2024-35164. Le contrôle initial utilisant seulement generic purl n’avait rien détecté ; le contrôle CPE qualifié en détecte 222, dont les deux attendues. Un zéro dans ce contrôle est donc un échec de couverture.

Le scan local a également prouvé que la base peut être montée en lecture seule avec rootfs RO, réseau désactivé, tmpfs 64 MiB et mémoire 256 MiB : 222 résultats attendus en 18 secondes, base valide, sans écriture possible dans son montage. Le propriétaire local de cette cache était UID0 ; en CI, téléchargement et scans doivent utiliser le même UID de runner pour garantir les permissions de lecture/exécution.

Cette mesure concerne le contrôle SBOM, qui n'extrait pas les couches d'image. Les deux CI95fe14f ont ensuite échoué sur l'archive OS avec `no space left on device` dans ce tmpfs64MiB ; aucun verdict de vulnérabilité complet n'en découle. `deploy/check_scan_scratch.py` mesure désormais les flux raw-tar/gzip de l'archive exacte, sans les extraire, et impose `2 × octets décompressés + taille archive + 128MiB <= 1GiB`. Formats inconnus, couches dupliquées/liens et dépassements échouent. Le scanner dispose de1GiB de tmpfs nosuid/nodev/noexec,1536MiB de mémoire/swap, CPU1 et128processus ; GOMEMLIMIT192MiB et timeout240s sont conservés. Le quota reste une borne dure ; l'estimation n'est pas une garantie sur les besoins futurs de Grype. Chaque code de sortie est conservé, y compris un crash, et aucun JSON partiel ne satisfait le gate.

Sur le témoin B2 historique, le dimensionnement mesuré demande837063680octets, inférieur au quota. Huit tests synthétiques couvrent raw/gzip, expansion excessive, doublons, liens, chemins, codecs inconnus, gzip tronqué et conservation exclusive du rapport. Cette qualification du dimensionnement ne remplace pas le scan du candidat final.

Le rejeu Docker B2 avec ce profil a terminé en24,422s : code scanner2 correspondant au seuil High,343 matches dans un JSON complet, base valide et aucun OOM. Le cache était monté en lecture seule ; l'UID0 correspondait uniquement à son propriétaire local et ne qualifie pas l'UID du runner GitHub. Les35 groupes High restent bloquants. Preuve hors dépôt : `output/p1-f-grype-scratch-b2-execution.json`.

## Décision de sécurité

Les seuils sont dans le code, sans option CLI pour les abaisser :

1. Toute correspondance **Critical réelle** bloque.
2. Toute correspondance **High avec correctif disponible** bloque, même si une exception est déclarée.
3. Tout High nouveau, modifié ou non trié bloque.
4. Une décision individuelle ne concerne qu’une empreinte exacte, avec analyse, sources fournisseur, preuves locales hashées, conditions vérifiées dans l’archive et revue expirant au plus tard après trente jours. Les dispositions disponibles sont `not_reachable`, `fixed_by_backport`, `not_affected_build` et `code_not_present`, avec les restrictions ci-dessous. L'ajout d'un type de décision n'accepte aucun finding existant.

L’empreinte couvre le scope OS/compiled, paquet source, identifiant de vulnérabilité, sévérité, état de correction, namespace, source de données, distribution/version et liste précise des binaires, versions, types et purl concernés. Elle regroupe les répétitions d’une même CVE sur plusieurs binaires Debian sans effacer leurs identités. Un changement de version, de distribution ou d’autorité de scan invalide l’ancienne empreinte. Une exception OS ne s’applique pas implicitement au composant compilé ou à une copie vendored.

Chaque décision exige un analyste et deux identifiants de relecteurs distincts de l’analyste. **Ces chaînes sont des métadonnées de revue déclaratives** : le contrôle hors ligne n’authentifie pas les personnes et ne démontre pas leur indépendance. L’authenticité des décisions dépend des permissions du dépôt, de la revue des modifications et des protections GitHub existantes. Aucun nouveau mécanisme de consentement utilisateur n’est introduit par ce fichier.

Les preuves locales doivent rester dans des chemins du dépôt contrôlés, avec hash inchangé. Les conditions disponibles sont l’absence d’un basename glob, l’absence d’un suffixe de chemin ou l’identité SHA-256/classe d’un ELF précis. Le gate lit les layers sans extraire ni exécuter leur contenu. Pour les absences, l’union des noms de **tous** les layers est volontairement conservatrice : supprimer un composant dans un layer supérieur ne prouve pas qu’il n’existe plus dans l’artefact distribué. Pour les preuves ELF, whiteouts, répertoires opaques et remplacement d’ancêtres invalident le sous-arbre ; les liens ne sont jamais suivis. Une analyse de non-invocation exige des preuves et conditions couvrant aussi les consommateurs pertinents, pas seulement la bibliothèque vulnérable. La validation structurelle d’une décision ne remplace pas sa justification technique.

Une classification « composant absent » ne s’étend pas aux fonctions présentes du même paquet ; « profil réduit » n’est pas « non affecté ». Les propositions de triage restent bloquantes tant qu’elles n’ont pas de preuves suffisantes et de contre-revue. La politique initiale ne contient aucune exemption, même pour les candidats de clôture proposés dans `docs/p1-f-os-high-triage.md`.

### Backport Kerberos distinct d'une absence de chemin

`fixed_by_backport` est réservé au scope OS, source krb5, CVE-2026-119079 et aux quatre paquets Debian locaux de version exacte définis dans `krb5_inventory`. L'entrée doit référencer un inventaire revu dans `local_evidence`, à la même empreinte SHA. Le gate valide son contrat typé puis exige exactement les conditions générées par cet inventaire : manifeste, provenance, toutes les preuves et les quatre ELF de l'archive qualifiée. Les versions, sources, patch MIT, ABI et résultats ASN.1 ne peuvent être remplacés par une absence supposée d'atteignabilité. Les Critical et High avec correctif distribué disponible restent bloquants.

Les exclusions de tests KEYRING documentées par l'inventaire ne qualifient pas le trousseau noyau. Les logs makecheck peuvent également révéler d'autres tests amont non exécutés, notamment LDAP KDB absent ou résolution DNS externe interdite dans N0. Leur inventaire complet et leurs limites doivent figurer au rapport réel de B3 ; les seules exclusions KEYRING typées ne doivent pas être présentées comme une couverture complète des capacités Kerberos. Le lecteur de politique ne modifie ni seccomp, ni DNS, ni les résultats amont.

### Deux justifications GCC bornées

`not_affected_build` est réservé à CVE-2026-95619, scope OS/gcc-14, distribution Debian et aux quatre paquets du groupe brut gcc-14-base/libatomic1/libgcc-s1/libstdc++6, de version14.2.0-19. Un paquet inattendu est refusé ; cette liste décrit l'attribution par paquet source du scanner, sans prétendre que chacun embarque l'allocateur vulnérable. La justification décrit une implémentation POSIX non affectée, sans prétendre que l'allocateur n'est jamais appelé. La preuve `gcc_evidence`, hashée et revue, suit `pamolive.gcc-finding-evidence.v1` et fixe :

- `source_version`, `vulnerability_id` et le commit GCC14 `200183d4ab5d57575f3dfebc6af3baf649910b9e` ; la source primaire correspondante doit aussi figurer dans `vendor_evidence`.
- `justification=posix_memalign_implementation`, `platform=linux/amd64` et la fonction `_ZnwmSt11align_val_t`, taille125, backend `posix_memalign`.
- Le chemin, la classe et le SHA exact de libstdc++ examinée. La seule condition de cette justification est l'identité de cet ELF connu ; une autre version/architecture ou un autre binaire requiert une nouvelle étude.

`code_not_present` est réservé à CVE-2026-102010 dans le même scope/version de paquets. Le type affecté est précisément `__gnu_pbds::priority_queue<binary_heap_tag>::erase_if`, pas tous les tas ni std::priority_queue. La preuve typée fixe le commit GCC `aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6`, les hashes et versions des archives ICU/APT/HarfBuzz déjà relues,7112 fichiers examinés, zéro usage du type affecté et27 consommateurs uniques (6 ICU,20 APT,1 HarfBuzz) avec leurs SHA/classe. L'analyse des sources et de leur provenance reste une responsabilité de la revue ; un champ JSON n'est pas une preuve autonome d'absence de code.

Cette seconde décision exige exactement27 conditions ELF, l'absence du header `erase_fn_imps.hpp` et une condition `elf_set` sur l'archive entière. Aucun consommateur nouveau ne peut ainsi hériter silencieusement de l'ancienne analyse, même si le paquet libstdc++ lui-même ne change pas. Les deux dispositions sont limitées à leur CVE respective ; elles n'acceptent pas la famille gcc-14 en bloc. `all_findings_clear` demeure faux.

### Sentinelle finale d'ELF et d'alias

La condition `elf_set` contient exactement `kind`, `schema=pamolive.elf-set.v1`, `sha256`, `count`, `elf_count` et `alias_count`. Les compteurs sont des entiers stricts, leur somme est cohérente et le total est compris entre1 et5000. Aucun choix de racine, exclusion, wildcard ou option CLI ne réduit le périmètre.

Le gate parcourt toutes les couches et calcule un SHA canonique des lignes finales triées : chaque ELF régulier (chemin, classe, machine, SHA) et chaque lien symbolique/hardlink (chemin, type et cible). Les hardlinks portent également le hash/classe/machine des octets liés, conservés même après suppression du chemin initial. Les liens ne sont jamais suivis sur le système hôte. Toute écriture à travers un ancêtre non répertoire, cible de hardlink non résolue dans les états déjà observés ou réécriture ambiguë d'un groupe hardlink actif fait refuser la sentinelle. Cette restriction peut refuser des archives valides mais ambiguës pour ce lecteur ; aucune identité n'est devinée.

Les whiteouts et répertoires opaques retirent les entrées des couches inférieures, indépendamment de leur ordre dans le TAR ; ils ne suppriment pas les nouveaux fichiers du même layer. Les remplacements d'ancêtres invalident leurs descendants. Les limites existantes restent100000 entrées,128 layers,4GiB de contenu cumulé et64MiB par fichier lu pour l'identité. Aucun contenu n'est extrait ni exécuté.

La contre-revue a identifié un cas particulier : un nouveau hardlink ne doit pas lire les octets d'une cible de couche inférieure masquée par un whiteout ou un répertoire opaque du même layer. Le gate refuse ce cas dans les deux ordres du TAR, ainsi que le remplacement d'un ancêtre masquant cette dépendance. Il conserve le cas distinct d'un hardlink créé dans une couche antérieure, qui garde ses octets après suppression ultérieure du nom d'origine. Un lien créé vers un fichier nouveau du même layer reste valable, y compris si un whiteout masque l'ancien fichier homonyme. Cette distinction ferme une divergence d'ordre sans inventer de résolution de liens sur l'hôte.

La sentinelle est un contrôle fini de changement de périmètre, pas une preuve formelle d'absence de PBDS dans tout programme. Les sources et consommateurs revus fournissent la justification ; la sentinelle empêche de la réutiliser après modification de l'ensemble. Un changement de lien non ELF peut aussi l'invalider : cette prudence est volontaire.

Sur B2 historique `91f42c…6091`, la lecture seule finale a mesuré831 ELF réguliers et609 alias,1440 entrées, en29,813s. La preuve finale est `output/p1-f-b2-elf-set-final-measurement.json`. Le premier hash expérimental qui ne liait pas encore le contenu des hardlinks n'est pas une preuve finale. Aucune décision GCC n'a été ajoutée à la politique à partir de cette mesure, et elle ne vaut pas pour une future image B3.

## Recette examinée et preuves propres à chaque archive (ADR-021)

L'implémentation locale ajoute le modèle2 de l'ADR-021 ; le chemin historique ci-dessus reste disponible comme modèle1 à26 identités exactes. **Aucune des35 dispositions réelles n'est activée.** La recette est une entrée à examiner, distincte du manifeste de sorties de chaque build. Un journal honnêtement différent peut ainsi être accepté par le vérificateur de cohérence sans devenir un nouveau hash universel. Ses octets et ses liens restent contrôlés et conservés pour le sujet courant.

`deploy.build_recipe` utilise Git et la bibliothèque standard. `capture()` crée un **candidat non approuvé**, `validate()` contrôle le schéma et `verify()` recalcule l'inventaire du checkout. `deploy.qualify_image_scan.verify_archive_backport(archive, recipe, repo)` vérifie les preuves de l'archive ; `elf_delta(recipe, facts)` applique ensuite la relation GCC bornée aux faits ainsi vérifiés. Aucun script ou binaire extrait n'est exécuté, aucune extraction sur disque n'est nécessaire.

```sh
python -m deploy.build_recipe capture --root . \
  --backport-manifest /proof/current-inventory.json \
  --elf-reference /proof/reviewed-elf-entries.json \
  --generated-assets /proof/reviewed-generated-assets.json \
  --external-evidence .github/qualification/evidence/review.json \
  --output /proof/build-recipe-candidate.json

python -m deploy.build_recipe verify --root . \
  --recipe .github/qualification/build-recipe.v1.json \
  --output /proof/source-verification.json

python -m deploy.build_recipe verify-archive --root . \
  --recipe .github/qualification/build-recipe.v1.json \
  --archive /proof/pamolive-linux-amd64.tar \
  --output /proof/archive-backport-verification.json
```

`--generated-assets` est facultatif si aucun asset n'est livré ; `--external-evidence` se répète pour chaque pièce externe. Les trois sorties doivent être nouvelles ; code0 signifie candidat créé ou cohérence vérifiée selon l'opération, code1 signifie refus. Il ne s'agit jamais d'une signature ni d'une décision d'acceptation d'un High. Les chemins `reviewed-*` désignent les entrées effectivement examinées, pas des sorties automatiquement approuvées par leur nom.

La recette inventorie tous les fichiers Git suivis, en lisant les octets du checkout réellement utilisé : ajout, retrait ou modification d'un fichier suivi invalide la recette. Le mode Git doit être un fichier régulier sans conflit ; liens symboliques Git, liens du système de fichiers et sous-modules ne sont pas acceptés. Le code, Dockerfile, Dockerignore, scripts, workflows, locks, documentation et tests suivis restent couverts, même lorsqu'ils ne sont pas copiés dans `/app`. Les fichiers non suivis de travaux futurs ne sont pas lus ; s'ils sont néanmoins injectés dans `/app`, la comparaison de l'archive les refuse. Il n'y a aucune normalisation silencieuse CRLF/LF : la recette doit correspondre aux octets du contexte livré.

Les seules exclusions de cet inventaire sont les chemins exacts `.github/qualification/build-recipe.v1.json`, `.github/qualification/image-scan-policy.v1.json`, `.secrets.baseline`, et les preuves `.json`/`.md` déclarées individuellement, directement sous `.github/qualification/evidence/`. Elles évitent l'auto-référence des digests. Aucun code ni workflow ne peut être déclaré comme preuve externe. Si `.github/workflows/diagnose-partition.yml` ou `deploy/Dockerfile.partition-probe` devient suivi, l'inventaire est refusé ; ces diagnostics ne sont pas une exclusion de code autorisée.

Le manifeste référence du backport fixe les quatre bibliothèques stock, leurs hashes et ABI examinés, les noms des preuves et tests, les chemins de la chaîne APT et ses signataires déclarés. Les hashes du patch MIT, du harness ASN.1, du wrapper, du keyring et, lorsqu'ils sont présents, du patch test-only et du probe KEYRING sont obligatoirement fixes. Les journaux, rapports, provenance et ELF reconstruits conservent leurs hashes actuels dans le manifeste de chaque sujet ; ils ne sont pas comparés au hash d'un ancien journal.

La lecture de l'archive se fait en deux passes bornées : manifeste courant, puis au plus20 preuves, provenance, état dpkg et quatre ELF. Le SHA de l'archive est contrôlé avant/après ; le manifeste relu doit garder les mêmes octets. Les clés JSON dupliquées, noms de layers répétés, chemins ambigus et layers présentés comme liens sont refusés. Le vérificateur recroise les liens APT, versions des quatre paquets installés, ABI/SONAME/exportations des ELF courants, les douze cas ASN.1 et les preuves/logs KEYRING. Les logs baseline/patched doivent contenir les marqueurs de fin attendus et aucune erreur reconnue. Les exclusions KDB/DNS éventuelles restent visibles dans les journaux ; elles ne sont pas transformées en tests exécutés.

Le contenu final régulier de `/app` doit être exactement celui des sources couvertes par le profil COPY actuel et de `generated_assets`. Cette dernière entrée est une map finie `chemin absolu → SHA256` sous `/app/staticfiles/`, limitée à JS/CSS/SVG/fonts et leurs variantes gzip/Brotli. Un asset supplémentaire, absent ou modifié, un fichier Python, `.pth`, script serveur, extension native ou alias dans ce périmètre est refusé. Les noms inconnus ne bénéficient d'aucune exclusion par préfixe. Une évolution du profil COPY exige la revue du vérificateur et de la recette.

Une décision modèle2 référence la recette hashée dans `local_evidence` et dans `build_recipe`. Pour `fixed_by_backport`, sa condition est exactement `{"kind":"backport_recipe","sha256":"<hash du fichier recette>"}`. Pour GCC102010, `gcc_conditions()` produit les27 conditions fixes et la condition `elf_recipe_delta` liée au même hash. La sentinelle détaillée de référence doit correspondre à la preuve GCC examinée. Aucun ajout/retrait/alias n'est permis ; seule la valeur SHA des quatre chemins ELF Kerberos exacts peut différer, après validation des preuves du backport courant. Un des27 consommateurs modifié ou tout autre ELF nouveau reste bloquant. La sentinelle intégrale du sujet courant reste dans le résultat.

**Limites encore ouvertes :** `verified=true` désigne uniquement la cohérence locale des éléments ci-dessus. Tous les résultats exposent `build_verified=false` ; les champs de vérification d'attestation cryptographique restent faux. Le fichier `gpgv.status` provient du build et n'est pas une vérification cryptographique indépendante hors ligne. La provenance actuelle ne fournit pas un inventaire complet des paquets/outils compiler/SDK/APT des stages builder : l'examen des scripts et de l'image de base ne prouve pas à lui seul ces matériaux effectivement employés. L'attestation authentifiée du dépôt/workflow fiable, révision exacte, événement/ref, run/attempt, artefact et dossier immuable n'est pas raccordée ici. Le workflow/runner et le vérificateur revus restent des bases de confiance explicites. Ces lacunes doivent être comblées avant d'annoncer la qualification complète ADR-021 ou de promouvoir un artefact. La reproductibilité entre builds indépendants n'est pas démontrée.

Le hash de configuration est maintenant relié au contenu des couches : `rootfs.type=layers` et la liste ordonnée `rootfs.diff_ids` doivent correspondre à chaque SHA256 du flux TAR décompressé réellement lu. Le vérificateur draine également le padding et la fin du flux après lecture TAR. Formats de layers admis : raw TAR et gzip ; count, ordre, digest manquant/modifié/dupliqué et gzip tronqué sont refusés. La limite4GiB porte aussi sur les flux décompressés cumulés, pas seulement sur les tailles des fichiers. Les métadonnées externes sont limitées à2048 membres, les headers étendus PAX/GNU à64KiB ; les formats sparse sont refusés avant la lecture de leurs maps. Les identités de layers effectivement contrôlées figurent dans `layer_diff_ids`. Le CLI de politique effectue cette liaison même lorsqu'aucune exception n'est activée.

La fermeture de `/app` et la sentinelle ELF globale ne constituent pas un inventaire universel des autres fichiers interprétés : Python/site-packages, `.pth`, configuration du chargeur sous `/etc`, par exemple, restent dépendants des locks, matériaux et de l'origine builder/workflow de confiance. Ajouter un de ces fichiers en gardant une ancienne configuration échoue désormais sur son diff_id ; modifier aussi la configuration crée un nouveau sujet qui exige cette chaîne de confiance. De même, la recette du worktree doit être reliée explicitement au manifeste du contexte source effectivement fourni au builder ; le label Git seul ne réalise pas cette liaison. Aucune exception réelle du modèle2 ne doit être activée avant complétion de cette chaîne et des matériaux manquants.

## Résultat, limites et conservation des preuves

Le chemin de décision utilisant `build_recipe` est **désactivé par refus
inconditionnel** `recipe_build_authority_unavailable` dans `recipe_artifact`.
La contre-revue a montré qu'une cohérence offline pouvait auparavant rendre
une exception vraie tout en conservant `build_verified=false`. Une recette
candidate, un cache ou des champs JSON mis à `true` n'ont donc aucune autorité
pour lever ce refus. Les CLI de cohérence et tests internes du delta ELF restent
disponibles, sans pouvoir autoriser une publication. Le mode historique de
preuve sur sujet exact et les35entrées `untriaged` ne changent pas. Remplacer ce
verrou exigera l'implémentation et les essais de la chaîne authentifiée complète
ADR021, pas un commutateur ou un nom de reviewer.

La sortie est créée exclusivement en mode 0600 avant lecture des entrées ; un fichier existant n’est pas écrasé. Les clés JSON dupliquées, dépassements de budgets et chemins de preuve non autorisés échouent. Les inputs sont conservés par leurs hashes, sans publier la configuration brute ou des secrets. Codes : `0` politique satisfaite, `2` résultats complets mais promotion bloquée, `1` preuve ou format invalide. Le wrapper conserve séparément les codes scanner : un `2` Grype peut être un seuil dépassé, mais un crash produisant un JSON vide ne passe jamais le gate.

`passed=true` n’est pas synonyme d’absence de vulnérabilités. `all_findings_clear` reste faux si des findings ou suppressions subsistent, même après une décision individuelle conforme. Les rapports complets et les risques résiduels restent disponibles ; aucune règle globale ne les masque.

Le scope SBOM déclaré couvre applications et composants natifs explicitement inventoriés, notamment FreeRDP/Guacamole ; le scan d’archive complète le suivi des paquets OS. Des bibliothèques embarquées dans les wheels peuvent rester hors de ces inventaires. Le vendoring de psycopg-binary a été identifié comme tel et doit être supprimé ou qualifié séparément avant toute affirmation plus large. Les scans ne remplacent ni les tests fonctionnels, ni TLS/SCRAM, ni l’isolation multi-organisations, ni les migrations/restaurations. Aucune qualification NAS ne découle de ce gate.

## Tests

Reprise ADR-021 : `python -m unittest tests.test_build_recipe tests.test_image_scan_policy tests.test_krb5_inventory` couvre79 tests synthétiques, dont18 de recette et42 de politique. Les nouveaux cas couvrent source/workflow suivi ajouté-retiré-modifié, diagnostics devenus suivis, liens Git Windows, preuves fixes omises, variation honnête des logs, ABI altérée, archive changée entre passes, contexte/config d'un autre sujet,27 consommateurs GCC réellement relus et seulement quatre sorties C variables, assets fermés, ordre/count/digests raw/gzip, padding changé, gzip tronqué, métadonnées étendues et sparse. Aucun scanner, image, réseau, binaire Linux ou base n'est exécuté par cette suite. Le paragraphe suivant conserve la mesure historique du gate avant ADR-021.

`python -m unittest tests.test_image_scan_policy` : **39/39 en1,119s**, aucun skip, Ruff réussi. Les données sont entièrement synthétiques, sans Grype exécuté, réseau, Docker ou base de données. Le test CLI complet construit un petit bundle avec labels/révision/config cohérents et vérifie aussi le rejet d’un scanner altéré. Les contre-exemples incluent Critical, High corrigible, High non trié, nouvelles identités/versions/distributions, mauvais scope, filtres/VEX/suppressions, contrôle positif manquant, base périmée/mixte/future, configuration incohérente, preuves modifiées/expirées, output existant et archives à deux/trois layers avec suppressions et ancêtres remplacés. Les cas ajoutés couvrent les deux dispositions GCC et les quatre paquets réels du groupe (un paquet inconnu est refusé), leur portée stricte, date future/expiration, preuves de source/build, sentinelle typée, ajout/retrait/modification de code et d'alias, hardlink survivant à son origine, refus des réécritures ambiguës et ordre des whiteouts/opaque dans une même couche.
