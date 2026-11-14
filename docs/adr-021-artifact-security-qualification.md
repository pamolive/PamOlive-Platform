# ADR-021 — Qualification de sécurité des artefacts sans circularité des hashes

Date : 12 novembre 2026. Statut : **accepté par le coordinateur pour implémentation locale du modèle2 avec dossier immuable du modèle1**. Cette décision suit l'analyse indépendante et le contre-exemple réel/synthétique ci-dessous. Cet ADR n’implémente aucune modification de code, workflow, protection GitHub ou exception. Les gates actuels restent fermés ; aucun ancien échec CI ne devient une réussite par cette décision.

## Problème vérifié

Le gate actuel mélange deux identités différentes : les **règles et entrées examinées**, qui autorisent une recette bornée, et les **sorties exactes d’un build**, qui doivent être conservées pour cet artefact sans être nécessairement identiques à celles d’un autre build.

Dans `deploy/qualify_image_scan.py`, `reviewed_exception()` charge le manifeste de backport depuis une preuve committée et exige que les conditions soient exactement celles de `krb5_inventory.archive_conditions()`. Ces **26 conditions** lient le manifeste, la provenance, vingt preuves et les quatre ELF. Les preuves incluent deux journaux de compilation/tests. La validation de l’archive exacte est nécessaire ; imposer que toute construction future reproduise les sorties du témoin N0 est une exigence supplémentaire de reproductibilité actuellement non démontrée.

Le manifeste R3 du diagnostic d’intégration a pour SHA-256 `315c8319ef8744852632ba90dde40e0ac07921a175af80dd3eda91383d0fc90e`. Le journal `debian-build.log` lié par ce manifeste contient un horodatage, des durées et des chemins de build ; son hash est `e30850adf872980a08aee58eaf4a0bbccd3215b3e54ecdcdc2fdd03085183ac4`. Le journal baseline, hash `7e4a5ecc50e3ab7a4b4020682eb14cc3333bd4a6371cdb0a8541c2d78c0e07d3`, contient aussi chemins et mesures. Le contenu de ces preuves peut varier honnêtement entre deux constructions.

Un contre-exemple Python pur a été exécuté : `conditions_hold()` accepte les 26 faits identiques au manifeste réel, puis retourne faux si seul le hash du journal patched est remplacé par une valeur synthétique différente, **sans changer aucun hash ELF**. Ce test démontre l’exigence d’identité des sorties ; il ne prétend pas avoir réalisé un second build indépendant ni qualifié l’image applicative B3. Le diagnostic R3 ne couvre que la chaîne et quatre bibliothèques Kerberos.

La décision GCC102010 ajoute un second couplage : les 27 consommateurs C++ Debian identifiés peuvent rester identiques, mais `gcc_conditions()` exige également un `elf_set` global identique, incluant les quatre bibliothèques C Kerberos reconstruites. Un changement de ces seuls ELF invalide la sentinelle, même sans nouveau consommateur PBDS. Cette invalidation est actuellement correcte et conservatrice ; il manque une règle explicite pour analyser ce delta, pas une raison de supprimer la sentinelle.

Le problème n’est pas une impossibilité mathématique pour tout build : un cache peut réutiliser exactement un stage natif. Il devient toutefois un obstacle à une CI froide normale, dont ni les journaux, ni l’ensemble des sorties natives ne sont garantis reproductibles. Le schéma naïf est : image A → hashes A committés dans une politique → nouvelle révision S’ → construction B → comparaison aux hashes A → nouvel échec possible. Remplacer continuellement les hashes de référence par ceux du dernier échec entretient ce cycle.

## Invariants conservés

- Toute Critical bloque ; toute High avec correctif disponible bloque ; toute nouvelle High non examinée, preuve invalide ou décision expirée bloque. Aucun filtre global `only-fixed`, ignore, source ou `wont-fix`.
- Les résultats bruts, multiplicités, erreurs, paramètres du scanner, contrôle positif, identité/fraîcheur de la base et limites de couverture restent conservés.
- Une preuve correspond aux octets de **l’artefact réellement testé**, pas à une image locale précédente ni à une reconstruction ultérieure.
- L’origine du build et le droit d’émettre une qualification doivent être authentifiés. Des champs analyst/reviewers textuels ne sont pas des identités cryptographiques indépendantes.
- Les garanties P0, tests fonctionnels, transport, PostgreSQL, isolation, migrations/restauration et contrôle des secrets restent obligatoires. Un scan seul n’autorise aucune publication.
- La fusion respecte les protections et validations requises du dépôt ; cet ADR n’en affirme pas la configuration distante effective et n’autorise aucun contournement. Le coordinateur tranche l’architecture dans le cadre de la délégation existante ; aucune nouvelle permission humaine par étape n’est inventée.
- Aucun accès NAS, compte réel, déploiement ou usage privilégié de production n’entre dans cette décision.

## Identités à séparer

| Identité | Garantie attendue |
| --- | --- |
| Révision source et recette | SHA Git complet et contenu des sources/scripts/locks/options/outils/règles effectivement utilisés ; une déclaration de version seule ne suffit pas. |
| Build et environnement | Dépôt, workflow et version du vérificateur approuvés, événement/ref, run ID, attempt et identité de l’artefact émis. Le runner et la chaîne de compilation restent des bases de confiance. |
| Archive produite | SHA-256 exact du TAR transféré ; sert à détecter substitution ou corruption pendant la qualification. |
| Configuration d’image | Hash de configuration OCI/Docker, actuellement `qualified-image.json.image_id`. Ce n’est pas le digest de manifeste du registre. |
| Image publiée | Digest OCI effectivement poussé, lié à la même configuration et aux mêmes couches testées par les contrôles existants ; conserver le mapping explicite. |
| Qualification | Hash du dossier de preuves et de chaque rapport, version des règles/vérificateurs, verdict, portée N0, date et expiration, tous liés au sujet exact. |

Un même contenu d’image peut être sérialisé dans des archives TAR différentes ; cela n’autorise pas à substituer une archive sans revérifier sa configuration/couches. Une attestation de promotion du digest du registre ne remplace pas, à elle seule, une attestation du verdict de sécurité et de ses rapports.

## Modèle 1 — Examen après build d’un artefact immuable

Construire et tester une fois, conserver l’artefact adressé par son identité, puis faire examiner **ces sorties**. La décision et ses signatures sont des pièces jointes externes au contenu de l’image ; les committer dans celle-ci après examen n’est pas requis. Une étape de qualification fiable vérifie le dossier, les règles, les approbations authentifiées et le sujet exact. La promotion réutilise cet artefact, sans rebuild.

Ce modèle permet de conserver les 26 hashes exacts et l’elf_set intégral propres à chaque build. Toute variation impose une nouvelle décision pour ce sujet. Une décision peut être émise par un processus de revue technique autorisé ; deux noms d’agents dans un JSON ne suffisent pas à prouver deux autorités. Le mécanisme de signature, ses identités et les personnes/services autorisés doivent être définis et testés avant emploi.

**Compatibilité GitHub :** séparer construction/tests et qualification en jobs, publier l’archive immuable après réussite des tests, puis exiger la qualification dans les checks requis. Un job de qualification refusé peut être rejoué sur l’artefact du même producteur, sans rejouer le job de build. Le run/attempt qui consomme une preuve peut différer du producteur ; leurs liens et l’ID immuable de l’artefact doivent rester explicites. Un artefact collecté par `always()` reste une preuve de diagnostic tant que toutes les autres portes ne sont pas satisfaites.

Après fusion, la révision main exacte possède sa propre qualification. Un artefact PR portant une autre révision ne doit pas être réétiqueté main pour satisfaire les labels. Si main reconstruit, le nouveau sujet doit être qualifié ; la revue du sujet PR ne se transfère pas silencieusement.

**Garanties :** identité forte du sujet examiné, comparaison binaire intégrale, absence de circularité de commit. **Dépendances :** stockage durable des artefacts, signature vérifiée et contrôle d’accès à la qualification. **Risques :** coût d’une revue à chaque sujet, expiration/perte des artefacts et mélange de runs. Ne pas attribuer une qualification à une archive simplement parce qu’elle est accessible sous le même nom.

## Modèle 2 — Recettes examinées et preuves vérifiées par artefact

La règle committée décrit les entrées et invariants admis ; les sorties variables restent conservées et vérifiées dans le dossier du build courant. Elle ne fixe plus le hash d’un ancien journal comme condition universelle. Elle fixe en revanche ce qui rend le build acceptable :

1. Sources Debian/amont, patch MIT, patch test-only, scripts, harness, compilateur/SDK, options, architecture et schémas approuvés par leurs identités exactes. Les mises à jour APT doivent respecter un manifeste de matériaux examiné ; « même distribution » n’autorise pas un changement silencieux d’entrées.
2. Chaîne signée APT validée dans le build, liens de hashes réévalués, versions locales honnêtes et quatre paquets/runtime/SDK cohérents. Un statut gpgv textuel provenant d’un dossier inconnu ne devient pas une signature indépendante.
3. Vérification réelle des quatre ELF de **cette** archive, SONAME, exports/versionnements ABI, paquets et absence de substitution. Les hashes actuels sont émis dans le dossier, puis recroisés dans l’archive et l’attestation du même sujet.
4. Tests Debian et régression ASN.1 avant/après réellement exécutés : six cas par phase, compteurs/allocation/nettoyage imposés, retours et logs liés. Les exclusions KEYRING/KDB/DNS restent typées et visibles ; aucune chaîne `passed` seule ne remplace ces preuves.
5. Source applicative et extensions approuvées dans le périmètre des analyses de non-accessibilité, notamment chargement dynamique/ctypes. Une égalité du recipe Kerberos ne qualifie pas automatiquement un nouvel appelant Python ou natif.
6. Vérificateur et workflow de qualification identifiés comme autorités fiables, avec provenance du build et du résultat, puis contrôles d’archive indépendants des scripts exécutables contenus dans l’artefact.

La portée d’un hash d’entrées doit être définie sans auto-référence : les identités d’un build et son verdict sont émises **après** le build en sidecar attesté. Il n’est pas demandé de committer à l’intérieur d’un fichier le SHA Git du commit qui le contient. Pour les analyses dépendant du code applicatif, utiliser un inventaire de contenu explicitement couvert et examiner tout nouveau fichier/code/extension ; l’étiquette du commit dans l’image n’est pas un substitut à cette couverture. Les exclusions de fichiers non exécutables doivent être finies, justifiées et testées, jamais un motif large cachant du code nouveau.

### Delta ELF limité pour GCC102010

Conserver la sentinelle brute intégrale de chaque artefact et les 27 hashes C++ examinés. Comparer le nouvel ensemble au précédent : aucun ajout/retrait/renommage/alias inattendu, aucun changement non autorisé d’un consommateur. Une règle future peut reconnaître **les quatre chemins C Kerberos exacts** comme sorties reconstruites variables, uniquement si la recette et les preuves ci-dessus réussissent pour eux. Elle conserve leurs hashes actuels dans la sentinelle du sujet et n’autorise pas un ensemble arbitraire de fichiers `.so` ou un package entier.

Ce delta est une nouvelle relation d’équivalence examinée, pas l’égalité du vieux hash. Un nouvel ELF, un alias différent, un consommateur C++ modifié, un fichier dans un préfixe inconnu ou une variation d’un autre binaire doit bloquer et être examiné. Si d’autres sorties légitimes deviennent variables, elles demandent une extension explicite des règles avec preuve, pas une extension implicite de l’exception. L’absence d’instanciation PBDS dans les consommateurs examinés reste la justification ; « compilé en C » ne suffit pas seul.

**Garanties :** CI froide utilisable sans égalité des journaux, provenance et contrôle des sorties conservés, changements sans lien traités par des deltas finis. **Dépendances :** schémas séparant matériaux/invariants/résultats, vérification du build courant et chaîne d’attestation fiable. **Risques :** règle trop large, source prétendue mais non utilisée, vérificateur modifiable par le contributeur, fausse réussite de tests. La confiance dans le builder/runner reste explicite : ABI, hashes et attestations ne prouvent pas mathématiquement que le compilateur a exécuté les sources annoncées.

## Modèle 3 — Reproductibilité complète

Rendre les sorties pertinentes identiques entre builds indépendants : snapshots des paquets et clés APT, outils, chemins, locale, timezone, ordre, caches, timestamps, options et export OCI déterministes. Séparer les journaux bruts horodatés des preuves déterministes, sans réécrire les originaux pour simuler une identité. Comparer des builds indépendants avec analyse des différences ; un cache du même stage n’est pas cette démonstration.

Le [standard SOURCE_DATE_EPOCH](https://reproducible-builds.org/docs/source-date-epoch/) traite la représentation de dates par les outils qui le supportent ; il ne fige pas à lui seul les paquets APT, les tests, le noyau ou toute la sérialisation d’une image. Ici, les probes seccomp/KEYRING et limites réseau sont aussi des faits d’environnement : ils doivent rester vrais, pas être normalisés vers une réussite commune. On peut viser la reproductibilité des ELF sans exiger celle des durées ou de chaque octet de log.

**Garanties :** détection indépendante forte de divergence de sortie, compatibilité avec des hashes binaires fixes. **Dépendances/coût :** infrastructure reproductible, double construction, archivage des matériaux et enquête des écarts. **Risques :** fausse promesse de reproductibilité, suppression de diagnostics, sécurité APT figée indéfiniment ou deux builders partageant le même compromis. Non démontré actuellement ; ce n’est pas une solution immédiate à la livraison N0.

## Comparaison et recommandation

| Modèle | Circularité | Protection des changements | Usage recommandé |
| --- | --- | --- | --- |
| 1 — Revue par sujet immuable | Supprimée si la décision reste externe à l’image | Chaque sujet/dossier doit être examiné et authentifié | Solution de réception ponctuelle forte et référence pour la promotion |
| 2 — Recette et invariants examinés | Supprimée en distinguant entrées et sorties | Évaluation dynamique du sujet exact ; delta fini et blocage des entrées inconnues | **Cible CI recommandée**, avec le transport/attestation du modèle1 |
| 3 — Reproductibilité | Réduit la variation seulement après preuve | Deux constructions indépendantes et comparaisons | Amélioration ultérieure, pas prérequis simulé ni raison de masquer les logs |

Recommandation : **modèle2 pour les règles automatiques, associé au modèle1 pour le dossier immuable, l’authentification de la qualification et la promotion sans rebuild**. Les sorties exactes restent essentielles, mais propres au sujet. Le modèle3 devient un objectif séparé, mesurable, sans supprimer les preuves variables. Cette recommandation n’accepte aucune des35 dispositions proposées et ne change pas leur analyse d’exploitabilité.

### Décision et limites de l'implémentation locale

Le coordinateur retient cette combinaison. La recette examinée doit couvrir le code applicatif réellement livré, les extensions, Dockerfile/Dockerignore, scripts, locks, outils, matériaux natifs et workflow de qualification. Son inventaire doit détecter ajout, retrait et changement ; ne pas remplacer cette vérification par le seul label de révision. Les règles et décisions externes à l'image restent séparées des sorties du build pour éviter l'auto-référence. Les exclusions de métadonnées non exécutables sont explicites et testées.

Les preuves sont relues depuis l'archive exacte par du code de qualification de confiance ; aucun script extrait de l'image ne devient l'autorité hors ligne du verdict. Elles conservent leurs propres hashes, leurs erreurs/exclusions et les quatre ELF actuels. La première tolérance de variation GCC est limitée aux quatre sorties Kerberos vérifiées, sans ajout/retrait/renommage/alias ni nouvelle bibliothèque. Une variation supplémentaire, même issue d'un build légitime, reste un refus avant nouvelle analyse. Les hashes des27consommateurs C++ demeurent fixes.

La CI de PR peut produire des résultats préliminaires sans permission de publication ni attestation privilégiée. La qualification publiée de main doit en plus être liée au dépôt, workflow fiable, révision exacte, run/attempt et sujet par une attestation réellement vérifiée. La présence d'une signature ou de noms de reviewers seule ne suffit pas. Le dossier immuable attesté reste extérieur à l'image ; la publication ne reconstruit pas l'image. L'implémentation doit vérifier toute la nouvelle chaîne complète avant d'annoncer un résultat qualifié.

La confiance dans les mainteneurs autorisés, le workflow et le runner demeure une hypothèse explicite, comme dans la chaîne actuelle. Une recette et une attestation ne rendent pas un compilateur compromis inoffensif. Aucun classement High n'est activé par cette décision ; les35entrées non arbitrées et les seuils continuent à bloquer jusqu'à leurs analyses individuelles et à la validation complète des nouveaux contrôles.

## Chaîne de confiance et protections GitHub

La [documentation GitHub sur les attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) permet d’attester un fichier, une image ou un SBOM et de vérifier son origine. Une signature doit être vérifiée avec une identité de dépôt/workflow attendue et son sujet ; sa simple présence ne prouve ni la correction ni la réussite des tests. Le workflow de qualification doit être revu/épinglé ; GitHub documente aussi [l’épinglage des workflows réutilisables par SHA](https://docs.github.com/en/actions/concepts/workflows-and-actions/reusing-workflow-configurations).

La conception future doit vérifier : dépôt, source complète, workflow/version fiable, événement/ref, run/attempt producteur, ID/digest de l’artefact, verdict et toutes ses pièces. Refuser signature d’un autre dépôt/workflow, simple nom de reviewer, rapport de réussite isolé, réutilisation d’un ancien dossier ou modification post-qualification. Les permissions d’attestation/publication ne doivent pas être confiées à un job PR exécutant du code non approuvé. Un workflow déclenché par la fin d’un autre ne doit pas exécuter ses scripts téléchargés avec des secrets : les artefacts restent des données non fiables jusqu’à validation.

Dans l’existant, `qualified_image.verify_run()` exige une CI push terminée avec succès sur la révision main exacte et le bon dépôt. `publish-image.yml` télécharge cette archive, la vérifie, la charge et pousse **sans rebuild**, puis vérifie le lien registre/configuration et atteste la promotion. Ces garanties sont à conserver. L’étape d’attestation actuelle porte sur la promotion ; cet ADR ne prétend pas qu’elle contient déjà un verdict de sécurité structuré ou une signature de revue indépendante.

Si les jobs sont découpés, la condition de succès doit être exprimée pour la **nouvelle chaîne complète**, pas remplacée par « un build existe ». Tous les checks obligatoires du SHA exact doivent réussir avant publication. Une ancienne CI rouge reste rouge et historisée ; son dossier peut servir à diagnostiquer ou à tester le nouveau vérificateur, jamais à annoncer rétroactivement une livraison validée. Toute évolution des checks requis passe par les protections ordinaires, sans bypass ni force-push.

## Transition proposée et tests requis

1. Décision technique du coordinateur sur cet ADR ; conserver les gates et35 findings actuels tant que l’implémentation suivante n’est pas validée.
2. Introduire un schéma séparé pour règles de matériaux/invariants et dossier propre au sujet. Émettre tous les hashes réels ; lire et vérifier les preuves depuis l’archive exacte, pas seulement un manifeste fourni au gate.
3. Tests adverses : log légitimement différent conservé et validé ; log tronqué/faux statut/échec inconnu refusé ; source/patch/compiler/options modifiés refusés ; mauvaise chaîne APT ; mauvais ABI ; mauvais compteurs ASN.1 ; preuve d’un autre run/image ; signature/identité/source/ref incorrectes ; TTL expiré ; substitution de l’archive après qualification.
4. Tests du delta : quatre sorties C admissibles avec recette vérifiée, 27 consommateurs inchangés ; ajout/retrait/alias/whiteout/hardlink/ELF C++ inconnu refusé ; modification d’un appelant Python/extension invalide la décision correspondante. Conserver les tests OCI adverses existants.
5. Construction froide de la révision finale, toutes suites et scans exacts, émission puis vérification indépendante du dossier attesté. Une panne de vérification cryptographique reste un échec explicite, sans fallback non sécurisé.
6. Vérifier la promotion de ce même artefact et la correspondance du digest OCI publié. Prévoir conservation durable des pièces publiques approuvées au-delà des sept jours d’artefacts CI actuels ; supprimer tout secret des pièces avant publication, sans tronquer les findings.

Validation de cet ADR : lecture des chemins réels de politique/build/promotion, examen des preuves R3 et reproduction Python pure d’un changement de hash de journal. Aucun nouveau build, scan, accès GitHub en écriture, modification de gate/politique/CI ou contact NAS effectué. Les modèles ci-dessus sont des propositions à implémenter et tester ; aucun succès de publication n’est annoncé.
