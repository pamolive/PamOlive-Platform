# Inventaire indépendant des composants natifs

Statut : outils testés et inventaire vérifié réellement sur les checkpoints locaux identifiés ; chaque nouvelle archive exige ses propres preuves. La promotion reste bloquée par la politique High non triée et la couverture partielle des bibliothèques embarquées. Aucun résultat d’un témoin ne vaut validation de l’image suivante.

## Problème traité

Le scan du premier candidat P1-F identifie FreeRDP via la base dpkg. Un remplacement par une compilation amont peut enlever ces métadonnées sans permettre au scanner de reconnaître le nouveau composant. Une baisse du compteur de CVE ne prouve donc ni la présence de la bonne version, ni son chargement par guacd. Le [rapport initial](p1-f-image-security.md) reste conservé, avec tous les findings et leurs limites.

`deploy/native_inventory.py` complète le scanner. Il fonctionne sans Django, secret, réseau, installation de paquet ou socket Docker. Il doit être exécuté uniquement dans une image de qualification contrôlée, identifiée par digest. Il lance le `ldd` du système sur les ELF des deux préfixes d’installation approuvés ; il n’est pas un analyseur de fichiers ELF arbitraires téléversés.

## Contrôles réalisés

- Version et hash source exacts : FreeRDP 3.33.1 et Guacamole server 1.6.0. Empreinte attendue du signataire FreeRDP, trace de validation GPG, hash du patch guacd et options de compilation réelles sont comparés à une politique locale révisable.
- Deux patches Guacamole distincts sont obligatoires : le refus de redirection P0 conserve son hash historique ; le correctif de compatibilité GDI est lié au commit Apache `ab36756b596520ae2a94cd4d25e406e0b5aa820b` et au hash `22abebc3df34da38a96bd476b7387754c97eefc51477112a7ad812dd08a3cb05`. Le [correctif amont](https://github.com/apache/guacamole-server/commit/ab36756b596520ae2a94cd4d25e406e0b5aa820b) initialise GDI et ses handlers dans PostConnect, après création du cache FreeRDP. Le backport local conserve paramètres/canaux dans PreConnect, les contrôles d’authentification/certificat et le callback de refus de redirection. Une capture qui ignore ce second patch est refusée. Une revue statique n’est pas le test RDP effectif.
- Métadonnées relues depuis les fichiers produits par les builds, notamment le `CMakeCache.txt` conservé. Les options de sécurité doivent être typées `BOOL` ; `UNINITIALIZED` ou `STRING` sont refusés. Seul `WITH_CLIENT_SDL` peut être `INTERNAL`, car l’option dépendante est désactivée par `WITH_CLIENT=OFF`. La valeur compilée est également contrôlée. USB est contrôlé par le vrai `CHANNEL_URBDRC=OFF` ; le paramètre inexistant `WITH_LIBUSB` ne constitue aucune garantie. LTO et SIMD doivent être désactivés par `CMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF` et `WITH_SIMD=OFF`.
- Trace de transformation ELF par patchelf : version de l’outil, opération `--set-rpath` et valeur absolue attendue. Le hash d’ELF porte sur les octets **après** transformation. La whitelist des chemins de chargement reste inchangée.
- Trace du contrôle des commandes de compilation et de liaison effectivement générées : schéma, succès explicite, hash de `compile_commands.json`, compte positif de commandes et fichiers de liaison, refus des préfixes `-flto`/`-mavx` et seule cible explicite `-march=x86-64` autorisée. Seules les deux sondes de configuration CMake `build/CMakeFiles/_CMakeLTOTest-C` et `_CMakeLTOTest-CXX` peuvent être exclues du contrôle de liaison : elles testent la disponibilité de LTO et ne sont pas installées. Cette liste exacte figure dans le manifeste ; tout ajout, joker ou réécriture de chemin est refusé. Le vérificateur valide la structure et conserve cette trace ; les commandes intermédiaires absentes du runtime ne sont pas réexécutées ou réinspectées par lui.
- Inventaire de **tous les ELF** présents sous `/opt/pamolive-freerdp` et `/opt/pamolive-guac`, avec hash SHA-256, composant propriétaire et alias. Les liens symboliques sortant de leur préfixe sont refusés. La présence de guacd, des clients SSH/RDP et des bibliothèques FreeRDP/WinPR est obligatoire.
- Lecture autonome des entrées ELF64 amd64 `DT_NEEDED`, `DT_RPATH` et `DT_RUNPATH`. Aucun chemin relatif, `$ORIGIN`, élément vide ou répertoire autre que les deux préfixes approuvés n’est accepté dans les chemins de recherche déclarés.
- Résolution réelle des dépendances de chaque ELF par `/usr/bin/ldd`, avec environnement limité, `LD_PRELOAD` vide, délai de 15 secondes et `LD_LIBRARY_PATH` exactement égal à `/opt/pamolive-freerdp/lib:/opt/pamolive-guac/lib`. Une dépendance manquante, ambiguë ou native résolue ailleurs est refusée. Les bibliothèques système restent soumises au scan OS séparé.
- Absence de paquets Debian FreeRDP/WinPR hérités dans le runtime. Ce contrôle évite de conserver les anciennes bibliothèques vulnérables sous un overlay de bibliothèques plus récentes.
- Versions **réellement retournées** par les API publiques FreeRDP/WinPR et par `guacd -v`. Les API de version sont appelées dans un processus Python séparé borné ; le daemon guacd ne démarre pas. Une bibliothèque ancienne avec des fichiers texte de provenance prétendant une autre version est refusée. L’API publique `freerdp_get_build_config(void)` confirme également les booléens `WITH_*` attendus ; seuls ces champs autorisés sortent du processus, jamais les CFLAGS complets ni chemins du compilateur. Le générateur amont n’inclut pas les variables `CHANNEL_*` ou `CMAKE_*` : elles restent vérifiées par le cache typé et la trace des commandes. Les signatures et le format sont confirmés dans les sources exactes [FreeRDP 3.33.1](https://github.com/FreeRDP/FreeRDP/blob/3.33.1/include/freerdp/freerdp.h), [générateur des options](https://github.com/FreeRDP/FreeRDP/blob/3.33.1/CMakeLists.txt) et [WinPR](https://github.com/FreeRDP/FreeRDP/blob/3.33.1/winpr/include/winpr/winpr.h).

L’inventaire est canonique : les adresses ASLR ne sont pas conservées, les fichiers et dépendances sont triés, les alias restent explicites. Le schéma est `pamolive.native-inventory.v1`.

## Capture et vérification

Après installation et copie du script dans l’image, le build produit un manifeste public en lecture seule :

```sh
python deploy/native_inventory.py --capture \
  --output /opt/pamolive-native-manifest.json
```

Dans un conteneur local isolé lancé depuis **le digest exact** du candidat, sans réseau, avec rootfs en lecture seule et `/tmp` en tmpfs :

```sh
python deploy/native_inventory.py \
  --manifest /opt/pamolive-native-manifest.json \
  --output /tmp/native-verification.json
```

La deuxième commande recalcule hashes, métadonnées, versions et résolutions ; elle compare l’ensemble au manifeste du build. Une suppression, un ajout d’ELF ou un changement de résolution bloque la vérification. Les clés JSON dupliquées sont refusées. La destination du rapport est créée exclusivement avant toute sonde ; un fichier existant n’est jamais écrasé. En cas d’échec, le fichier réservé peut rester vide et ne constitue jamais une preuve de succès. Le manifeste public est créé avec le mode 0444, le rapport de vérification avec 0600.

Le rapport brut détaillé reste dans les preuves de qualification ; une publication peut exposer son inventaire public après revue. Aucun secret, fichier de configuration applicative ou environnement complet n’est collecté.

## Limites de preuve

La comparaison démontre la cohérence du contenu observé, des métadonnées de build, des versions retournées et des bibliothèques résolues dans le processus de qualification. Elle ne prouve pas mathématiquement qu’un binaire est issu d’une source donnée et n’atteste pas tous les environnements possibles d’un futur processus. Un binaire malveillant peut mentir sur sa version. Le digest d’image, les sources épinglées, le workflow revu, la preuve de signature des sources et l’attestation de construction doivent donc rester liés.

Le statut GPG conservé est une trace du build ; le script ne revérifie pas une archive source absente du runtime. Les dépendances système autorisées ne sont pas réputées sûres parce que leur répertoire est autorisé. Le scan OS, l’inventaire des composants compilés dans le SBOM et la revue des advisories amont restent obligatoires. Le contrôleur doit aussi vérifier que les processus applicatifs utilisent l’environnement de chargement approuvé.

L’outil qualifie actuellement ELF64 little-endian amd64 seulement. Il refuse une architecture différente ; il ne constitue pas une qualification Synology ou ARM. La capture exécute des sondes de version de composants de confiance, pas des entrées d’un attaquant. Elle doit rester confinée au conteneur de qualification et n’est pas une fonction d’une interface utilisateur.

## Politique de traitement des vulnérabilités proposée

Le scan de l’archive exacte conserve toutes les sévérités, tous les états de correction et les données fournisseur. Aucun `ignore` global, aucune exclusion de paquet et aucun filtre `only-fixed` ne doivent maquiller le résultat complet.

1. Un correctif High/Critical disponible et applicable bloque la promotion jusqu’à reconstruction et nouvelle qualification. Les versions de Debian se comparent selon leur sémantique, pas par ordre lexicographique.
2. Un finding sans correction distribuée reste ouvert. Le statut `wont-fix`/`no-dsa` n’est pas une analyse d’exposition. Pour autoriser une livraison limitée, une décision explicite doit identifier le digest, la CVE, le composant, le chemin d’exécution et ses préconditions, les preuves fournisseur, les mesures compensatoires, le responsable et la date de réexamen. Une classification « non atteint actuellement » ne vaut pas exemption d’un autre usage du paquet.
3. Un finding supposé inapplicable exige une preuve précise : architecture, option de compilation, module absent ou fonction inaccessible. L’absence de test d’exploitation n’est pas une preuve d’inapplicabilité. La preuve est révoquée par tout changement pertinent du build ou de l’exposition.
4. Les composants compilés qui ne sont pas détectés automatiquement sont inventoriés explicitement. Le pipeline ne doit pas rendre un succès par disparition d’un paquet de la base dpkg.
5. La promotion référence l’image analysée et son digest ; reconstruire une image après les tests exige une nouvelle qualification. Un résultat de tests applicatifs ou de pip-audit ne remplace pas le scan natif.

Cette proposition ne transforme pas le candidat initial en livraison approuvée. La décision de gouvernance CI et son ADR appartiennent au coordinateur ; les findings non traités demeurent visibles dans le rapport.

## Tests de l’outil

Commandes : `python -m unittest tests.test_native_inventory tests.test_native_sbom`. Dernier résultat combiné : **47/47 en 3,164 s**, aucun skip (23 tests d’inventaire, 24 d’enrichissement SBOM), dans l’outillage de sécurité isolé complet. Ruff : succès. Les tests d’inventaire n’exécutent aucun ELF et n’utilisent ni Docker ni réseau : ils construisent des en-têtes ELF synthétiques et injectent des sondes de résolution/version synthétiques explicites.

Ils couvrent capture/vérification, altération binaire, omission et ajout de fichier, version source/hash/signature/options incorrects, types CMake invalides et doublons, options compilées différentes du cache, trace patchelf invalide, politique de compilation incomplète ou affaiblie, consommateurs absents, ancien paquet Debian, version binaire différente des métadonnées, bibliothèque chargée hors préfixe ou attribuée au mauvais composant, dépendance non résolue, recherche relative/`$ORIGIN`/élément vide, ELF tronqué, sortie ldd ambiguë, JSON dupliqué, fichier de rapport préexistant et environnement de chargement non autorisé. La validation Linux sur la nouvelle image reste à exécuter.

## SBOM applicatif et composants compilés

`deploy/native_sbom.py` enrichit une copie du SBOM pip-audit, sans modifier les trois fichiers d’entrée. Il exige un inventaire, un rapport de vérification réelle (`verified=true`, `live_link_probe=true`, inventaire exactement identique) et le digest exact de l’image. Il ne lance ni ELF ni commande Docker, ne contacte aucune URL et ne télécharge aucun schéma.

```sh
python deploy/native_sbom.py \
  --app-sbom app.cdx.json \
  --native-manifest native-manifest.json \
  --native-report native-verification.json \
  --image-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --output combined.cdx.json
```

Le paramètre `--image-digest-kind` distingue `oci_manifest` (défaut) et `image_config`. Avant publication, `qualified-image.json.image_id` est le **hash de configuration**, même si Docker 29 expose un autre `.Id` : le pipeline doit donc passer `--image-digest-kind image_config`. Cette valeur ne constitue pas un digest de pull du registre. Le kind est explicite dans les propriétés et les références ; deux kinds associés au même hash ont des identités de document différentes. Pour `image_config`, aucun hash de conteneur complet n’est déclaré. La publication rattache ensuite séparément manifeste de registre et configuration vérifiée.

Le digest de l’exemple est fictif. Le pipeline doit fournir celui de l’image effectivement vérifiée, dans sa chaîne d’artefacts de confiance. Le script ne peut prouver qu’un opérateur lui a donné le bon digest ; la provenance CI et l’attestation lient cette déclaration à la construction.

La validation stricte CycloneDX s’appuie sur les schémas locaux de `cyclonedx-python-lib[json-validation]==11.12.0`, épinglé uniquement dans `requirements-security.lock`. Une bibliothèque absente bloque l’outil. Les versions CycloneDX 1.4/1.5/1.6 sont acceptées, la version d’entrée est conservée. Les composants, références, métadonnées, propriétés et hashes applicatifs sont préservés. Les additions comprennent un composant conteneur lié au digest, les deux paquets compilés, chaque ELF avec son hash et ses alias et les liens de dépendance correspondants. Les hashes d’archive source, d’ELF installé et d’image restent distincts. Les trois hashes des octets d’entrée et celui de l’inventaire canonique sont inscrits dans les propriétés ; la sérialisation et l’identité de ce nouveau document sont déterministes pour les mêmes entrées.

Les conflits de versions/identités, les références partagées ou réservées, les clés JSON dupliquées, les algorithmes de hash contradictoires et les alias hors composant sont refusés. Des budgets bornent taille, profondeur et nombre de nœuds. Les champs natifs non reconnus ne sont pas exportés comme propriétés arbitraires. La sortie est créée exclusivement en mode 0600 avant lecture des entrées ; aucun fichier existant n’est écrasé. Les pointeurs `$schema` hors CycloneDX et les références de schéma embarquées sont refusés.

Le format respecte les références primaires [CycloneDX](https://cyclonedx.org/docs/1.6/json/) et [purl generic](https://github.com/package-url/purl-spec/blob/main/types/generic-definition.json). Les paquets compilés portent des purl generic ; ils ne sont pas déguisés en paquets Debian. Un contrôle positif a établi que **generic seul ne déclenche pas les advisories Grype** pour les anciennes versions synthétiques FreeRDP 3.15.0/Guacamole 1.5.5. Un résultat de zéro match de ce premier contrôle était donc une lacune de couverture.

Les tuples CPE ont ensuite été qualifiés dans les configurations de l’API officielle NVD : `freerdp:freerdp` pour [CVE-2026-45700](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-45700) et `apache:guacamole` pour [CVE-2024-35164](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-35164). Seule la version est remplacée par celle réellement vérifiée. Aucune supposition de fournisseur ou de produit n’est utilisée. Les réponses officielles et leurs hashes sont conservés dans les preuves locales.

Avec ces CPE qualifiés, le contrôle positif synthétique détecte **222 correspondances**, dont les deux CVE attendues (221 FreeRDP, une Guacamole). Le SBOM applicatif/natif de l’archive intermédiaire `86651d…`, avant backport GDI, a ensuite donné zéro correspondance en 15,219 s. Cela concerne uniquement les composants applicatifs et compilés déclarés : **le scan OS de cette même archive conserve 102 High et aucun Critical**. Cette archive n’était pas fonctionnellement qualifiée pour RDP ; elle reste témoin et ne valide pas le prochain candidat avec backport. Toute nouvelle archive exige ses propres rapports d’inventaire, SBOM et rescans.

## État du checkpoint B2 et intégration CI

Sous Linux, le pilote PostgreSQL est désormais compilé localement via psycopg-c 3.2.10 contre libpq système ; le wheel psycopg-binary demeure limité au développement hors Linux. Le gate driver refuse sa présence physique sous Linux et contrôle implémentation/API publiques, extensions effectivement chargées, liaison système et identité des bibliothèques. Il ne modifie ni migrations ni données. Les artefacts B2, leurs versions et les résultats exacts du scan sont documentés dans [p1-f-image-security.md](p1-f-image-security.md). La présence de libpq système étend le suivi OS ; elle ne qualifie pas automatiquement les bibliothèques statiques embarquées par d’autres wheels, dont OpenSSL de cryptography.

La campagne intégrée d’outillage rapporte **100/100 tests en 3,578 s**, Ruff réussi ; les 47 tests d’inventaire/SBOM détaillés plus haut en sont un sous-ensemble. Le [gate de scan CI](image-scan-policy.md) contrôle source, configuration, base fraîche, analyse exhaustive sans filtres et contrôle positif. Il conserve 35 empreintes High **non triées**, sans aucune exemption acceptée : la CI de qualification peut donc être volontairement rouge tout en produisant les preuves complètes. Les assertions `analyst`/`reviewers` sont déclaratives et ne remplacent pas les protections du dépôt. Aucune publication ou qualification de production ne découle d’un checkpoint source seul.

Le scan strict réellement exécuté sur B2 (`91f42c…`, configuration `bb310b…`) conserve **343 correspondances, zéro Critical et 102 High**, sans résultat ignoré. Les 35 empreintes sont inchangées et non triées ; cette qualification de cohérence n’autorise donc aucune promotion. Le format Grype peut omettre une liste `ignoredMatches` vide : le gate accepte cette omission uniquement après vérification des options strictes ; `null` ou un type invalide reste refusé. Le delta possède 22 tests de régression réussis et ne modifie pas les bibliothèques natives.
