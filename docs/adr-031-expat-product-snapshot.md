# ADR-031 — Expat produit et snapshot de système de fichiers

Statut : choix accepté pour qualification Linux ; aucune admission produit.

La référence d’intégration exacte est `3d960926c8984d6074bc777a2f3a44b6caeb9836`,
Dockerfile011ceaa38b7080a23e0fc9c79a509a81bb31db0d756172f078146480f37e6447.
Le succès réel549 concerne le laboratoire, ses signatures et ses contrôles natifs.
Il ne qualifie ni cette nouvelle image produit, ni ses consommateurs, ni ses CVE.

## Choix

Le Dockerfile produit conserve ses constructions Kerberos/FreeRDP/guacd/Python.
Il ajoute les étapes de préparation et compilation Expat déjà exécutées en549 :
authentification des matériaux avant extraction, deux paquets locaux runtime/SDK,
corpus C narrow et wide complet, gardes négatives, contrôle source et UBSan.
Le SDK distribué et la bibliothèque wide restent unsigned-short UTF16 ; aucun
XML_UNICODE_WCHAR_T, -fshort-wchar ou abandon d'assertion n'est introduit.

Les deux extensions CPython3.12.16 sont reconstruites ensemble avec la politique
explicite xml-local-no-pgo-v1. Les deux seuls flags PGO retirés le sont par le
helper549 conservé ; les contrôles ABI, capsule, imports et oracles restent ceux
de549. Cela ne démontre aucune équivalence de performance avec le Python initial.

Les SDK des consommateurs héritent du nouveau runtime Expat. Une garde dpkg
explicite exige runtime et SDK2.10.0-1+pamolive1 avant leurs compilations. Le
runtime conserve les paquets, chemins LD, rôles1000/1001, certificats et fichiers
NSS/Kerberos de la recette produit ; les deux modules sont copiés du même build.
Le vérificateur existant recontrôle les chemins actifs après toutes les étapes
APT/Python produit, puis dans un enfant CI non-root borné et sans réseau.

Un simple remplacement APT conserve les anciennes bibliothèques dans les couches
de l'image. Le runtime final part donc de scratch et copie le système de fichiers
résolu de runtime-build. Aucun chown/chmod global n'est ajouté. La configuration
Python est restaurée depuis le config OCI réellement reçu par GET officiel et
vérifié aux trois digests, puis les ENV/Cmd/Healthcheck produit sont réappliqués.
Les cinq ENV de base incluent le PATH exact avec son doublon /usr/local/bin.

Le snapshot compare réellement en construction type, mode, UID/GID numériques,
cible de symlink et taille de chaque fichier régulier. Les contenus des montages
éphémères /dev,/proc,/sys,/run,/tmp et le montage de comparaison sont exclus,
ainsi que les trois fichiers /etc injectés par le moteur. Toute différence dans
le périmètre comparé refuse. Les hardlinks, ACL/xattrs, l'égalité de contenu et
les origines ne sont pas attestés par ce contrôle de métadonnées. Le contrôle
archive des quatre ELF actifs porte, lui, sur leurs octets réels.

Cette copie ne constitue pas une équivalence de provenance OCI : les couches de
base disparaissent du graphe final. La recette, les matériaux authentifiés,
les sorties de build et la référence de base restent des preuves séparées à
examiner ; l'absence de l'ancien code ne prouve pas son origine. La recipe
enforcement et qualified-image existantes peuvent refuser cette nouvelle forme.
Elles restent actives ; aucun pin observé ne devient automatiquement approuvé.

## Contrôles produit

La même archive que la qualification est examinée sur un FD régulier conservé,
avec hash avant/après et stabilité FD/chemin. Le config OCI exact et les quatre
ELF actifs sont liés à cette archive. Les SHA des anciens quatre ELF sont tirés
du reçu ABI avant remplacement, validés distincts puis interdits physiquement
dans toutes ses couches, même masqués ensuite par une réécriture/whiteout.
Tout autre nom physique libexpat/libexpatw.so est également refusé. Cela ne
prétend pas reconnaître un ancien code arbitrairement renommé et transformé.

Le SBOM existant est enrichi du paquet source Debian orig distinct de l'archive
upstream, des deux bibliothèques et des deux extensions avec leurs SHA réels.
Les relations pyexpat→Expat et _elementtree→pyexpat sont conservées. Le purl
générique n'est pas annoncé comme un matching CPE exhaustif de code compilé.
Les scans OS/dpkg et applicatifs, schéma CycloneDX complet, contrôles positifs,
seuils Grype et règles d'autorité existants restent obligatoires et inchangés.

Il faut recevoir l'image exacte et tous les résultats Platform : DNS, chemins
LD/RPATH, chargements réels, LDAP/Kerberos/TLS/CA/NSS, NLA/RDP, SSH et PAM/P0.
Les anciennes références ELF/recipe exigent éventuellement une nouvelle revue
Root sur les sorties réelles ; elles ne sont ni ignorées ni auto-remplacées.
Aucun groupe High n'est clos par ce document ou par des tests synthétiques.

## Composition Jansson

Appliquer les hunks Expat sur011ce puis les hunks de la branche Jansson/ADR030.
Ne pas recopier son ancien Dockerfile entier. Conserver les nouvelles bases SDK,
étapes snapshot et vérifications Expat ; substituer seulement les dépendances et
choix CMake JSON de Jansson. Composer explicitement les options archive_stream,
forbidden_elf_sha256 et reject_cjson_elf dans archive_facts, puis les deux enrichissements
SBOM et les arguments CI. Les listes de tests et pins doivent refléter cette
composition revue. Aucun conflit n'autorise un fallback cJSON ou une désactivation
du contrôle d'absence physique de l'une des deux migrations.

## Correction de la vue comparée après réception Linux

Le [run0f2bf83](https://github.com/pamolive/PamOlive-Platform/actions/runs/43871934888/job/133315062835)
a reçu15737 entrées par côté et exactement deux écarts : les répertoires /proc
et /sys ont mode0755 dans le snapshot image et0555 dans le RUN vivant. Type,
UID/GID et toutes les autres entrées sont identiques. Cette mesure ne prouve
pas une image qualifiée ; elle révèle que la comparaison précédente mélangeait
une vue image avec les montages du worker.

La correction compare deux racines d'image immuables montées en lecture seule.
Le stage runtime-copy part toujours de scratch et copie runtime-build avec
les mêmes ENV/Cmd/User/Healthcheck. Le stage snapshot-check dérive séparément
de runtime-build et monte runtime-build et runtime-copy sous deux préfixes.
Il appelle le même comparateur, sans aucun changement de champ, de permission,
de PRUNED/INJECTED, de normalisation ou d'exception. Une vraie différence de
mode /proc ou /sys entre images reste refusée, comme toute différence du scope.

Le runtime final hérite de runtime-copy et ne copie depuis snapshot-check que
le snapshot.json qui n'existe qu'après succès. Aucun système de fichiers du
worker ou montage de vérification n'est copié vers le payload final. Le graphe
reste dépendant du contrôle ; il n'y a ni fallback, ni nouvelle couche de base
réintroduisant les anciens ELF, ni chmod/chown global. Comme auparavant, le
reçu ajouté ensuite ne prouve ni contenu, hardlinks, xattrs, origine ou égalité
de provenance OCI. Les contrôles archive/config/provider restent obligatoires.

La [référence Dockerfile](https://docs.docker.com/reference/dockerfile/#run---mounttypebind)
et la [construction multi-stage](https://docs.docker.com/build/building/multi-stage/)
décrivent ces mécanismes de bind en lecture seule et de copie sélective. Elles
ne démontrent pas que cette nouvelle recette s'exécute : un nouveau build et
tous les tests/scans réels restent requis. Les SDK et les autres étapes sont
conservés. Le pin Dockerfile est recalculé depuis Git ; les13 autres pins produit
et les35 sources Expat restent inchangés.


The historical pamolive1/SOURCE-REBUILD V1 counts above remain scoped to their
original image. The proposed local pamolive2 two-advisory reconstruction and
current V2 receipt requirements are recorded in ADR035; no old native receipt
is transferred to that candidate. The snapshot comparison policy is unchanged.
