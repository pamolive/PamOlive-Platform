# ADR-028 — Corpus C Expat sur l’ABI Linux UTF-16 ushort

Statut : choix Root du16novembre2026 pour préparation et contre-revue source.
L’exécution Linux reste à recevoir. ADR-027 reste réservé à l’architecture PGO.
Aucune admission CVE ni promotion d’image n’est accordée.

## Problème confirmé

Le vrai diagnostic e256 s’arrête à `make-buildw-check`, rc2, H1 terminé : le
garde de `tests/common.h` refuse explicitement XML_UNICODE sans wchar_t. Debian
2.10 ne construit que `buildw/lib`, avec `-DXML_UNICODE`. Son ABI est donc
XML_Char unsigned-short/2 et XML_LChar char/1 ; le wchar_t Linux reste sur4octets.
Forcer XML_UNICODE_WCHAR_T ou -fshort-wchar changerait cette frontière et serait
incorrect avec la libc existante. Le garde de `expat_external.h` le dit aussi.

Les sources2.10 exactes ont un unique `runtests` C : Autotools liste les.c et
CMake déclare LANGUAGES C/C99. Aucun corpus runtestspp/C++ n’est livré ici. Le
support ushort existe pour les fonctions internes xcs, mais pas pour les
littéraux/diagnostics du banc. Le même garde subsiste dans master consulté.

## Alternatives

| Voie | Couverture et coût | Choix |
| --- | --- | --- |
| Forcer wchar/short-wchar ou enlever le garde | ABI/CRT incohérents ; faux succès | Refusée |
| Remplacer le corpus par quelques cas | Ne couvre ni OOM ni les milliers d’exécutions existantes | Refusée comme équivalent |
| Full upstream wchar sous Windows/MinGW avec CRT réellement compatible | Utile indépendamment ; XML_LChar/plateforme diffèrent du binaire Linux ushort | Complément éventuel, pas preuve ABI Linux |
| Port test-only du corpus C complet | Quelques coutures de types/diagnostics ; conserve les cas et l’ABI Debian | Retenue |

## Décision

Après authentification des matériaux et **après construction des paquets**, un
patch pinné touche sept fichiers sous srcw/tests. Les35 C/h d’origine sont
vérifiés avant/après ;444 déclarations START_TEST, toutes les lignes de
registration et les appels assert/fail sont conservés. Les sources OOM restent
inchangées. Aucun fichier lib/, header public installé, configure ou règle de
production n’est modifié ; les deux.deb exportés sont hashés avant/après.

La nouvelle branche ushort exige C11, l’identité de type char16_t/XML_Char
unsigned-short, les tailles2/1 et des octets8bits. Elle utilise des littéraux
statiques `u##s`, sans cast ni allocation. Elle refuse explicitement C++ et C99.
La branche wchar authentiquement compatible et la branche narrow restent
disponibles ; le garde n’est pas remplacé par une suppression de contrôle.

XML_Char et XML_LChar ont leurs traits séparés. Les noms/attributs XML_Char
utilisent des diagnostics hexadécimaux limités à16 unités, sur buffers de pile
propres à chaque argument. Les erreurs et versions XML_LChar gardent un format
narrow en mode ushort ; la comparaison de version utilise un comparateur
LChar. Aucun malloc, codec wchar, locale ou compteur OOM n’est ajouté.

Le runner C complet est compilé en C11 avec erreurs de types/formats fatales.
`buildw/tests/check` exécute le même TESTS=runtests et sa matrice6×2 ; il évite de
compiler les exemples wide qui n’ont pas de formatage ushort portable. Cela ne
revendique pas la qualification de ces exemples/outils. Les résumés non nuls,
TRS PASS, mêmes comptes narrow/wide et journaux réels sont exigés. Inconnu,
échec, absence de résumé, SKIP et sortie réutilisée restent bloquants.

## Réception nécessaire

Un self-test natif du header vérifie types, littéraux concaténés, BMP/paires,
canaris et toutes les capacités de buffer. Le full C port ne devient validé
qu’après compilation et réception des deux journaux complets. Les contrôles
négatifs C99/C++/type incompatible doivent refuser à la compilation ; aucun
résultat de ces compilations n’est encore reçu.

Le runner upstream lie libtestpat avec XML_TESTING, pas le.so installé. Il est
donc complété par le corpus C borné existant, inchangé, lié à -lexpatw, et un
smoke C++ distinct de l’ABI exportée : tableaux XML_Char explicites, callbacks
BMP/surrogates, entrées UTF-8/UTF-16LE fragmentées, features2/1 et wchar_t4.
Aucune réinterprétation de char16_t C++ ni aucun full corpus C++ n’est revendiqué.

La comparaison ABI/SONAME/exports, les deux modules Python, les tests Python,
UBSan existant, l’image exacte et ses nouveaux scans restent obligatoires.
Le très gros déclencheur118370 n’est pas exécuté ; ce port ne crée aucune
équivalence de couverture ni admission des quatre High à lui seul.

## Raccordement des contrôles négatifs

Après le self-test positif, les trois compilations C99, C++ et XML_Char signed-short sont exécutées dans un dossier privé de tests. Le SDK public et le header testé restent inchangés. Un refus attendu exige exit non nul normal, H1 complet, outil identique avant/après et diagnostics GCC JSON pointant exactement le garde du header pinné. Le journal UNKNOWN de common est conservé avec son empreinte ; un reçu distinct atteste seulement le refus attendu. Les 22 modèles purs et sept contre-cas indépendants passent ; compilations natives et format réel des diagnostics restent à recevoir.
