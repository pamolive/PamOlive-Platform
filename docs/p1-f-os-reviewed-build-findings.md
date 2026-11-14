# P1-F — Décisions proposées sur les 17 fermetures OS

Revue indépendante du 12 novembre 2026. **Ce document propose des décisions individuelles ; aucune exception CI n'est activée.** Il reprend seulement les 17 propositions A du triage antérieur, sans réouvrir les 35 couples ni prétendre qualifier une image de production.

La conclusion est plus précise que «17 A» : neuf propositions `code_not_present`, deux propositions `not_affected_build`, une proposition `code_not_present` limitée aux consommateurs C++ identifiés, et cinq propositions de non-accessibilité qui ne démontrent aucune absence de code. Ces cinq dernières restent soumises à une décision `not_reachable` avec profil vérifié ; une couverture insuffisante doit rester indéterminée. Aucun finding brut n'est supprimé.

## Identité et preuves publiques

Le seul témoin de ces constats est l'archive historique GDI :

- Archive SHA-256 `bf5d0075a25d2fc834aa5b21690fac709c62244a5f3330eee8296e1f58512cca`.
- Configuration image SHA-256 `cd487974f48fd1ed1c2bbb2f79b1fedc6bbcf5aa790329ff2118155502b80e77`, architecture `amd64`, Linux.
- Manifeste OCI historique identifié par le triage initial : `0585b52ad0db2aac7e3da04b6cea30f810773e03498583ef06a8b4630d5a6943`. Ce digest ne se substitue pas au hash de configuration ou d'archive.
- `var/lib/dpkg/status` SHA-256 `47d60aed637e0da779d0c786ed4c3da5f3e0b2b724542c64029f36c3fe0074dc`.

**Ces identités ne sont pas celles d'un candidat B3 final.** Chacune des conditions ci-dessous doit être réévaluée sur son archive effectivement scannée. Les bibliothèques privées de l'ancien wheel psycopg-binary ne sont pas assimilées aux paquets Debian système.

Deux extraits publics minimaux sont fournis, sans configuration applicative, secret, compte, adresse privée ni journal brut :

| Preuve | SHA-256 des octets du fichier | Contenu et portée |
| --- | --- | --- |
| [Faits d'archive](../.github/qualification/evidence/p1-f-reviewed-build-facts-gdi.v1.json) | `2f6eebfb31690ac1b87ca7fe0a1a2f5072d950f0819a8ac9a398e1ed39d60704` | 17 340 entrées finales après whiteouts, sélecteurs d'absence, versions dpkg, hashes de fichiers système, imports ciblés et références aux preuves originales. |
| [Preuves C++](../.github/qualification/evidence/p1-f-reviewed-build-cxx-gdi.v1.json) | `41ad151ab290cc926fedd80373c19a2e90841cf6ddd638a8a41a5c106211612f` | Instructions du symbole aligned new, sources/patches des trois consommateurs, correspondance des 27 ELF avec leurs paquets et sentinelle de l'ensemble des 844 ELF. |

Le hash de l'archive a été recalculé. L'inventaire des chemins a été reconstruit par lecture successive des layers TAR, avec whiteouts opaques et remplacements ; aucun fichier n'a été extrait ni exécuté. Les hashes de fichiers sélectionnés sont recalculés sur les octets archivés. Le graphe ELF complet antérieur est relié au même hash d'archive ; les importateurs et exports repris en proviennent. Une liste d'imports dynamiques n'est pas un graphe complet des appels, des templates ou des résolutions `dlsym`.

Les JSON sont des preuves d'analyse lisibles, pas des rapports signés ni un nouveau format de politique. Leur champ `qualification` est `false`. Les hashes de sources figurent lorsque les archives exactes étaient disponibles dans les preuves antérieures. Aucune reconstruction d'un hash source manquant à partir d'un numéro de version n'est effectuée.

## Identités de composants réutilisées par les décisions

Les abréviations ci-dessous évitent de répéter des hashes sans changer leur portée. Tous les paquets sont les versions **installées dans ce témoin**, distinctes de l'état d'un paquet source dans le suivi fournisseur.

| Identifiant | Paquet/version et preuve du fichier |
| --- | --- |
| K | libkrb5-3, libgssapi-krb5-2, libk5crypto3 et libkrb5support0 `1.21.3-5+deb13u1`. libkrb5.so.3.3 : `c4ab64e6bc2874a83e649e4439be752465da027a0041e2bb5343f81c80f0882d` ; libgssapi_krb5.so.2.2 : `c290f761873ebeac539911010526e1c5db86218bfcb29672760da46841741de0`. Aucun libgssrpc, kadmind ou krb5kdc dans les chemins finaux. |
| J | libcjson1 `1.7.18-3.1+deb13u1`. libcjson.so.1.7.18 : `9bb1c2cfb9a48b062008eb2bf2a73b7e2283574ce17f1ba21ba7ff2422c38028` ; libcjson_utils.so.1.7.18 : `33bafc885efb8de411c2e011a02cc23d936b9e9c67104c5ffc60068ac9aa05c9`. Les deux bibliothèques sont présentes. |
| P | perl-base `5.40.1-6+deb13u1`. usr/bin/perl : `b85210f03baeb859ee20b1324e59497f27f319eda9e2d3d1ecd163a79d884a7d`. Les chemins Pod/Text.pm et Archive/Tar.pm, y compris leurs suffixes, sont absents. |
| S | libsasl2-2 et libsasl2-modules-db `2.1.28+dfsg1-9`. libsasl2.so.2.0.25 : `3f93968591811eb3972c3467c69c2968dd9cb2b51f7b7bb48de22ba8e17d13fd`. Aucun chemin contenant digestmd5. |
| L | libacl1 `2.3.2-2+b1`, source acl `2.3.2-2`. libacl.so.1.1.2302 : `3c03774961231d8485a4dba36ec359a95939a84719799c58cd26173e44bbde90`. Aucun getfacl, setfacl ou chacl ; la bibliothèque ACL reste présente. |
| E | libexpat1 `2.9.0-1~deb13u1`, libfontconfig1 `2.15.0-2.3`. libexpat.so.1.13.0 : `36e7e50d21edcabed383bfddc594bb261c1c7cce456afdf23c5f53e849cda67c` ; libfontconfig.so.1.12.1 : `d6344f71a0cfd5fcb154278f0be706021f75f79d1fcc973fc4ddb1dff40ab0ee`. |
| G | libstdc++6/gcc-14-base `14.2.0-19`, libstdc++.so.6.0.33 : `972bb2a18b71140dab0240f8a1f68ab3fb1d56bcd4c4f824a91b70888faf5a00`. Consommateurs examinés : ICU `76.1-4`, APT `3.0.4`, HarfBuzz `10.2.0-1+deb13u1`. |

Pour K, les archives sources de la même révision Debian ont les hashes amont `b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35` et Debian `02b873b239fbe7ddf016dfe44deba4130673f4606c18c93da0622e2bc8500fb4`. Cela identifie les sources analysées, sans prétendre un rebuild reproductible du témoin. Les sources exactes J/P/S/L/E ne sont pas publiées dans ces extraits : leurs hashes manquent à cette revue. L'absence d'un module/outil est démontrée par l'archive, pas par une compilation supposée de ces sources.

## Neuf décisions proposées : code non présent

Chaque ligne est une proposition distincte. Le suivi Debian demeure l'autorité sur la plage du **paquet source** ; les conditions vérifient la présence du composant binaire précis dans l'archive, sans déclarer le paquet source corrigé.

| CVE et référence primaire | Identité, précondition et justification | Condition vérifiable / contre-exemple / limite |
| --- | --- | --- |
| [CVE-2026-112314](https://security-tracker.debian.org/tracker/CVE-2026-112314) | K ; fuite du client RPC dans lib/rpc/clnt_tcp.c, fonction clnttcp_call. Proposition `code_not_present` : la bibliothèque GSS-RPC n'est pas distribuée dans ce runtime. Le client Kerberos normal n'est pas ce client RPC. | Exiger sélecteur gssrpc_components vide sur la vue finale, absence du paquet binaire libgssrpc et mêmes composants autorisés. Contre-exemple : ajout de libgssrpc ou d'un outil RPC lié statiquement. Ne couvre pas le décodeur ASN.1 des bibliothèques clientes. |
| [CVE-2026-112320](https://security-tracker.debian.org/tracker/CVE-2026-112320) | K ; changement de flavor d'authentification côté transport serveur GSS-RPC. Proposition `code_not_present` : ce transport et kadmind ne sont pas installés. | Même inventaire final, aucun serveur RPC ajouté. Contre-exemple : ajout de kadmind/GSS-RPC, même si NLA n'en fait pas usage. L'absence de port ouvert seule ne suffirait pas. |
| [CVE-2026-112321](https://security-tracker.debian.org/tracker/CVE-2026-112321) | K ; nettoyage d'arguments AUTH_GSSAPI côté lib/rpc/svc_auth_gssapi.c. Proposition `code_not_present` pour ce composant serveur absent. | Interdire l'assimilation libgssapi_krb5 = libgssrpc ; noms/paquets/hashes restent séparés. Contre-exemple : service AUTH_GSSAPI additionnel. Aucune conclusion sur d'autres fonctions GSSAPI. |
| [CVE-2026-112322](https://security-tracker.debian.org/tracker/CVE-2026-112322) | K ; nettoyage quadratique clean_client dans le serveur GSS-RPC. Proposition `code_not_present` : composant serveur non livré. | Même sélecteur et versions ; ne pas accepter simplement un profil à faible charge. Contre-exemple : réintroduction du service ou de son code. |
| [CVE-2026-112323](https://security-tracker.debian.org/tracker/CVE-2026-112323) | K ; accumulation d'états serveur AUTH_GSSAPI. Proposition `code_not_present` : handler GSS-RPC/kadmind absent. | Absence physique du composant, à contrôler après changement d'image. Contre-exemple : ajout d'un mécanisme serveur RPC. Aucune exemption globale krb5. |
| [CVE-2026-82560](https://security-tracker.debian.org/tracker/CVE-2026-82560) | P ; boucle de formatage dans Pod::Text avant 6.1.1. Proposition `code_not_present` : perl-base contient l'interpréteur, mais pas ce module. | Sélecteur pod_text_module vide dans les chemins finaux ; examiner aussi tout nouveau bundle Perl. Contre-exemple : installation de podlators/perl complet ou copie du module dans une dépendance. Ne qualifie pas l'interpréteur entier. |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | P ; allocation dictée par un en-tête TAR dans Archive::Tar avant 3.10. Proposition `code_not_present` : module absent. | Sélecteur archive_tar_module vide, aucun bundle Perl nouveau. Contre-exemple : ajout d'Archive::Tar. Le tarfile Python et l'outil tar système sont d'autres implémentations et ne sont pas déclarés corrigés par cette décision. |
| [CVE-2026-107161](https://security-tracker.debian.org/tracker/CVE-2026-107161) | S ; dépassement du plugin DIGEST-MD5 dans add_to_challenge. Proposition `code_not_present` : le plugin manque, alors que le core SASL et le plugin DB sont présents. | Sélecteur sasl_digestmd5_plugin vide et liste des paquets/plugins stable. Contre-exemple : installation des modules DIGEST-MD5/HTTP Digest ou implémentation statique supplémentaire. Le simple bind LDAP actuel n'est qu'une corroboration, pas le fondement de l'absence. |
| [CVE-2026-54370](https://security-tracker.debian.org/tracker/CVE-2026-54370) | L ; course dans le parcours récursif des outils getfacl/setfacl/chacl. Proposition `code_not_present` pour ces outils absents, alors que libacl1 est conservée. | Sélecteur acl_recursive_tools vide, absence du paquet d'outils acl. Contre-exemple : ajout d'un outil vulnérable utilisé sur un chemin contrôlé. Ne ferme pas CVE-2026-54369, qui vise l'API de bibliothèque présente. |

Les cinq cas RPC partagent une condition d'absence, mais restent cinq CVE distinctes. La revue ne démontre pas l'absence de copies arbitraires de code source réintroduites sous un nom inconnu ; cette limite n'autorise aucun nouveau composant sans réexamen du BOM et du contenu. Elle ne remplace pas le fait concret que les composants Debian vulnérables identifiés sont absents de ce témoin.

## Deux décisions proposées : build non affecté

### CVE-2026-16554 — cJSON et taille de pointeur

Identité J. L'[avis fournisseur Debian](https://security-tracker.debian.org/tracker/CVE-2026-16554) décrit le débordement du compteur size_t 32 bits dans print_string_ptr. Les octets archivés portent ELFCLASS64 (`2`), little-endian et EM_X86_64 (`62`), avec paquet amd64, sans ABI x32/ELF32. **Proposition `not_affected_build` pour cette architecture précise**, indépendamment de la possibilité d'appeler l'impression JSON. La fonction n'est pas déclarée absente ni inaccessible.

Condition : même architecture, ABI et hash de bibliothèque, ou nouvelle preuve équivalente sur une bibliothèque différente ; contrôler aussi tout ajout de copie privée. Contre-exemple : une image i386/ELF32 ou un nouveau composant avec size_t 32 bits invalide la décision. Cette conclusion ne couvre ni Compare ni Utils et ne transforme pas la version Debian en version corrigée. Le hash de source cJSON exact manque ; le raisonnement repose ici sur la précondition d'architecture publiée et les octets du binaire, pas sur une recherche textuelle de sources.

### CVE-2026-95619 — aligned new avec implémentation POSIX

Identité G. Le [correctif GCC14 officiel 200183d4ab5d57575f3dfebc6af3baf649910b9e](https://github.com/gcc-mirror/gcc/commit/200183d4ab5d57575f3dfebc6af3baf649910b9e.patch) distingue explicitement l'implémentation posix_memalign, sans arrondi de taille vulnérable, des branches aligned_alloc/fallback concernées. Le suivi [Debian individuel](https://security-tracker.debian.org/tracker/CVE-2026-95619) conserve la plage du paquet source.

La preuve C++ publique contient les 39 instructions et octets du symbole `_ZnwmSt11align_val_t`, adresse `0xb3c20`, taille 125 octets, dans le vrai libstdc++.so.6.0.33 du témoin. L'appel `0xb3c81` est résolu par sa relocation vers **posix_memalign** ; la taille demandée reste transmise sans l'arrondi vulnérable. **Proposition `not_affected_build`**, fondée sur cette branche réellement compilée. L'absence d'import depuis un consommateur n'est pas utilisée comme justification.

Condition : hash du DSO exact et même corps/relocation, puis contre-revue du désassemblage lié au patch. Contre-exemple : bibliothèque reconstruite utilisant aligned_alloc ou fallback malloc sans contrôle d'overflow. Un nouveau hash oblige à refaire la preuve, même si le numéro Debian ne change pas. L'analyse Capstone est statique ; aucun ELF Linux n'a été chargé/exécuté et aucun test runtime d'allocation n'est prétendu réussi.

## Une décision C++ à portée explicitement bornée

### CVE-2026-102010 — type GNU PBDS précis

Identité G et consommateurs ICU/APT/HarfBuzz liés dans la preuve C++. Le [correctif GCC officiel aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6](https://github.com/gcc-mirror/gcc/commit/aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6.patch) vise `__gnu_pbds::priority_queue<..., binary_heap_tag>::erase_if`, dans le header `ext/pb_ds/detail/binary_heap_/erase_fn_imps.hpp`. Il ne vise pas toutes les files de priorité, ni std::priority_queue. [Debian](https://security-tracker.debian.org/tracker/CVE-2026-102010) indique la plage du paquet source.

La proposition `code_not_present` porte sur **les instanciations vulnérables dans les consommateurs identifiés de cet ensemble exact**, pas sur l'absence du header dans toutes les distributions. L'examen ne repose pas sur l'absence de symbole dynamique : les sources et patches Debian ont été examinés, y compris les fichiers .hh et templates. ICU ne référence pas PBDS ; APT utilise vector avec les algorithmes standard de tas ; HarfBuzz utilise son propre hb_priority_queue_t/hb_vector_t. Aucun nouveau consommateur concret de PBDS n'a été identifié pendant cette relecture.

| Source exacte | SHA-256 de l'archive | Couverture de la recherche antérieure |
| --- | --- | --- |
| icu_76.1.orig.tar.gz | `dfacb46bfe4747410472ce3e1144bf28a102feeaa4e3875bac9b4c6cf30f4f3e` | 2 497 fichiers réguliers ; zéro hit PBDS/type vulnérable. |
| icu_76.1-4.debian.tar.xz | `5f9ff8b3a8e89a01b52c84bfebd35e7825ac561669d24e5a3d5f25d158e4f412` | 28 fichiers ; zéro hit. |
| apt_3.0.4.tar.xz | `e853aec49afbe520ebcd4dbcbc98e1c55262c6bf1c119cf43e6aec69752443c6` | 875 fichiers ; solver3.h distingue explicitement sa structure de priority_queue. |
| harfbuzz_10.2.0.orig.tar.xz | `620e3468faec2ea8685d32c46a58469b850ef63040b3565cde05959825b48227` | 3 682 fichiers ; structure propre, pas GNU PBDS. |
| harfbuzz_10.2.0-1+deb13u1.debian.tar.xz | `7694792ba03256931cbd068b9100d5bcca1d63496434af3c30b56babddd01d90` | 30 fichiers ; zéro hit PBDS/type vulnérable. |

Les hashes des 27 ELF installés ont été comparés aux .deb liés aux buildinfo : 6 ICU, 20 APT, 1 HarfBuzz. Les buildinfo déclarent GCC/G++14.2.0-19 ; les sections .comment des ELF ne permettent pas de confirmer seules le compilateur. Les signatures OpenPGP n'ont pas été revérifiées par cet agent ; la cohérence HTTPS/archives/binaires ne devient pas une attestation cryptographique du compilateur.

La sentinelle de contenu complète du témoin est la table canonique `{chemin ELF: SHA-256}`, **844 entrées**, SHA-256 `55a12ab5fda86da67a522cbcb6bb4d328f2c7064e58006fafece9247c1c693d5`. La preuve JSON précise sa canonisation. Elle détecte un changement ; elle ne démontre pas à elle seule la nature C++ de tous les fichiers. La décision proposée exige de conserver la liste exacte de consommateurs/source/ELF/BOM examinés et de refaire l'analyse de tout nouveau consommateur C++ ou binaire modifié. Le passage B3 est un changement de contenu à confronter aux composants modifiés, jamais une reprise aveugle du hash historique.

Contre-exemple concret de condition : un nouveau plugin instancie le type GNU PBDS vulnérable ou une nouvelle version d'ICU/APT/HarfBuzz l'introduit. Il faut alors corriger le header dans son builder et recompiler **ce consommateur** ; remplacer uniquement libstdc++.so n'élimine pas un template déjà compilé. La revue n'impose pas un audit universel de toutes les instructions pour accepter l'ensemble identifié ; elle refuse seulement une exemption globale gcc-14 dépourvue de périmètre et de sentinelle.

## Cinq anciennes propositions A à ne pas déclarer code absent

Pour ces cinq cas, **le code vulnérable est présent**. Une décision `not_reachable` peut être examinée avec les restrictions et preuves exactes ci-dessous. Ce document ne l'active pas. Si le périmètre des consommateurs, des appels internes ou du chargement de plugins reste insuffisamment établi par la contre-revue, la décision demeure indéterminée/bloquante ; les ressources limitées ou l'absence de nom dans dynsym ne suffisent pas.

| CVE et référence primaire | Faits observés | Décision proposée, condition et contre-exemple |
| --- | --- | --- |
| [CVE-2026-67215](https://security-tracker.debian.org/tracker/CVE-2026-67215) | J ; cJSONUtils_ApplyPatches amplifie la profondeur. libcjson_utils est présente. Aucun DT_NEEDED sur Utils, aucun import cJSONUtils dans les 844 ELF ; aucune référence trouvée dans les sources FreeRDP/Guacamole examinées. | Candidat `not_reachable`, jamais `code_not_present`. Condition : même ensemble de consommateurs/plugins, aucun chargement Utils ni appel dynamique depuis Python ou un nouveau canal PATCH natif. Contre-exemple : ajout de ctypes/plugin appliquant des patches cJSONUtils. Une preuve source cJSON exacte et la fermeture des consommateurs doivent être confrontées ; le PATCH SCIM Python ne constitue pas ce chemin natif. |
| [CVE-2026-29036](https://security-tracker.debian.org/tracker/CVE-2026-29036) | J ; résolution de JSON Pointer dans cJSON_Utils.c. Mêmes faits de présence et chargement que 67215. | Candidat `not_reachable`, décision individuelle séparée. Exiger les mêmes conditions, sans les confondre avec une correction du décodage ~0/~1. Contre-exemple : une application applique un patch attaquant via Utils. La version source n'est pas corrigée par la restriction. |
| [CVE-2026-67216](https://security-tracker.debian.org/tracker/CVE-2026-67216) | J ; récursion exponentielle de cJSON_Compare. La fonction est réellement exportée par libcjson ; aucun import de ce nom dans le graphe, ni référence dans FreeRDP/Guacamole. | Candidat `not_reachable` pour le graphe applicatif courant. Condition : pas de nouvel appel direct/interne/dynamique de Compare sur données influencées. Contre-exemple : ajout d'une comparaison JSON native sur entrée distante. La présence de Parse/Print dans WinPR n'est ni une preuve d'appel à Compare ni une preuve générale contre tout appel interne. |
| [CVE-2026-113351](https://security-tracker.debian.org/tracker/CVE-2026-113351) | E ; le défaut exige XML_ParserReset. La fonction est exportée, sans import externe dans les 844 ELF. Fontconfig est le consommateur dynamique identifié de libexpat Debian ; ses sources amont créent/libèrent les parsers sans ce reset. | Candidat `not_reachable`, sous rattachement des sources/options exactes Fontconfig et fermeture des consommateurs. Contre-exemple : nouvelle bibliothèque réutilisant le parser via Reset. La copie Expat intégrée à Python doit être traitée selon sa propre version/preuve ; elle n'est pas automatiquement couverte par le paquet Debian. |
| [CVE-2026-117610](https://security-tracker.debian.org/tracker/CVE-2026-117610) | E ; sous-parser d'entité externe avec premier chunk vide. Aucun import XML_ExternalEntityParserCreate, XML_SetExternalEntityRefHandler ou XML_SetParamEntityParsing ; fonction disponible dans la bibliothèque. | Candidat `not_reachable`, sous preuve que les consommateurs approuvés ne créent pas ce sous-parser. Contre-exemple : activation d'un handler externe XML dans un nouveau consommateur ou plugin. L'absence d'endpoint XML web ne suffit pas, et les autres CVE Expat restent distinctes. |

Les recherches propres portent sur FreeRDP3.33.1, archive `4431bbf04d370545cfe2924b9d9f116b95c90c64ff156b2550bbaf82d34e7124`, 1 774 fichiers C/C++/headers, et Guacamole1.6.0, archive `8bc45675da96d7b6f39728160181e3d4ff3c08f460f6d26de5805b642bf13f2b`, 502 fichiers. L'absence d'appel dans ces deux sources ne constitue pas, seule, une fermeture de toutes les bibliothèques système.

## Porte avant toute décision CI

1. Contre-revue indépendante de chaque justification et de son type ; aucun passage mécanique du marqueur historique A vers une disposition autorisée.
2. Nouveau scan brut sur l'archive finale ; conservation des multiplicités, empreintes fournisseur/paquets et résultats High. Les constats du témoin ne remplacent pas le scan B3.
3. Vérification des versions, hashes, architecture, composants absents et sentinelles de contenu contre cette archive. Tout changement non expliqué réouvre les décisions concernées, pas nécessairement tous les cas sans lien.
4. Attribution par le propriétaire du gate d'un analyste/relecteur, date, échéance, preuve publique et conditions vérifiables. Aucun de ces champs n'est créé ici dans la politique.
5. Pour une éventuelle décision `not_reachable`, restrictions de chargement/plugin et de profil appliquées au lancement ; si elles manquent, refus. Une décision fondée sur un build non affecté reste distincte d'une simple non-accessibilité.

Le backport ASN.1 B3 et ses exclusions KEYRING sont des portes séparées, hors des 17 cas. Aucun résultat de compilation B3, test de transport, disponibilité du NAS ou autorisation de production n'est déduit de cette revue documentaire.

## Validation effectuée pour ce document

Lecture de l'archive historique et des preuves antérieures, relecture en ligne des 17 suivis Debian et des deux patches GCC officiels. Création limitée au présent document et aux deux extraits JSON publics. Aucun code produit, test existant, politique, dépendance, build, conteneur, base, système réel ou NAS n'a été modifié. Aucun commit, push ou déploiement.
