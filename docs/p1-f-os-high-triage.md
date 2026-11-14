# P1-F — Triage indépendant des High OS du témoin GDI

Revue du 11 novembre 2026. **Aucune qualification globale de l'image ni autorisation de production.** Le seuil scanner reste dépassé. Ce document ne modifie aucun code, test, politique CI ou fichier d'exemption.

## Périmètre et identité des preuves

Les rapports privés `output/p1-f-gdi-independent-security.json` et `output/p1-f-grype-gdi-os.private.json` concernent l'archive `p1-f-production-gdi-qualified.tar`, SHA-256 `bf5d0075a25d2fc834aa5b21690fac709c62244a5f3330eee8296e1f58512cca`, configuration `sha256:cd487974f48fd1ed1c2bbb2f79b1fedc6bbcf5aa790329ff2118155502b80e77`, manifeste `sha256:0585b52ad0db2aac7e3da04b6cea30f810773e03498583ef06a8b4630d5a6943`.

Le scan conserve **349 correspondances dont 102 High, zéro Critical, 35 couples distincts (paquet source, CVE), 13 familles**. La mention préliminaire «45 couples» était une erreur de comptage, pas dix CVE éliminées par triage. La matrice source de `p1-f-remediated-independent-security.json` appartient à l'archive intermédiaire `86651d…` ; le rapport indépendant GDI compare explicitement les tuples résiduels. Les identités d'archives ne sont pas interchangeables.

Outil Grype0.121.3, base v6.1.10 du 11 novembre2026 à06:21:32Z. Aucun des 102 matches High n'annonce de correction distribuée dans cette base ; plusieurs avis amont indiquent des correctifs qui ne sont pas livrés en trixie. `no-dsa`/`wont-fix` ne signifie pas absence de risque. Une nouvelle image, notamment après actualisation de pip, exige son propre scan et une comparaison exacte.

Références de méthode : ADR-019, `native-supply-chain.md`, `p1-f-image-security.md`. Les avis Debian individuels ci-dessous ont été consultés en ligne ; la page119079 a échoué à plusieurs reprises et son détail a été recoupé avec l'[annonce krb5 amont publiée sur oss-security](https://www.openwall.com/lists/oss-security/2026/11/09/38) et le [suivi Ubuntu](https://ubuntu.com/security/CVE-2026-119079). Aucun système utilisateur, secret applicatif ou NAS n'a été interrogé.

## Preuves locales et portée

Lecture en mémoire des layers TAR de l'archive, sans extraction ni démarrage d'application :

- Aucun `kadmind`, `krb5kdc`, fichier `libgssrpc*`, plugin `libdigestmd5*`, module `Pod/Text.pm` ou `Archive/Tar.pm` n'apparaît dans les layers. Le runtime contient des bibliothèques clientes Kerberos et SASL, pas l'intégralité de leurs paquets sources.
- `libcjson.so.1.7.18` est ELFCLASS64, SHA-256 `9bb1c2cfb9a48b062008eb2bf2a73b7e2283574ce17f1ba21ba7ff2422c38028`. Le problème32bits16554 ne s'applique donc pas à ce binaire amd64. Cela ne qualifie pas un futur build32bits.
- `libcjson_utils.so.1.7.18` est **présent**, SHA-256 `33bafc885efb8de411c2e011a02cc23d936b9e9c67104c5ffc60068ac9aa05c9`. Il serait faux de considérer la famille Utils absente sur la seule base des options FreeRDP.
- `libsqlite3.so.0.8.6` est ELFCLASS64, SHA-256 `317d80bf5d592f98a71e14d2330591d6a339f631f37c5977835af748a1f26715`. Les chaînes `ENABLE_FTS5` et `ENABLE_SESSION` sont présentes ; l'absence des extensions ne peut servir de justification.
- `infocmp`, `mount`, `nsenter` sont présents. L'absence de ces outils ne peut être invoquée.
- Le manifeste natif GDI recense10ELF et confirme FreeRDP3.33.1/guacd1.6.0. FreeRDP est compilé avec X11/Wayland/serveur/SDL désactivés, Kerberos activé dans le script de build, Cairo activé. Le fait que FreeRDP ne crée pas de client X11 ne supprime pas les bibliothèques X11 transitives de Cairo/Pango.
- Recherche dans **tous les fichiers C/C++** de l'archive FreeRDP3.33.1 vérifiée, SHA-256 `4431bbf04d370545cfe2924b9d9f116b95c90c64ff156b2550bbaf82d34e7124` : aucun appel `cJSON_Compare`, `cJSONUtils_*`, `cJSON_PrintBuffered`, `gss_accept_sec_context` ou `krb5_rd_cred` ; `kerberos.c` appelle `krb5_rd_req`. Cette recherche n'est pas une preuve exhaustive des appels internes des autres bibliothèques système.

Le superviseur `deploy/runtime.py` fournit au moteur UID1001 un environnement neuf avec `LANG=C.UTF-8`, sans `DISPLAY` ni `LANGUAGE`. Il ne transmet pas les secrets Django/PostgreSQL au moteur. `directory_adapters.py` effectue un simple bind LDAP après StartTLS, pas un échange SASL DIGEST-MD5. Le profil Compose retire toutes les capacités puis ajoute seulement SETUID/SETGID/KILL, active `no-new-privileges`, racine en lecture seule, réseaux internes et PostgreSQL. Ces restrictions sont des conditions de déploiement à contrôler sur l'instance réelle ; leur présence dans un fichier n'est pas une attestation d'exécution.

## Classification des 35 couples

**A** : composant/fonction vulnérable absent ou architecture non affectée démontrée sur ce témoin ; candidat à une décision individuelle, après revue des preuves et rattachement au nouveau digest. **I** : applicabilité indéterminée, donc bloquante pour promotion normale. **R** : chemin réduit par restrictions de profil mais composant affecté présent ; reste ouvert, au mieux décision explicite de laboratoire, jamais «corrigé». Les constats A ci-dessous ne sont pas des règles d'ignorance installées.

Chaque lien désigne le suivi fournisseur Debian individuel. Les versions installées sont celles de la matrice brute, sans déduction à partir d'une comparaison lexicographique.

| Source / version | CVE | Précondition et analyse locale | Statut |
| --- | --- | --- | --- |
| krb5 1.21.3-5+deb13u1 | [112314](https://security-tracker.debian.org/tracker/CVE-2026-112314) | Fuite du client GSS-RPC `clnttcp_call` lors de réponses/retries ; libgssrpc absente, distinct de la bibliothèque cliente krb5. | A |
| krb5 | [112320](https://security-tracker.debian.org/tracker/CVE-2026-112320) | Changement de flavor sur transport serveur GSS-RPC ; libgssrpc/kadmind absents. | A |
| krb5 | [112321](https://security-tracker.debian.org/tracker/CVE-2026-112321) | Fuite serveur AUTH_GSSAPI sur erreurs ; composant GSS-RPC absent. | A |
| krb5 | [112322](https://security-tracker.debian.org/tracker/CVE-2026-112322) | Coût quadratique nettoyage clients GSS-RPC/kadmind ; composants absents. | A |
| krb5 | [112323](https://security-tracker.debian.org/tracker/CVE-2026-112323) | Accumulation d'états serveur AUTH_GSSAPI ; composants absents. | A |
| krb5 | [119079](https://security-tracker.debian.org/tracker/CVE-2026-119079) | Coût quadratique de décodage ASN.1, attaque publiée contre KDC ; KDC absent mais fonctions ASN.1 présentes dans bibliothèque cliente. Il manque une preuve complète des décodeurs accessibles depuis NLA/Kerberos. | I |
| krb5 | [107778](https://security-tracker.debian.org/tracker/CVE-2026-107778) | KRB-CRED incohérent dans `make_cred_list`, notamment acceptor GSS. Pas d'appel direct repéré, mais cela ne prouve pas l'absence d'appel indirect depuis WinPR/krb5. | I |
| cjson 1.7.18-3.1+deb13u1 | [67215](https://security-tracker.debian.org/tracker/CVE-2026-67215) | Amplification par JSON Patch Utils, épuisement de pile ; Utils présente. Aucun appel FreeRDP trouvé, chaîne exhaustive de consommateurs non établie. | I |
| cjson | [67216](https://security-tracker.debian.org/tracker/CVE-2026-67216) | Comparaison récursive exponentielle `cJSON_Compare` sur documents influencés ; aucun appel FreeRDP, autres consommateurs non prouvés. | I |
| cjson | [29036](https://security-tracker.debian.org/tracker/CVE-2026-29036) | Résolution incorrecte JSON Pointer dans Utils ; bibliothèque présente, chaîne d'appels non entièrement prouvée. Le PATCH SCIM Python n'est pas un appel cJSONUtils. | I |
| cjson | [16554](https://security-tracker.debian.org/tracker/CVE-2026-16554) | Débordement `size_t`32bits d'impression de chaîne ; bibliothèque et cible amd64/ELF64. | A |
| perl 5.40.1-6+deb13u1 | [82560](https://security-tracker.debian.org/tracker/CVE-2026-82560) | Formatage POD dans Pod::Text<6.1.1 ; module absent du runtime perl-base. | A |
| perl | [9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | Taille TAR non bornée dans Archive::Tar<3.10 ; module absent. Cela ne concerne pas automatiquement tarfile Python. | A |
| expat 2.9.0-1~deb13u1 | [113351](https://security-tracker.debian.org/tracker/CVE-2026-113351) | Compteurs de mémoire lors de XML_ParserReset ; bibliothèque vulnérable présente. Aucun endpoint XML produit trouvé, mais consommateurs natifs/configuration non entièrement retracés. | I |
| expat | [115506](https://security-tracker.debian.org/tracker/CVE-2026-115506) | Détection tardive d'amplification d'entités/DTD ; pas d'exemption de version. Déterminer tous les consommateurs et leurs limites. | I |
| expat | [117610](https://security-tracker.debian.org/tracker/CVE-2026-117610) | Sous-parser d'entité externe, premier chunk vide non final ; absence de ce chemin non démontrée. | I |
| expat | [118370](https://security-tracker.debian.org/tracker/CVE-2026-118370) | Très grand nombre d'attributs provoquant écriture hors limites. Plafonds mémoire réduisent l'exposition, sans prouver absence d'overflow pour tous appels. | I |
| ncurses 6.5+20250216-2 | [2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | Débordement outil infocmp/analyze_string. Outil présent ; aucun appel produit trouvé. Interdire l'exécution de cet outil sur entrée non fiable dans le profil. | R |
| gcc-14 14.2.0-19 | [95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | Allocation C++ aligned new avec taille excessive ; bibliothèques C++ transitives présentes. Graphe complet des appelants et tailles non établi. | I |
| gcc-14 | [102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | `erase_if` de priority_queue binaire libstdc++ ; peut être instancié dans des consommateurs compilés. Remplacer uniquement libstdc++.so ne suffit pas forcément à corriger un template déjà compilé. | I |
| cyrus-sasl2 2.1.28+dfsg1-9 | [107161](https://security-tracker.debian.org/tracker/CVE-2026-107161) | Plugin DIGEST-MD5/add_to_challenge ; plugin absent, LDAP simple bind StartTLS. Réévaluation obligatoire avant tout ajout de plugin/mécanisme. | A |
| glibc 2.41-12+deb13u4 | [19499](https://security-tracker.debian.org/tracker/CVE-2026-19499) | Format monétaire strfmon avec padding vulnérable. Aucun appel produit direct ; possibles consommateurs natifs non entièrement exclus. | I |
| glibc | [84243](https://security-tracker.debian.org/tracker/CVE-2026-84243) | LANGUAGE contrôlé + locale non-C + catalogue .mo inscriptible/accessible. Environnement moteur fixé C.UTF-8 ; environnement Web hérité reste une condition opérateur à contrôler. | R |
| glibc | [5435](https://security-tracker.debian.org/tracker/CVE-2026-5435) | Impression DNS TSIG via fonctions dépréciées ns_printrr/fp_nquery. Résolution DNS normale n'est pas cette fonction ; fermeture du graphe d'appels native encore nécessaire. | I |
| sqlite3 3.46.1-7+deb13u2 | [119379](https://security-tracker.debian.org/tracker/CVE-2026-119379) | Session extension/changeset contrôlé ; extension non prouvée absente, chaîne ENABLE_SESSION présente. Serveur PostgreSQL requis mais bibliothèque reste chargeable. | R |
| sqlite3 | [119374](https://security-tracker.debian.org/tracker/CVE-2026-119374) | Index FTS5 corrompu + secure-delete ; FTS5 présent. Interdire bases fournies par l'utilisateur et activation SQLite serveur ; ne pas affirmer build non affecté. | R |
| sqlite3 | [119373](https://security-tracker.debian.org/tracker/CVE-2026-119373) | FTS5 detail=none/prefix MATCH avec rowids négatifs ; SQL/base sous contrôle requis, non utilisé par le serveur PostgreSQL. | R |
| libxrender 1:0.9.12-1 | [88807](https://security-tracker.debian.org/tracker/CVE-2026-88807) | Réponse de serveur X malveillant dans RenderQueryPictFormats. FreeRDP X11 désactivé et aucun DISPLAY moteur ; bibliothèques transitives présentes. Ne pas monter socket X ou injecter DISPLAY. | R |
| util-linux 2.41.5-0+deb13u1 | [78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | Opérateur privilégié exécutant nsenter --join-cgroup sur cible attaquant ; outil présent mais pas d'appel runtime ni SYS_ADMIN/host cgroup dans le profil. | R |
| util-linux | [76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | Helper mount échoue puis hooks privilégiés X-mount ; pas de permission de montage dans le profil, paquet affecté présent. | R |
| util-linux | [78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | Montage bind SUID autorisé par fstab avec source modifiable et changements de propriétaire ; no-new-privileges/capabilities insuffisantes au montage dans profil. | R |
| util-linux | [78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | X-mount.subdir, noyau récent et fstab autorisant ce montage. Ne pas déclarer non affecté sur numéro2.41 : Debian classe sa révision vulnérable. | R |
| libx11 2:1.8.12-1 | [88806](https://security-tracker.debian.org/tracker/CVE-2026-88806) | Serveur X malveillant lors de XkbGetMap ; aucune session X nécessaire au moteur, mais libX11 conservée. | R |
| acl 2.3.2-2+b1 | [54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | Fonction libacl par chemin sur composant contrôlé ; libacl présente, absence d'appel privilégié sur chemin d'utilisateur non entièrement démontrée. | I |
| acl | [54370](https://security-tracker.debian.org/tracker/CVE-2026-54370) | Outils récursifs ACL avec course de symlink ; getfacl/setfacl/chacl absents des layers observés. Ne couvre pas54369, qui vise l'API de bibliothèque. | A |

## Remédiations minimales recommandées

La voie normale reste bloquée par les I et R ouverts. Aucun de ces états n'autorise un système privilégié réel. Les A doivent encore être revus et transformés, si approuvés, en décisions à portée exacte et expiration ; une mise à jour de dépendance ou de profil les invalide.

1. **Fermer les graphes natifs ciblés**, pas seulement rechercher le nom de CVE. Examiner les imports ELF et sources des consommateurs cJSON Utils/Compare, Kerberos ASN.1/forwarded credentials, libc strfmon/TSIG, libacl et C++ ; conserver les versions/options et hashes de chaque consommateur. Un test d'exécution réussi n'est pas cette preuve.
2. **Expat** : qualifier un backport trixie revu ou une version2.10 corrigée et ses consommateurs, notamment Fontconfig/Pango, plutôt qu'utiliser aveuglément sid. Les avis Debian référencent les correctifs amont1431/1433/1444/1450. Distinguer la bibliothèque Debian de l'Expat éventuellement intégré à Python ; mettre à jour l'une ne remplace pas automatiquement l'autre.
3. **Kerberos** : les correctifs amont sont disponibles dans la branche1.22.3 selon l'annonce du mainteneur, mais la distribution trixie n'est pas corrigée dans le rapport. Si les chemins clients sont démontrés atteignables, qualifier un backport ABI-compatible et rejouer NLA réel. Ne pas désactiver silencieusement Kerberos/NLA pour faire disparaître un match.
4. **Réduction ciblée de surface** : retirer proprement les exécutables facultatifs de maintenance uniquement si leurs dépendances ne sont pas nécessaires ; conserver la vérité de dpkg/SBOM et rescanner. Une suppression physique de l'outil vulnérable avec preuve peut traiter une CVE CLI ; supprimer son enregistrement dpkg sans supprimer le code est interdit.
5. **Profil R** : Docker sans privilèges additionnels, socket Docker/host cgroup/X11 non montés, pas d'environnement LANGUAGE/DISPLAY non maîtrisé, rootfs en lecture seule, PostgreSQL requis, aucune base/SQL/POD/TAR arbitraire traité par des outils système. Ces conditions doivent être contrôlées automatiquement au lancement. Elles ne suffisent pas à autoriser les cas I.
6. **GCC/templates et ACL** : évaluer les correctifs amont avant d'importer une nouvelle ABI. Le [correctif aligned new GCC14](https://github.com/gcc-mirror/gcc/commit/200183d4ab5d57575f3dfebc6af3baf649910b9e) est distinct d'une recompilation des consommateurs template ; ACL2.4 ajoute une API qui requiert une qualification des outils appelants. La présence de versions fixes en sid n'autorise aucun mélange automatique de distributions.

Une décision de laboratoire éventuelle doit citer chaque couple, le nouveau digest, les contraintes enforceables, un responsable, une échéance de réexamen et la revue contradictoire. Pas d'allowlist globale de source, de distribution, d'état `wont-fix`, ni de filtre `only-fixed`. Le gate doit échouer si une CVE nouvelle apparaît, si un paquet/version/preuve change, ou si une justification expire. Les102 multiplicités brutes restent disponibles même lorsque plusieurs binaires héritent d'une seule CVE source.

## Limites de cette revue

Analyse statique et documentaire, pas de nouvelle exploitation ni scan exécuté par cet agent. La lecture d'archive/source ne démontre pas les conditions d'une future instance. Les limites ci-dessus sont intentionnellement bloquantes ; ce document ne constitue pas un VEX global «not affected». Aucun fichier de production, donnée privée ou preuve historique n'a été modifié.

## Approfondissement des 14 I — graphe complet, sans exécution

Preuves complémentaires privées, hors dépôt :

- `output/triage_os_elf_graph.py` reconstruit les entrées des layers et leurs whiteouts sans extraction. Il lit les tables ELF64 dynamiques de **844 fichiers ELF**, conserve hashes, imports/exports, DT_NEEDED, SONAME et alias. `output/p1-f-os-elf-graph.json` porte le hash d'archive bf5d… ci-dessus. Ce n'est ni un scan de dix seuls ELF maison, ni l'exécution de `ldd` sur un binaire non fiable.
- `output/p1-f-os-source-call-review.json` recense les recherches et hashes de **1 774 fichiers C/C++/headers FreeRDP** et **502 fichiers Guacamole**, sources identifiées plus haut. Aucun appel ou nom de résolution dynamique de Compare/Utils, strfmon/TSIG, libacl ou `krb5_rd_cred` n'est trouvé dans ces sources. Le seul appel Kerberos retenu est `krb5_rd_req` dans `kerberos.c:1723`.
- `var/lib/dpkg/status` de l'archive confirme Fontconfig2.15.0-2.3, ICU76.1-4 et HarfBuzz10.2.0-1+deb13u1. Les sources [Fontconfig2.15.0 fcxml](https://raw.githubusercontent.com/fontconfig/fontconfig/2.15.0/src/fcxml.c), [initialisation](https://raw.githubusercontent.com/fontconfig/fontconfig/2.15.0/src/fcinit.c) et [configuration](https://raw.githubusercontent.com/fontconfig/fontconfig/2.15.0/src/fccfg.c) sont consultées comme sources amont, pas comme preuve d'absence de tout patch Debian.

### Cinq propositions de fermeture précises, à relire indépendamment

Ces propositions renforcent la matrice initiale ; elles ne modifient aucune exemption CI. La revue doit accepter chaque décision et vérifier à nouveau son digest avant d'abaisser un I dans le gate.

| CVE | Preuve supplémentaire | Fermeture proposée et condition |
| --- | --- | --- |
| cjson67215 | Aucun ELF n'a de DT_NEEDED sur libcjson_utils ; aucun import cJSONUtils ; aucune résolution de ces noms dans FreeRDP/Guac. La bibliothèque vulnérable est physiquement présente mais n'est pas chargée par le parcours. | Fonction non invoquée dans le profil applicatif vérifié ; ne pas transformer cela en version corrigée. Tout nouveau plugin/code ou appel ctypes l'invalide. |
| cjson29036 | Même fermeture du chargement Utils ; les opérations PATCH SCIM restent des objets Python, distincts de cJSONUtils. | Même justification individuelle, même invalidation. |
| cjson67216 | Aucun import cJSON_Compare dans844ELF ; WinPR importe Parse/Print et accès d'objets, sans Compare ; aucun appel interne dans les sources propres FreeRDP/Guac. | Fonction non invoquée par les consommateurs identifiés ; révoquer à tout changement de dépendance/canal JSON natif. |
| expat113351 | Seul consommateur dynamique de la libexpat Debian : libfontconfig ; aucun import XML_ParserReset dans844ELF. Fontconfig crée/libère son parser sans reset. | Le prérequis reset n'est pas satisfait dans les consommateurs identifiés ; garder distinct de l'Expat statique intégré à Python. |
| expat117610 | Aucun import XML_ExternalEntityParserCreate, XML_SetExternalEntityRefHandler ou XML_SetParamEntityParsing. Fontconfig ne crée pas de sous-parser d'entité externe. | Le chemin de sous-parser externe nécessaire n'est pas invoqué par le consommateur identifié. Ne couvre pas les autres CVE Expat. |

Le chargement dynamique a été examiné explicitement : guacd compose `libguac-client-<protocol>` et résout `guac_client_init` ; `pam/native.py` sélectionne le protocole de l'endpoint, limité à SSH/RDP par le service/modèle, sans instruction connect/select libre venant du navigateur. Les préfixes et bibliothèques restent contrôlés par l'inventaire natif ; le profil ne monte aucun plugin externe. WinPR résout notamment des fonctions de plateforme/Kerberos, pas Compare/Utils. La présence de `dlopen` dans Python/ctypes, SASL, ICU, OpenSSL et GLib interdit néanmoins une déclaration générale «aucun chargement dynamique» : la fermeture suppose le code et les plugins approuvés, non une faculté d'exécuter du code Python/C arbitraire.

### Six propositions de réduction à un profil R, sans déclarer une correction

- **Expat115506 et118370** : la chaîne concrète est guacd→Pango/Cairo→Fontconfig→XML de configuration locale, pas un endpoint XML réseau. Les sources Fontconfig lisent également des inclusions sous HOME/XDG. Le moteur reçoit un HOME neuf mode0700, pas celui de l'opérateur, et les configurations système résident dans le rootfs readonly ; aucun FONTCONFIG_FILE/PATH/XDG non maîtrisé n'est transmis au moteur. Sous ces conditions vérifiées au lancement, la donnée distante affichée par RDP/SSH ne devient pas un fichier de configuration XML. Des limites mémoire seules ne justifient pas cette conclusion. Une configuration Fontconfig montée writable ou un canal de dépôt de fichier vers le HOME moteur invalide la restriction.
- **glibc19499** : aucun import strfmon/strfmon_l dans844ELF ni appel dans les sources propres. Ne pas assimiler cela à une preuve de suppression de la fonction : elle est exportée par libc et peut être appelée par un futur consommateur ou par résolution dynamique. Le profil n'accepte ni extension native supplémentaire ni format monétaire traité par ces APIs.
- **glibc5435** : vérification aussi des noms effectivement exportés par libresolv `ns_sprintrr`, `ns_sprintrrf`, `__fp_nquery` : aucun import. Les appels `res_nquery` de Gio/APT sont des requêtes DNS, pas l'impression de TSIG vulnérable. Restriction au graphe actuel, sans outil de diagnostic DNS ajouté.
- **acl54369** : les consommateurs ELF sont précisément cp/install/mv/sed/tar, avec acl_get_file/acl_set_file/delete_def_file. Aucun import dans les moteurs natifs, Python ou extensions produit. Le serveur ne doit pas lancer ces outils comme opérateur privilégié sur des chemins fournis par un utilisateur ; les chemins de capture/restauration restent traités par les contrôles existants. Cela demeure une restriction de workflow, pas une bibliothèque corrigée.
- **krb5107778** : la copie système et la copie embarquée de libgssapi importent réellement krb5_rd_cred. La [source MIT accept_sec_context](https://raw.githubusercontent.com/krb5/krb5/krb5-1.22.3-final/src/lib/gssapi/krb5/accept_sec_context.c) situe son usage dans la réception de credentials délégués. Aucun ELF consommateur n'importe gss_accept_sec_context ; le client libpq embarqué importe gss_init_sec_context et son [implémentation amont](https://raw.githubusercontent.com/postgres/postgres/REL_17_STABLE/src/interfaces/libpq/fe-secure-gssapi.c) est initiateur. LDAP utilise simple bind ; aucun serveur GSS/KDC n'est lancé. Rester limité aux rôles clients actuels et interdire plugin acceptor supplémentaire. Une API vulnérable présente n'est pas un défaut affectant automatiquement l'initiateur, mais le graphe statique ne suffit pas à la déclarer supprimée.

### Trois I qui restent bloquants après cet approfondissement

1. **krb5119079** : le décodeur ASN.1 est partagé. Les [tables ASN.1 MIT](https://raw.githubusercontent.com/krb5/krb5/krb5-1.22.3-final/src/lib/krb5/asn.1/asn1_k_encode.c) utilisent des SEQUENCE OF aussi dans des structures traitées par les clients ; [asn1_encode.c](https://raw.githubusercontent.com/krb5/krb5/krb5-1.22.3-final/src/lib/krb5/asn.1/asn1_encode.c) contient la croissance et son correctif. L'absence de krb5kdc ne ferme donc pas le risque d'un KDC/peer malveillant ou d'une réponse modifiée. Une borne exacte de taille/coût côté tous les appelants ou un backport du correctif reste nécessaire ; aucun contournement par désactivation silencieuse de NLA/Kerberos.
2. **gcc95619** : aucun import d'operator new aligné n'est observé, mais des bibliothèques C++ exportent et peuvent appeler des méthodes à l'intérieur du même DSO. L'analyse dynsym ne reconstitue pas ces appels internes. Le correctif amont GCC14 cité plus haut est une piste ABI-compatible à qualifier, sans remplacer aveuglément toute la chaîne par sid.
3. **gcc102010** : le [correctif GCC](https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6) concerne le code de conteneur compilé ; l'absence d'un symbole erase_if après stripping/inlining n'en prouve pas l'absence. Il reste à confronter les sources et options exactes des consommateurs C++ (ICU et outils APT notamment), puis recompiler ceux utilisant le template affecté ou prouver leur absence. FreeRDP/Guac C ne sont pas une preuve pour les dépendances transitives.

Ces trois I ne deviennent pas acceptables parce que cinq autres chemins sont fermables. Aucun I global n'est accepté ; les propositions doivent être revues individuellement. La matrice initiale reste la trace de l'état avant approfondissement. Si les propositions ci-dessus sont acceptées après revue, le décompte deviendrait15 A,17 R,3 I, toujours102 matches bruts et sans autorisation normale de promotion tant que les I persistent.

### Couverture nouvelle à ne pas manquer : bibliothèques embarquées par psycopg

Le parcours de tous les ELF révèle `site-packages/psycopg_binary.libs` contenant **ses propres libpq, libkrb5, libgssapi, libk5crypto, libldap, libsasl, OpenSSL et autres dépendances**, aux noms avec hashes. Ces fichiers ne sont pas remplacés par apt et leurs versions exactes ne peuvent être déduites des versions Debian du tableau. Le SBOM natif initial des10ELF propres ne suffit pas à les qualifier ; le scan PyPI du nom psycopg-binary ne démontre pas l'absence de CVE de leurs composants C.

Le gate doit les inventorier avec hashes/version/origine de wheel et advisories amont, ou qualifier une stratégie de compilation psycopg contre un ensemble système maintenu. Ce dernier choix est une remédiation distincte qui nécessite lock, build et PostgreSQL/TLS/SCRAM/GSS tests ; aucun changement de dépendance n'est effectué ici. Les copies embarquées de GSSAPI importent effectivement krb5_rd_cred : il serait faux de prétendre la copie système seule dans l'image.

## Décision ciblée pour les trois I — préparation N0, sans patch appliqué

Ce complément propose deux justifications supplémentaires de non-affectation et **une remédiation nécessaire**. Il ne modifie aucun gate, binaire ou dépendance. Les états antérieurs restent la chronologie des incertitudes ; une décision individuelle de revue doit encore valider chaque fermeture et son rattachement au digest final.

### GCC CVE-2026-95619 : branche POSIX réellement compilée

Le [correctif officiel GCC14 200183d4ab5d57575f3dfebc6af3baf649910b9e](https://github.com/gcc-mirror/gcc/commit/200183d4ab5d57575f3dfebc6af3baf649910b9e.patch), backport de59d235f…, distingue les implémentations : le problème d'arrondi taille/alignement concerne aligned_alloc, le fallback malloc et certains environnements Wine ; l'implémentation posix_memalign n'effectue pas l'arrondi vulnérable.

Les octets du **vrai** `libstdc++.so.6.0.33` de l'archive GDI ont été désassemblés hors ligne. SHA-256 `972bb2a18b71140dab0240f8a1f68ab3fb1d56bcd4c4f824a91b70888faf5a00`. Le symbole `_ZnwmSt11align_val_t` commence à0xb3c20, taille125octets. L'appel à0xb3c81 est résolu par la relocation GOT/PLT à **posix_memalign** ; le registre taille transmis conserve la taille demandée, sans arrondi additionnel susceptible de wraparound. Le corps complet et les octets sont conservés dans `output/p1-f-gcc-aligned-new-disassembly.json`.

Outil d'analyse : Capstone5.0.9, wheel Windowsamd64 obtenu via les métadonnées officielles PyPI et vérifié SHA-256 `732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0`, identité dans `output/p1-f-os-disassembler-tool.json`. L'outil ne charge ni n'exécute le code Linux ; aucun runtime/container n'est démarré. Le programme d'analyse est `output/triage_gcc_binary.py`.

**Décision proposée : A, build non affecté sur ce binaire amd64 exact**, fondée sur l'implémentation et l'avis du mainteneur, indépendamment de l'absence de calls dans les consommateurs. La justification expire si le hash/libstdc++/architecture change. Aucune montée de version GCC ni bibliothèque sid n'est nécessaire pour ce cas. Si la branche compilée d'un futur binaire diffère, le correctif GCC14 ci-dessus doit être qualifié, avec comparaison des symboles/versions ABI et tests upstream d'overflow d'alignement.

### GCC CVE-2026-102010 : type GNU précis, sources des consommateurs et toolchain

Le [correctif officiel aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6](https://github.com/gcc-mirror/gcc/commit/aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6.patch) vise `__gnu_pbds::priority_queue<…, __gnu_pbds::binary_heap_tag>::erase_if` dans `ext/pb_ds/detail/binary_heap_/erase_fn_imps.hpp`. Il réaffecte le pointeur `m_a_entries` après réallocation. Cela ne vise ni tous les tas binaires, ni `std::priority_queue` en général. Le test inclus comporte une coquille d'identifiant dans son commentaire ; le sujet du commit et le suivi Debian identifient bien102010.

Le graphe complet identifie les consommateurs dynamiques libstdc++ parmi les programmes/bibliothèques APT et ICU. HarfBuzz, qui implémente du C++ avec ABI C et sans dépendance libstdc++ directe, a aussi été examiné pour éviter un faux négatif fondé sur les imports.

Archives sources **et patches Debian** téléchargés depuis les pools Debian, hashes comparés aux `.dsc` exacts :

| Consommateur | Version source | Fichiers réguliers examinés (<10MiB chacun) | Type utilisé |
| --- | --- | ---: | --- |
| ICU |76.1-4 |2 497 amont +28 Debian | Aucune référence pb_ds, __gnu_pbds, binary_heap_tag, priority_queue ou erase_if |
| APT |3.0.4 |875, paquet source natif Debian | `solver3.h` utilise vector +std::make_heap/push_heap/pop_heap, explicitement distinct de priority_queue ; aucun pb_ds/erase_if |
| HarfBuzz |10.2.0-1+deb13u1 |3 682 amont +30 Debian | `hb_priority_queue_t`, implémentation propre dans hb-priority-queue.hh, stockée dans hb_vector_t ; pas de conteneur GNU PBDS ni erase_if |

La seconde passe a examiné aussi les fichiers `.hh`, templates et règles/patches, pas seulement C/C++ et `.h`. Résultats et hashes dans `output/p1-f-pbds-source-review.json`. Une recherche du simple symbole dynamique erase_if n'a pas servi de preuve d'absence de template.

Les [buildinfo ICU](https://buildinfos.debian.net/buildinfo-pool/i/icu/icu_76.1-4_amd64.buildinfo), [APT](https://buildinfos.debian.net/buildinfo-pool/a/apt/apt_3.0.4_amd64.buildinfo) et [HarfBuzz](https://buildinfos.debian.net/buildinfo-pool/h/harfbuzz/harfbuzz_10.2.0-1+deb13u1_amd64.buildinfo) déclarent tous GCC/G++14.2.0-19. Les sections `.comment` des ELF installés sont vides : la version du compilateur n'est donc pas inventée à partir du numéro de libstdc++. Les `.deb` correspondants ont été obtenus depuis Debian, leurs SHA-256 comparés aux buildinfo, puis **27 ELF** extraits en mémoire ont été comparés par SHA-256 aux octets exacts du runtime (6 ICU,20 APT,1 HarfBuzz). Preuve : `output/p1-f-cxx-buildinfo-package-binding.json`.

Limite de provenance explicite : les signatures OpenPGP de ces documents n'ont pas été revérifiées par cet agent. Le contrôle démontre la cohérence de documents HTTPS, archives officielles et binaires, pas une preuve cryptographique autonome du compilateur réellement exécuté ni un rebuild reproductible indépendant. La chaîne APT/build CI et sa vérification de signatures restent nécessaires à la décision finale.

**Décision proposée : A, type vulnérable non utilisé par les consommateurs identifiés de cet ensemble exact**, sous revue de la couverture source et de la provenance. Si un consommateur supplémentaire instancie le type, backporter l'unique affectation amont dans les headers GCC14 de son builder et **recompiler ce consommateur** ; remplacer seulement libstdc++.so ne corrige pas un template déjà instancié. Le test upstream erase_if sous sanitizers constitue alors une porte dédiée. Aucun changement ABI public n'est introduit par cette affectation, mais la compatibilité du binaire reconstruit reste à qualifier.

### Kerberos CVE-2026-119079 : correction maintenue minimale sur trixie

Le [commit MIT de la branche1.22.3 205832663330da308d9d031a17326b68a16715fd](https://github.com/krb5/krb5/commit/205832663330da308d9d031a17326b68a16715fd.patch), cherry-pick du commit principal782e5ac4fb1496a79de0b87e1fc485f897e97d6d, corrige le décodage en deux passes : compter/vérifier les éléments, allouer une seule fois, puis décoder. SHA-256 des octets du patch `e676f3727b3c984aa5a7baaafdb39394c8774c913ace0c3ce302e9b81aaa19ee`. La fonction concernée est interne et le défaut existe depuis MIT1.11. La note amont vise aussi des serveurs applicatifs, pas uniquement le KDC ; la fonction générique traite les structures de clients comme de serveurs.

La source **Debian security1.21.3-5+deb13u1**, correspondant aux bibliothèques installées, a été récupérée via son [dsc](https://security.debian.org/debian-security/pool/updates/main/k/krb5/krb5_1.21.3-5+deb13u1.dsc) :

- Archive amont SHA-256 `b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35`.
- Archive Debian SHA-256 `02b873b239fbe7ddf016dfe44deba4130673f4606c18c93da0622e2bc8500fb4`.
- Le bloc ancien du hunk du correctif correspond **exactement une fois**, sans fuzz, à la fonction dans la source1.21.3 ; aucun patch Debian inclus ne touche ce fichier.
- Le helper k5calloc utilisé par le correctif existe déjà dans k5-int.h ; asn1_encode.h l'inclut déjà. Aucun ajout d'API publique nécessaire.

Ces contrôles sont de la lecture/comparaison en mémoire : aucun patch n'a été appliqué. Preuve `output/p1-f-krb5-backport-feasibility.json`. Le patch modifie une seule fonction `static` de src/lib/krb5/asn.1/asn1_encode.c, sans changer signature publique ni SONAME. **Un backport ABI-compatible sur trixie est donc la remédiation minimale recommandée**, à démontrer par build/tests ; une migration complète vers1.22.3 ou sid n'est pas nécessaire.

Plan exécutable proposé au propriétaire du packaging, uniquement dans son builder N0 isolé :

1. Épingler les archives Debian et le patch aux hashes ci-dessus ; vérifier leur provenance/signature dans la chaîne de construction. Conserver la série Debian et ajouter ce patch amont avec application sans fuzz. Nommer la révision locale explicitement, par exemple1.21.3-5+deb13u1+pamolive1, sans la faire passer pour un paquet corrigé publié par Debian.
2. Reconstruire les paquets de bibliothèques avec les options Debian actuelles. Ne copier dans le runtime que les bibliothèques déjà nécessaires à ses clients, sans ajouter KDC, kadmind ou service supplémentaire. Comparer SONAME, symboles exportés et versions de symboles avec le témoin ; aucune API ne doit disparaître.
3. Exécuter les tests ASN.1 amont, séquences longues valides et malformées avec bornes de temps/mémoire dans le laboratoire, puis requalifier les échanges clients AS/TGS, NLA RDP et PostgreSQL/GSS si utilisé. Rejouer PostgreSQL TLS/CA/hostname/SCRAM, driver système, P0 et transports synthétiques. Aucun annuaire/KDC réel ni charge sur un NAS.
4. Inventorier hashes/options/patch appliqué/versions réellement chargées dans l'image finale. Le remplacement psycopg-binary par psycopg-c doit aussi être prouvé, pour éviter qu'une ancienne copie Kerberos de wheel subsiste. Le simple changement d'un paquet Debian n'y suffit pas.
5. Rescanner l'archive finale complète. Le scanner peut continuer à signaler la plage Debian non corrigée : conserver le match et lier **cette CVE précise** au backport et aux tests/digest, selon une décision revue/expirante. Ne falsifier ni version, ni SBOM, ni résultat brut et ne rendre aucune exemption globale pour krb5.

Cette préparation ne démontre pas la réussite de ces cinq portes : le build, la comparaison ABI et les tests restent à exécuter par leurs propriétaires. **119079 reste I/bloquant tant que la remédiation n'est pas appliquée et validée.** Après acceptation indépendante des deux justifications GCC et des propositions précédentes, la matrice projetée serait17 A,17 R,1 I. Aucun reclassement implicite n'est effectué par ce document.

### Portée de la livraison de développement

Une livraison de développement synthétique peut distinguer les risques R de l'usage privilégié réel, mais ne doit pas convertir un I en acceptation collective. Chaque R doit imposer son profil : aucun plugin/type/API nouveau, pas de fichiers de configuration Fontconfig ou catalogue gettext inscriptibles par la source distante, aucune session X, montage/namespace privilégié, SQL/base SQLite fournie par l'utilisateur ou outil ACL/infocmp sur entrée non fiable. Ces restrictions doivent être contrôlées au lancement et réévaluées avec chaque digest. Un conteneur «local» seul n'est pas une mesure suffisante.
