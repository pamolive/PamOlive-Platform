# P1-F — qualification de sécurité de l’image

Statut : **scan OS et bibliothèques du candidat initial terminé, seuil High/Critical non satisfait ; remédiation et scan final en attente**. Le candidat actuel ne reçoit pas de validation de sécurité pour une publication utilisable avec PAM/RDP. Les correspondances ci-dessous nécessitent correction ou analyse d’applicabilité explicite. Cette revue ne modifie ni Dockerfile, dépendances, workflow, NAS ou installation existante.

## Candidat identifié

Le candidat est un snapshot contrôlé du working tree, pas une image publiée de main :

| Élément | Identité vérifiée |
| --- | --- |
| Archive locale | `p1-f-production-qualification.tar`, 149 893 632 octets |
| SHA-256 de l’archive | `21803b525a4f953217f304e9f8f6a7bd0c82a865b80f959783a2328f8e29019d` |
| Digest des octets de configuration | `sha256:2f1543e2ef134aa2cb4e021180164d7f1be2cc5fc41755264ad9987ef1bb20ee` |
| Manifeste signalé par le build local | `sha256:fe47d3627fae069b231a0c831e84559a240e49e1e329f3a05a145c23259e9c3b` |
| Plateforme | `linux/amd64` |

Le hash d’archive et le digest de configuration ont été recalculés indépendamment depuis les fichiers. Le manifeste et l’identifiant retourné par Docker 29 ne doivent pas être confondus avec le digest des octets de configuration. Une nouvelle construction ou une image CI différente exige son propre rattachement aux preuves.

## Outil et données

Grype **0.121.3**, release officielle immutable publiée le 9 novembre 2026, a été choisi après consultation des [releases Anchore](https://github.com/anchore/grype/releases/tag/v0.121.3) et de la [procédure officielle de vérification](https://oss.anchore.com/docs/installation/verification/).

Archives officielles téléchargées par HTTPS vérifié, avec digest comparé à l’API de release et au fichier de checksums :

- Windows amd64 : `3007a5afea25c60030a49d6c24d4e5abb6c94c0dbeed7ea303eb26df8e900c18`.
- Linux amd64 : `e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85`.
- Fichier de checksums : `1f8cea030e00f362d6b0bb0d1843b123af1d6baad70975dff1cf6fe14096866f`.

Le bundle de signature du fichier de checksums est conservé ; sa vérification cryptographique n’a pas été exécutée dans cette étape. Le contrôle réalisé porte sur l’identité des artefacts servis par les endpoints officiels, pas sur une attestation indépendante de la construction du scanner.

La [base publique Grype](https://oss.anchore.com/docs/guides/vulnerability/database/) a été obtenue séparément par HTTPS, sans credential utilisateur : schéma `v6.1.10`, build du 11 novembre 2026 à 06:21:32 UTC, archive de 200 236 695 octets, SHA-256 `47f709e0217cf091eaf8dc57c8cdea33f9ba2c7d5374237c5011871a0c99d24e`. Son checksum a été vérifié. Les contrôles d’âge et d’intégrité ne sont pas désactivés.

## Exécution et limites observées

Le téléchargement automatique de la base par le CLI Windows a dépassé la borne de 240 secondes. L’import local séparé n’a pas abouti dans le créneau de ressources ; son seul processus a été identifié par son exécutable et sa ligne de commande, puis arrêté pour laisser la priorité aux qualifications applicatives. Les caches partielles sont conservées et ne sont pas considérées comme des bases valides. Aucun verdict de scan n’en découle.

L’outil Linux a ensuite analysé l’archive locale en [mode archive officiel](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/), sans socket Docker, sans réseau et sans démarrage de l’application. Aucun contenu de l’image n’est envoyé à un service. Le pull de l’exécuteur Python officiel épinglé a échoué par résolution DNS DockerHub ; le repli explicitement autorisé utilise le candidat comme système de fichiers d’exécution, avec **ELF Grype statique vérifié comme entrée directe**, sans shell, `LD_PRELOAD` et `LD_LIBRARY_PATH` vidés. Cette dépendance à l’image cible comme exécuteur est une limite d’indépendance ; le scanner lui-même ne provient pas de cette image.

Le conteneur est non privilégié, sans capacités, `no-new-privileges`, rootfs en lecture seule, réseau `none`, CPU 1, mémoire et swap 256 MiB, `GOMEMLIMIT=192MiB`. Seuls l’ELF, la configuration et l’archive sont montés en lecture seule ; une nouvelle cache dédiée contient la base et le rapport. Aucun service existant n’est arrêté. L’import de base a abouti en 264,343 s, sans OOM. Son healthcheck hérité avait effectué des sondes localhost ; le scan final désactive explicitement ce healthcheck. Aucune sonde externe ni application PamOlive n’a démarré.

Premier scan Linux : échec Go `newosproc` à la limite de 32 tâches, rapport vide ; **son code 2 ne constitue pas un verdict CVE**. Second scan : limite de tâches portée à 128, mêmes plafonds mémoire/CPU, **terminé en 54,391 s, sans OOM**, JSON complet et base validée. Son code 2 correspond cette fois au seuil `--fail-on high` dépassé.

Commande effective : `grype -c /grype.json --from docker-archive /image.tar --scope squashed --fail-on high -o json --file /scan/image-report2.json`. Toutes les sévérités et tous les états de correction sont conservés. Aucune règle utilisateur d’ignorance, exclusion ou VEX. Grype ajoutait cependant quatre règles internes pour les kernel headers ; aucun `ignoredMatches` n’était rapporté sur ces témoins. Le mode initial ne rendait pas toutes les suppressions internes visibles : le mode strict décrit ci-dessous corrige cette limite. Enrichissement externe et mise à jour automatique désactivés, contrôles d’âge et de hash de base actifs, conformément aux [options Grype](https://oss.anchore.com/docs/reference/grype/configuration/).

## Couverture requise

Le rapport doit distinguer paquets Debian, bibliothèques LDAP/SASL/TLS et Python réellement présents dans le runtime. Les findings doivent conserver identifiant, version installée, version corrigée éventuelle, statut fournisseur et correspondance précise de paquet. Une absence de fix n’est pas une absence de vulnérabilité ; un match de version n’est pas à lui seul une preuve d’exploitation.

Guacamole server est compilé depuis une archive Apache vérifiée et patchée ; il n’est pas nécessairement catalogué comme paquet Debian. La version source 1.6.0 et le patch doivent donc être recensés séparément. La [page de sécurité Apache](https://guacamole.apache.org/security/) indique que CVE-2024-35164 est corrigée en 1.6.0. Le build actuel désactive VNC, Telnet et plusieurs fonctions média ; cela ne permet pas d’ignorer globalement les vulnérabilités des bibliothèques présentes.

Cette qualification ne remplace ni les tests TLS/SSH/RDP ni une validation d’exposition ou d’exploitabilité. Elle ne qualifie pas un NAS, une architecture ARM, une nouvelle image reconstruite ou l’ensemble des vulnérabilités inconnues.

## Résultats exacts

Le rapport utilise Grype 0.121.3 et la base `v6.1.10` du 11 novembre 2026, déclarée valide. Il identifie Debian 13.6 (trixie).

| Mesure | Résultat |
| --- | ---: |
| Correspondances paquet/vulnérabilité | 1 326 |
| Identifiants de vulnérabilité distincts | 548 |
| Critical / High | 69 / 570 |
| Medium / Low | 450 / 59 |
| Negligible / Unknown | 138 / 40 |
| État `fixed` / `not-fixed` / `wont-fix` | 144 / 631 / 551 |
| Correspondances High/Critical avec fix annoncé | 74 |
| Correspondances Debian / binaire Python / paquet Python | 1 280 / 40 / 6 |
| Correspondances ignorées | 0 |

Ces chiffres ne sont pas autant d’exploitations distinctes. Plusieurs binaires Debian issus du même paquet source portent la même CVE. Par exemple, les trois bibliothèques FreeRDP/WinPR cumulent chacune 118 correspondances High/Critical. Les états Grype reflètent le suivi fournisseur ; `wont-fix` ou `no-dsa` ne signifient pas absence de risque. Le scan ne démontre pas l’accessibilité de chaque chemin vulnérable.

### Corrections prioritaires

1. **Interpréteur Python ancien.** L’image contient réellement Python **3.12.13**, indépendamment de la version du runner CI et des paquets PyPI verrouillés. Grype trouve 40 correspondances binaires, dont 2 Critical et 11 High. Python publie **3.12.16** comme release de sécurité et confirme notamment CVE-2026-115557 (défiance de clés intermédiaires eMudhra compromises), des mises à jour Expat et un correctif tarfile. Il faut actualiser le digest de base, reconstruire, tester et scanner cette nouvelle image ; `pip install` ne met pas à jour l’interpréteur. [Python 3.12.16](https://www.python.org/downloads/release/python-31216/).
2. **Bibliothèques RDP vulnérables, sans correction trixie disponible pour plusieurs problèmes.** FreeRDP **3.15.0+dfsg-2.1+deb13u3** reste explicitement vulnérable selon Debian. CVE-2026-45700 concerne une écriture hors limites dans le décodeur planar (fix amont 3.26.0). CVE-2026-121954 permet à un serveur RDP malveillant de corrompre le tas du client via ResetGraphics/GFX (fix amont 3.32.2). Le patch local interdisant la redirection ne corrige pas les codecs. Une mise à jour APT des paquets disponibles en trixie ne suffit donc pas. Il faut qualifier une version corrigée de FreeRDP et sa compatibilité guacd, ou conserver l’exécution RDP désactivée dans une livraison limitée et clairement documentée. Ne pas mélanger aveuglément des dépôts sid au runtime stable. [CVE-2026-45700](https://security-tracker.debian.org/tracker/CVE-2026-45700), [CVE-2026-121954](https://security-tracker.debian.org/tracker/CVE-2026-121954), [suivi FreeRDP Debian](https://security-tracker.debian.org/tracker/source-package/freerdp3).
3. **Paquets de base hérités à actualiser.** Le runtime conserve notamment glibc `2.41-12+deb13u3` et perl `5.40.1-6`, avec fixes disponibles. Debian confirme glibc CVE-2026-5450 corrigée en `2.41-12+deb13u4` et perl CVE-2026-8376 en `5.40.1-6+deb13u1`. Cette dernière décrit spécifiquement des builds Perl 32 bits ; la cible amd64 n’autorise pas à conclure automatiquement à son exploitabilité. Ces différences de contexte doivent rester dans le triage, sans effacer le finding brut. [glibc](https://security-tracker.debian.org/tracker/CVE-2026-5450), [Perl](https://security-tracker.debian.org/tracker/CVE-2026-8376).

Autres familles avec correctifs High/Critical annoncés par la base : apt `3.0.3→3.0.4`, gzip `1.13-1→1.13-1+deb13u1`, zlib `1:1.3.dfsg+really1.3.1-1+b1→1:1.3.dfsg+really1.3.1-1+deb13u1`, PCRE2 `10.46-1~deb13u1` vers les révisions corrigées u2/u3 selon CVE, SQLite `3.46.1-7+deb13u1→u2` et famille util-linux `2.41-5→2.41.5-0+deb13u1`. La liste exhaustive paquet/CVE/version/fix est conservée hors dépôt ; les versions doivent être vérifiées au moment de la reconstruction. Ne pas fabriquer une unique version minimale à partir d’un tri lexicographique des versions Debian.

### LDAP, SASL, TLS, paquets Python et guacd

Inventaire indépendant de `/var/lib/dpkg/status` dans l’archive : **213 paquets Debian installés**, dont :

| Composant | Version installée | Résultat et applicabilité |
| --- | --- | --- |
| OpenLDAP `libldap2` | `2.6.10+dfsg-1` | 5 correspondances Negligible, non corrigées dans la base ; ne signifie pas « sans vulnérabilité ». |
| Cyrus SASL `libsasl2-2`, `libsasl2-modules-db` | `2.1.28+dfsg1-9` | CVE-2026-107161 High, trixie vulnérable selon Debian. Le problème vise le plugin DIGEST-MD5 ; l’adaptateur utilise simple bind après StartTLS et le seul plugin observé dans l’archive est sasldb, pas DIGEST-MD5. Chemin annoncé non exercé par le collecteur actuel ; toute activation SASL exige réévaluation. |
| OpenSSL `libssl3t64` | `3.5.7-1~deb13u3` | 5 correspondances Unknown/non corrigées ; pas de classement arbitraire « sûr ». |
| FreeRDP/WinPR | `3.15.0+dfsg-2.1+deb13u3` | 18 Critical + 100 High par bibliothèque, corrections/triage nécessaires avant usage RDP. |
| `python-ldap` | `3.4.8` | Métadonnées de distribution présentes ; aucun finding Grype Python attribué à ce paquet. Les bibliothèques natives ci-dessus restent évaluées séparément. |
| `pip` | `25.0.1` | 6 correspondances, 5 Medium/1 Low, fixes annoncés jusqu’à 26.2.0 ; outil de build présent en runtime à actualiser ou retirer proprement. |
| guacd compilé | `1.6.0` + patch redirection | Inventorié séparément, pas de preuve de couverture intégrale du binaire compilé par le scanner. |

Debian confirme le défaut SASL dans DIGEST-MD5 et l’absence actuelle de correction trixie ; ce statut ne vaut pas exemption globale pour tous les usages de SASL. [CVE-2026-107161](https://security-tracker.debian.org/tracker/CVE-2026-107161).

Les bibliothèques ffmpeg `libavcodec61`, `libavutil59`, `libswresample5`, `libswscale8` sont également présentes et chacune porte 24 correspondances High/Critical. La désactivation de l’option ffmpeg au build guacd n’enlève pas automatiquement ces dépendances transitives. Réduire les dépendances et séparer le broker des services Django sont des mesures de réduction de surface à étudier avec les propriétaires du packaging, sans retirer un contrôle P0.

### Matrice High/Critical par paquet source

Comptage dédupliqué par `(paquet source, identifiant)` : **226 couples**, 24 familles. Les états sont ceux de Grype, pas une déclaration d’exploitabilité. Les identifiants et versions corrigées individuels restent dans `output/p1-f-image-hc-matrix.json` ; aucune correspondance n’est éliminée.

| Source | Critical / High uniques | États des couples | Exposition et préconditions à ce stade |
| --- | ---: | --- | --- |
| `acl` | 0 / 2 | wont-fix: 2 | Gestion ACL native ; nécessite une entrée/chemin déclenchant le défaut, accès applicatif non démontré. |
| `apt` | 0 / 1 | fixed: 1 | Gestionnaire de paquets conservé ; chaîne de mise à jour/installation concernée, pas une route HTTP. |
| `cups` | 0 / 2 | not-fixed: 1, wont-fix: 1 | Bibliothèque transitive ; aucune impression prévue par P1-F, appel vulnérable non démontré. |
| `cyrus-sasl2` | 0 / 1 | wont-fix: 1 | Serveur DIGEST-MD5 malveillant requis ; plugin DIGEST-MD5 absent, simple bind StartTLS utilisé. Réexaminer tout futur SASL. |
| `expat` | 0 / 4 | wont-fix: 2, not-fixed: 2 | Parsing XML natif ; vérifier tous les consommateurs et XML contrôlables, absence de chemin non démontrée. |
| `ffmpeg` | 1 / 23 | wont-fix: 24 | Bibliothèques transitives présentes malgré option guacd ffmpeg désactivée ; entrées média/codecs à inventorier. |
| `freerdp3` | 18 / 100 | wont-fix: 39, not-fixed: 79 | Serveur RDP compromis/malveillant et codecs/PDUs atteignables ; TLS pinning ne rend pas honnête un serveur autorisé. |
| `gcc-14` | 0 / 2 | wont-fix: 2 | Bibliothèques runtime GCC, pas preuve de compilateur installé ; préconditions propres à chaque CVE à analyser. |
| `glibc` | 1 / 4 | fixed: 2, wont-fix: 3 | Libc partagée de nombreux processus ; CVE5450 exige scanf %mc avec largeur>1024 ; chemin applicatif non démontré. |
| `gzip` | 0 / 1 | fixed: 1 | Traitement de flux compressé contrôlable ; restauration/outillage à examiner, pas exploitation démontrée. |
| `krb5` | 0 / 7 | not-fixed: 6, wont-fix: 1 | Usage des mécanismes Kerberos/SSP ; simple bind LDAP actuel n’utilise pas Kerberos, usages RDP à vérifier. |
| `libsndfile` | 0 / 2 | wont-fix: 2 | Parsing fichier audio ; chemin média effectif et options build à confirmer. |
| `libx11` | 0 / 1 | wont-fix: 1 | Bibliothèques X11 transitives ; absence de session X11 prévue ne prouve pas absence de tout appel vulnérable. |
| `libxml2` | 1 / 7 | not-fixed: 7, wont-fix: 1 | Parsing XML ; consommateurs de XML non fiable à inventorier. |
| `libxrender` | 0 / 1 | wont-fix: 1 | Fonctions XRender ; pas de serveur X prévu, chemin effectif non établi. |
| `ncurses` | 0 / 1 | wont-fix: 1 | Traitement terminal/capacités ; entrées et consommateurs à inventorier. |
| `pcre2` | 0 / 4 | fixed: 4 | Compilation/exécution regex via bibliothèque native ; regex contrôlée ou entrée pathologique à vérifier. |
| `perl` | 5 / 8 | fixed: 11, wont-fix: 2 | Usage Perl requis ; CVE8376 spécifiquement build32bits, cibleamd64 ; autres CVE à trier séparément. |
| `python` | 2 / 11 | fixed: 13 | Interpréteur en exécution ; ssl/tarfile/Expat/tempfile selon CVE, dépend de données ou chaîneTLS atteignable. |
| `speex` | 0 / 1 | not-fixed: 1 | Traitement codec audio ; usages guacd/FreeRDP à vérifier. |
| `sqlite3` | 0 / 4 | wont-fix: 3, fixed: 1 | Moteur SQLite présent ; backend produit PostgreSQL ne suffit pas à exclure autres usages/outils. |
| `tiff` | 1 / 0 | wont-fix: 1 | Décodage image TIFF ; aucune entrée TIFF de P1-F identifiée, chemin natif non démontré. |
| `util-linux` | 0 / 8 | wont-fix: 4, fixed: 4 | Outils/bibliothèques système ; préconditions locales/mount/terminal propres à chaque CVE à vérifier. |
| `zlib` | 0 / 2 | fixed: 2 | Décompression native partagée ; flux contrôlable et consommateur nécessaires selon CVE. |

### Preuves, limites et suite de qualification

Preuves hors dépôt : `output/p1-f-image-scan-identity.json`, `p1-f-grype-installation.json`, `p1-f-grype-linux-db-import.json`, `p1-f-grype-linux-scan-execution.json` (échec initial), `p1-f-grype-linux-scan2-execution.json` (scan terminé), `p1-f-os-package-inventory.json`, `p1-f-image-security-findings.json`. Le rapport brut `p1-f-grype-report2.private.json` porte le SHA-256 `f61d41fbac605fa39e5524788979a194a9fee31e64c7471a24154b778d73aba6` ; il n’est pas ajouté au dépôt.

La revue ne revendique ni exploitation démontrée de chacune des CVE, ni audit exhaustif du binaire guacd compilé, ni qualification ARM/NAS. Aucun test destructif ou charge réseau n’a été effectué. Le résultat concerne exclusivement l’archive identifiée en tête. Les ressources du scanner sont de nouveaux conteneurs arrêtés et une cache propre à cette tâche ; aucun volume existant n’est supprimé.

Avant publication utilisable : reconstruire avec interpréteur et paquets corrigés, traiter le risque RDP séparément, relancer le scan complet sur **l’image finale exacte**, puis les tests d’import LDAP, `pip check`, TLS/StartTLS et broker concernés. Conserver les états non corrigés et les limites d’applicabilité dans un suivi révisable ; ne pas ajouter une exclusion générale pour obtenir une CI verte. Le succès des tests applicatifs ou de pip-audit ne remplace pas ce contrôle OS/native.

## Requalification du candidat local avec backport GDI

Le rapport initial ci-dessus est conservé comme preuve de découverte. Un premier remplacement FreeRDP/Python (`86651d…`) a corrigé les versions mais révélé une incompatibilité fonctionnelle de guacd 1.6.0 avec le cycle GDI de FreeRDP ≥3.31. Cette archive reste un témoin, pas un candidat fonctionnel approuvé.

Le candidat suivant intègre un backport ciblé du [commit Apache ab36756](https://github.com/apache/guacamole-server/commit/ab36756b596520ae2a94cd4d25e406e0b5aa820b), distinct du patch P0 qui interdit les redirections. La revue statique indépendante confirme le déplacement de GDI et des handlers dans PostConnect, le maintien de la configuration des canaux dans PreConnect et la conservation des callbacks d’authentification/certificat et du refus de redirection. Le hash des deux patches et le commit amont sont désormais imposés par le vérificateur natif.

| Identité du nouveau snapshot local | Valeur |
| --- | --- |
| Archive | `p1-f-production-gdi-qualified.tar` |
| SHA-256 recalculé indépendamment | `bf5d0075a25d2fc834aa5b21690fac709c62244a5f3330eee8296e1f58512cca` |
| Manifeste OCI | `sha256:0585b52ad0db2aac7e3da04b6cea30f810773e03498583ef06a8b4630d5a6943` |
| Configuration, octets vérifiés dans l’archive | `sha256:cd487974f48fd1ed1c2bbb2f79b1fedc6bbcf5aa790329ff2118155502b80e77` |

Le manifeste natif extrait de l’archive a été comparé au rapport réel en rootfs lecture seule : égalité exacte, `verified=true`, `live_link_probe=true`, 10 ELF et versions API FreeRDP/WinPR 3.33.1, guacd 1.6.0. Les options, chemins de chargement, métadonnées de compilation et deux patches attendus sont contrôlés. Le [contrat d’inventaire et de SBOM](native-supply-chain.md) détaille les limites de cette preuve.

### Résultats du scan exact

Même Grype 0.121.3, base du 11 novembre 2026 validée, aucune règle utilisateur d’ignorance/exclusion (quatre règles kernel internes sans `ignoredMatches` rapporté sur ce témoin), réseau désactivé, un seul scanner séquentiel borné à 256 MiB / CPU 1 / 128 tâches, aucun OOM :

| Mesure | Résultat |
| --- | ---: |
| Analyse complète de l’archive OS/native | terminée en 34,594 s |
| Correspondances / identifiants distincts | 349 / 158 |
| Critical / High | **0 / 102** |
| Medium / Low / Negligible / Unknown | 111 / 20 / 77 / 39 |
| `fixed` / `not-fixed` / `wont-fix` | 14 / 164 / 171 |
| High/Critical avec correctif disponible pour la distribution selon la base | **0** |
| Analyse du SBOM applicatif/compilé avec CPE qualifiés | terminée en 14,547 s, **0 correspondance** |

Le code de sortie de l’analyse OS reste **2**, puisque le seuil High est dépassé. Il n’est pas réinterprété en succès universel. Les résidus OS ont été comparés aux findings du témoin précédent par tuple paquet/version/CVE/sévérité/état/version corrigée : égalité exacte.

Le SBOM de 40 composants préserve les 27 composants applicatifs et ajoute identité de l’image, deux paquets compilés et dix ELF. Les tuples fournisseur/produit CPE sont qualifiés par l’API officielle NVD ; une contre-épreuve de versions anciennes synthétiques déclenche 222 correspondances et les deux CVE attendues. Le contrôle initial avec generic purl seul avait donné zéro et a été identifié comme une lacune de couverture, pas comme un succès. Le scan SBOM ne remplace pas celui des paquets OS.

### Risques résiduels conservés

Les 102 correspondances High représentent 35 couples `(paquet source, CVE)`, répartis sur 13 familles : krb5 (7), cJSON (4), perl (2), Expat (4), ncurses (1), gcc-14 (2), cyrus-sasl2 (1), glibc (3), SQLite (3), libXrender (1), util-linux (4), libX11 (1), acl (2). Aucun de ces couples n’est effacé pour rendre un seuil vert. Leur exposition exige une analyse précise par fonction, composant effectivement lié et entrée contrôlable.

Exemples vérifiés dans le suivi fournisseur : cJSON CVE-2026-67215 vise l’application de JSON Patch par cJSONUtils, krb5 CVE-2026-112314 vise des clients GSS-RPC, Expat CVE-2026-117610 vise un sous-parseur d’entité externe avec découpage spécifique des entrées. Ces préconditions ne sont ni une démonstration d’exploitation ni une exemption de tous les usages du paquet. [cJSON](https://security-tracker.debian.org/tracker/CVE-2026-67215), [krb5](https://security-tracker.debian.org/tracker/CVE-2026-112314), [Expat](https://security-tracker.debian.org/tracker/CVE-2026-117610).

Les 14 correspondances `fixed` restantes concernent pip 25.0.1 (six Medium/Low) et des matches binaires Python 3.12.16 (huit Medium/Low/Negligible). Certaines listes de versions corrigées Python ne mentionnent pas la branche 3.12 : elles doivent être confrontées aux versions réellement affectées et aux plateformes, sans migration aveugle vers une autre branche ni suppression globale des résultats.

Le build amont FreeRDP a aussi produit des avertissements GCC dans des fonctions WinPR. Aucun patch arbitraire ne les masque. La provenance signée et un scan de vulnérabilités ne constituent pas une revue exhaustive de ces chemins C.

### Portée et preuves finales locales

Preuve consolidée : `output/p1-f-gdi-independent-security.json`. Rapports bruts OS `p1-f-grype-gdi-os.private.json` (SHA-256 `fc39e20965d63ae1787bb6c1b71a56d709a803205fc555770403ac6629712d83`) et SBOM `p1-f-grype-gdi-sbom.private.json` (SHA-256 `253c3b3afcdd85b9d454d35185668d23883072b70b54dcffafde89833aa42ed7`). Matrice résiduelle complète : `p1-f-remediated-independent-security.json`, validée identique pour ce candidat. Les versions de scanner/base et durées sont conservées dans les rapports d’exécution dédiés.

L’agent infrastructure rapporte ensuite **10/10 SSH en 42,881 s et 9/9 RDP en 36,118 s**, avec DNS fermé. Les premiers échecs (9/10 SSH, cause non attribuée, et 1/9 RDP en phase préauthentification) restent conservés dans les preuves ; ils ne sont pas retirés de l’historique. La régression P0 ciblée rapporte **193 tests en 263,261 s avec un skip explicitement réservé à SQLite**. Aucun de ces résultats ne constitue une qualification NAS ni une autorisation de publication.

Ce candidat est un snapshot de travail local ; ses bibliothèques sont identifiées, mais il ne doit pas être présenté comme l’image exacte d’un futur commit ou d’un build CI différent. Les annotations de documentation ont été complétées après la construction. Toute publication exige le rattachement au commit approuvé, les qualifications fonctionnelles manquantes et le scan de l’artefact effectivement promu, avec décision explicite sur les risques résiduels.

## Checkpoints B1 et B2 : configuration de scan stricte et pilote système

Le témoin B1 (`p1-f-runtime-20261111-b1-production.tar`, SHA-256 `fda9262804e47baedaac28e57fe27e658294281400fb2f03359b04d4dc7c0fb7`) met pip à jour en 26.3. Son scan **strict** a réellement terminé en 56,047 s, mémoire 256 MiB, sans OOM : **343 correspondances, 0 Critical, 102 High, 106 Medium, 19 Low, 77 Negligible, 39 Unknown**. Les six findings pip ont disparu. La configuration rapportée a `ignore=[]`, `match-upstream-kernel-headers=true`, `include-matcher-suppressions=true` et `ignoredMatches=0`. Ce résultat ne reprend pas les limites de visibilité des premiers témoins. Les High restent 35 couples source/CVE sur 13 familles, sans exemption installée.

Le checkpoint B2 remplace sous Linux psycopg-binary par **psycopg-c 3.2.10** lié à libpq système, afin de supprimer les copies vendored de krb5/gssapi/ldap/sasl/crypto qui échappaient au suivi dpkg. L’archive locale `p1-f-runtime-20261111-b2-production.tar` a pour SHA-256 `91f42cac5b0700f61129b9b136a4626efb1c95c13ee5df95e74c2d9c4c756091`, manifeste `sha256:d0f194f8a34c33ae659c76acad6879414f83a9a7d86f93db672bac7522dbb3a8`, configuration `sha256:bb310bd26a512a93a5cecf7b9e55109a5551878969a1e6baf939080a325f008b`. Hash d’archive et octets de configuration ont été vérifiés indépendamment. Le rescan exact B2 a réellement terminé en **34,813 s**, mémoire 256 MiB, sans OOM : **343 correspondances, 0 Critical, 102 High, 106 Medium, 19 Low, 77 Negligible, 39 Unknown**. Configuration stricte validée, aucune règle `ignore`/`exclude`/VEX et zéro résultat ignoré. Les **35 empreintes source/CVE correspondent exactement** à la politique initiale, toujours toutes `untriaged`. Le résultat B1 ne lui a pas été recyclé. Rapport brut local : `output/p1-f-grype-psycopg-c-strict-os.private.json`.

Le gate driver réel rapporte implémentation C 3.2.10, libpq de build/runtime **170011**, deux extensions ELF et dix-huit dépendances système. La suite complète de transport B2 et les connexions TLS/SCRAM ont leurs preuves séparées. La fermeture de ce vendoring ne prouve pas que toutes les dépendances natives du Python runtime sont recensées : le wheel cryptography utilise notamment sa propre version OpenSSL, à vérifier séparément. Aucun zéro natif global n’est annoncé.

Le checkpoint source inclut **100/100 tests d’outillage en 3,578 s, Ruff réussi**, dont le gate hors ligne, les inventaires, le SBOM, les contrôles driver et DNS. Le contrôle pre-commit sur 612 fichiers a réussi hors réseau ; les faux positifs historiques sont préservés et les nouveaux hashes publics ont été revus individuellement. La politique [image-scan-policy](image-scan-policy.md) bloque volontairement la promotion avec ses 35 entrées `untriaged` ; la revue de triage et l’éventuel backport Kerberos sont des travaux distincts. Le code peut être présenté en revue CI sans fusion main, publication d’image ou déploiement tant que ces blocages ne sont pas levés. Le delta de compatibilité JSON Grype (champ vide `ignoredMatches` omis par le format officiel) a ensuite été validé séparément : **22/22 tests du gate en 0,257 s**, Ruff réussi, sans changement applicatif. Le rapport final CI doit concerner l’artefact exact construit depuis le commit, pas ce témoin local.
