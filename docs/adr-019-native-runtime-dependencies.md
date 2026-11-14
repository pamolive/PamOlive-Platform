# ADR-019 — actualiser et qualifier les dépendances natives du runtime

Statut : décision retenue, implémentation et qualification en cours. 11 novembre2026. Cette décision bloque la promotion de l’image candidate initiale ; elle ne constitue pas une qualification du remplacement.

## Problème démontré

L’archive locale du premier candidat F1/F2 contient Python3.12.13 et les bibliothèques FreeRDP3.15 de Debian trixie. Le scan Python applicatif n’inventorie ni l’interpréteur ni toutes les bibliothèques natives. Un scan Grype local, avec base publique vérifiée et sans envoi de l’image, a produit1326correspondances, dont69Critical et570High ; ce ne sont pas1326exploitations distinctes. Le [rapport indépendant](p1-f-image-security.md) conserve versions, doublons, états fournisseur et limites.

Les [correctifs Python3.12.16](https://www.python.org/downloads/release/python-31216/) nécessitent une nouvelle image de base. Debian confirme notamment FreeRDP vulnérable à [CVE-2026-45700](https://security-tracker.debian.org/tracker/CVE-2026-45700) et [CVE-2026-121954](https://security-tracker.debian.org/tracker/CVE-2026-121954) dans la version trixie alors disponible. Un serveur RDP autorisé mais compromis peut attaquer les décodeurs du client. Le pin TLS et l’interdiction des redirections conservent leur utilité, mais ne corrigent pas un décodeur vulnérable.

## Alternatives et décision

| Option | Garantie et limite | Décision |
| --- | --- | --- |
| Conserver uniquement le lock PyPI et le pin Docker actuels | Reproduit des dépendances anciennes ; ne corrige ni l’interpréteur ni les codecs | Insuffisant |
| Mettre à jour les seuls paquets trixie disponibles | Corrige des paquets de base ; certains correctifs FreeRDP requis ne sont pas livrés dans cette branche | Nécessaire, mais insuffisant seul |
| Importer des paquets sid dans le runtime stable | Introduit un mélange de distribution et des changements de dépendances/ABI difficiles à qualifier | Écarté |
| Désactiver le parcours RDP | Réduit l’exposition mais retire une fonction existante demandée | Écarté pour cette remédiation |
| Compiler une version FreeRDP3 maintenue et corrigée, puis requalifier guacd et ses pairs | Préserve le parcours RDP et permet d’identifier exactement les sources, options et bibliothèques utilisées | Retenu avec mise à jour du socle |

Utiliser une base Python de la série3.12 avec correctifs de sécurité actuels, explicitement épinglée par digest officiel vérifié. Actualiser les paquets Debian lors de la construction, puis installer les bibliothèques nécessaires. Chaque image réellement construite est qualifiée et promue sans reconstruction ; le build futur à partir de dépôts APT évolutifs n’est pas déclaré identique.

La première version source proposée est [FreeRDP3.33.1](https://github.com/FreeRDP/FreeRDP/releases/tag/3.33.1), publiée en amont. L’archive, sa somme, sa signature et l’identité de clé attendue doivent être vérifiées avant compilation. Une erreur de signature ou de checksum interrompt le build. Conserver les licences et métadonnées de provenance.

Compiler FreeRDP dans un préfixe propre, puis guacd1.6 et le pair de test RDP contre les mêmes en-têtes et bibliothèques. Le runtime contient les bibliothèques nécessaires et leurs licences, sans ancien FreeRDP Debian en concurrence, compilateur, en-têtes ou archive de construction. Les options de fonctionnalités et chemins de chargement sont explicites ; aucun dépôt sid ou fallback vers une bibliothèque ancienne n’est ajouté.

Le patch de redirections, NLA, le contrôle de certificat, les gardes de destination, les limites de session, les révocations et captures P0 restent obligatoires. Une compilation réussie ne prouve pas leur conservation. Les modifications de code nécessaires à la nouvelle API doivent être ciblées, relues et couvertes par les essais de transport réels.

## Pilote PostgreSQL et bibliothèques embarquées

La revue du graphe ELF révèle que `psycopg_binary.libs` embarque aussi des copies Kerberos, LDAP, SASL et OpenSSL hors dpkg. Le seul scan des paquets Debian et des préfixes FreeRDP/Guacamole ne couvre donc pas tous les composants natifs de l’image. Les mises à jour Debian ne corrigent pas ces copies. De plus, un SBOM généré avec `--no-deps` ne développe pas automatiquement les dépendances d’un extra : le lock doit énumérer explicitement l’implémentation du pilote.

| Variante | Conséquence | Décision |
| --- | --- | --- |
| Conserver le wheel binaire et ajouter chaque copie native à l’inventaire | Deux chaînes de bibliothèques TLS/Kerberos et de mise à jour restent à qualifier ; un upgrade du paquet Python ne prouve pas leur correction | Écarté pour le runtime Linux |
| Utiliser l’implémentation Python avec libpq système | Même protocole, mais perte de l’accélération C et fallback possible si le packaging est incomplet | Non retenu |
| Compiler psycopg-c contre libpq système, même version que le cœur | Élimine les copies du wheel binaire sur Linux et réutilise les bibliothèques réellement suivies par Debian ; nécessite build et vérification de liaison | Retenu |

Conserver le cœur et l’extension C en3.2.10 pour cette correction de packaging, sans changement de l’API ORM ni migration de données. Compiler la source PyPI vérifiée de psycopg-c dans le stage natif avec `libpq-dev`, installer `libpq5` dans le runtime et retirer toute dépendance au wheel binaire Linux. Le lock énumère explicitement cœur, extension C Linux et binaire non-Linux. Les marqueurs `pyproject.toml` suivent la même séparation pour éviter une réintroduction par un autre installateur. Le développement non-Linux garde son pilote binaire historique : il n’est pas qualifié comme runtime de production par cette décision.

Le bootstrap pip et les outils de build sont épinglés par version et hash de roues officielles ; la compilation psycopg-c utilise son sdist épinglé avec `--require-hashes --no-build-isolation --no-deps`. Le builder ne transmet ni compilateur ni roue intermédiaire au runtime. `PSYCOPG_IMPL=c` refuse un fallback implicite. Le [gate du pilote](database-driver-runtime.md) vérifie versions publiques, deux extensions réellement chargées, hashes, liaisons système et propriété dpkg, absence physique de l’ancien paquet et libpq réellement mappée. Il ne se substitue pas à une connexion PostgreSQL/TLS, aux transactions, à la concurrence ou à la restauration.

Cette variante est confirmée par la [documentation officielle Psycopg](https://www.psycopg.org/psycopg3/docs/basic/install.html#local-installation), les [API publiques du wrapper](https://www.psycopg.org/psycopg3/docs/api/pq.html) et la [source PyPI3.2.10](https://pypi.org/pypi/psycopg-c/3.2.10/json). Les spécialistes sécurité et infrastructure ont confronté le choix : accord sous réserve de l’absence physique des copies, du rescan des nouvelles dépendances et des suites PG/TLS/restauration ; aucune diminution de TLS, des timeouts ou des contrôles P0 n’est autorisée.

Les versions OpenSSL de Python et de cryptography sont inventoriées séparément. Ce changement ne prétend pas résoudre automatiquement l’inventaire de tous les autres wheels natifs ou bibliothèques statiquement incorporées. Une lacune de couverture reste explicite et interdit une déclaration de couverture native exhaustive.

## Itération B3 — backport Kerberos ciblé

Le [suivi Debian de CVE-2026-119079](https://security-tracker.debian.org/tracker/CVE-2026-119079) conserve trixie1.21.3-5+deb13u1 vulnérable. La croissance répétée d’un tableau ASN.1 peut provoquer un coût quadratique avant authentification. Le décodeur est partagé : l’absence de KDC dans le runtime ne suffit pas à démontrer l’absence de chemin client. Le [correctif MIT2058326](https://github.com/krb5/krb5/commit/205832663330da308d9d031a17326b68a16715fd) compte et valide les tags avant une allocation unique, puis décode les éléments. Il modifie une seule fonction statique, sans modifier de déclaration d’API exportée. La compatibilité ABI reste à mesurer, pas à déduire de cette seule observation.

| Variante | Risque ou dépendance | Décision |
| --- | --- | --- |
| Accepter `wont-fix` ou l’absence de serveur KDC comme exemption | N’écarte pas le code partagé réellement présent et ne corrige pas la fonction | Refusé |
| Désactiver Kerberos pour réduire le nombre de findings | Retire une capacité existante et ne constitue pas la correction demandée | Refusé |
| Importer sid ou superposer des SO amont sans cohérence dpkg/SDK | Risque ABI, dépendances et provenance contradictoires | Refusé |
| Backporter le correctif MIT minimal sur les sources Debian exactes, reconstruire paquets runtime et SDK | Maintient le packaging et réduit le delta ; exige tests, preuve ABI et chaîne de provenance | Retenu pour implémentation locale B3 |

Les spécialistes infrastructure, analyse des sources et Red Team ont confronté ce choix. Le hunk ancien correspond exactement une fois à la source1.21.3 et les patches Debian ne touchent pas ce fichier. `k5calloc` existe déjà et gère les tailles nulles et l’échec de calloc. Ces vérifications justifient une tentative de backport ; elles ne valent pas réussite de compilation ni qualification fonctionnelle.

Conditions de construction : sources APT trixie validées par InRelease/Sources, SHA256 exacts des archives et du correctif MIT, série Debian conservée, application sans fuzz, révision locale explicite `+pamolive1`, compilation séquentielle et tests activés. Les tests KDC/clients restent exclusivement synthétiques et loopback, dans un stage sans réseau externe. Ne copier ni KDC, outils de développement, keytabs ou fixtures privées dans le runtime. Les bibliothèques et paquets SDK employés par FreeRDP doivent partager la même révision locale, afin qu’une dépendance exacte du SDK ne réintroduise pas le paquet stock.

Portes avant réception : comparaison SONAME/symboles/versionnements avec les paquets Debian d’origine, tests ASN.1 vide/long/malformé/mauvais tag/échec d’allocation et nettoyage partiel sous limites, suites MIT/KDC locales, NLA et PostgreSQL TLS/SCRAM/concurrence/restauration, non-régressions P0, inventaire système et nouveau scan de l’archive exacte. Les essais B1/B2 demeurent historiques ; ils ne valident pas B3.

Le scanner peut conserver une CVE sur un paquet dont la version amont reste1.21.3 : conserver ce résultat brut. Une décision future `fixed_by_backport` doit être distincte de `not_reachable` et exiger sources, patch, paquets, ELF, preuve ABI et résultats réellement vérifiés. Aucun résultat de compilation, numéro de version artificiellement avancé ou fichier texte de provenance isolé ne suffit. Les autres findings du même paquet conservent leur analyse propre.

Le bac à sable refuse KEYRING via seccomp : le patch de compatibilité affecte uniquement le test Debian, aux deux arbres, sans autoriser le syscall. La réception distingue `passed_with_capability_skips`, avec probe EPERM, source et patch hashés, occurrences réelles et journaux des deux phases. Les autres exclusions amont sont inventoriées séparément ; ni LDAP KDB serveur absent ni DNS externe interdit ne sont déclarés qualifiés. Les tests ASN.1 avant/après demeurent obligatoires. Les diagnostics de préparation12cas démontrent le harnais et les compteurs ; ils ne remplacent pas le rebuild et les tests Debian des paquets finaux.

Les classifications individuelles doivent décrire leur garantie exacte. Pour les deux avis GCC étudiés, un build POSIX non affecté (`not_affected_build`) diffère du template GNU PBDS non employé par les consommateurs examinés (`code_not_present`). Le gate borne ces deux dispositions aux CVE/versions/preuves concernées, conserve les mêmes exigences de revue et d'expiration, et impose une sentinelle de l'ensemble ELF et de ses alias pour détecter les changements de périmètre. Une sentinelle détecte un changement ; elle ne prouve pas l'absence de tout chemin vulnérable. Les anciens constats de source et les signatures non vérifiées restent déclarés comme tels. Aucun de ces ajouts ne classe automatiquement l'un des35groupes High ni n'abaisse Critical, High corrigible, finding nouveau ou preuve invalide.

## Inventaire et scanner

Retirer un paquet Debian vulnérable peut supprimer un match du scanner tout en le rendant aveugle à son remplacement compilé. Produire donc un inventaire explicite de version, archive/signature/hash, options et fichiers compilés. Vérifier les dépendances réellement chargées par guacd, son plugin RDP et le pair de test ; un fichier de version isolé ne suffit pas. Le SBOM et le rapport de livraison doivent distinguer composants PyPI, Debian et compilés.

Conserver le rapport complet du scanner : états `fixed`, `not-fixed`, `wont-fix` et sévérité ne sont pas des verdicts d’exploitabilité. Tout reste doit être confronté à la plage de version réellement affectée, au suivi fournisseur et au chemin exposé. Aucune exemption globale d’un paquet, falsification de version, suppression de finding ou transformation d’un échec d’outil en scan réussi n’est autorisée.

Le pipeline doit analyser l’archive finale exacte avant sa publication et conserver identité d’image, version de l’outil/base, résultats et erreurs. La politique de qualification documente les risques résiduels ; elle ne transforme pas cette livraison de laboratoire en version de production.

## Réception et compatibilité

1. Build Linux réel des targets production et native-test, puis inventaire et chargement des bibliothèques vérifiés.
2. Essais SSH/RDP avec pairs synthétiques : pin/CA incorrects avant credentials, NLA, saisie/affichage, capture, redirections refusées et révocation fermant le transport.
3. Rejeu des gardes P0, isolation, concurrence, migration et restauration sur l’image et PostgreSQL restreint ; preuves V7/V8 et captures historiques conservées.
4. Démarrage Web/worker/PostgreSQL/TLS et démonstrateur local, arrêt/redémarrage sans perte.
5. Nouvelle analyse exhaustive de l’archive finale, triage indépendant, CI du SHA exact, puis digest et attestation de l’image promue.

Aucune migration de données ou régénération de clé applicative n’est impliquée par cette mise à jour de bibliothèques. Garder les anciennes archives pour preuves et récupération ne vaut pas autorisation de redéployer une version vulnérable. Aucun NAS, annuaire, serveur RDP ou compte privilégié réel n’est utilisé pour cette qualification. La compatibilité avec des serveurs commerciaux et les architectures non testées conserve son statut explicite.
