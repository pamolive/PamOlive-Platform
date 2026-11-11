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

## Décision de sécurité

Les seuils sont dans le code, sans option CLI pour les abaisser :

1. Toute correspondance **Critical réelle** bloque.
2. Toute correspondance **High avec correctif disponible** bloque, même si une exception est déclarée.
3. Tout High nouveau, modifié ou non trié bloque.
4. Une exception ne peut concerner qu’une empreinte exacte classée `not_reachable`, assortie d’une analyse d’exposition individuelle, de sources fournisseur, de preuves locales hashées, de conditions vérifiées dans l’archive et d’une revue datée expirant au plus tard après trente jours.

L’empreinte couvre le scope OS/compiled, paquet source, identifiant de vulnérabilité, sévérité, état de correction, namespace, source de données, distribution/version et liste précise des binaires, versions, types et purl concernés. Elle regroupe les répétitions d’une même CVE sur plusieurs binaires Debian sans effacer leurs identités. Un changement de version, de distribution ou d’autorité de scan invalide l’ancienne empreinte. Une exception OS ne s’applique pas implicitement au composant compilé ou à une copie vendored.

Une entrée `not_reachable` exige un analyste et deux identifiants de relecteurs distincts de l’analyste. **Ces chaînes sont des métadonnées de revue déclaratives** : le contrôle hors ligne n’authentifie pas les personnes et ne démontre pas leur indépendance. L’authenticité des décisions dépend des permissions du dépôt, de la revue des modifications et des protections GitHub existantes. Aucun nouveau mécanisme de consentement utilisateur n’est introduit par ce fichier.

Les preuves locales doivent rester dans des chemins du dépôt contrôlés, avec hash inchangé. Les conditions disponibles sont l’absence d’un basename glob, l’absence d’un suffixe de chemin ou l’identité SHA-256/classe d’un ELF précis. Le gate lit les layers sans extraire ni exécuter leur contenu. Pour les absences, l’union des noms de **tous** les layers est volontairement conservatrice : supprimer un composant dans un layer supérieur ne prouve pas qu’il n’existe plus dans l’artefact distribué. Pour les preuves ELF, whiteouts, répertoires opaques et remplacement d’ancêtres invalident le sous-arbre ; les liens ne sont jamais suivis. Une analyse de non-invocation exige des preuves et conditions couvrant aussi les consommateurs pertinents, pas seulement la bibliothèque vulnérable. La validation structurelle d’une décision ne remplace pas sa justification technique.

Une classification « composant absent » ne s’étend pas aux fonctions présentes du même paquet ; « profil réduit » n’est pas « non affecté ». Les propositions de triage restent bloquantes tant qu’elles n’ont pas de preuves suffisantes et de contre-revue. La politique initiale ne contient aucune exemption, même pour les candidats de clôture proposés dans `docs/p1-f-os-high-triage.md`.

## Résultat, limites et conservation des preuves

La sortie est créée exclusivement en mode 0600 avant lecture des entrées ; un fichier existant n’est pas écrasé. Les clés JSON dupliquées, dépassements de budgets et chemins de preuve non autorisés échouent. Les inputs sont conservés par leurs hashes, sans publier la configuration brute ou des secrets. Codes : `0` politique satisfaite, `2` résultats complets mais promotion bloquée, `1` preuve ou format invalide. Le wrapper conserve séparément les codes scanner : un `2` Grype peut être un seuil dépassé, mais un crash produisant un JSON vide ne passe jamais le gate.

`passed=true` n’est pas synonyme d’absence de vulnérabilités. `all_findings_clear` reste faux si des findings ou suppressions subsistent, même après une décision individuelle conforme. Les rapports complets et les risques résiduels restent disponibles ; aucune règle globale ne les masque.

Le scope SBOM déclaré couvre applications et composants natifs explicitement inventoriés, notamment FreeRDP/Guacamole ; le scan d’archive complète le suivi des paquets OS. Des bibliothèques embarquées dans les wheels peuvent rester hors de ces inventaires. Le vendoring de psycopg-binary a été identifié comme tel et doit être supprimé ou qualifié séparément avant toute affirmation plus large. Les scans ne remplacent ni les tests fonctionnels, ni TLS/SCRAM, ni l’isolation multi-organisations, ni les migrations/restaurations. Aucune qualification NAS ne découle de ce gate.

## Tests

`python -m unittest tests.test_image_scan_policy` : **22/22 en 0,257 s**, aucun skip, Ruff réussi. Les données sont entièrement synthétiques, sans Grype exécuté, réseau, Docker ou base de données. Le test CLI complet construit un petit bundle avec labels/révision/config cohérents et vérifie aussi le rejet d’un scanner altéré. Les contre-exemples incluent Critical, High corrigible, High non trié, nouvelles identités/versions/distributions, mauvais scope, filtres/VEX/suppressions, contrôle positif manquant, base périmée/mixte/future, configuration incohérente, preuves modifiées/expirées, output existant et archives à deux/trois layers avec suppressions et ancêtres remplacés.
