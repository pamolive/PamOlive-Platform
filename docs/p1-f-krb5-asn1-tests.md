# B3 — régression ASN.1 MIT Kerberos, uniquement dans le builder

Le harnais `tests/fixtures/krb5_asn1_regression.c` appelle le **véritable décodeur MIT1.21.3 `decode_krb5_etype_list`**, depuis les objets de construction asn1_encode et asn1_k_encode. Il ne copie pas l'algorithme ASN.1, ne réécrit pas le codec et n'utilise aucune API privée depuis l'application Django. L'utilisation des headers internes MIT est limitée à ce test versionné de construction.

Le harnais n'est pas installé dans le runtime et n'est pas exécuté par les suites Django/PostgreSQL. Il n'accède à aucun socket, credential, KDC, compte ou système réel. Ses données sont exclusivement des séquences DER synthétiques bornées :256entiers de valeur7, moins de1KiB.

## Pourquoi le compteur remplace un test temporel

Le correctif MIT205832663330da308d9d031a17326b68a16715fd remplace la croissance du tableau par élément par une allocation après comptage des tags. Le linker du **binaire test seulement** intercepte malloc/calloc/realloc/free avec `--wrap`. Les deux vrais objets MIT sont liés directement ; passer seulement une bibliothèque partagée rendrait les hooks potentiellement inopérants.

Le cas long valide calibre les hooks :

- Phase `baseline` :256realloc et1calloc pour l'objet racine.
- Phase `patched` :0realloc et2calloc, soit l'objet racine et **un seul tableau de séquence**.
- Même nombre d'éléments décodés et mêmes valeurs dans les deux phases ; aucune allocation vivante après nettoyage.

Un wrapper absent, un mauvais jeu d'objets, le mauvais décodeur ou un repli DSO ne produit pas un succès silencieux : le calibrage exact échoue. Aucune durée d'exploitation ni benchmark de saturation n'est revendiqué.

## Cinq groupes, six résultats nommés

1. `long_valid` :256INTEGER DER valides, succès, longueur et valeurs contrôlées. Compteurs avant/après comme ci-dessus.
2. `empty` :SEQUENCE vide acceptée selon le contrat existant, nettoyage complet.
3. `bad_tag` et `truncated` :respectivement deuxième élément de mauvais type et DER tronqué ; refus, sortie nulle et aucune fuite.
4. `allocation_failure` :chaque point d'allocation du cas valide est forcé à échouer une fois, de1à257avant et de1à2après. Chaque décodage doit échouer avec sortie nulle et nettoyage complet ; aucune exception simulée de codec ne remplace l'appel réel.
5. `partial_cleanup` :deux INTEGER de bon tag, dont le second dépasse le domaine int32. Cela oblige le décodeur à traiter un préfixe valide avant erreur sémantique, même après prévalidation des tags du correctif. Refus et nettoyage complet requis.

Le compteur de pointeurs est borné à1024entrées. Les sorties stdout sont un JSON contrôlé ; la preuve n'inclut pas de données externes.

## Interface de la porte builder

```sh
sh deploy/check_krb5_asn1.sh \
  --source /build/krb5-baseline/src \
  --build /build/krb5-baseline-build \
  --phase baseline \
  --harness /build-fixtures/krb5_asn1_regression.c \
  --output /proofs/asn1-baseline.json

sh deploy/check_krb5_asn1.sh \
  --source /build/krb5-patched/src \
  --build /build/krb5-patched-build \
  --phase patched \
  --harness /build-fixtures/krb5_asn1_regression.c \
  --output /proofs/asn1-patched.json
```

Les chemins d'exemple sont propres à un builder neuf ; ils ne désignent aucune installation utilisateur. `--source` est le répertoire `src/` MIT. Les répertoires de build doivent avoir leurs headers générés et leurs objets correspondants. Le suffixe PIC MIT `.so` est accepté uniquement si l'en-tête ELF prouve un objet relocatable ET_RELamd64, jamais une bibliothèque ET_DYN. `.o` est préféré s'il est disponible. Aucun objet d'un autre build n'est recherché sur le système.

Compilation du binaire test :C99, pas de LTO ni transformation builtin des allocateurs, avertissements traités en erreurs, headers source/build explicites et bibliothèques de ce build. CPU30secondes, mémoire512MiB ; exécution CPU5secondes, mémoire256MiB, core dumps refusés et stdout bornée. Le conteneur englobant doit imposer réseau `none` et ses propres plafonds ; les limites du script ne remplacent pas cette isolation.

Le schéma de chaque phase est `pamolive.krb5-asn1-regression.v1` :phase, six cases, compteurs, résultat sémantique, allocations vivantes après nettoyage, hash du source encodeur, des deux objets, du harnais et du binaire test. Le hash du patch référencé est `e676f3727b3c984aa5a7baaafdb39394c8774c913ace0c3ce302e9b81aaa19ee`. Une sortie0600est réservée exclusivement avant les sondes ; un fichier existant n'est pas écrasé et un échec peut laisser une réservation vide, sans faux verdict de réussite.

L'agrégateur du builder doit conserver les deux rapports complets et leurs hashes, vérifier les sources et le patch exacts, puis relier les résultats au paquet de bibliothèques et au digest final. Ces champs sont des références de construction, pas une attestation cryptographique autonome de compilation. Une invocation avec un autre harnais ne remplace pas le hash approuvé du harnais fourni par le dépôt.

## Portes qui restent obligatoires

Ce test ciblé **ne remplace pas `make check` MIT** :encodage/décodage/fuites, tests de protocole et régressions amont restent exécutés par le propriétaire du build. Il ne remplace ni la comparaison d'ABI, les contrôles des bibliothèques réellement chargées, l'inventaire du backport, ni PostgreSQL TLS/SCRAM/GSS et PAM/NLA synthétiques. Une preuve de nombre d'allocations ne démontre pas toutes les propriétés de performance ou d'intégrité du décodeur.

État initial :sources du harnais et de la porte créées ; aucune réussite avant/après n'est revendiquée tant que le propriétaire du builder n'a pas exécuté les deux phases sur les vrais objets et communiqué les résultats. Les résultats Linux seront consignés séparément avec leurs identités de build.

## Diagnostic des échecs de qualification

Le premier build B3r2 a atteint la porte après les tests Debian baseline, puis a échoué avec le seul message générique `krb5_asn1_regression_failed`. Ce message ne permet pas d'attribuer la cause à la compilation ou au décodeur. Aucun résultat ASN.1 réussi n'en est déduit et aucun des six cas n'est retiré.

La porte distingue désormais `stage=structural`, `compile`, `run` ou `validate`, en plus de la phase baseline/patched. Un défaut de sélection d'objet indique les noms et tailles des candidats, puis les vingt premiers octets d'en-tête ELF du candidat choisi ; il ne transforme pas un mauvais objet en repli DSO. Un échec de processus conserve code de retour, expiration éventuelle, tailles stdout/stderr et au plus 4 096 octets de stderr. Les chemins source/build/harnais/temporaire sont remplacés par des marqueurs. Les diagnostics JSON sont émis sur stderr ; une sortie de preuve réservée mais vide reste un échec.

Les sorties du compilateur et du harnais sont dirigées vers des fichiers temporaires soumis à RLIMIT_FSIZE de 4 MiB par fichier, en plus des budgets CPU/mémoire/temps existants. La lecture du diagnostic est bornée avant décodage ; la sortie JSON réussie du harnais reste limitée à 65 536 octets. Aucun environnement, commande complète, source arbitraire ou contenu de sortie réussie n'est recopié dans les diagnostics. Cet affichage n'est autorisé que dans le builder synthétique de confiance, sans secret ni donnée réelle.

Le C émet un nom de cas statique et ses compteurs d'allocation lorsqu'un des cas ou la calibration échoue. Les assertions, données DER, attentes de comptage et nettoyages restent identiques. Les diagnostics ne remplacent ni la compréhension de la cause par le propriétaire du builder, ni une nouvelle exécution avant/après réussie.

Le diagnostic Linux v2 a identifié la cause effective du premier échec : six avertissements `unused-parameter` dans les fonctions inline de l'en-tête MIT `k5-thread.h`, promus en erreurs par `-Wextra -Werror`. La compilation du harnais s'arrêtait avant la liaison ; aucune erreur de longueur ou d'objet ELF n'a été démontrée. Les trois répertoires d'en-têtes MIT sont désormais transmis avec `-isystem` pour distinguer ces headers tiers du fichier C du harnais. Les options `-Wall -Wextra -Werror` restent actives sur le harnais ; aucun `-Wno-unused-parameter` global, changement de source MIT, retrait de cas ou affaiblissement du calibrage n'est ajouté. Les objets de bibliothèque et leurs propres tests Debian conservent leur compilation d'origine. Une nouvelle exécution Linux reste nécessaire pour qualifier la liaison et les six cas.
