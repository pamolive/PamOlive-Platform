# ADR-030 — Jansson pour le JSON natif de FreeRDP/WinPR

Décision d'architecture acceptée pour qualification ; aucune promotion produit.

## Problème et décision

Le candidat historique contient cJSON et quatre groupes High associés. Remplacer
ce composant exige de contrôler le backend effectivement compilé, ses consommateurs
et tous les fichiers physiques de l'image, y compris les couches masquées.

Utiliser le backend Jansson existant de FreeRDP 3.33.1, avec le paquet Debian
Jansson `2.14-2+b3` précisément identifié. Exiger Jansson dans CMake et refuser
cJSON, JSON-C et le backend désactivé dans les options, les commandes générées,
l'inventaire natif et le SBOM. Conserver les contrôles de signature des sources,
de chargement, de RPATH, de compilation et les transports SSH/RDP existants.

Le patch limité au wrapper WinPR refuse les clés dupliquées, les longueurs
incompatibles et les NUL incorporés ; il conserve les scalaires en lecture et
écriture et renvoie NaN pour une demande numérique sur un autre type. Les erreurs
n'incluent pas le contenu fourni. Aucun analyseur JSON propre à PamOlive n'est créé.

## Alternatives et compatibilité

Un backport cJSON maintiendrait le composant vulnérable et demanderait une preuve
par advisory. JSON-C introduit d'autres coercitions et écarts de parsing. Jansson
réutilise un backend amont, mais sa casse, son ordre d'impression, ses entiers et
sa profondeur diffèrent de cJSON : ne pas annoncer une équivalence générale.

Un exécutable de référence compare les anciennes décisions aux règles retenues.
Il reste dans une étape Docker distincte ; seuls six fichiers JSON/JSONL sortent
de la cible scratch. Aucune bibliothèque cJSON ni ELF de référence n'appartient
aux ancêtres de production ou de native-test.

## Preuves et limites

La réception lie les sources committées et réellement exécutées, la révision,
l'archive qualifiée, sa configuration et ses bibliothèques aux oracles build et
runtime. Elle refuse cJSON dans toutes les couches, dpkg et l'inventaire dérivé.
Cet inventaire dpkg est une projection DATA, pas un scanner indépendant. Les
scans Grype complets et leur politique de blocage restent obligatoires.

La capture des empreintes lit un seul descripteur borné et vérifie son identité
avant/après, ainsi que celle du chemin. L'heure d'accès est exclue ; propriétaire,
permissions, liens, taille, modification et changement restent contrôlés. Ce
mécanisme ne constitue pas un snapshot du noyau ni une attestation du builder.

Les contrôles synthétiques ne prouvent ni la compilation ni la compatibilité
native. La première campagne est limitée à la branche de qualification. Avant
promotion, rendre ce contrôle applicable à la branche livrée et requalifier
l'image exacte, SSH/RDP/NLA, PostgreSQL, les P0, restauration et scans. Aucun
finding n'est clos sur la seule absence d'un paquet dans dpkg.

## Migration et récupération

Aucune migration Django ou donnée métier ne change. Le remplacement nécessite
une nouvelle image qualifiée ; conserver le digest et les preuves historiques.
Un retour à une ancienne image réintroduirait ses risques connus : ne pas le
présenter comme une récupération sûre ni restaurer les données en service.

Voir [la campagne de qualification](p1-f-jansson-qualification.md).
